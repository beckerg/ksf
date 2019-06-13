/*
 * Copyright (c) 2019 Greg Becker.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/sched.h>
#include <sys/sdt.h>
#include <sys/smp.h>
#include <vm/uma.h>
#include <sys/unistd.h>
#include <machine/stdarg.h>
#include <sys/sysctl.h>
#include <sys/cpuset.h>
#include <sys/sbuf.h>
#include <sys/mman.h>
#include <sys/module.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

#include "xx.h"
#include "tdp.h"

MALLOC_DEFINE(M_TPOOL, "tpool", "thread pool");

struct tdargs {
    void      (*func)(void *arg);
    void       *argv[4];
    char        name[15];
    u_char      prio;
    cpuset_t    cpuset;
};

STAILQ_HEAD(twhead, tpreq);

/* A thread group manages a work queue and zero or more threads
 * that are affined to one core (except the maintenance thread
 * group whose threads can run on any vCPU).
 */
struct tgroup {
    struct mtx          mtx;
    struct twhead       head;
    u_long              callbacks;
    bool                running;
    bool                growing;
    uint16_t            tdsleeping;
    uint16_t            tdcnt;
    uint16_t            tdmax;

    struct cv           cv;
    uint16_t            tdmin;
    u_long              grows;
    struct tpreq        grow;

    struct tpool       *tpool;
    struct tdargs       tdargs;

    /* Add extra padding so that the size is an odd number
     * of cache lines.
     */
    char                pad[CACHE_LINE_SIZE];
} __aligned(CACHE_LINE_SIZE);

/* A thread pool exists for the purpose of asynchronous task
 * execution that requiring kthread context.  It is comprised
 * of one or more thread groups, where there is one thread
 * group for each core.
 */
struct tpool {
#if MAXCPU > 256
    uint16_t            cpu2tgroup[MAXCPU];
#else
    uint8_t             cpu2tgroup[MAXCPU];
#endif
    int                 refcnt;
    int                 cgmax;
    size_t              allocsz;
    void               *magic;

    struct tgroup       tgroupv[];
};

static cpuset_t tpool_cpuset;

static inline struct tgroup *
tpool_cpu2tgroup(struct tpool *tpool, int cpu)
{
    uint8_t idx = tpool->cpu2tgroup[cpu % MAXCPU];

    return tpool->tgroupv + idx;
}

/* Create and start a kernel thread.
 */
static int
tpool_kthread_create(struct tdargs *tdargs)
{
    struct thread *td;
    int rc;

    if (!tdargs || !tdargs->func)
        return EINVAL;

    rc = kthread_add(tdargs->func, tdargs, NULL, &td, RFSTOPPED, 0, "%s", tdargs->name);
    if (rc) {
        eprint("kthread_add: name %s, rc %d\n", tdargs->name, rc);
        return rc;
    }

    rc = cpuset_setthread(td->td_tid, &tdargs->cpuset);
    if (rc)
        eprint("cpuset_setthread: name %s, rc %d\n", tdargs->name, rc);

    thread_lock(td);
    sched_prio(td, tdargs->prio);
    sched_add(td, SRQ_BORING);
    thread_unlock(td);

    return 0;
}

static int
tpool_hold(struct tpool *tpool)
{
    KASSERT(tpool->magic == tpool, "invalid tpool magic");
    KASSERT(tpool->refcnt > 0, "invalid tpool refcnt");

    return atomic_fetchadd_int(&tpool->refcnt, 1) + 1;
}

void
tpool_rele(struct tpool *tpool)
{
    int i;

    KASSERT(tpool->magic == tpool, "invalid tpool magic");
    KASSERT(tpool->refcnt > 0, "invalid tpool refcnt");

    if (atomic_fetchadd_int(&tpool->refcnt, -1) > 1)
        return;

    /* Give kthreads a brief opportunity to finish exiting.
     * Is there a way to to this synchronously???
     */
    tsleep(tpool, 0, "tpwait", 1);

    for (i = 0; i < tpool->cgmax + 1; ++i) {
        mtx_destroy(&tpool->tgroupv[i].mtx);
        cv_destroy(&tpool->tgroupv[i].cv);
    }

    tpool->magic = NULL;
    contigfree(tpool, tpool->allocsz, M_TPOOL);
}

static void
tpool_grow(struct tpreq *req)
{
    struct tgroup *tgroup = container_of(req, struct tgroup, grow);
    int rc;

    KASSERT(req && tgroup && ttpool, "invalid thread pool request");

    rc = tpool_kthread_create(&tgroup->tdargs);
    if (rc)
        tpool_rele(tgroup->tpool);

    tgroup->growing = false;
}

void
tpool_enqueue(struct tpool *tpool, struct tpreq *req, int cpu)
{
    struct tgroup *tgroup;

    KASSERT(tpool && req && req->func, "invalid thread pool request");

    tgroup = tpool_cpu2tgroup(tpool, cpu);

    /* Append work to the target queue.  If we need to increase
     * the thread count of the target queue then append grow work
     * to the maintenance queue.
     */
    mtx_lock(&tgroup->mtx);
    STAILQ_INSERT_TAIL(&tgroup->head, req, entry);
    req = NULL;

    if (tgroup->tdsleeping > 0) {
        cv_signal(&tgroup->cv);
    }
    else if (tgroup->tdcnt < tgroup->tdmax && !tgroup->growing) {
        tgroup->growing = true;
        req = &tgroup->grow;
        ++tgroup->grows;
    }
    mtx_unlock(&tgroup->mtx);

    if (req) {
        tgroup = tpool->tgroupv + tpool->cgmax;

        tpool_hold(tpool);

        mtx_lock(&tgroup->mtx);
        STAILQ_INSERT_TAIL(&tgroup->head, req, entry);
        if (tgroup->tdsleeping > 0)
            cv_signal(&tgroup->cv);
        mtx_unlock(&tgroup->mtx);
    }
}

void
tpool_shutdown(struct tpool *tpool)
{
    int i;

    KASSERT(tpool->magic == tpool, "invalid tpool magic");
    KASSERT(tpool->refcnt > 0, "invalid tpool refcnt");

    for (i = 0; i < tpool->cgmax + 1; ++i) {
        struct tgroup *tgroup = tpool->tgroupv + i;

        if (tgroup->callbacks > 0)
            dprint("tgroup %2d, grows %3lu, callbacks %8lu\n",
                   i, tgroup->grows, tgroup->callbacks);

        mtx_lock(&tgroup->mtx);
        tgroup->running = false;
        tgroup->tdmin = 0;
        tgroup->tdmax = 0;
        cv_broadcast(&tgroup->cv);
        mtx_unlock(&tgroup->mtx);
    }

    for (i = 0; i < tpool->cgmax + 1; ++i) {
        struct tgroup *tgroup = tpool->tgroupv + i;

        mtx_lock(&tgroup->mtx);
        while (tgroup->tdcnt > 0)
            cv_timedwait(&tgroup->cv, &tgroup->mtx, hz);
        mtx_unlock(&tgroup->mtx);
    }
}

static void
tpool_run(void *arg)
{
    struct tdargs *tdargs = arg;
    struct tgroup *tgroup;
    struct tpool *tpool;
    int timedout = 0;

    tpool = tdargs->argv[0];
    tgroup = tdargs->argv[1];

    mtx_lock(&tgroup->mtx);
    ++tgroup->tdcnt;
    mtx_unlock(&tgroup->mtx);

    while (1) {
        struct tpreq *req;

        mtx_lock(&tgroup->mtx);
      again:
        req = STAILQ_FIRST(&tgroup->head);
        if (!req) {
            if ((timedout && tgroup->tdcnt > tgroup->tdmin) || !tgroup->running)
                break;

            ++tgroup->tdsleeping;
            timedout = cv_timedwait(&tgroup->cv, &tgroup->mtx, hz * 30);
            --tgroup->tdsleeping;
            goto again;
        }

        STAILQ_REMOVE_HEAD(&tgroup->head, entry);
        ++tgroup->callbacks;
        mtx_unlock(&tgroup->mtx);

        req->func(req);
    }

    if (--tgroup->tdcnt < 1)
        cv_signal(&tgroup->cv);
    mtx_unlock(&tgroup->mtx);

    tpool_rele(tpool);

    kthread_exit();
}

extern struct cpu_group *smp_topo(void);
extern struct cpu_group *smp_topo_find(struct cpu_group *, int);

struct tpool *
tpool_create(u_int tdmin, u_int tdmax)
{
    struct cpu_group *cpu_top, **cgv;
    struct tgroup *tgroup;
    struct tdargs *tdargs;
    struct tpool *tpool;
    struct cpuset *set;
    struct thread *td;
    struct proc *proc;
    int i, rc, width;
    size_t tpoolsz;
    int cgmax;

    if (tdmin > 1024 || tdmax > 1024)
        return NULL;

    if (tdmax < tdmin)
        tdmax = tdmin;
    if (tdmax < 1)
        tdmax = 1;

    rc = cpuset_which(CPU_WHICH_CPUSET, -1, &proc, &td, &set);
    if (rc) {
        eprint("cpuset_which: rc %d\n", rc);
        return NULL;
    }

    CPU_COPY(&set->cs_mask, &tpool_cpuset);
    cpuset_rel(set);

    /* Count the number of cpu groups which we'll use as the number
     * of thread groups.
     */
    cgmax = 0;
    cpu_top = smp_topo();
    CPU_FOREACH(i)
        ++cgmax;

    cgv = malloc(sizeof(*cgv) * cgmax, M_TPOOL, M_ZERO);
    if (!cgv)
        return NULL;

    tpoolsz = sizeof(*tpool) + sizeof(tpool->tgroupv[0]) * (cgmax + 1);

    tpool = contigmalloc(tpoolsz, M_TPOOL, M_ZERO, 0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
    if (!tpool) {
        free(cgv, M_TPOOL);
        return NULL;
    }

    tpool->refcnt = 2;
    tpool->cgmax = cgmax;
    tpool->allocsz = tpoolsz;
    tpool->magic = tpool;

    for (i = 0; i < cgmax + 1; ++i) {
        tgroup = tpool->tgroupv + i;

        mtx_init(&tgroup->mtx, "wqmtx", NULL, MTX_DEF);
        cv_init(&tgroup->cv, "wqcv");
        STAILQ_INIT(&tgroup->head);
        tgroup->running = true;
        tgroup->tdmin = tdmin;
        tgroup->tdmax = tdmax;

        tdargs = &tgroup->tdargs;
        tdargs->func = tpool_run;
        tdargs->argv[0] = tpool;
        tdargs->argv[1] = tgroup;
        CPU_ZERO(&tdargs->cpuset);
        snprintf(tdargs->name, sizeof(tdargs->name), "tpool-%d", i);
        tdargs->prio = PRI_MAX_KERN;

        tpreq_init(&tgroup->grow, tpool_grow, NULL);

        if (i == cgmax) {
            strlcpy(tdargs->name, "tpool-maint", sizeof(tdargs->name));
            tdargs->prio = PRI_MAX_KERN - 1;
            tgroup->tdmin = 1;
            tgroup->tdmax = 1;
        }
    }

    /* For each vCPU, find the thread group to which it belongs
     * and add it to the vcpu-to-thread-group map and the thead
     * group's affinity set.
     */
    for (i = 0; i < CPU_COUNT(&tpool_cpuset); ++i) {
        struct cpu_group *cg;
        int j;

        if (!CPU_ISSET(i, &tpool_cpuset))
            continue;

        cg = smp_topo_find(cpu_top, i);
        if (!cg)
            continue;

        for (j = 0; j < cgmax; ++j) {
            if (!cgv[j] || cg == cgv[j])
                break;
        }

        if (!cgv[j])
            cgv[j] = cg;

        tpool->cpu2tgroup[i] = j;

        tgroup = tpool_cpu2tgroup(tpool, i);
        tdargs = &tgroup->tdargs;

        CPU_SET(i, &tdargs->cpuset);
    }

    /* Ensure that each thread group's affinity set is non-zero.
     */
    width = 0;
    for (i = 0; i < cgmax + 1; ++i) {
        char buf[CPUSETBUFSIZ];

        tgroup = tpool->tgroupv + i;
        tdargs = &tgroup->tdargs;

        if (CPU_EMPTY(&tdargs->cpuset))
            CPU_COPY(&tpool_cpuset, &tdargs->cpuset);

        cpusetobj_strprint(buf, &tdargs->cpuset);
        if (strlen(buf) > width)
            width = strlen(buf);
    }

    for (i = 0; i < cgmax + 1; ++i) {
        char buf[CPUSETBUFSIZ];

        tgroup = tpool->tgroupv + i;
        tdargs = &tgroup->tdargs;

        dprint("tgroup %3d %-12s  %2u %2u  %*s\n",
               i, tdargs->name, tgroup->tdmin, tgroup->tdmax,
               width, cpusetobj_strprint(buf, &tdargs->cpuset));
    }

    /* Start the maintenance kthread.
     */
    tgroup = tpool->tgroupv + cgmax;
    tdargs = &tgroup->tdargs;

    rc = tpool_kthread_create(tdargs);
    if (rc) {
        dprint("unable to create maint kthread: rc %d\n", rc);
        free(tpool, M_TPOOL);
        free(cgv, M_TPOOL);
        return NULL;
    }

    dprint("%s: %4zu  sizeof tdargs\n", __func__, sizeof(struct tdargs));
    dprint("%s: %4zu  sizeof tpool\n", __func__, sizeof(struct tpool));
    dprint("%s: %4zu  sizeof tgroup\n", __func__, sizeof(struct tgroup));
    dprint("%s: %4zu  sizeof tpreq\n", __func__, sizeof(struct tpreq));
    dprint("%s: %4u  MSIZE\n", __func__, MSIZE);
    dprint("%s: %4u  MHLEN\n", __func__, MHLEN);
    dprint("%s: %4u  MLEN\n", __func__, MLEN);

    dprint("tdmin %u, tdmax %u, refcnt %d\n", tdmin, tdmax, tpool->refcnt);

    /* Consider adjusting the tgroup padding if you see this message.
     */
    if (((sizeof(struct tgroup) / CACHE_LINE_SIZE) & 1) == 0)
        dprint("struct tgroup is an even number of cache lines\n");

    free(cgv, M_TPOOL);

    return tpool;
}
