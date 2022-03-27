/*
 * Copyright (c) 2019,2022 Greg Becker.  All rights reserved.
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
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <vm/uma.h>
#include <sys/unistd.h>
#include <sys/sysctl.h>
#include <sys/cpuset.h>
#include <machine/stdarg.h>

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
    __aligned(CACHE_LINE_SIZE * 2)
    struct mtx          mtx;
    struct twhead       head;
    u_long              callbacks;
    bool                running;
    bool                growing;
    uint16_t            waiters;
    uint16_t            tdcnt;
    uint16_t            tdmax;

    __aligned(CACHE_LINE_SIZE)
    struct cv           cv;
    uint16_t            tdmin;
    u_long              grows;
    struct tpreq        grow;

    struct tpool       *tpool;
    struct tdargs       tdargs;
};

/* A thread pool exists for the purpose of asynchronous task
 * execution requiring kthread context.  It is comprised of
 * one or more thread groups, where there is one thread
 * group for each core.
 */
struct tpool {
#if MAXCPU > 256
    uint16_t            cpu2tgroup[MAXCPU];
#else
    uint8_t             cpu2tgroup[MAXCPU];
#endif
    int                 refcnt;
    int                 tgroupc;
    size_t              allocsz;
    uintptr_t           magic;

    struct tgroup       tgroupv[];
};

static inline struct tgroup *
tpool_cpu2tgroup(struct tpool *tpool, int cpu)
{
    uint8_t idx = tpool->cpu2tgroup[cpu % MAXCPU];

    return tpool->tgroupv + idx;
}

/* Create and start a kernel thread.
 */
static int
tpool_kthread_add(struct tdargs *tdargs)
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

#if (__FreeBSD__ < 13)
    thread_unlock(td);
#endif

    return 0;
}

int
tpool_hold(struct tpool *tpool)
{
    KASSERT(tpool->magic == (uintptr_t)tpool,
            ("bad magic: tpool %p, magic %lx", tpool, tpool->magic));
    KASSERT(tpool->refcnt > 0,
            ("bad refcnt: tpool %p, refcnt %d", tpool, tpool->refcnt));

    return atomic_fetchadd_int(&tpool->refcnt, 1) + 1;
}

void
tpool_rele(struct tpool *tpool)
{
    int i;

    KASSERT(tpool->magic == (uintptr_t)tpool,
            ("bad magic: tpool %p, magic %lx", tpool, tpool->magic));
    KASSERT(tpool->refcnt > 0,
            ("bad refcnt: tpool %p, refcnt %d", tpool, tpool->refcnt));

    if (atomic_fetchadd_int(&tpool->refcnt, -1) > 1)
        return;

    for (i = 0; i < tpool->tgroupc + 1; ++i) {
        mtx_destroy(&tpool->tgroupv[i].mtx);
        cv_destroy(&tpool->tgroupv[i].cv);
    }

    tpool->magic = ~tpool->magic;
    free(tpool, M_TPOOL);
}

static void
tpool_grow(struct tpreq *req)
{
    struct tgroup *tgroup = container_of(req, struct tgroup, grow);
    int rc;

    KASSERT(req && tgroup, ("invalid thread pool request"));

    rc = tpool_kthread_add(&tgroup->tdargs);
    if (rc)
        tpool_rele(tgroup->tpool);

    tgroup->growing = false;
}

void
tpool_enqueue(struct tpool *tpool, struct tpreq *req, int cpu)
{
    struct tgroup *tgroup;

    KASSERT(tpool && req && req->func, ("invalid thread pool request"));

    tgroup = tpool_cpu2tgroup(tpool, cpu);

    /* Append work to the target queue.  If we need to increase
     * the thread count of the target queue then append grow work
     * to the maintenance queue.
     */
    mtx_lock(&tgroup->mtx);
    STAILQ_INSERT_TAIL(&tgroup->head, req, entry);
    req = NULL;

    if (tgroup->waiters > 0) {
        cv_signal(&tgroup->cv);
    }
    else if (tgroup->tdcnt < tgroup->tdmax && !tgroup->growing) {
        tgroup->growing = true;
        req = &tgroup->grow;
        ++tgroup->grows;
    }
    mtx_unlock(&tgroup->mtx);

    if (req) {
        tgroup = tpool->tgroupv + tpool->tgroupc;

        tpool_hold(tpool);

        mtx_lock(&tgroup->mtx);
        STAILQ_INSERT_TAIL(&tgroup->head, req, entry);
        if (tgroup->waiters > 0)
            cv_signal(&tgroup->cv);
        mtx_unlock(&tgroup->mtx);
    }
}

void
tpool_shutdown(struct tpool *tpool)
{
    int i;

    KASSERT(tpool->magic == (uintptr_t)tpool,
            ("bad magic: tpool %p, magic %lx", tpool, tpool->magic));
    KASSERT(tpool->refcnt > 0,
            ("bad refcnt: tpool %p, refcnt %d", tpool, tpool->refcnt));

    /* Awaken all worker threads and tell them to exit.
     */
    for (i = 0; i < tpool->tgroupc + 1; ++i) {
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

    /* Wait for all worker threads to leave the run loop.
     */
    for (i = 0; i < tpool->tgroupc + 1; ++i) {
        struct tgroup *tgroup = tpool->tgroupv + i;

        mtx_lock(&tgroup->mtx);
        while (tgroup->tdcnt > 0)
            cv_timedwait(&tgroup->cv, &tgroup->mtx, hz);
        mtx_unlock(&tgroup->mtx);
    }

    /* Wait for all worker threads to drop their tpool references.
     */
    while (atomic_load_int(&tpool->refcnt) > 1)
        tsleep(tpool, 0, "tpwait1", hz / 10);

    /* Wait for all kthreads to exit.  Is there a way to do this
     * synchronously (other than sleeping on struct thread?)
     */
    for (i = 0; i < 5; ++i)
        tsleep(tpool, 0, "tpwait2", hz / 10);

    tpool_rele(tpool);
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

            ++tgroup->waiters;
            timedout = cv_timedwait(&tgroup->cv, &tgroup->mtx, hz * 30);
            --tgroup->waiters;
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

extern struct cpu_group *smp_topo_find(struct cpu_group *, int);
extern struct cpu_group *cpu_top;

struct tpool *
tpool_create(u_int tdmin, u_int tdmax)
{
    struct cpu_group **cgv;
    struct tgroup *tgroup;
    struct tdargs *tdargs;
    struct tpool *tpool;
    struct cpuset *set;
    struct thread *td;
    struct proc *proc;
    int i, rc, width;
    cpuset_t cpuset;
    size_t tpoolsz;
    int cgc;

#if MAXCPU > 256
    uint16_t cpu2tgroup[MAXCPU];
#else
    uint8_t cpu2tgroup[MAXCPU];
#endif

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

    CPU_COPY(&set->cs_mask, &cpuset);
    cpuset_rel(set);

    cgv = malloc(sizeof(*cgv) * mp_maxid, M_TPOOL, M_ZERO | M_WAITOK);
    if (!cgv)
        return NULL;

    /* Count the number of cpu groups (cores?) which we'll use as the
     * number of thread groups.  For each vCPU, add an entry to the
     * vcpu-to-thread-group map.
     */
    cgc = 0;

    CPU_FOREACH(i) {
        struct cpu_group *cg;
        int j;

        if (!CPU_ISSET(i, &cpuset))
            continue;

        cg = smp_topo_find(cpu_top, i);
        if (!cg)
            continue;

        for (j = 0; j < cgc; ++j) {
            if (!cgv[j] || cg == cgv[j])
                break;
        }

        cpu2tgroup[i] = j;

        if (!cgv[j]) {
            cgv[j] = cg;
            cgc++;
        }
    }

    free(cgv, M_TPOOL);

    tpoolsz = sizeof(*tpool) + sizeof(tpool->tgroupv[0]) * (cgc + 1);
    tpoolsz = (tpoolsz + 4095) & ~4095;

    tpool = malloc(tpoolsz, M_TPOOL, M_ZERO | M_WAITOK);
    if (!tpool)
        return NULL;

    tpool->refcnt = 2;
    tpool->tgroupc = cgc;
    tpool->allocsz = tpoolsz;
    tpool->magic = (uintptr_t)tpool;
    memcpy(tpool->cpu2tgroup, cpu2tgroup, sizeof(tpool->cpu2tgroup));

    for (i = 0; i < cgc + 1; ++i) {
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

        if (i == cgc) {
            strlcpy(tdargs->name, "tpool-maint", sizeof(tdargs->name));
            tdargs->prio = PRI_MAX_KERN - 1;
            tgroup->tdmin = 1;
            tgroup->tdmax = 1;
        }
    }

    /* For each vCPU, find the thread group to which it belongs
     * and add it to the thread group's affinity set.
     */
    for (i = 0; i < CPU_COUNT(&cpuset); ++i) {
        tgroup = tpool_cpu2tgroup(tpool, i);
        tdargs = &tgroup->tdargs;

        CPU_SET(i, &tdargs->cpuset);
    }

    /* Ensure that each thread group's affinity set is non-zero.
     */
    width = 0;
    for (i = 0; i < cgc + 1; ++i) {
        char buf[CPUSETBUFSIZ];

        tgroup = tpool->tgroupv + i;
        tdargs = &tgroup->tdargs;

        if (CPU_EMPTY(&tdargs->cpuset))
            CPU_COPY(&cpuset, &tdargs->cpuset);

        cpusetobj_strprint(buf, &tdargs->cpuset);
        if (strlen(buf) > width)
            width = strlen(buf);
    }

    for (i = 0; i < cgc + 1; ++i) {
        char buf[CPUSETBUFSIZ];

        tgroup = tpool->tgroupv + i;
        tdargs = &tgroup->tdargs;

        dprint("tgroup %3d %-12s  %2u %2u  %*s\n",
               i, tdargs->name, tgroup->tdmin, tgroup->tdmax,
               width, cpusetobj_strprint(buf, &tdargs->cpuset));
    }

    /* Start the maintenance kthread.
     */
    tgroup = tpool->tgroupv + cgc;
    tdargs = &tgroup->tdargs;

    rc = tpool_kthread_add(tdargs);
    if (rc) {
        dprint("unable to create maint kthread: rc %d\n", rc);
        tpool_rele(tpool);
        tpool_rele(tpool);
        return NULL;
    }

    dprint("%s: %4zu  sizeof mtx\n", __func__, sizeof(struct mtx));
    dprint("%s: %4zu  sizeof cv\n", __func__, sizeof(struct cv));
    dprint("%s: %4zu  sizeof tdargs\n", __func__, sizeof(struct tdargs));
    dprint("%s: %4zu  sizeof tpool\n", __func__, sizeof(struct tpool));
    dprint("%s: %4zu  sizeof tgroup\n", __func__, sizeof(struct tgroup));
    dprint("%s: %4zu  offsetof tgroup.cv\n", __func__, offsetof(struct tgroup, cv));
    dprint("%s: %4zu  sizeof tpreq\n", __func__, sizeof(struct tpreq));

    dprint("tdmin %u, tdmax %u, refcnt %d\n", tdmin, tdmax, tpool->refcnt);

    return tpool;
}
