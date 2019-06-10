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

MALLOC_DEFINE(M_XX_TDP, "xx_tdp", "xx thread pool");

struct xx_tdargs {
    void      (*func)(void *arg);
    void       *argv[4];
    char        name[15];
    u_char      prio;
    cpuset_t    cpuset;
};

/* A thread group manages a work queue and zero or more threads
 * that are affined to one core (except that maintence thread
 * group whose threads can run on any vCPU).
 */
struct xx_tdp_workq {
    struct mtx                  mtx;
    STAILQ_HEAD(, xx_tdp_work)  head;
    bool                        running;
    bool                        growing;
    u_int                       tdsleeping;
    u_int                       tdcnt;
    u_int                       tdmax;
    u_int                       tdmin;
    u_int                       spare;

    u_long                      callbacks;
    u_long                      grows;
    struct cv                   cv;
    struct xx_tdp_work          grow;

    struct xx_tdargs            tdargs;

    /* Add extra padding so that the size is an odd number
     * of cache lines.
     */
    char                        pad[CACHE_LINE_SIZE];
} __aligned(CACHE_LINE_SIZE);


struct xx_tdp {
#if MAXCPU > 256
    uint16_t                cpu2workq[MAXCPU];
#else
    uint8_t                 cpu2workq[MAXCPU];
#endif
    int                     refcnt;
    int                     cgmax;
    size_t                  allocsz;
    void                   *magic;

    struct xx_tdp_workq     workqv[];
};

static cpuset_t xx_tdp_cpuset;

static __always_inline struct xx_tdp_workq *
xx_tdp_cpu2workq(struct xx_tdp *tdp, int cpu)
{
    uint8_t idx = tdp->cpu2workq[cpu % MAXCPU];

    return tdp->workqv + idx;
}

/* Create and start a kernel thread.
 */
static int
xx_tdp_kthread_create(struct xx_tdargs *tdargs)
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
xx_tdp_hold(struct xx_tdp *tdp)
{
    KASSERT(tdp->magic == tdp, "invalid tdp magic");
    KASSERT(tdp->refcnt > 0, "invalid tdp refcnt");

    return atomic_fetchadd_int(&tdp->refcnt, 1) + 1;
}

void
xx_tdp_rele(struct xx_tdp *tdp)
{
    int i;

    KASSERT(tdp->magic == tdp, "invalid tdp magic");
    KASSERT(tdp->refcnt > 0, "invalid tdp refcnt");

    if (atomic_fetchadd_int(&tdp->refcnt, -1) > 1)
        return;

    /* Give kthreads a brief opportunity to finish exiting.
     * Is there a way to to this synchronously???
     */
    tsleep(tdp, 0, "tdpwait", 1);

    for (i = 0; i < tdp->cgmax + 1; ++i) {
        mtx_destroy(&tdp->workqv[i].mtx);
        cv_destroy(&tdp->workqv[i].cv);
    }

    tdp->magic = NULL;
    contigfree(tdp, tdp->allocsz, M_XX_TDP);
}

static void
xx_tdp_grow(struct xx_tdp_work *work)
{
    struct xx_tdp_workq *workq = work->argv[0];
    int rc;

    KASSERT(work && !work->tdp || !work->func, "invalid work");

    rc = xx_tdp_kthread_create(&workq->tdargs);
    if (rc)
        xx_tdp_rele(work->tdp);

    workq->growing = false;
}

void
xx_tdp_enqueue(struct xx_tdp_work *work, int cpu)
{
    struct xx_tdp_workq *workq;
    struct xx_tdp *tdp;

    KASSERT(work && !work->tdp || !work->func, "invalid work");

    tdp = work->tdp;
    workq = xx_tdp_cpu2workq(tdp, cpu);

    /* Append work to the target queue.  If we need to increase
     * the thread count of the target queue then append grow work
     * to the maintenance queue.
     */
    mtx_lock(&workq->mtx);
    STAILQ_INSERT_TAIL(&workq->head, work, wqe);
    work = NULL;

    if (workq->tdsleeping > 0) {
        cv_signal(&workq->cv);
    }
    else if (workq->tdcnt < workq->tdmax && !workq->growing) {
        workq->growing = true;
        work = &workq->grow;
        ++workq->grows;
    }
    mtx_unlock(&workq->mtx);

    if (work) {
        workq = tdp->workqv + tdp->cgmax;

        xx_tdp_hold(tdp);

        mtx_lock(&workq->mtx);
        STAILQ_INSERT_TAIL(&workq->head, work, wqe);
        if (workq->tdsleeping > 0)
            cv_signal(&workq->cv);
        mtx_unlock(&workq->mtx);
    }
}

void
xx_tdp_shutdown(struct xx_tdp *tdp)
{
    int i;

    KASSERT(tdp->magic == tdp, "invalid tdp magic");
    KASSERT(tdp->refcnt > 0, "invalid tdp refcnt");

    for (i = 0; i < tdp->cgmax + 1; ++i) {
        struct xx_tdp_workq *workq = tdp->workqv + i;

        if (workq->callbacks > 0)
            dprint("workq %2d, grows %3lu, callbacks %8lu\n",
                   i, workq->grows, workq->callbacks);

        mtx_lock(&workq->mtx);
        workq->running = false;
        workq->tdmin = 0;
        workq->tdmax = 0;
        cv_broadcast(&workq->cv);
        mtx_unlock(&workq->mtx);
    }

    for (i = 0; i < tdp->cgmax + 1; ++i) {
        struct xx_tdp_workq *workq = tdp->workqv + i;

        mtx_lock(&workq->mtx);
        while (workq->tdcnt > 0)
            cv_timedwait(&workq->cv, &workq->mtx, hz);
        mtx_unlock(&workq->mtx);
    }
}

static void
xx_tdp_run(void *arg)
{
    struct xx_tdargs *tdargs = arg;
    struct xx_tdp_workq *workq;
    struct xx_tdp *tdp;
    int timedout = 0;

    tdp = tdargs->argv[0];
    workq = tdargs->argv[1];

    mtx_lock(&workq->mtx);
    ++workq->tdcnt;

    while (1) {
        struct xx_tdp_work *work;

        work = STAILQ_FIRST(&workq->head);
        if (!work) {
            if ((timedout && workq->tdcnt > workq->tdmin) || !workq->running)
                break;

            ++workq->tdsleeping;
            timedout = cv_timedwait(&workq->cv, &workq->mtx, hz * 30);
            --workq->tdsleeping;
            continue;
        }

        STAILQ_REMOVE_HEAD(&workq->head, wqe);
        ++workq->callbacks;
        mtx_unlock(&workq->mtx);

        work->func(work);

        mtx_lock(&workq->mtx);
    }

    if (--workq->tdcnt < 1)
        cv_signal(&workq->cv);
    mtx_unlock(&workq->mtx);

    xx_tdp_rele(tdp);

    kthread_exit();
}

extern struct cpu_group *smp_topo(void);
extern struct cpu_group *smp_topo_find(struct cpu_group *, int);

struct xx_tdp *
xx_tdp_create(u_int tdmin, u_int tdmax)
{
    struct cpu_group *cpu_top, **cgv;
    struct xx_tdp_workq *workq;
    struct xx_tdargs *tdargs;
    struct xx_tdp *tdp;
    struct cpuset *set;
    struct thread *td;
    struct proc *proc;
    int i, rc, width;
    size_t tdpsz;
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

    CPU_COPY(&set->cs_mask, &xx_tdp_cpuset);
    cpuset_rel(set);

    /* Count the number of cpu groups which we'll use as the number
     * of thread groups.
     */
    cgmax = 0;
    cpu_top = smp_topo();
    CPU_FOREACH(i)
        ++cgmax;

    cgv = malloc(sizeof(*cgv) * cgmax, M_XX_TDP, M_ZERO);
    if (!cgv)
        return NULL;

    tdpsz = sizeof(*tdp) + sizeof(tdp->workqv[0]) * (cgmax + 1);

    tdp = contigmalloc(tdpsz, M_XX_TDP, M_ZERO, 0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
    if (!tdp) {
        free(cgv, M_XX_TDP);
        return NULL;
    }

    tdp->refcnt = 2;
    tdp->cgmax = cgmax;
    tdp->allocsz = tdpsz;
    tdp->magic = tdp;

    for (i = 0; i < cgmax + 1; ++i) {
        workq = tdp->workqv + i;

        mtx_init(&workq->mtx, "wqmtx", NULL, MTX_DEF);
        cv_init(&workq->cv, "wqcv");
        STAILQ_INIT(&workq->head);
        workq->running = true;
        workq->tdmin = tdmin;
        workq->tdmax = tdmax;

        tdargs = &workq->tdargs;
        tdargs->func = xx_tdp_run;
        tdargs->argv[0] = tdp;
        tdargs->argv[1] = workq;
        CPU_ZERO(&tdargs->cpuset);
        snprintf(tdargs->name, sizeof(tdargs->name), "tdp-%d", i);
        tdargs->prio = PRI_MAX_KERN;

        workq->grow.tdp = tdp;
        workq->grow.func = xx_tdp_grow;
        workq->grow.argv[0] = workq;

        if (i == cgmax) {
            strlcpy(tdargs->name, "tdp-maint", sizeof(tdargs->name));
            tdargs->prio = PRI_MAX_KERN - 1;
            workq->tdmin = 1;
            workq->tdmax = 1;
        }
    }

    /* For each vCPU, find the thread group to which it belongs
     * and add it to the vcpu-to-thread-group map and the thead
     * group's affinity set.
     */
    for (i = 0; i < CPU_COUNT(&xx_tdp_cpuset); ++i) {
        struct cpu_group *cg;
        int j;

        if (!CPU_ISSET(i, &xx_tdp_cpuset))
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

        tdp->cpu2workq[i] = j;

        workq = xx_tdp_cpu2workq(tdp, i);
        tdargs = &workq->tdargs;

        CPU_SET(i, &tdargs->cpuset);
    }

    /* Ensure that each thread group's affinity set is non-zero.
     */
    width = 0;
    for (i = 0; i < cgmax + 1; ++i) {
        char buf[CPUSETBUFSIZ];

        workq = tdp->workqv + i;
        tdargs = &workq->tdargs;

        if (CPU_EMPTY(&tdargs->cpuset))
            CPU_COPY(&xx_tdp_cpuset, &tdargs->cpuset);

        cpusetobj_strprint(buf, &tdargs->cpuset);
        if (strlen(buf) > width)
            width = strlen(buf);
    }

    for (i = 0; i < cgmax + 1; ++i) {
        char buf[CPUSETBUFSIZ];

        workq = tdp->workqv + i;
        tdargs = &workq->tdargs;

        dprint("workq %3d %12s  %2u %2u  %*s\n",
               i, tdargs->name, workq->tdmin, workq->tdmax,
               width, cpusetobj_strprint(buf, &tdargs->cpuset));
    }

    /* Start the maintenance kthread.
     */
    workq = tdp->workqv + cgmax;
    tdargs = &workq->tdargs;

    rc = xx_tdp_kthread_create(tdargs);
    if (rc) {
        dprint("unable to create maint kthread: rc %d\n", rc);
        free(tdp, M_XX_TDP);
        free(cgv, M_XX_TDP);
        return NULL;
    }

    dprint("%s: %4zu  sizeof xx_tdargs\n", __func__, sizeof(struct xx_tdargs));
    dprint("%s: %4zu  sizeof xx_tdp_work\n", __func__, sizeof(struct xx_tdp_work));
    dprint("%s: %4zu  sizeof xx_tdp_workq\n", __func__, sizeof(struct xx_tdp_workq));
    dprint("%s: %4zu  sizeof xx_tdp_tdp\n", __func__, sizeof(struct xx_tdp));
    dprint("%s: %4u  MSIZE\n", __func__, MSIZE);
    dprint("%s: %4u  MHLEN\n", __func__, MHLEN);
    dprint("%s: %4u  MLEN\n", __func__, MLEN);

    dprint("tdmin %u, tdmax %u, refcnt %d\n", tdmin, tdmax, tdp->refcnt);

    /* Consider adjusting the xx_tdp_workq padding if you see this message.
     */
    if (((sizeof(struct xx_tdp_workq) / CACHE_LINE_SIZE) & 1) == 0)
        dprint("struct xx_tdp_workq is an even number of cache lines\n");

    free(cgv, M_XX_TDP);

    return tdp;
}
