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
#include <sys/sx.h>
#include <sys/rmlock.h>
#include <sys/rwlock.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/sched.h>
#include <vm/uma.h>
#include <sys/unistd.h>
#include <machine/stdarg.h>
#include <sys/sysctl.h>
#include <sys/smp.h>
#include <sys/cpuset.h>
#include <sys/sbuf.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <netinet/in.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

#include "xx.h"
#include "tdp.h"

MALLOC_DEFINE(M_XX_TDP, "xx_tdp", "xx thread pool");

#define XX_TDP_WORKQ_MAX        (32)
#define XX_TDP_TDPCPU_MAX       (2)  // Max threads per vCPU
#define XX_TDP_CPUPWORKQ        (2)  // Max vCPUs per work queue
#define XX_TDP_CPU2WORKQ(_cpu)  (((_cpu) / XX_TDP_CPUPWORKQ) % XX_TDP_WORKQ_MAX)

struct xx_tdargs {
    void      (*func)(void *arg);
    void       *argv[4];
    char        name[15];
    u_char      prio;
    cpuset_t    cpuset;
};

struct xx_tdp_workq {
    struct mtx                  mtx;
    TAILQ_HEAD(, xx_tdp_work)   head;
    bool                        running;
    bool                        growing;
    u_int                       tdsleeping;
    u_int                       tdcnt;

    u_int                       tdmax;
    u_int                       tdmin;
    u_long                      callbacks;
    u_long                      grows;
    struct cv                   cv;
    struct xx_tdargs            tdargs;
    struct xx_tdp_work          grow;
} __aligned(CACHE_LINE_SIZE);

struct xx_tdp {
    int                     refcnt;
    void                   *magic;
    struct xx_tdp_workq     workqv[XX_TDP_WORKQ_MAX + 1];
};

static cpuset_t xx_tdp_cpuset;

/* Create and start a kernel thread.  We acquire a reference on xx_inst
 * to prevent the kmod from being unloaded until all kthreads created
 * by this function have exited.
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

    for (i = 0; i < XX_TDP_WORKQ_MAX + 1; ++i) {
        mtx_destroy(&tdp->workqv[i].mtx);
        cv_destroy(&tdp->workqv[i].cv);
    }

    dprint("%s %p\n", __func__, tdp);
    tdp->magic = NULL;
    free(tdp, M_XX_TDP);
}

static void
xx_tdp_grow(struct xx_tdp_work *work)
{
    struct xx_tdp_workq *workq = work->arg;
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
    workq = tdp->workqv + XX_TDP_CPU2WORKQ(cpu);

    /* Append work to the target queue.  If we need to increase
     * the thread count of the target queue then append grow work
     * to the maintenance queue.
     */
    mtx_lock(&workq->mtx);
    TAILQ_INSERT_TAIL(&workq->head, work, wqe);
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
        workq = tdp->workqv + XX_TDP_WORKQ_MAX;

        xx_tdp_hold(tdp);

        mtx_lock(&workq->mtx);
        TAILQ_INSERT_TAIL(&workq->head, work, wqe);
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

    for (i = 0; i < XX_TDP_WORKQ_MAX + 1; ++i) {
        struct xx_tdp_workq *workq = tdp->workqv + i;

        if (workq->callbacks > 0)
            dprint("workq %2d, callbacks %lu, grows %lu\n",
                   i, workq->callbacks, workq->grows);

        mtx_lock(&workq->mtx);
        workq->running = false;
        workq->tdmin = 0;
        workq->tdmax = 0;
        cv_broadcast(&workq->cv);
        mtx_unlock(&workq->mtx);
    }

    for (i = 0; i < XX_TDP_WORKQ_MAX + 1; ++i) {
        struct xx_tdp_workq *workq = tdp->workqv + i;

        mtx_lock(&workq->mtx);
        cv_broadcast(&workq->cv);
        while (workq->tdcnt > 0)
            cv_timedwait(&workq->cv, &workq->mtx, hz);
        mtx_unlock(&workq->mtx);
    }

    dprint("%s %p\n", __func__, tdp);
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

        work = TAILQ_FIRST(&workq->head);
        if (!work) {
            if ((timedout && workq->tdcnt > workq->tdmin) || !workq->running)
                break;

            ++workq->tdsleeping;
            timedout = cv_timedwait(&workq->cv, &workq->mtx, hz * 10);
            --workq->tdsleeping;
            continue;
        }

        TAILQ_REMOVE(&workq->head, work, wqe);
        ++workq->callbacks;
        mtx_unlock(&workq->mtx);

        work->func(work);

        mtx_lock(&workq->mtx);
    }

    --workq->tdcnt;
    mtx_unlock(&workq->mtx);

    xx_tdp_rele(tdp);

    kthread_exit();
}

struct xx_tdp *
xx_tdp_create(u_int tdmin, u_int tdmax)
{
    struct xx_tdp_workq *workq;
    struct xx_tdargs *tdargs;
    struct xx_tdp *tdp;
    struct cpuset *set;
    struct thread *td;
    struct proc *proc;
    int i, rc;

    if (tdmin > 1024 || tdmax > 1024)
        return NULL;

    rc = cpuset_which(CPU_WHICH_CPUSET, -1, &proc, &td, &set);
    if (rc) {
        eprint("cpuset_which: rc %d\n", rc);
        return NULL;
    }

    CPU_COPY(&set->cs_mask, &xx_tdp_cpuset);
    cpuset_rel(set);

    tdmax = (tdmax > tdmin) ? tdmax : tdmin;

    tdp = malloc(sizeof(*tdp), M_XX_TDP, M_ZERO | M_WAITOK);
    if (!tdp)
        return NULL;

    tdp->refcnt = 2;
    tdp->magic = tdp;

    for (i = 0; i < XX_TDP_WORKQ_MAX + 1; ++i) {
        workq = tdp->workqv + i;

        mtx_init(&workq->mtx, "wqmtx", NULL, MTX_DEF);
        cv_init(&workq->cv, "wqcv");
        TAILQ_INIT(&workq->head);
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
        workq->grow.arg = workq;
    }

    /* For each vCPU, find the work queue to which it hashes
     * and add it to the work queue's cpu-affinity set.
     */
    for (i = 0; i < CPU_COUNT(&xx_tdp_cpuset); ++i) {
        if (CPU_ISSET(i, &xx_tdp_cpuset)) {
            workq = tdp->workqv + XX_TDP_CPU2WORKQ(i);
            tdargs = &workq->tdargs;

            CPU_SET(i, &tdargs->cpuset);
        }
    }

    for (i = 0; i < XX_TDP_WORKQ_MAX; ++i) {
        workq = tdp->workqv + i;
        tdargs = &workq->tdargs;

        if (CPU_EMPTY(&tdargs->cpuset))
            CPU_COPY(&xx_tdp_cpuset, &tdargs->cpuset);
    }

    /* Start the maintenance kthread.
     */
    workq = tdp->workqv + XX_TDP_WORKQ_MAX;
    tdargs = &workq->tdargs;
    CPU_COPY(&xx_tdp_cpuset, &tdargs->cpuset);
    strlcpy(tdargs->name, "tdp-maint", sizeof(tdargs->name));
    tdargs->prio = PRI_MAX_KERN - 1;
    workq->tdmin = 1;
    workq->tdmax = 1;

    rc = xx_tdp_kthread_create(tdargs);
    if (rc) {
        dprint("unable to create maint kthread: rc %d\n", rc);
        free(tdp, M_XX_TDP);
        return NULL;
    }

    dprint("%s: %4zu  sizeof xx_tdargs\n", __func__, sizeof(struct xx_tdargs));
    dprint("%s: %4zu  sizeof xx_tdp_work\n", __func__, sizeof(struct xx_tdp_work));
    dprint("%s: %4zu  sizeof xx_tdp_workq\n", __func__, sizeof(struct xx_tdp_workq));

    dprint("tdmin %u, tdmax %u, refcnt %d\n", tdmin, tdmax, tdp->refcnt);

    return tdp;
}
