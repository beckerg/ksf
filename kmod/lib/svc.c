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
#include <vm/uma.h>
#include <sys/unistd.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/cpuset.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "xx.h"
#include "tdp.h"
#include "svc.h"

MALLOC_DEFINE(M_XX_SVC, "xx_svc", "xx service");
MALLOC_DEFINE(M_XX_CONN, "xx_conn", "xx connection");

struct xx_svc;

struct xx_svc {
    int                     refcnt;
    struct xx_tdp          *tdp;

    struct mtx              mtx;
    struct cv               cv;
    TAILQ_HEAD(, xx_conn)   connq;

    void                   *magic;
};

struct xx_lsn_priv {
    xx_conn_cb_t   *accept_cb;
    xx_conn_cb_t   *recv_cb;
    xx_conn_cb_t   *destroy_cb;
    size_t          privsz;
};

static int xx_svc_hold(struct xx_svc *svc);
static int xx_svc_rele(struct xx_svc *svc);

int
xx_conn_hold(struct xx_conn *conn)
{
    KASSERT(conn->refcnt > 0, "invalid conn refcnt");

    return atomic_fetchadd_int(&conn->refcnt, 1) + 1;
}

static void
xx_conn_destroy(struct xx_conn *conn)
{
    struct xx_svc *svc = conn->svc;

    KASSERT(conn->magic == conn, "invalid conn magic");
    KASSERT(conn->refcnt == 0, "invalid conn refcnt");

    mtx_lock(&svc->mtx);
    TAILQ_REMOVE(&svc->connq, conn, connq_entry);
    conn->active = false;
    mtx_unlock(&svc->mtx);

    if (conn->destroy_cb)
        conn->destroy_cb(conn);

    soclose(conn->so);
    free(conn->laddr, M_SONAME);

    conn->magic = NULL;
    free(conn, M_XX_CONN);

    mtx_lock(&svc->mtx);
    if (xx_svc_rele(svc) == 1)
        cv_broadcast(&svc->cv);
    mtx_unlock(&svc->mtx);
}

void
xx_conn_reln(struct xx_conn *conn, int n)
{
    KASSERT(conn->magic == conn, "invalid conn magic");
    KASSERT(conn->refcnt > 0, "invalid conn refcnt zero");
    KASSERT(conn->refcnt >= n, "invalid conn refcnt");

    if (atomic_fetchadd_int(&conn->refcnt, -n) > n)
        return;

    xx_conn_destroy(conn);
}

void
xx_conn_rele(struct xx_conn *conn)
{
    xx_conn_reln(conn, 1);
}

static struct xx_conn *
xx_conn_create(struct xx_svc *svc, struct socket *so,
               xx_tdp_work_cb_t *workcb, xx_conn_cb_t *recv_cb,
               xx_conn_cb_t *destroy_cb, size_t privsz)
{
    struct xx_conn *conn;
    size_t sz;

    sz = sizeof(*conn) + roundup(privsz, __alignof(*conn));

    conn = malloc(sz, M_XX_CONN, M_ZERO | M_WAITOK);
    if (conn) {
        conn->so = so;
        conn->svc = svc;
        conn->refcnt = 1;
        conn->active = true;
        conn->recv_cb = recv_cb;
        conn->destroy_cb = destroy_cb;
        conn->privsz = privsz;
        conn->magic = conn;
        conn->work.tdp = svc->tdp;
        conn->work.func = workcb;
        conn->work.argv[0] = conn;

        mtx_lock(&svc->mtx);
        TAILQ_INSERT_TAIL(&svc->connq, conn, connq_entry);
        xx_svc_hold(svc);
        mtx_unlock(&svc->mtx);
    }

    if ((uintptr_t)conn % __alignof(*conn))
        dprint("conn %p not %zu-byte aligned\n", conn, __alignof(*conn));

    return conn;
}

/* xx_rcv_soupcall() is called by the socket layer when the socket
 * is ready for reading.  It arranges for xx_rcv_receive() to be
 * called via the thread pool so that xx_rcv_receive() can run in
 * a kthread context outside of the socket receive lock.
 */
static
int
xx_rcv_soupcall(struct socket *so, void *arg, int wait)
{
    struct xx_conn *conn = arg;

    soupcall_clear(so, SO_RCV);

    xx_conn_hold(conn);

    //++conn->nsoupcalls;

    xx_tdp_enqueue(&conn->work, curcpu);

    return SU_OK;
}

static void
xx_rcv_receive(struct xx_tdp_work *work)
{
    struct xx_conn *conn = work->argv[0];

    //++conn->ncallbacks;

    conn->recv_cb(conn);

    /* Reschedule this callback if there is more data to be read,
     * otherwise re-arm the socket receive upcall.
     */
    if (conn->active) {
        struct socket *so = conn->so;
        bool rearm;

        SOCKBUF_LOCK(&so->so_rcv);
        rearm = !soreadable(so);
        if (rearm)
            soupcall_set(so, SO_RCV, xx_rcv_soupcall, conn);
        SOCKBUF_UNLOCK(&so->so_rcv);

        if (!rearm) {
            xx_tdp_enqueue(&conn->work, curcpu);
            xx_conn_hold(conn);
        }
    }

    xx_conn_rele(conn);
}

/* xx_lsn_soupcall() is called by the socket layer when a new
 * connection is waiting to be accepted.  It disables the soupcall
 * and arrange for xx_svc_accept() to be called via the thread
 * pool so that xx_svc_accept() can run in a kthread context
 * outside of the socket listen lock.
 */
static
int
xx_lsn_soupcall(struct socket *so, void *arg, int wait)
{
    struct xx_conn *conn = arg;

    solisten_upcall_set(so, NULL, NULL);

    xx_conn_hold(conn);
    ++conn->nsoupcalls;

    xx_tdp_enqueue(&conn->work, curcpu);

    return SU_OK;
}

static void
xx_svc_accept_tcp(struct xx_tdp_work *work)
{
    struct xx_conn *lsn = work->argv[0];
    struct xx_svc *svc = lsn->svc;
    struct sockaddr *laddr = NULL;
    struct xx_conn *conn = NULL;
    struct socket *so = NULL;
    struct xx_lsn_priv *priv;
    struct socket *head;
    short nbio;
    int rc;

    ++lsn->ncallbacks;
    head = lsn->so;

    SOLISTEN_LOCK(head);
    nbio = head->so_state & SS_NBIO;

    rc = solisten_dequeue(head, &so, 0);
    KNOTE_UNLOCKED(&head->so_rdsel.si_note, 0);

    if (rc) {
        eprint("solist_dequeue: lsn %p, rc %d\n", lsn, rc);
        if (rc != EWOULDBLOCK) {
            lsn->active = false;
            xx_conn_rele(lsn);
        }
        goto errout;
    }

    so->so_state |= nbio;

    rc = soaccept(so, &laddr);
    if (rc) {
        eprint("soaccept: lsn %p, rc %d\n", lsn, rc);
        goto errout;
    }

    priv = xx_conn_priv(lsn);

    conn = xx_conn_create(svc, so, xx_rcv_receive,
                          priv->recv_cb, priv->destroy_cb, priv->privsz);
    if (conn) {
        conn->laddr = laddr;

        if (priv->accept_cb)
            priv->accept_cb(conn);

        SOCKBUF_LOCK(&so->so_rcv);
        soupcall_set(so, SO_RCV, xx_rcv_soupcall, conn);
        sorwakeup_locked(so);
    }

    laddr = NULL;
    so = NULL;

    /* Reschedule this callback if there is more data to be read,
     * otherwise re-arm the socket listen upcall.
     */
  errout:
    if (lsn->active) {
        bool rearm;

        SOLISTEN_LOCK(head);
        rearm = TAILQ_EMPTY(&head->sol_comp);
        if (rearm)
            solisten_upcall_set(head, xx_lsn_soupcall, lsn);
        SOLISTEN_UNLOCK(head);

        if (!rearm) {
            xx_tdp_enqueue(&lsn->work, curcpu);
            xx_conn_hold(lsn);
        }
    }

    if (so) {
        free(laddr, M_SONAME);
        soclose(so);
    }

    xx_conn_rele(lsn);
}

static void
xx_svc_accept_udp(struct xx_tdp_work *work)
{
    struct xx_conn *lsn = work->argv[0];
    struct xx_lsn_priv *priv, privbuf;

    ++lsn->ncallbacks;

    priv = xx_conn_priv(lsn);
    privbuf = *priv;
    memset(priv, 0, sizeof(*priv));

    if (privbuf.accept_cb)
        privbuf.accept_cb(lsn);

    lsn->recv_cb = privbuf.recv_cb;
    lsn->destroy_cb = privbuf.destroy_cb;
    lsn->work.func = xx_rcv_receive;

    xx_rcv_receive(work);
}

/* xx_lsn_create() creates a listening socket at the given address.
 * For each socket it successfully accepts it creates a connection
 * object and arranges for recv() to be called when the socket is
 * ready to read.
 */
int
xx_svc_listen(struct xx_svc *svc, int type, const char *host, in_port_t port,
              xx_conn_cb_t *accept_cb, xx_conn_cb_t *recv_cb,
              xx_conn_cb_t *destroy_cb,
              size_t privsz)
{
    struct xx_lsn_priv *priv;
    xx_tdp_work_cb_t *workcb;
    struct sockaddr_in sin;
    struct xx_conn *conn;
    struct thread *td;
    struct socket *so;
    struct timeval tv;
    size_t privszmax;
    int val, rc;

    if (!svc || !host || !recv_cb)
        return EINVAL;

    bzero(&sin, sizeof(sin));
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    if (!inet_aton(host, &sin.sin_addr)) {
        eprint("invalid address %s\n", host);
        return EINVAL;
    }

    td = curthread;

    rc = socreate(PF_INET, &so, type, 0, td->td_ucred, td);
    if (rc) {
        eprint("socreate: type %d, rc %d\n", type, rc);
        return rc;
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    rc = xx_sosetopt(so, SO_RCVTIMEO, &tv, sizeof(tv));
    if (rc) {
        eprint("sosetopt(SO_RCVTIMEO): rc %d\n", rc);
        soclose(so);
        return rc;
    }

    val = 1;
    rc = xx_sosetopt(so, SO_REUSEADDR, &val, sizeof(val));
    if (rc) {
        eprint("sosetopt(SO_REUSEADDR): rc %d\n", rc);
        soclose(so);
        return rc;
    }

    rc = sobind(so, (struct sockaddr *)&sin, td);
    if (rc) {
        eprint("sobind(): rc %d\n", rc);
        soclose(so);
        return rc;
    }

    if (type == SOCK_STREAM || type == SOCK_SEQPACKET) {
        workcb = xx_svc_accept_tcp;

        rc = solisten(so, -1, td);
        if (rc) {
            eprint("solisten(): rc %d\n", rc);
            soclose(so);
            return rc;
        }
    }
    else {
        workcb = xx_svc_accept_udp;
    }

    privszmax = max(sizeof(*priv), privsz);

    conn = xx_conn_create(svc, so, workcb, NULL, NULL, privszmax);
    if (!conn) {
        eprint("xx_conn_create(): rc %d\n", rc);
        soclose(so);
        return ENOMEM;
    }

    priv = xx_conn_priv(conn);
    priv->accept_cb = accept_cb;
    priv->recv_cb = recv_cb;
    priv->destroy_cb = destroy_cb;
    priv->privsz = privsz;

    if (type == SOCK_STREAM || type == SOCK_SEQPACKET) {
        SOLISTEN_LOCK(so);
        solisten_upcall_set(so, xx_lsn_soupcall, conn);
        //so->so_state |= SS_NBIO;
        solisten_wakeup(so);
    }
    else {
        SOCKBUF_LOCK(&so->so_rcv);
        soupcall_set(so, SO_RCV, xx_rcv_soupcall, conn);
        sorwakeup_locked(so);
    }

    return 0;
}

static int
xx_svc_hold(struct xx_svc *svc)
{
    KASSERT(svc->magic == svc, "invalid svc magic");
    KASSERT(svc->refcnt > 0, "invalid svc refcnt");

    return atomic_fetchadd_int(&svc->refcnt, 1) + 1;
}

static int
xx_svc_rele(struct xx_svc *svc)
{
    int refcnt;

    KASSERT(svc->magic == svc, "invalid svc magic");
    KASSERT(svc->refcnt > 0, "invalid svc refcnt");

    refcnt = atomic_fetchadd_int(&svc->refcnt, -1);
    if (refcnt > 1)
        return refcnt - 1;

    xx_tdp_shutdown(svc->tdp);
    xx_tdp_rele(svc->tdp);

    mtx_destroy(&svc->mtx);
    cv_destroy(&svc->cv);

    svc->magic = NULL;
    free(svc, M_XX_SVC);

    return 0;
}

int
xx_svc_shutdown(struct xx_svc *svc)
{
    struct xx_conn *conn, *next;
    int rc;

    /* Shut down all connections and wait for them all to be destroyed.
     */
    mtx_lock(&svc->mtx);
    while (!TAILQ_EMPTY(&svc->connq)) {
        TAILQ_FOREACH_SAFE(conn, &svc->connq, connq_entry, next) {
            if (conn->active) {
                conn->active = false;
                soshutdown(conn->so, SHUT_RDWR);
            }
        }

        rc = cv_wait_sig(&svc->cv, &svc->mtx);
        if (rc && rc != EWOULDBLOCK) {
            mtx_unlock(&svc->mtx);
            return EINTR;
        }
    }

    while (atomic_load_int(&svc->refcnt) > 1)
        cv_wait(&svc->cv, &svc->mtx);
    mtx_unlock(&svc->mtx);

    xx_svc_rele(svc);

    return 0;
}

int
xx_svc_create(struct xx_svc **svcp)
{
    struct xx_svc *svc;

    svc = malloc(sizeof(*svc), M_XX_SVC, M_ZERO | M_WAITOK);
    if (!svc)
        return ENOMEM;

    mtx_init(&svc->mtx, "svcxmtx", NULL, MTX_DEF);
    cv_init(&svc->cv, "svcxcv");
    TAILQ_INIT(&svc->connq);

    svc->refcnt = 1;
    svc->magic = svc;

    svc->tdp = xx_tdp_create(0, 8);
    if (!svc->tdp) {
        xx_svc_rele(svc);
        return ENOMEM;
    }

    *svcp = svc;

    return 0;
}
