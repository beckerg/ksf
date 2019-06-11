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

MALLOC_DEFINE(M_SVC, "svc", "network service");
MALLOC_DEFINE(M_CONN, "conn", "network connection");

struct svc;

struct svc {
    int                     refcnt;
    struct tpool           *tpool;

    struct mtx              mtx;
    struct cv               cv;
    TAILQ_HEAD(, conn)      connq;

    void                   *magic;
};

struct svc_lsn_priv {
    conn_cb_t      *accept;
    conn_cb_t      *recv;
    conn_cb_t      *destroy;
    size_t          privsz;
};

static int svc_hold(struct svc *svc);
static int svc_rele(struct svc *svc);

int
conn_hold(struct conn *conn)
{
    KASSERT(conn->refcnt > 0, "invalid conn refcnt");

    return atomic_fetchadd_int(&conn->refcnt, 1) + 1;
}

static void
conn_destroy(struct conn *conn)
{
    struct svc *svc = conn->svc;

    KASSERT(conn->magic == conn, "invalid conn magic");
    KASSERT(conn->refcnt == 0, "invalid conn refcnt");

    mtx_lock(&svc->mtx);
    TAILQ_REMOVE(&svc->connq, conn, entry);
    conn->active = false;
    mtx_unlock(&svc->mtx);

    if (conn->destroy)
        conn->destroy(conn);

    soclose(conn->so);
    free(conn->laddr, M_SONAME);

    conn->magic = NULL;
    free(conn, M_CONN);

    mtx_lock(&svc->mtx);
    if (svc_rele(svc) == 1)
        cv_broadcast(&svc->cv);
    mtx_unlock(&svc->mtx);
}

void
conn_reln(struct conn *conn, int n)
{
    KASSERT(conn->magic == conn, "invalid conn magic");
    KASSERT(conn->refcnt > 0, "invalid conn refcnt zero");
    KASSERT(conn->refcnt >= n, "invalid conn refcnt");

    if (atomic_fetchadd_int(&conn->refcnt, -n) > n)
        return;

    conn_destroy(conn);
}

void
conn_rele(struct conn *conn)
{
    conn_reln(conn, 1);
}

static struct conn *
conn_create(struct svc *svc, struct socket *so,
            tpool_cb_t *soupcallcb, conn_cb_t *recv,
            conn_cb_t *destroy, size_t privsz)
{
    struct conn *conn;
    size_t sz;

    sz = sizeof(*conn) + roundup(privsz, __alignof(*conn));

    conn = malloc(sz, M_CONN, M_ZERO | M_WAITOK);
    if (conn) {
        conn->so = so;
        conn->svc = svc;
        conn->tpool = svc->tpool;
        conn->refcnt = 1;
        conn->active = true;
        conn->recv = recv;
        conn->destroy = destroy;
        conn->privsz = privsz;
        conn->magic = conn;

        tpreq_init(&conn->tpreq, soupcallcb, NULL);

        mtx_lock(&svc->mtx);
        TAILQ_INSERT_TAIL(&svc->connq, conn, entry);
        svc_hold(svc);
        mtx_unlock(&svc->mtx);
    }

    if ((uintptr_t)conn % __alignof(*conn))
        dprint("conn %p not %zu-byte aligned\n", conn, __alignof(*conn));

    return conn;
}

/* svc_rcv_soupcall() is called by the socket layer when the socket
 * is ready for reading.  It arranges for svc_rcv_receive() to be
 * called via the thread pool so that svc_rcv_receive() can run in
 * a kthread context outside of the socket receive lock.
 */
static
int
svc_rcv_soupcall(struct socket *so, void *arg, int wait)
{
    struct conn *conn = arg;

    soupcall_clear(so, SO_RCV);

    conn_hold(conn);

    tpool_enqueue(conn->tpool, &conn->tpreq, curcpu);

    return SU_OK;
}

static void
svc_rcv_receive(struct tpreq *req)
{
    struct conn *conn = container_of(req, struct conn, tpreq);

    conn->recv(conn);

    /* Reschedule this callback if there is more data to be read,
     * otherwise re-arm the socket receive upcall.
     */
    if (conn->active) {
        struct socket *so = conn->so;
        bool rearm;

        SOCKBUF_LOCK(&so->so_rcv);
        rearm = !soreadable(so);
        if (rearm)
            soupcall_set(so, SO_RCV, svc_rcv_soupcall, conn);
        SOCKBUF_UNLOCK(&so->so_rcv);

        if (!rearm) {
            tpool_enqueue(conn->tpool, &conn->tpreq, curcpu);
            conn_hold(conn);
        }
    }

    conn_rele(conn);
}

/* svc_lsn_soupcall() is called by the socket layer when a new
 * connection is waiting to be accepted.  It disables the soupcall
 * and arrange for svc_accept() to be called via the thread
 * pool so that svc_accept() can run in a kthread context
 * outside of the socket listen lock.
 */
static
int
svc_lsn_soupcall(struct socket *so, void *arg, int wait)
{
    struct conn *conn = arg;

    solisten_upcall_set(so, NULL, NULL);

    conn_hold(conn);

    tpool_enqueue(conn->tpool, &conn->tpreq, curcpu);

    return SU_OK;
}

static void
svc_accept_tcp(struct tpreq *req)
{
    struct conn *lsn = container_of(req, struct conn, tpreq);
    struct sockaddr *laddr = NULL;
    struct svc_lsn_priv *priv;
    struct socket *so = NULL;
    struct conn *conn = NULL;
    struct socket *head;
    short nbio;
    int rc;

    head = lsn->so;

    SOLISTEN_LOCK(head);
    nbio = head->so_state & SS_NBIO;

    rc = solisten_dequeue(head, &so, 0);
    KNOTE_UNLOCKED(&head->so_rdsel.si_note, 0);

    if (rc) {
        eprint("solist_dequeue: lsn %p, rc %d\n", lsn, rc);
        if (rc != EWOULDBLOCK) {
            lsn->active = false;
            conn_rele(lsn);
        }
        goto errout;
    }

    so->so_state |= nbio;

    rc = soaccept(so, &laddr);
    if (rc) {
        eprint("soaccept: lsn %p, rc %d\n", lsn, rc);
        goto errout;
    }

    priv = conn_priv(lsn);

    conn = conn_create(lsn->svc, so, svc_rcv_receive,
                       priv->recv, priv->destroy, priv->privsz);
    if (conn) {
        conn->laddr = laddr;

        if (priv->accept)
            priv->accept(conn);

        SOCKBUF_LOCK(&so->so_rcv);
        soupcall_set(so, SO_RCV, svc_rcv_soupcall, conn);
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
            solisten_upcall_set(head, svc_lsn_soupcall, lsn);
        SOLISTEN_UNLOCK(head);

        if (!rearm) {
            tpool_enqueue(lsn->tpool, &lsn->tpreq, curcpu);
            conn_hold(lsn);
        }
    }

    if (so) {
        free(laddr, M_SONAME);
        soclose(so);
    }

    conn_rele(lsn);
}

static void
svc_accept_udp(struct tpreq *req)
{
    struct conn *lsn = container_of(req, struct conn, tpreq);
    struct svc_lsn_priv *priv, privbuf;

    priv = conn_priv(lsn);
    privbuf = *priv;
    memset(priv, 0, sizeof(*priv));

    /* TODO: Create a new socket and connect to the peer to establish
     * unique session (best matching inpcb).  For now we just handle
     * all UDP packets over the "listening" socket.
     */
    if (privbuf.accept)
        privbuf.accept(lsn);

    lsn->recv = privbuf.recv;
    lsn->destroy = privbuf.destroy;
    lsn->tpreq.func = svc_rcv_receive;

    svc_rcv_receive(req);
}

/* svc_listen() creates a listening socket for the given address.  For
 * each successful call to accept() it creates a new connection object
 * and arranges for recv() to be called when the new socket is ready
 * to read.
 */
int
svc_listen(struct svc *svc, int type, const char *host, in_port_t port,
           conn_cb_t *accept, conn_cb_t *recv, conn_cb_t *destroy,
           size_t privsz)
{
    struct svc_lsn_priv *priv;
    struct sockaddr_in sin;
    struct conn *conn;
    struct thread *td;
    struct socket *so;
    struct timeval tv;
    tpool_cb_t *func;
    size_t privszmax;
    int val, rc;

    if (!svc || !host || !recv)
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
        func = svc_accept_tcp;

        rc = solisten(so, -1, td);
        if (rc) {
            eprint("solisten(): rc %d\n", rc);
            soclose(so);
            return rc;
        }
    }
    else {
        func = svc_accept_udp;
    }

    privszmax = max(sizeof(*priv), privsz);

    conn = conn_create(svc, so, func, NULL, NULL, privszmax);
    if (!conn) {
        eprint("conn_create(): rc %d\n", rc);
        soclose(so);
        return ENOMEM;
    }

    priv = conn_priv(conn);
    priv->accept = accept;
    priv->recv = recv;
    priv->destroy = destroy;
    priv->privsz = privsz;

    if (type == SOCK_STREAM || type == SOCK_SEQPACKET) {
        SOLISTEN_LOCK(so);
        solisten_upcall_set(so, svc_lsn_soupcall, conn);
        //so->so_state |= SS_NBIO;
        solisten_wakeup(so);
    }
    else {
        SOCKBUF_LOCK(&so->so_rcv);
        soupcall_set(so, SO_RCV, svc_rcv_soupcall, conn);
        sorwakeup_locked(so);
    }

    return 0;
}

static int
svc_hold(struct svc *svc)
{
    KASSERT(svc->magic == svc, "invalid svc magic");
    KASSERT(svc->refcnt > 0, "invalid svc refcnt");

    return atomic_fetchadd_int(&svc->refcnt, 1) + 1;
}

static int
svc_rele(struct svc *svc)
{
    int refcnt;

    KASSERT(svc->magic == svc, "invalid svc magic");
    KASSERT(svc->refcnt > 0, "invalid svc refcnt");

    refcnt = atomic_fetchadd_int(&svc->refcnt, -1);
    if (refcnt > 1)
        return refcnt - 1;

    tpool_shutdown(svc->tpool);
    tpool_rele(svc->tpool);

    mtx_destroy(&svc->mtx);
    cv_destroy(&svc->cv);

    svc->magic = NULL;
    free(svc, M_SVC);

    return 0;
}

int
svc_shutdown(struct svc *svc)
{
    struct conn *conn, *next;
    int rc;

    /* Shut down all connections and wait for them all to be destroyed.
     */
    mtx_lock(&svc->mtx);
    while (!TAILQ_EMPTY(&svc->connq)) {
        TAILQ_FOREACH_SAFE(conn, &svc->connq, entry, next)
            soshutdown(conn->so, SHUT_RDWR);

        rc = cv_wait_sig(&svc->cv, &svc->mtx);
        if (rc && rc != EWOULDBLOCK) {
            mtx_unlock(&svc->mtx);
            return EINTR;
        }
    }

    while (atomic_load_int(&svc->refcnt) > 1)
        cv_wait(&svc->cv, &svc->mtx);
    mtx_unlock(&svc->mtx);

    svc_rele(svc);

    return 0;
}

int
svc_create(struct svc **svcp)
{
    struct svc *svc;

    svc = malloc(sizeof(*svc), M_SVC, M_ZERO | M_WAITOK);
    if (!svc)
        return ENOMEM;

    mtx_init(&svc->mtx, "svcxmtx", NULL, MTX_DEF);
    cv_init(&svc->cv, "svccv");
    TAILQ_INIT(&svc->connq);

    svc->refcnt = 1;
    svc->magic = svc;

    svc->tpool = tpool_create(0, 8);
    if (!svc->tpool) {
        svc_rele(svc);
        return ENOMEM;
    }

    *svcp = svc;

    return 0;
}
