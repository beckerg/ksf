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
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/sched.h>
#include <sys/unistd.h>
#include <sys/sysctl.h>
#include <sys/cpuset.h>
#include <sys/uio.h>
#include <vm/uma.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpc_msg.h>
#include <rpc/clnt.h>
#include <rpc/clnt_stat.h>

#include "xx.h"
#include "tdp.h"
#include "svc.h"
#include "ksf.h"

MODULE_VERSION(krpc2, 1);

MALLOC_DEFINE(M_XX_KRPC2, "krpc2", "krpc2 service");

static int xx_sosndbuf = IP_MAXPACKET * 32;
static int xx_sorcvbuf = IP_MAXPACKET * 16;
static u_int xx_port = 62049;
static u_int xx_tdmin = 1;
static u_int xx_tdmax = 8;

SYSCTL_NODE(_kern, OID_AUTO, krpc2,
            CTLFLAG_RW,
            0, "krpc2 kmod");

SYSCTL_INT(_kern_krpc2, OID_AUTO, sosndbuf,
           CTLFLAG_RW,
           &xx_sosndbuf, 0,
           "Set initial send buffer size");

SYSCTL_INT(_kern_krpc2, OID_AUTO, sorcvbuf,
           CTLFLAG_RW,
           &xx_sorcvbuf, 0,
           "Set initial receive buffer size");

SYSCTL_UINT(_kern_krpc2, OID_AUTO, port,
            CTLFLAG_RW,
            &xx_port, 0,
            "Set listening port");

SYSCTL_UINT(_kern_krpc2, OID_AUTO, tdmin,
            CTLFLAG_RW,
            &xx_tdmin, 0,
            "Set threadpool minimum threads per core");

SYSCTL_UINT(_kern_krpc2, OID_AUTO, tdmax,
            CTLFLAG_RW,
            &xx_tdmax, 0,
            "Set threadpool maximum threads per core");

SYSCTL_UINT(_kern_krpc2, OID_AUTO, debug,
            CTLFLAG_RW,
            &xx_debug, 0,
            "Show debug tracing on console");

struct clreq;
STAILQ_HEAD(clhead, clreq);

/* A client request object is allocated for each RPC call message we pull
 * off the wire.  It is used to provide space for decoding the message
 * and sheparding the request through the system.  Note that it retains
 * most of the intermediate results so that they are available at all
 * stages of request processing.
 */
struct clreq {
    struct tpreq        tpreq;

    STAILQ_ENTRY(clreq) clentry;
    struct mbuf        *mreply;
    struct mbuf        *mcall;

    XDR                 rxdr;
    struct rpc_msg      rmsg;

    XDR                 cxdr;
    struct rpc_msg      cmsg;

    char credbuf[MAX_AUTH_BYTES];
    char verfbuf[MAX_AUTH_BYTES];
};

/* A connection private object is created for each new client
 * connection.  It is used to accumulate RPC message fragments
 * between calls to soreceive() and to provide a per-connection
 * send queue which serializes outgoing reply messages.
 */
struct conn_priv {
    __aligned(CACHE_LINE_SIZE * 2)
    struct mbuf    *frag;
    struct mbuf    *last;
    struct mbuf    *mcall;
    struct clreq   *clreq;

    int             rcvlowat;
    u_long          nrcvlowat;
    u_long          nmisaligned;

    __aligned(CACHE_LINE_SIZE)
    struct mtx      txq_mtx;
    struct clhead   txq_head;
    bool            txq_active;

    uintptr_t       magic;
};

static struct svc *krpc2_svc;
static uma_zone_t clzone;

static void
krpc_send(struct tpreq *tpreq)
{
    struct clhead todo, done;
    struct conn_priv *priv;
    struct clreq *req, *tmp;
    struct conn *conn;
    int sndpercb = 16;
    int refs = 0;
    int rc;

    STAILQ_INIT(&done);
    STAILQ_INIT(&todo);

    conn = tpreq->arg;
    tpreq = NULL;

    priv = conn_priv(conn);

    KASSERT(priv->magic == (uintptr_t)priv,
            ("bad magic: conn %p, priv %p, magic %lx\n",
             conn, priv, priv->magic));

    mtx_lock(&priv->txq_mtx);
    STAILQ_CONCAT(&todo, &priv->txq_head);
    mtx_unlock(&priv->txq_mtx);

    while (STAILQ_FIRST(&todo) && sndpercb-- > 0) {
        struct mbuf *mreply;

        req = STAILQ_FIRST(&todo);
        STAILQ_REMOVE_HEAD(&todo, clentry);
        STAILQ_INSERT_TAIL(&done, req, clentry);

        mreply = req->mreply;
        req->mreply = NULL;

        /* TODO: Restrict mreply length to mitigate sosend() blocking...
         */
        while (STAILQ_FIRST(&todo) && mreply->m_pkthdr.len < 768) {
            req = STAILQ_FIRST(&todo);
            STAILQ_REMOVE_HEAD(&todo, clentry);
            STAILQ_INSERT_TAIL(&done, req, clentry);

            m_catpkt(mreply, req->mreply);
            req->mreply = NULL;
        }

        if (conn->shut_wr) {
            rc = ECONNABORTED;
            m_freem(mreply);
            break;
        }

        rc = sosend(conn->so, NULL, NULL, mreply, NULL, 0, curthread);
        if (rc) {
            conn->shut_wr = true;
            sndpercb = 0;
        }
    }

    mtx_lock(&priv->txq_mtx);
    STAILQ_CONCAT(&todo, &priv->txq_head);
    STAILQ_CONCAT(&priv->txq_head, &todo);
    if (rc)
        STAILQ_CONCAT(&done, &priv->txq_head);
    req = STAILQ_FIRST(&priv->txq_head);
    priv->txq_active = !!req;
    mtx_unlock(&priv->txq_mtx);

    if (req) {
        req->tpreq.func = krpc_send;
        tpool_enqueue(conn->tpool, &req->tpreq, curcpu);
    }

    STAILQ_FOREACH_SAFE(req, &done, clentry, tmp) {
        uma_zfree(clzone, req);
        ++refs;
    }

    conn_reln(conn, refs);
}

static void
krpc_recv_rpc(struct tpreq *tpreq)
{
    enum accept_stat ar_stat;
    struct conn_priv *priv;
    struct rpc_msg *msg;
    struct clreq *req;
    struct conn *conn;
    struct mbuf *h;
    uint32_t mark;
    uint32_t xid;

    req = container_of(tpreq, struct clreq, tpreq);
    conn = tpreq->arg;
    priv = conn_priv(conn);

    KASSERT(priv->magic == (uintptr_t)priv,
            ("bad magic: conn %p, priv %p, magic %lx\n",
             conn, priv, priv->magic));

    /* Decode the incoming RPC call message...
     */
    msg = &req->cmsg;
    msg->ru.RM_cmb.cb_cred.oa_base = req->credbuf;
    msg->ru.RM_cmb.cb_verf.oa_base = req->verfbuf;

    xdrmbuf_create(&req->cxdr, req->mcall, XDR_DECODE);

    if (!xdr_callmsg(&req->cxdr, msg)) {
        eprint("%s: xdr_callmsg failed: xid %u, len %u\n",
               __func__, msg->rm_xid, m_length(req->mcall, NULL));
        uma_zfree(clzone, req);
        conn_rele(conn);
        return;
    }

    /* By convention, procedure 0 of any RPC protocol should have the
     * same semantics and never require any kind of authentication.
     * https://tools.ietf.org/html/rfc5531, Section 12.1
     */
    switch (msg->rm_call.cb_proc) {
    case 0:
        ar_stat = SUCCESS;
        break;

    default:
        ar_stat = PROC_UNAVAIL;
        break;
    }

    xid = msg->rm_xid;

    /* Encode the outgoing RPC reply message...
     */
    msg = &req->rmsg;
    msg->rm_xid = xid;
    msg->rm_direction = REPLY;
    msg->rm_reply.rp_stat = MSG_ACCEPTED;

    msg->acpted_rply.ar_verf = _null_auth;
    msg->acpted_rply.ar_stat = ar_stat;
    msg->acpted_rply.ar_results.where = NULL;
    msg->acpted_rply.ar_results.proc = (xdrproc_t)xdr_void;

    h = m_gethdr(M_WAITOK, MT_DATA);
    m_align(h, 64);

    xdrmbuf_create(&req->rxdr, h, XDR_ENCODE);

    /* Reserve space for the RPC record mark.
     */
    mark = 0xdeadbeef;
    xdr_uint32_t(&req->rxdr, &mark);

    if (!xdr_replymsg(&req->rxdr, msg)) {
        eprint("%s: xdr_replymsg failed: xid %u\n", __func__, msg->rm_xid);
        uma_zfree(clzone, req);
        conn_rele(conn);
        m_freem(h);
        return;
    }

    /* Ensure the RPC record mark is in contiguous memory (this should
     * always be the case).
     */
    if (unlikely( h->m_len < RPC_RECMARK_SZ )) {
        h = m_pullup(h, RPC_RECMARK_SZ);
        if (!h) {
            eprint("%s: m_pullup mark failed: xid %u\n", __func__, msg->rm_xid);
            uma_zfree(clzone, req);
            conn_rele(conn);
            return;
        }
    }

    m_fixhdr(h);

    rpc_recmark_set(mtod(h, void *), h->m_pkthdr.len - RPC_RECMARK_SZ, true);
    req->mreply = h;

    mtx_lock(&priv->txq_mtx);
    STAILQ_INSERT_TAIL(&priv->txq_head, req, clentry);
    if (priv->txq_active)
        req = NULL;
    priv->txq_active = true;
    mtx_unlock(&priv->txq_mtx);

    if (req) {
        req->tpreq.func = krpc_send;
        tpool_enqueue(conn->tpool, &req->tpreq, curcpu);
    }
}

/* The tcp receive callback is called whenever the socket has changed
 * status or has data ready to read.
 */
static void
krpc_recv_tcp(struct conn *conn)
{
    struct socket *so = conn->so;
    struct conn_priv *priv;
    u_int fraglen, reclen;
    struct mbuf *m;
    struct uio uio;
    bool reclast;
    uint32_t rm;
    int flags;
    int rc;

    priv = conn_priv(conn);

    KASSERT(priv->magic == (uintptr_t)priv,
            ("bad magic: conn %p, priv %p, magic %lx\n",
             conn, priv, priv->magic));

    uio.uio_resid = IP_MAXPACKET;
    uio.uio_td = curthread;
    flags = MSG_DONTWAIT;
    m = NULL;

    rc = soreceive(so, NULL, &uio, &m, NULL, &flags);
    if (rc || !m)
        return;

    /* Append new data to the current record fragment.
     */
    if (priv->last)
        m_cat(priv->last, m);
    else
        priv->frag = m;

  more:
    fraglen = m_length(priv->frag, &priv->last);
    if (fraglen < RPC_RECMARK_SZ)
        return;

    /* The record mark tells us the length of the record and whether
     * or not it's the last record in the RPC message.
     */
    m_copydata(priv->frag, 0, RPC_RECMARK_SZ, (caddr_t)&rm);
    rpc_recmark_get(&rm, &reclen, &reclast);

    if (fraglen < reclen + RPC_RECMARK_SZ) {
        priv->rcvlowat = reclen + RPC_RECMARK_SZ - fraglen;
        if (priv->rcvlowat > 4096)
            priv->rcvlowat = 4096;
        xx_sosetopt(conn->so, SO_RCVLOWAT, &priv->rcvlowat, sizeof(priv->rcvlowat));
        return;
    }

    m = priv->frag;
    m_adj(m, RPC_RECMARK_SZ);

    /* We now have at least one full RPC message, so split it
     * from the ensuing data.
     */
    priv->frag = m_split(m, reclen, M_WAITOK);
    if (!priv->frag)
        priv->last = NULL;

    if (mtod(m, uintptr_t) & 0x03)
        ++priv->nmisaligned;

    /* Accumulate RPC records until we see the last record.
     */
    if (priv->mcall) {
        m_cat(priv->mcall, m);
    } else {
        priv->mcall = m;
    }

    if (reclast) {
        struct tpreq *tpreq;
        struct clreq *clreq;

        conn_hold(conn);

        clreq = priv->clreq;
        if (!clreq)
            clreq = uma_zalloc(clzone, M_WAITOK);

        clreq->mcall = priv->mcall;
        clreq->mreply = NULL;

        priv->mcall = NULL;
        priv->clreq = NULL;

        tpreq = &clreq->tpreq;
        tpreq_init(tpreq, krpc_recv_rpc, conn);

        if (priv->frag)
            tpool_enqueue(conn->tpool, tpreq, curcpu);
        else
            tpreq->func(tpreq);

        priv->clreq = uma_zalloc(clzone, M_NOWAIT);
    }

    if (priv->frag)
        goto more;

    if (priv->rcvlowat != RPC_RECMARK_SZ) {
        priv->rcvlowat = RPC_RECMARK_SZ;
        xx_sosetopt(conn->so, SO_RCVLOWAT, &priv->rcvlowat, sizeof(priv->rcvlowat));
        ++priv->nrcvlowat;
    }
}

/* The tcp accept callback is called just once right after a new connection
 * is accepted and just prior to receive upcall activation.  This makes it
 * the ideal place to initialize the connection private data.
 */
static void
krpc_accept_cb(struct conn *conn)
{
    struct conn_priv *priv = conn_priv(conn);
    int val, rc;

    KASSERT(priv->magic == 0,
            ("bad magic: conn %p, priv %p, magic %lx\n",
             conn, priv, priv->magic));

    mtx_init(&priv->txq_mtx, "rpcmtx", NULL, MTX_DEF);
    STAILQ_INIT(&priv->txq_head);
    priv->rcvlowat = RPC_RECMARK_SZ;
    priv->clreq = uma_zalloc(clzone, M_NOWAIT);
    priv->magic = (uintptr_t)priv;

    rc = xx_sosetopt(conn->so, SO_RCVLOWAT, &priv->rcvlowat, sizeof(priv->rcvlowat));
    if (rc)
        eprint("%s: conn %p, SO_RCVLOWAT, rc %d\n", __func__, conn, rc);

    val = xx_sorcvbuf;
    rc = xx_sosetopt(conn->so, SO_RCVBUF, &val, sizeof(val));
    if (rc)
        eprint("%s: conn %p, SO_SNDBUF %d, rc %d\n", __func__, conn, xx_sorcvbuf, rc);

    val = xx_sosndbuf;
    rc = xx_sosetopt(conn->so, SO_SNDBUF, &val, sizeof(val));
    if (rc)
        eprint("%s: conn %p, SO_SNDBUF %d, rc %d\n", __func__, conn, xx_sosndbuf, rc);
}

/* The tcp destroy callback is called once all the references to conn
 * have been released and just prior to socket close, making it the
 * ideal place to teardown the connection private data.
 */
static void
krpc_destroy_cb(struct conn *conn)
{
    struct conn_priv *priv = conn_priv(conn);

    KASSERT(priv->magic == (uintptr_t)priv,
            ("bad magic: conn %p, priv %p, magic %lx\n",
             conn, priv, priv->magic));

    priv->magic = ~priv->magic;

    uma_zfree(clzone, priv->clreq);
    mtx_destroy(&priv->txq_mtx);
    m_freem(priv->frag);
    m_freem(priv->mcall);
}

static void
krpc_clzone_dtor(void *mem, int size, void *arg)
{
    struct clreq *req = mem;

    if (req->mcall) {
        m_freem(req->mcall);
        req->mcall = NULL;
    }

    if (req->mreply) {
        m_freem(req->mreply);
        req->mreply = NULL;
    }
}

int
krpc2_mod_load(module_t mod, int cmd, void *data)
{
    const char *host = "0.0.0.0";
    struct svc *svc;
    int rc;

    clzone = uma_zcreate(KSF_MOD_NAME "_clzone",
                         sizeof(struct clreq),
                         NULL, krpc_clzone_dtor, NULL, NULL,
                         UMA_ALIGN_CACHE, UMA_ZONE_ZINIT);
    if (!clzone)
        return ENOMEM;

    /* TODO: Provide an alternate way to start/stop services
     * so that we can avoid doing it in module load/unload.
     */
    rc = svc_create(xx_tdmin, xx_tdmax, &svc);
    if (rc) {
        eprint("svc_create() failed: %d\n", rc);
        uma_zdestroy(clzone);
        return rc;
    }

    rc = svc_listen(svc, SOCK_STREAM, host, xx_port,
                    krpc_accept_cb, krpc_recv_tcp, krpc_destroy_cb,
                    sizeof(struct conn_priv));
    if (rc) {
        eprint("svc_listen() failed: %d\n", rc);
        svc_shutdown(svc);
        uma_zdestroy(clzone);
        return rc;
    }

    krpc2_svc = svc;

    return 0;
}

int
krpc2_mod_unload(module_t mod, int cmd, void *data)
{
    int rc;

    rc = svc_shutdown(krpc2_svc);
    if (rc)
        return rc;

    krpc2_svc = NULL;

    uma_zdestroy(clzone);
    clzone = NULL;

    return 0;
}
