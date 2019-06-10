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

static u_int xx_port = 62049;

SYSCTL_NODE(_kern, OID_AUTO, krpc2,
            CTLFLAG_RW,
            0, "krpc2 kmod");

SYSCTL_UINT(_kern_krpc2, OID_AUTO, debug,
            CTLFLAG_RW,
            &xx_debug, 0,
            "Show debug tracing on console");

SYSCTL_UINT(_kern_krpc2, OID_AUTO, port,
            CTLFLAG_RW,
            &xx_port, 0,
            "Set listening port");

struct clreq;
STAILQ_HEAD(clhead, clreq);

/* A client request object is allocated for each RPC call message we pull
 * off the wire.  It is used to provide space for decoding the message
 * and sheparding the request through the system.  Note that it retains
 * most of the intermediate results so that they are available at all
 * stages of request processing.
 */
struct clreq {
    struct xx_tdp_work  work;

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
    struct mbuf    *frag;
    struct mbuf    *last;
    struct mbuf    *mcall;
    struct clreq   *req;

    int     rcvlowat;
    u_long  nrcvlowat;
    u_long  nmisaligned;
    u_long  pad;

    struct mtx      txq_mtx;
    struct clhead   txq_head;
    bool            txq_active;

};

static struct xx_svc *krpc2_svc;
static uma_zone_t clzone;

static void
krpc_send(struct xx_tdp_work *work)
{
    struct clhead todo, done;
    struct conn_priv *priv;
    struct clreq *req, *tmp;
    struct xx_conn *conn;
    struct mbuf *mreply;
    int sndpercb = 16;
    int refs = 0;
    int rc;

    STAILQ_INIT(&done);
    STAILQ_INIT(&todo);

    conn = work->argv[0];
    work = NULL;

    priv = xx_conn_priv(conn);

    mtx_lock(&priv->txq_mtx);
    STAILQ_CONCAT(&todo, &priv->txq_head);
    mtx_unlock(&priv->txq_mtx);

  again:
    mreply = NULL;

    while (( req = STAILQ_FIRST(&todo) )) {
        STAILQ_REMOVE_HEAD(&todo, clentry);
        STAILQ_INSERT_TAIL(&done, req, clentry);

        if (mreply)
            m_catpkt(mreply, req->mreply);
        else
            mreply = req->mreply;

        req->mreply = NULL;

        /* TODO: Restrict mreply length to available send buffer
         * size so as to mitigate blocking in sosend().
         */
        if (mreply->m_pkthdr.len > 768)
            break;
    }

    rc = sosend(conn->so, NULL, NULL, mreply, NULL, 0, curthread);
    if (rc) {
        dprint("sosend: conn %p, rc %d, %lu %lu, %lu %lu\n",
               conn, rc, conn->nsoupcalls, conn->ncallbacks,
               priv->nrcvlowat, priv->nmisaligned);
        sndpercb = 0;
    }

    if (STAILQ_FIRST(&todo) && --sndpercb > 0)
        goto again;

    mtx_lock(&priv->txq_mtx);
    STAILQ_CONCAT(&todo, &priv->txq_head);
    STAILQ_CONCAT(&priv->txq_head, &todo);
    if (rc)
        STAILQ_CONCAT(&done, &priv->txq_head);
    req = STAILQ_FIRST(&priv->txq_head);
    priv->txq_active = !!req;
    mtx_unlock(&priv->txq_mtx);

    if (req) {
        req->work.func = krpc_send;
        xx_tdp_enqueue(&req->work, curcpu);
    }

    STAILQ_FOREACH_SAFE(req, &done, clentry, tmp) {
        uma_zfree(clzone, req);
        ++refs;
    }

    xx_conn_reln(conn, refs);
}

static void
krpc_recv_rpc(struct xx_tdp_work *work)
{
    enum accept_stat ar_stat;
    struct conn_priv *priv;
    struct xx_conn *conn;
    struct rpc_msg *msg;
    struct clreq *req;
    struct mbuf *h;
    uint32_t mark;

    conn = work->argv[0];
    req = work->argv[1];
    priv = xx_conn_priv(conn);

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
        xx_conn_rele(conn);
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

    /* Encode the outgoing RPC reply message...
     */
    msg = &req->rmsg;
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
        xx_conn_rele(conn);
        m_freem(h);
        return;
    }

    /* Ensure the RPC record mark is in contiguous memory (this should
     * always be the case).
     */
    if (unlikely( h->m_len < RPC_RM_SZ )) {
        h = m_pullup(h, RPC_RM_SZ);
        if (!h) {
            eprint("%s: m_pullup mark failed: xid %u\n", __func__, msg->rm_xid);
            uma_zfree(clzone, req);
            xx_conn_rele(conn);
            return;
        }
    }

    m_fixhdr(h);

    rpc_rm_set(mtod(h, void *), h->m_pkthdr.len - RPC_RM_SZ, true);
    req->mreply = h;

    mtx_lock(&priv->txq_mtx);
    STAILQ_INSERT_TAIL(&priv->txq_head, req, clentry);
    if (priv->txq_active)
        req = NULL;
    priv->txq_active = true;
    mtx_unlock(&priv->txq_mtx);

    if (req) {
        req->work.func = krpc_send;
        xx_tdp_enqueue(&req->work, curcpu);
    }
}

/* The tcp receive callback is called whenever the socket has changed
 * status or has data ready to read.
 */
static void
krpc_recv_tcp(struct xx_conn *conn)
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

    priv = xx_conn_priv(conn);

    uio.uio_resid = IP_MAXPACKET;
    uio.uio_td = curthread;
    flags = MSG_DONTWAIT;
    m = NULL;

    rc = soreceive(so, NULL, &uio, &m, NULL, &flags);

    if (rc || !m) {
        if (rc != EWOULDBLOCK) {
            if (rc) {
                dprint("soreceive: conn %p, rc %d, m %p, flags %x, %lu %lu, %lu %lu\n",
                       conn, rc, m, flags, conn->nsoupcalls, conn->ncallbacks,
                       priv->nrcvlowat, priv->nmisaligned);
            }

            conn->active = false;
            xx_conn_rele(conn);
        }

        return;
    }

    /* Append new data to the current record fragment.
     */
    if (priv->last)
        m_cat(priv->last, m);
    else
        priv->frag = m;

  more:
    fraglen = m_length(priv->frag, &priv->last);
    if (fraglen < RPC_RM_SZ)
        return;

    /* The record mark tells us the length of the record and whether
     * or not it's the last record in the RPC message.
     */
    m_copydata(priv->frag, 0, RPC_RM_SZ, (caddr_t)&rm);
    rpc_rm_get(&rm, &reclen, &reclast);

    if (fraglen < reclen + RPC_RM_SZ) {
        priv->rcvlowat = reclen + RPC_RM_SZ - fraglen;
        if (priv->rcvlowat > 4096)
            priv->rcvlowat = 4096;
        xx_sosetopt(conn->so, SO_RCVLOWAT, &priv->rcvlowat, sizeof(priv->rcvlowat));
        return;
    }

    m = priv->frag;
    m_adj(m, RPC_RM_SZ);

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
        struct xx_tdp_work *work;
        struct clreq *req;

        req = priv->req;
        if (!req)
            req = uma_zalloc(clzone, M_WAITOK);

        req->mcall = priv->mcall;
        priv->mcall = NULL;

        xx_conn_hold(conn);

        work = &req->work;
        work->tdp = conn->work.tdp;
        work->argv[0] = conn;
        work->argv[1] = req;
        work->func = krpc_recv_rpc;

        if (priv->frag)
            xx_tdp_enqueue(work, curcpu);
        else
            work->func(work);

        priv->req = uma_zalloc(clzone, M_NOWAIT);
    }

    if (priv->frag)
        goto more;

    if (priv->rcvlowat != RPC_RM_SZ) {
        priv->rcvlowat = RPC_RM_SZ;
        xx_sosetopt(conn->so, SO_RCVLOWAT, &priv->rcvlowat, sizeof(priv->rcvlowat));
        ++priv->nrcvlowat;
    }
}

/* The tcp accept callback is called just once right after a new connection
 * is accepted and just prior to receive upcall activation.  This makes it
 * the ideal place to initialize the connection private data.
 */
static void
krpc_accept_cb(struct xx_conn *conn)
{
    struct conn_priv *priv = xx_conn_priv(conn);

    mtx_init(&priv->txq_mtx, "rpcmtx", NULL, MTX_DEF);
    STAILQ_INIT(&priv->txq_head);
    priv->rcvlowat = RPC_RM_SZ;
    priv->req = uma_zalloc(clzone, M_NOWAIT);

    xx_sosetopt(conn->so, SO_RCVLOWAT, &priv->rcvlowat, sizeof(priv->rcvlowat));
}

/* The tcp destroy callback is called once all the references to conn
 * have been released and just prior to socket close, making it the
 * ideal place to teardown the connection private data.
 */
static void
krpc_destroy_cb(struct xx_conn *conn)
{
    struct conn_priv *priv = xx_conn_priv(conn);

    KASSERT(priv->inited, "priv not initialized");

    m_freem(priv->frag);
    m_freem(priv->mcall);
    uma_zfree(clzone, priv->req);

    mtx_destroy(&priv->txq_mtx);
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
    struct xx_svc *svc;
    int rc;

    clzone = uma_zcreate(KSF_MOD_NAME "_clzone",
                         sizeof(struct clreq),
                         NULL, krpc_clzone_dtor, NULL, NULL,
                         CACHE_LINE_SIZE, UMA_ZONE_ZINIT);
    if (!clzone)
        return ENOMEM;

    /* TODO: Provide an alternate way to start/stop services
     * so that we can avoid doing it in module load/unload.
     */
    rc = xx_svc_create(&svc);
    if (rc) {
        eprint("xx_svc_create() failed: %d\n", rc);
        uma_zdestroy(clzone);
        return rc;
    }

    rc = xx_svc_listen(svc, SOCK_STREAM, host, xx_port,
                       krpc_accept_cb, krpc_recv_tcp, krpc_destroy_cb,
                       sizeof(struct conn_priv));
    if (rc) {
        eprint("xx_svc_listen() failed: %d\n", rc);
        xx_svc_shutdown(svc);
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

    rc = xx_svc_shutdown(krpc2_svc);

    dprint("%s: rc %d\n", __func__, rc);

    if (!rc) {
        krpc2_svc = NULL;
        uma_zdestroy(clzone);
        clzone = NULL;
    }

    return rc;
}
