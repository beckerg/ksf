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

struct conn_priv {
    struct mbuf    *frag;
    struct mbuf    *last;
    struct mbuf    *msg;
    struct mbuf    *hdr;
    u_long  nrcvlowat;
    int     rcvlowat;

    struct mtx                  txq_mtx;
    STAILQ_HEAD(, xx_tdp_work)  txq_head;
    bool                        txq_active;

    char credbuf[MAX_AUTH_BYTES];
    char verfbuf[MAX_AUTH_BYTES];
};

static void
krpc_send(struct xx_tdp_work *work)
{
    struct conn_priv *priv;
    struct xx_conn *conn;
    int sndpercall = 8;
    struct mbuf *h;
    int rc;

  again:
    conn = work->argv[0];
    h = work->argv[1];
    m_fixhdr(h);

    rpc_rm_set(mtod(h, void *), h->m_pkthdr.len, true);
    h->m_len += RPC_RM_SZ;

    rc = sosend(conn->so, NULL, NULL, h, NULL, 0, curthread);
    if (rc) {
        eprint("sosend; conn %p, rc %d, %lu %lu\n",
               conn, rc, conn->nsoupcalls, conn->ncallbacks);
    }

    priv = xx_conn_priv(conn);

    mtx_lock(&priv->txq_mtx);
    work = STAILQ_FIRST(&priv->txq_head);
    if (work)
        STAILQ_REMOVE_HEAD(&priv->txq_head, wqe);
    priv->txq_active = !!work;
    mtx_unlock(&priv->txq_mtx);

    xx_conn_rele(conn);

    if (work) {
        if (--sndpercall > 0)
            goto again;

        work->func = krpc_send;
        xx_tdp_enqueue(work, curcpu);
    }
}

static void
krpc_recv_rpc(struct xx_tdp_work *work)
{
    struct xx_conn *conn = work->argv[0];
    enum accept_stat ar_stat;
    struct conn_priv *priv;
    struct rpc_msg msg;
    struct mbuf *h, *m;
    XDR xdr;

    priv = xx_conn_priv(conn);
    h = work->argv[1];
    m = h->m_next;

    /* Decode the incoming RPC call message...
     */
    msg.ru.RM_cmb.cb_cred.oa_base = priv->credbuf;
    msg.ru.RM_cmb.cb_verf.oa_base = priv->verfbuf;

    xdrmbuf_create(&xdr, m, XDR_DECODE);

    if (!xdr_callmsg(&xdr, &msg)) {
        eprint("%s: xdr_callmsg failed: m_len %d, xid %u\n",
               __func__, m_length(m, NULL), msg.rm_xid);
        xx_conn_rele(conn);
        xdr_destroy(&xdr);
        m_free(h);
        return;
    }

    /* By convention, procedure 0 of any RPC protocol should have the
     * same semantics and never require any kind of authentication.
     * https://tools.ietf.org/html/rfc5531, Section 12.1
     */
    switch (msg.rm_call.cb_proc) {
    case 0:
        ar_stat = SUCCESS;
        break;

    default:
        ar_stat = PROC_UNAVAIL;
        break;
    }

    m_freem(m->m_next);
    m_init(m, M_WAITOK, m->m_type, m->m_flags);

    /* Encode the outgoing RPC reply message...
     */
    msg.rm_direction = REPLY;
    msg.rm_reply.rp_stat = MSG_ACCEPTED;

    msg.acpted_rply.ar_verf = _null_auth;
    msg.acpted_rply.ar_stat = ar_stat;
    msg.acpted_rply.ar_results.where = NULL;
    msg.acpted_rply.ar_results.proc = (xdrproc_t)xdr_void;

    xdrmbuf_create(&xdr, m, XDR_ENCODE);

    if (!xdr_replymsg(&xdr, &msg)) {
        eprint("%s: xdr_replymsg failed: xid %u\n", __func__, msg.rm_xid);
        xx_conn_rele(conn);
        m_freem(h);
        return;
    }

    mtx_lock(&priv->txq_mtx);
    if (priv->txq_active) {
        STAILQ_INSERT_TAIL(&priv->txq_head, work, wqe);
        work = NULL;
    }
    priv->txq_active = true;
    mtx_unlock(&priv->txq_mtx);

    if (work) {
        work->func = krpc_send;
        xx_tdp_enqueue(work, curcpu);
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
    int rcvpercall = 8;
    struct mbuf *m;
    struct uio uio;
    bool reclast;
    uint32_t rm;
    int flags;
    int rc;

    priv = xx_conn_priv(conn);

  again:
    uio.uio_resid = IP_MAXPACKET;
    uio.uio_td = curthread;
    flags = MSG_DONTWAIT;
    m = NULL;

    rc = soreceive(so, NULL, &uio, &m, NULL, &flags);

    if (rc || !m) {
        if (rc != EWOULDBLOCK) {
            dprint("soreceive: conn %p, rc %d, m %p, flags %x, %lu %lu, %lu\n",
                   conn, rc, m, flags, conn->nsoupcalls, conn->ncallbacks,
                   priv->nrcvlowat);
            conn->active = false;
            xx_conn_rele(conn);
        }

        return;
    }

    /* Append new data to the current record fragment.
     */
    if (priv->last) {
        m_cat(priv->last, m);
    } else {
        priv->frag = m;
    }

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

        if (--rcvpercall > 0)
            goto again;
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

    /* Accumulate RPC records until we see the last record.
     */
    if (priv->msg) {
        m_cat(priv->msg, m);
    } else {
        priv->msg = m;
    }

    if (reclast) {
        struct xx_tdp_work *work;
        struct mbuf *h;

        h = priv->hdr;
        if (!h)
            h = m_gethdr(M_WAITOK, MT_DATA);

        h->m_next = priv->msg;
        priv->msg = NULL;

        xx_conn_hold(conn);

        work = mtod(h, struct xx_tdp_work *);
        work->tdp = conn->work.tdp;
        work->argv[0] = conn;
        work->argv[1] = h;
        work->func = krpc_recv_rpc;

        if (priv->frag)
            xx_tdp_enqueue(work, curcpu);
        else
            work->func(work);

        priv->hdr = m_gethdr(M_NOWAIT, MT_DATA);
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
    priv->hdr = m_gethdr(M_NOWAIT, MT_DATA);

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
    m_freem(priv->msg);
    m_freem(priv->hdr);

    mtx_destroy(&priv->txq_mtx);
}

static struct xx_svc *krpc2_svc;

int
krpc2_mod_load(module_t mod, int cmd, void *data)
{
    const char *host = "0.0.0.0";
    struct xx_svc *svc;
    int rc;

    rc = xx_svc_create(&svc);
    if (rc) {
        eprint("xx_svc_create() failed: %d\n", rc);
        return rc;
    }

    rc = xx_svc_listen(svc, SOCK_STREAM, host, xx_port,
                       krpc_accept_cb, krpc_recv_tcp, krpc_destroy_cb,
                       sizeof(struct conn_priv));
    if (rc) {
        eprint("xx_svc_listen() failed: %d\n", rc);
        xx_svc_shutdown(svc);
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

    if (!rc)
        krpc2_svc = NULL;

    return rc;
}
