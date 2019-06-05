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

#include "xx.h"
#include "tdp.h"
#include "svc.h"

MODULE_VERSION(kecho, 1);

MALLOC_DEFINE(M_XX_KECHO, "kecho", "kecho service");

SYSCTL_NODE(_debug, OID_AUTO, kecho,
            CTLFLAG_RW,
            0, "kecho kmod");

SYSCTL_UINT(_debug_kecho, OID_AUTO, debug,
            CTLFLAG_RW,
            &xx_debug, 0,
            "Show debug tracing on console");

struct conn_priv {
    struct mbuf *hdr;
};

/* The tcp destroy callback is called once all the references
 * to conn have been release, prior to socket close.  This
 * is where we teardown the connection private data.
 */
static void
kecho_destroy_cb(struct xx_conn *conn)
{
    struct conn_priv *priv = xx_conn_priv(conn);

    m_freem(priv->hdr);
}

static void
kecho_recv_tcp(struct xx_conn *conn)
{
    struct conn_priv *priv = xx_conn_priv(conn);
    struct socket *so = conn->so;
    struct mbuf *m = NULL;
    int rcvpercall = 8;
    struct mbuf *h;
    struct uio uio;
    int flags;
    int rc;

  again:
    uio.uio_resid = IP_MAXPACKET;
    uio.uio_td = curthread;
    flags = MSG_DONTWAIT;
    m = NULL;

    rc = soreceive(so, NULL, &uio, &m, NULL, &flags);

    if (rc || !m) {
        if (rc != EWOULDBLOCK) {
            if (rc) {
                dprint("soreceive: tcp conn %p, rc %d, m %p, flags %x, %lu %lu\n",
                       conn, rc, m, flags, conn->nsoupcalls, conn->ncallbacks);
            }

            conn->active = false;
            xx_conn_rele(conn);
        }

        return;
    }

    h = priv->hdr;
    if (!h)
        h = m_gethdr(M_WAITOK, MT_DATA);
    h->m_next = m;
    m_fixhdr(h);

    rc = sosend(so, NULL, NULL, h, NULL, 0, curthread);
    if (rc) {
        dprint("sosend: tcp conn %p, rc %d, m %p, flags %x, %lu %lu\n",
               conn, rc, m, flags, conn->nsoupcalls, conn->ncallbacks);
        conn->active = false;
        xx_conn_rele(conn);
    }

    priv->hdr = m_gethdr(M_NOWAIT, MT_DATA);

    if (--rcvpercall > 0)
        goto again;
}

static void
kecho_recv_udp(struct xx_conn *conn)
{
    struct conn_priv *priv = xx_conn_priv(conn);
    struct socket *so = conn->so;
    struct sockaddr *faddr;
    int rcvpercall = 8;
    struct mbuf *m;
    struct mbuf *h;
    struct uio uio;
    int flags;
    int rc;

  again:
    uio.uio_resid = IP_MAXPACKET;
    uio.uio_td = curthread;
    flags = MSG_DONTWAIT;
    faddr = NULL;
    m = NULL;

    rc = soreceive(so, &faddr, &uio, &m, NULL, &flags);

    if (rc || !m) {
        if (rc != EWOULDBLOCK) {
            if (rc) {
                dprint("soreceive: udp conn %p, rc %d, m %p, flags %x, %lu %lu\n",
                       conn, rc, m, flags, conn->nsoupcalls, conn->ncallbacks);
            }

            conn->active = false;
            xx_conn_rele(conn);
        }

        return;
    }

    h = priv->hdr;
    if (!h)
        h = m_gethdr(M_WAITOK, MT_DATA);
    h->m_next = m;
    m_fixhdr(h);

    rc = sosend(so, faddr, NULL, h, NULL, 0, curthread);
    if (rc) {
        dprint("sosend: udp conn %p, rc %d, m %p, flags %x, %lu %lu\n",
               conn, rc, m, flags, conn->nsoupcalls, conn->ncallbacks);
        conn->active = false;
        xx_conn_rele(conn);
    }

    free(faddr, M_SONAME);

    priv->hdr = m_gethdr(M_NOWAIT, MT_DATA);

    if (--rcvpercall > 0)
        goto again;
}

static struct xx_svc *kecho_svc;

int
kecho_mod_load(module_t mod, int cmd, void *data)
{
    const char *host = "0.0.0.0";
    in_port_t port = 60007;
    struct xx_svc *svc;
    int rc;

    rc = xx_svc_create(&svc);
    if (rc) {
        eprint("xx_svc_create() failed: %d\n", rc);
        return rc;
    }

#if 1
    rc = xx_svc_listen(svc, SOCK_DGRAM, host, port,
                       NULL, kecho_recv_udp, kecho_destroy_cb,
                       sizeof(struct conn_priv));
    if (rc)
        eprint("xx_svc_listen() failed: udp, rc %d\n", rc);
#endif

    rc = xx_svc_listen(svc, SOCK_STREAM, host, port,
                       NULL, kecho_recv_tcp, kecho_destroy_cb,
                       sizeof(struct conn_priv));
    if (rc)
        eprint("xx_svc_listen() failed: tcp, rc %d\n", rc);

    kecho_svc = svc;

    return 0;
}

int
kecho_mod_unload(module_t mod, int cmd, void *data)
{
    int rc;

    rc = xx_svc_shutdown(kecho_svc);
    if (rc)
        return rc;

    kecho_svc = NULL;

    return 0;
}
