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
#include <sys/uio.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

#include "xx.h"
#include "tdp.h"
#include "svc.h"

MALLOC_DEFINE(M_XX_KECHO, "kecho", "kecho service");

SYSCTL_NODE(_debug, OID_AUTO, kecho,
            CTLFLAG_RW,
            0, "kecho kmod");

SYSCTL_UINT(_debug_kecho, OID_AUTO, debug,
            CTLFLAG_RW,
            &xx_debug, 0,
            "Show debug tracing on console");

static void
kecho_recv(struct xx_conn *conn)
{
    struct socket *so = conn->so;
    struct mbuf *m = NULL;
    struct uio uio;
    int flags;
    int rc;

    uio.uio_td = curthread;
    uio.uio_resid = 1024 * 16;
    flags = MSG_DONTWAIT;

    rc = soreceive(so, NULL, &uio, &m, NULL, &flags);

    if (rc || !m) {
        dprint("conn %p, rc %d, m %p, flags %x, %lu %lu\n",
               conn, rc, m, flags, conn->nsoupcalls, conn->ncallbacks);
        if (rc != EWOULDBLOCK) {
            conn->active = false;
            xx_conn_rele(conn);
        }

        return;
    }

    rc = sosend(so, NULL, NULL, m, NULL, 0, curthread);
    if (rc) {
        eprint("sosend: conn %p, resid %zu, rc %d\n",
               conn, uio.uio_resid, rc);
        conn->active = false;
        xx_conn_rele(conn);
    }
}

static struct xx_svc *kecho_svc;

static int
xx_modevent(module_t mod, int cmd, void *data)
{
    const char *host = "0.0.0.0";
    in_port_t port = 60007;
    struct xx_svc *svc;
    int rc;

    switch (cmd) {
    case MOD_LOAD:
        rc = xx_svc_create(&svc);
        if (rc) {
            eprint("xx_svc_create() failed: %d\n", rc);
            break;
        }

        rc = xx_svc_listen(svc, SOCK_STREAM, host, port, kecho_recv);
        if (rc) {
            eprint("xx_lsn_create() failed: %d\n", rc);
            xx_svc_shutdown(svc);
            break;
        }

        kecho_svc = svc;
        break;

    case MOD_UNLOAD:
        rc = xx_svc_shutdown(kecho_svc);
        if (rc)
            break;

        kecho_svc = NULL;
        break;

    default:
        rc = EOPNOTSUPP;
        break;
    }

    return rc;
}

moduledata_t xx_mod = {
    "kecho",
    xx_modevent,
    NULL,
};

DECLARE_MODULE(kecho, xx_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_VERSION(kecho, 1);
