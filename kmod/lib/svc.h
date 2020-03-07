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

#ifndef SVC_H
#define SVC_H

struct conn;
typedef void conn_cb_t(struct conn *);

struct conn {
    int                     refcnt;
    bool                    shut_wr;
    conn_cb_t              *destroy;
    struct sockaddr        *laddr;
    size_t                  privsz;
    TAILQ_ENTRY(conn)       entry;
    uintptr_t               magic;

    __aligned(CACHE_LINE_SIZE)
    struct tpreq            tpreq;
    struct tpool           *tpool;
    struct socket          *so;
    conn_cb_t              *recv;
    struct svc             *svc;

    struct tpreq            tpshutdown;

    __aligned(CACHE_LINE_SIZE)
    char                    priv[];
};

int conn_hold(struct conn *conn);
void conn_reln(struct conn *conn, int n);

static inline void *
conn_priv(struct conn *conn)
{
    return conn->priv;
}

static inline void
conn_rele(struct conn *conn)
{
    conn_reln(conn, 1);
}

int svc_listen(struct svc *svc, int type, const char *host, in_port_t port,
               conn_cb_t *acceptb, conn_cb_t *recvb, conn_cb_t *destroyb,
               size_t privsz);
int svc_create(u_int tdmin, u_int tdmax, struct svc **svcp);
int svc_shutdown(struct svc *svc);

#endif /* SVC_H */
