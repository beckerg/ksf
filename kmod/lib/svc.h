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

#ifndef XX_SVC_H
#define XX_SVC_H

struct xx_conn;
typedef void xx_conn_cb_t(struct xx_conn *);

struct xx_conn {
    int                     refcnt;
    bool                    active;
    struct xx_tdp_work      work;

    xx_conn_cb_t           *recv_cb;
    struct socket          *so;
    struct xx_svc          *svc;

    xx_conn_cb_t           *destroy_cb;
    struct sockaddr        *laddr;
    TAILQ_ENTRY(xx_conn)    connq_entry;

    u_long                  nsoupcalls;
    u_long                  ncallbacks;
    size_t                  privsz;
    void                   *magic;

    __aligned(CACHE_LINE_SIZE)
    char                    priv[];
};

static inline void *
xx_conn_priv(struct xx_conn *conn)
{
    return conn->priv;
}

int xx_conn_hold(struct xx_conn *conn);
void xx_conn_rele(struct xx_conn *conn);
void xx_conn_reln(struct xx_conn *conn, int n);

int xx_svc_listen(struct xx_svc *svc, int type, const char *host, in_port_t port,
                  xx_conn_cb_t *accept_cb, xx_conn_cb_t *recv_cb,
                  xx_conn_cb_t *destroy_cb, size_t privsz);
int xx_svc_create(struct xx_svc **svcp);
int xx_svc_shutdown(struct xx_svc *svc);

#endif /* XX_SVC_H */
