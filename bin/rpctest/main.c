/*
 * Copyright (c) 2001-2006,2011,2014-2017,2019 Greg Becker.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <signal.h>
#include <sysexits.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <pthread_np.h>
#include <limits.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/endian.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/cpuset.h>
#endif

#include "main.h"
#include "clp.h"
#include "ksf.h"

#define BKTV_MAX    (1024 * 1024 * 4u)
#define MSGLAG_MAX  (1024)
#define NFS3_NULL   (0)

#define rdtsc()     __rdtsc()

char version[] = PROG_VERSION;
char *progname;
int verbosity;

FILE *dprint_fp;
FILE *eprint_fp;

pthread_barrier_t bar_start;
pthread_barrier_t bar_end;
unsigned int jobs = 1;
in_port_t port = 62049;
long duration = 600;
u_long msgcnt = 1000000;
size_t msgmax = 128 * 1024;
size_t msglag = 1;
u_int itermax = UINT_MAX;
bool headers = true;
bool fragged = false;
enum_t auth_flavor;
char *auth_type = "none";
AUTH *auth;
char *host;
bool udp;
uint64_t tsc_freq = 1000000;

struct tdargs {
    struct sockaddr_in faddr;
    cpuset_t mask;
    pthread_t td;
    char *rxbuf;
    size_t bytes;
    long iters;
    long usecs;
    long ru_usecs;
    long tx_eagain;
    long rx_eagain;
    uint64_t startv[MSGLAG_MAX];
    uint bktv[BKTV_MAX];
} __aligned(CACHE_LINE_SIZE);

static clp_posparam_t posparamv[] = {
    { .name = "host",
      .help = "[user@]host[:port]",
      .convert = clp_cvt_string, .cvtdst = &host, },

    CLP_PARAM_END
};

static clp_option_t optionv[] = {
    CLP_OPTION_VERBOSE(verbosity),
    CLP_OPTION_VERSION(version),
    CLP_OPTION_HELP,

    CLP_OPTION(string, 'A', auth_type, NULL, NULL, "auth type (none, sys, unix)"),
    CLP_OPTION(size_t, 'a', msglag, NULL, NULL, "max number of inflight RPCs (per thread)"),
    CLP_OPTION(u_long, 'c', msgcnt, NULL, NULL, "max messages to send (per thread)"),
    CLP_OPTION(bool, 'f', fragged, NULL, NULL, "break each RPC into three records"),
    CLP_OPTION(bool, 'H', headers, NULL, NULL, "suppress headers"),
    CLP_OPTION(u_int, 'i', itermax, NULL, NULL, "max iterations"),
    CLP_OPTION(u_int, 'j', jobs, NULL, NULL, "max number of threads/connections"),
    CLP_OPTION(bool, 'u', udp, NULL, NULL, "use UDP"),

    CLP_OPTION_END
};

int
rpc_encode(uint32_t xid, uint32_t proc, AUTH *auth, char *buf, size_t bufsz)
{
    struct rpc_msg msg;
    size_t offset;
    XDR xdr;
    int len;

    msg.rm_xid = xid;
    msg.rm_direction = CALL;
    msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
    msg.rm_call.cb_prog = NFS_PROGRAM;
    msg.rm_call.cb_vers = 3;
    msg.rm_call.cb_proc = proc;

    if (auth) {
        msg.rm_call.cb_cred = auth->ah_cred;
        msg.rm_call.cb_verf = auth->ah_verf;
    } else {
        msg.rm_call.cb_cred = _null_auth;
        msg.rm_call.cb_verf = _null_auth;
    }

    /* If fragged is true then we'll send the RPC message as three
     * RPC record fragments, where the first and last fragment
     * contain just the first/last byte of the RPC message.
     */
    offset = RPC_RECMARK_SZ;
    if (fragged)
        offset *= 2;

    if (bufsz < offset || !buf)
        return -1;

    /* Create the serialized RPC message, leaving sufficient space
     * at the front of the buffer for the record mark(s).
     */
    xdrmem_create(&xdr, buf + offset, bufsz - offset, XDR_ENCODE);
    len = -1;

    if (xdr_callmsg(&xdr, &msg)) {
        len = xdr_getpos(&xdr);

        if (fragged) {
            char c = buf[offset + len - 1];

            rpc_recmark_set(buf, 1, false);
            buf[RPC_RECMARK_SZ] = buf[offset];

            rpc_recmark_set(buf + RPC_RECMARK_SZ + 1, len - 2, false);

            rpc_recmark_set(buf + offset + len - 1, 1, true);
            buf[offset + len - 1 + RPC_RECMARK_SZ] = c;

            len += RPC_RECMARK_SZ * 2;
        }
        else {
            rpc_recmark_set(buf, len, true);
        }

        len += RPC_RECMARK_SZ;
    }

    return len;
}

enum clnt_stat
rpc_decode(XDR *xdr, struct rpc_msg *msg, struct rpc_err *err)
{
    msg->acpted_rply.ar_verf = _null_auth;
    msg->acpted_rply.ar_results.where = NULL;
    msg->acpted_rply.ar_results.proc = (xdrproc_t)xdr_void;

    err->re_status = RPC_CANTDECODERES;

    if (xdr_replymsg(xdr, msg))
        _seterr_reply(msg, err);

    return err->re_status;
}

/* Asynchronous send/recv loop.  Note that the send can race ahead
 * of the receiver by at most msglag messages.
 */
int
nullproc_async(int fd, struct tdargs *tdargs)
{
    char *rxbuf, *txbuf, errbuf[128];
    ssize_t rxlen, txlen, txfrag, txfragmax, cc;
    uint32_t rxmax, rxoff, rmlen;
    int rxflags, txflags;
    u_long msgrx, msgtx;
    uint64_t *startv, stop;
    u_int *bktv;
    bool last;
    int rc;

    rxbuf = tdargs->rxbuf;
    txbuf = rxbuf + roundup(msgmax, 4096);
    txflags = MSG_DONTWAIT;
    rxflags = MSG_DONTWAIT;
    msgrx = msgtx = 0;
    rc = 0;

    rxmax = rxlen = rmlen = 0;
    last = false;

    startv = tdargs->startv;
    bktv = tdargs->bktv;

    txfragmax = 8192;
    txlen = 0;

    while (msgrx < msgcnt) {
        if (msgtx < msgcnt && msgtx - msgrx < msglag) {
            if (txlen == 0) {
                startv[msgtx % MSGLAG_MAX] = rdtsc();

                txlen = rpc_encode(msgtx, NFS3_NULL, auth, txbuf, msgmax);

                txfragmax = 8192;
                if (txfragmax > txlen)
                    txfragmax = txlen;
                txfrag = txfragmax;
            }

            cc = send(fd, txbuf + (txfragmax - txfrag), txfrag, txflags);
            if (cc == -1) {
                if (errno != EAGAIN) {
                    strerror_r(rc = errno, errbuf, sizeof(errbuf));
                    eprint("send: cc %ld: %s\n", cc, errbuf);
                    break;
                }

                ++tdargs->tx_eagain;
            }
            else {
                tdargs->bytes += cc;
                txfrag -= cc;
                txlen -= cc;
                if (txlen == 0)
                    ++msgtx;
            }
        }

        rxflags = (msgtx - msgrx < msglag) ? MSG_DONTWAIT : 0;

        /* Peek at the RPC record mark so that we can get the
         * size of the record fragment.
         */
        if (rmlen == 0) {
            cc = recv(fd, rxbuf, RPC_RECMARK_SZ, MSG_PEEK | rxflags);
            if (cc < RPC_RECMARK_SZ) {
                if (cc > 0)
                    continue;

                if (cc == -1 && errno == EAGAIN) {
                    ++tdargs->rx_eagain;
                    continue;
                }

                strerror_r(rc = errno, errbuf, sizeof(errbuf));
                eprint("recv: cc %ld %s\n", cc, errbuf);
                break;
            }

            rpc_recmark_get(rxbuf, &rmlen, &last);
            assert(rmlen < 1024);

            rxmax = rmlen + RPC_RECMARK_SZ;
            rxoff = RPC_RECMARK_SZ;

            /* If we have enough RPC calls in flight then we can read
             * the record mark for reply message (n + 1) while reading
             * reply message n.
             */
            if (msgtx - msgrx > 2)
                rxmax += RPC_RECMARK_SZ;

            rxlen = rxmax;
        }

        cc = recv(fd, rxbuf + (rxmax - rxlen), rxlen, rxflags);
        if (cc < rxlen) {
            if (cc > 0) {
                rxlen -= cc;
                continue;
            }

            if (cc == -1 && errno == EAGAIN) {
                ++tdargs->rx_eagain;
                continue;
            }

            strerror_r(rc = errno, errbuf, sizeof(errbuf));
            eprint("recv: cc %ld %s\n", cc, errbuf);
            break;
        }

        rxlen -= cc;
        if (rxlen == 0) {
            enum clnt_stat stat;
            struct rpc_msg msg;
            struct rpc_err err;
            uint32_t rmlen2 = 0;
            bool last2 = false;
            XDR xdr;

            if (rxmax - rmlen - rxoff > 0) {
                assert(rxmax - rmlen - rxoff == RPC_RECMARK_SZ);

                rpc_recmark_get(rxbuf + rmlen + rxoff, &rmlen2, &last2);
                assert(rmlen < 1024);

                if (rmlen2 == 0) {
                    eprint("invalid record mark: %ld %u %u %u %u %lu %lu\n",
                           rxlen, rxmax, rmlen, rxoff, rmlen2, msgrx, msgtx);
                    break;
                }
            }

            tdargs->bytes += rmlen + RPC_RECMARK_SZ;

            if (last) {
                if (rxbuf > tdargs->rxbuf) {
                    if (rxoff > 0)
                        memmove(rxbuf, rxbuf + rxoff, rmlen);
                    rmlen += (rxbuf - tdargs->rxbuf);
                    rxbuf = tdargs->rxbuf;
                    rxoff = 0;
                }

                xdrmem_create(&xdr, rxbuf + rxoff, rmlen, XDR_DECODE);

                stat = rpc_decode(&xdr, &msg, &err);

                if (stat != RPC_SUCCESS) {
                    eprint("invalid rpc reply: %ld %u %u %u %u %lu %lu %u: %s\n",
                           rxlen, rxmax, rmlen, rxoff, rmlen2, msgrx, msgtx, stat,
                           clnt_sperrno(stat));
                    break;
                }

                stop = rdtsc() - startv[msg.rm_xid % MSGLAG_MAX];

                if (stop >= BKTV_MAX)
                    stop = BKTV_MAX - 1;

                ++bktv[stop];

#ifdef DEBUG
                assert(startv[msg.rm_xid % MSGLAG_MAX] > 0);
                startv[msg.rm_xid % MSGLAG_MAX] = 0;
#endif

                rxbuf = tdargs->rxbuf;
                ++msgrx;
            }
            else {
                if (rxoff > 0)
                    memmove(rxbuf, rxbuf + rxoff, rmlen);
                rxbuf += rmlen;
            }

            rmlen = rmlen2;
            rxmax = rmlen;
            last = last2;
            rxoff = 0;

            if (rmlen > 0 && (msgtx - msgrx) > 2)
                rxmax += RPC_RECMARK_SZ;

            rxlen = rxmax;
        }
    }

    tdargs->iters = msgrx;

    return rc;
}

/* Synchronous send/recv loop...
 */
int
nullproc_sync(int fd, struct tdargs *tdargs)
{
    char *rxbuf, *txbuf, errbuf[128];
    uint64_t *startv, stop;
    u_int *bktv;
    ssize_t cc;
    long msgrx;
    int rc;

    rxbuf = tdargs->rxbuf;
    txbuf = rxbuf + roundup(msgmax, 4096);
    msgrx = 0;
    rc = 0;

    startv = tdargs->startv;
    bktv = tdargs->bktv;

    while (msgrx < msgcnt) {
        struct rpc_msg rmsg;
        struct rpc_err rerr;
        enum clnt_stat stat;
        uint32_t rmlen;
        int rpclen;
        bool last;
        XDR xdr;

        startv[msgrx % MSGLAG_MAX] = rdtsc();

        rpclen = rpc_encode(msgrx, NFS3_NULL, auth, txbuf, msgmax);
        if (rpclen == -1) {
            eprint("rpc_encode: len %d, msgrx %ld\n", rpclen, msgrx);
            abort();
        }

        cc = send(fd, txbuf, rpclen, 0);

        if (cc != rpclen) {
            if (cc == -1) {
                strerror_r(rc = errno, errbuf, sizeof(errbuf));
                eprint("send: cc %ld: %s\n", cc, errbuf);
                break;
            }

            eprint("send: cc %ld: short write\n", cc);
            rc = EIO;
            break;
        }

        /* Peek at the RPC record mark so that we can get the
         * size of the record fragment.
         */
        cc = recv(fd, rxbuf, RPC_RECMARK_SZ, MSG_WAITALL);

        if (cc < RPC_RECMARK_SZ) {
            if (cc == -1) {
                strerror_r(rc = errno, errbuf, sizeof(errbuf));
                eprint("recv: recmark cc %ld %s\n", cc, errbuf);
                break;
            }

            eprint("recv: recmark cc %ld short read\n", cc);
            rc = EIO;
            break;
        }

        rpc_recmark_get(rxbuf, &rmlen, &last);

        cc = recv(fd, rxbuf, rmlen, MSG_WAITALL);

        if (cc != rmlen) {
            if (cc == -1) {
                strerror_r(rc = errno, errbuf, sizeof(errbuf));
                eprint("recv: cc %ld, expected %u: %s\n",
                       cc, rmlen, errbuf);
                break;
            }

            eprint("recv: cc %ld short read, expected %u\n",
                   cc, rmlen);
            rc = EIO;
            break;
        }

        xdrmem_create(&xdr, rxbuf, rmlen, XDR_DECODE);

        stat = rpc_decode(&xdr, &rmsg, &rerr);

        if (stat != RPC_SUCCESS) {
            eprint("recv: msgrx %ld, stat %d\n", msgrx, stat);
            break;
        }

        if (rmsg.rm_xid != msgrx) {
            eprint("recv: invalid xid %u, msgrx %ld\n", rmsg.rm_xid, msgrx);
            break;
        }

        stop = rdtsc() - startv[rmsg.rm_xid % MSGLAG_MAX];

        if (stop >= BKTV_MAX)
            stop = BKTV_MAX - 1;

        ++bktv[stop];

        tdargs->bytes += cc + rpclen + RPC_RECMARK_SZ;
        ++msgrx;
    }

    tdargs->iters = msgrx;

    return rc;
}

void *
run(void *arg)
{
    char errbuf[128];
    struct timeval tv_start, tv_stop, tv_diff;
    struct timeval ru_utime, ru_stime, ru_total;
    struct rusage ru_start, ru_stop;
    struct tdargs *tdargs = arg;
    long usecs;
    int fd, rc;

    rc = pthread_setaffinity_np(tdargs->td, sizeof(tdargs->mask), &tdargs->mask);
    if (rc) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint("pthread_setaffinity_np: %s\n", errbuf);
        abort();
    }

    fd = socket(PF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd == -1) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint("socket: %s\n", errbuf);
        abort();
    }

    rc = connect(fd, (struct sockaddr *)&tdargs->faddr, sizeof(tdargs->faddr));
    if (rc) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint("connect: %s\n", errbuf);
        abort();
    }

    errno = 0;
    rc = pthread_barrier_wait(&bar_start);
    if (rc && errno)
        abort();

    getrusage(RUSAGE_SELF, &ru_start);
    gettimeofday(&tv_start, NULL);

    if (msglag > 0)
        rc = nullproc_async(fd, tdargs);
    else
        rc = nullproc_sync(fd, tdargs);

    gettimeofday(&tv_stop, NULL);
    getrusage(RUSAGE_SELF, &ru_stop);

    pthread_barrier_wait(&bar_end);

    timersub(&tv_stop, &tv_start, &tv_diff);
    usecs = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
    tdargs->usecs = usecs;

    timersub(&ru_stop.ru_utime, &ru_start.ru_utime, &ru_utime);
    timersub(&ru_stop.ru_stime, &ru_start.ru_stime, &ru_stime);
    timeradd(&ru_utime, &ru_stime, &ru_total);
    tdargs->ru_usecs = ru_total.tv_sec * 1000000 + ru_total.tv_usec;

    dprint(1, "%p, fd %2d, usecs %ld, ru %ld %.2lf, msgs/sec %ld, bytes/sec %ld, %ld %ld\n",
           tdargs->td, fd, usecs,
           tdargs->ru_usecs, (double)tdargs->ru_usecs / tdargs->iters,
           (tdargs->iters * 1000000) / usecs,
           (tdargs->bytes * 1000000) / usecs,
           tdargs->tx_eagain, tdargs->rx_eagain);

    close(fd);
    pthread_exit(NULL);
}

static bool
given(int c)
{
    clp_option_t *opt = clp_option_find(optionv, c);

    return (opt && opt->given);
}

int
main(int argc, char **argv)
{
    char serverip[INET_ADDRSTRLEN + 1];
    long iters, usecs, ru_usecs;
    struct sockaddr_in faddr;
    struct tdargs *tdargv;
    double nsecspercycle;
    struct hostent *hent;
    char *server, *user;
    size_t tdargvsz;
    size_t rxbufsz;
    size_t bytes;
    long *prxbuf;
    char *rxbuf;
    int i;

    u_int cpu_count, cpu_offset, cpu_step;
    cpuset_t cpu_mask;

    uint index99, index95, index90, index50;
    uint pct99, pct95, pct90, pct50;
    uint first, last, avglat;
    int n, j, jmax;
    long nsecs;

    char errbuf[128];
    char state[256];
    int optind;
    char *pc;
    int rc;

    progname = strrchr(argv[0], '/');
    progname = (progname ? progname + 1 : argv[0]);

    dprint_fp = stderr;
    eprint_fp = stderr;

    initstate((u_long)time(NULL), state, sizeof(state));

    rc = clp_parsev(argc, argv, optionv, posparamv, errbuf, sizeof(errbuf), &optind);
    if (rc) {
        eprint("%s\n", errbuf);
        exit(rc);
    }

    if (given('h') || given('V'))
        return 0;

    argc -= optind;
    argv += optind;

    user = server = host;

    pc = strchr(user, '@');
    if (pc) {
        *pc++ = '\000';
        server = pc;
    }

    pc = strchr(server, ':');
    if (pc) {
        *pc++ = '\000';
        port = strtoul(pc, NULL, 0);
    }

    if (!isalpha(server[0]) && !isdigit(server[0])) {
        eprint("invalid host name %s\n", server);
        exit(1);
    }

    faddr.sin_family = AF_INET;
    faddr.sin_port = htons(port);

    hent = gethostbyname(server);
    if (!hent) {
        eprint("gethostbyname(%s) failed: %s\n", server, hstrerror(h_errno));
        exit(1);
    }

    if (hent->h_addrtype != AF_INET) {
        eprint("host %s does not have an AF_INET address\n", server);
        exit(1);
    }

    if (!inet_ntop(AF_INET, hent->h_addr_list[0],
                   serverip, sizeof(serverip))) {
        eprint("unable to convert server address %s to dotted quad notation: %s",
               server, strerror(errno));
        exit(1);
    }

    serverip[sizeof(serverip) - 1] = '\000';
    faddr.sin_addr.s_addr = inet_addr(serverip);


#ifdef __FreeBSD__
    size_t sz = sizeof(tsc_freq);
    int ival;

    sz = sizeof(ival);
    rc = sysctlbyname("kern.timecounter.smp_tsc", (void *)&ival, &sz, NULL, 0);
    if (rc) {
        eprint("sysctlbyname(kern.timecounter.smp_tsc): %s\n", strerror(errno));
        exit(EX_OSERR);
    }

    if (!ival) {
        dprint(0, "unable to determine if the TSC is SMP safe, "
               "output will likely be incorrect\n");
    }

    sz = sizeof(tsc_freq);
    rc = sysctlbyname("machdep.tsc_freq", (void *)&tsc_freq, &sz, NULL, 0);
    if (rc) {
        eprint("sysctlbyname(machdep.tsc_freq): %s\n", strerror(errno));
        exit(EX_OSERR);
    }

    dprint(1, "machedep.tsc_freq: %lu\n", tsc_freq);
#else
#error "Don't know how to determine the TSC frequency on this platform"
#endif

    if (msgcnt < 1)
        msgcnt = 1;
    if (msgmax < RPC_RECMARK_SZ + 8)
        msgmax = RPC_RECMARK_SZ + 8;
    if (msglag > MSGLAG_MAX)
        msglag = MSGLAG_MAX;

    rxbufsz = roundup(msgmax, 4096) * 2 * jobs;
    rxbufsz = roundup(rxbufsz, 1024 * 1024 * 2);

    rxbuf = mmap(NULL, rxbufsz, PROT_READ | PROT_WRITE,
                 MAP_ALIGNED_SUPER | MAP_SHARED | MAP_ANON, -1, 0);
    if (rxbuf == MAP_FAILED) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint("mmap: %s\n", errbuf);
        abort();
    }

    if (0 == strcasecmp(auth_type, "sys")) {
        auth_flavor = AUTH_SYS;
        auth = authunix_create_default();
    } else if (0 == strcasecmp(auth_type, "unix")) {
        auth_flavor = AUTH_UNIX;
        auth = authunix_create_default();
    } else if (0 == strcasecmp(auth_type, "none")) {
        auth_flavor = AUTH_NONE;
        auth = authnone_create();
    } else {
        eprint("invalid auth type %s, use -h for help\n", auth_type);
        exit(EX_USAGE);
    }

    rc = rpc_encode(msgcnt, NFS3_NULL, auth, rxbuf, rxbufsz);
    dprint(1, "sizeof(rpc_msg) %zu, sizeof(call_body) %zu, sizeof(nfsv3_null auth%s) %d\n",
           sizeof(struct rpc_msg), sizeof(struct call_body), auth_type, rc);

    prxbuf = (long *)rxbuf;
    for (i = 0; i < rxbufsz / sizeof(*prxbuf); i += sizeof(*prxbuf))
        *prxbuf++ = (long)(rxbuf + i);

    tdargvsz = roundup(sizeof(*tdargv) * (jobs + 1), 4096);
    tdargvsz = roundup(tdargvsz, 1024 * 1024 * 2);

    tdargv = mmap(NULL, tdargvsz, PROT_READ | PROT_WRITE,
                  MAP_ALIGNED_SUPER | MAP_SHARED | MAP_ANON, -1, 0);
    if (tdargv == MAP_FAILED) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint("mmap: %s\n", errbuf);
        abort();
    }

    rc = pthread_barrier_init(&bar_start, NULL, jobs);
    if (rc)
        abort();

    rc = pthread_barrier_init(&bar_end, NULL, jobs);
    if (rc)
        abort();

    rc = setpriority(PRIO_PROCESS, 0, -15);
    if (rc && errno != EACCES) {
        eprint("unable to set priority: %s\n", strerror(errno));
    }

    rc = pthread_getaffinity_np(pthread_self(), sizeof(cpu_mask), &cpu_mask);
    if (rc) {
        eprint("pthread_getaffinity_np: %s\n", strerror(errno));
        abort();
    }

  again:
    memset(tdargv, 0, tdargvsz); // ensure tdargv is fully mapped...

    cpu_count = CPU_COUNT(&cpu_mask);
    cpu_offset = 2;
    cpu_step = 1;

    /* Find a stepping that will evenly distribute workers across cores
     * (assumes two HT threads per core that have sequential logical CPU
     * numbering, which isn't always true).
     */
    for (i = 3; i < cpu_count; ++i) {
        if (cpu_count % i) {
            cpu_step = i;
            break;
        }
    }

    /* Start worker threads...
     */
    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;

        memcpy(&tdargs->faddr, &faddr, sizeof(tdargs->faddr));
        tdargs->rxbuf = rxbuf + roundup(msgmax, 4096) * 2 * i;
        CPU_COPY(&cpu_mask, &tdargs->mask);

        for (j = 0; j < cpu_count && jobs < cpu_count; ++j) {
            if (CPU_ISSET((cpu_offset + cpu_step * i) % cpu_count, &cpu_mask)) {
                CPU_SETOF((cpu_offset + cpu_step * i) % cpu_count, &tdargs->mask);
                break;
            }
        }

        rc = pthread_create(&tdargs->td, NULL, run, tdargs);
        if (rc) {
            eprint("pthread_create() failed: %s\n", strerror(errno));
            abort();
        }
    }

    bytes = usecs = iters = ru_usecs = jmax = 0;

    /* Wait for all worker threads to complete...
     */
    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;
        void *val;

        rc = pthread_join(tdargs->td, &val);

        bytes += tdargs->bytes;
        iters += tdargs->iters;
        usecs += tdargs->usecs;
        ru_usecs += tdargs->ru_usecs;

        /* Coalesce all per-bkt latency counts...
         */
        for (j = 0; j < BKTV_MAX; ++j) {
            if (tdargs->bktv[j] > 0) {
                tdargv[jobs].bktv[j] += tdargs->bktv[j];
                if (j >= jmax)
                    jmax = j + 1;
            }
        }
    }

    usecs /= jobs;

    memset(tdargv[0].bktv, 0, sizeof(tdargv[0].bktv));
    nsecspercycle = 1000000000.0 / tsc_freq;

    pct99 = pct95 = pct90 = pct50 = 0;
    index99 = iters * .99;
    index95 = iters * .95;
    index90 = iters * .90;
    index50 = iters * .50;
    first = last = avglat = 0;
    nsecs = n = 0;

    /* Convert latency info from cycles to hundredths of usecs...
     */
    for (j = 0; j < jmax; ++j) {
        if (tdargv[jobs].bktv[j] > 0) {
            nsecs = j * nsecspercycle;
            tdargv[0].bktv[nsecs / 100] += tdargv[jobs].bktv[j];
        }
    }

    /* Compute percentiles...
     */
    for (j = 0; j < (nsecs / 100) + 1; ++j) {
        if (tdargv[0].bktv[j] == 0)
            continue;

        avglat += tdargv[0].bktv[j] * j;
        n += tdargv[0].bktv[j];
        last = j;

        if (pct99 == 0) {
            if (n >= index99)
                pct99 = j;

            if (pct95 == 0) {
                if (n >= index95)
                    pct95 = j;

                if (pct90 == 0) {
                    if (n >= index90)
                        pct90 = j;

                    if (pct50 == 0) {
                        if (n >= index50)
                            pct50 = j;

                        if (first == 0)
                            first = j;
                    }
                }
            }
        }
    }

    if (headers) {
        printf("%10s %4s %4s %9s %9s %8s %8s %6s %6s %6s %6s %6s %6s %7s %7s\n",
               "DATE", "TDS", "INF", "MSGCNT", "DURATION", "MSG/s", "Mbps",
               "MIN", "AVG", "50%", "90%", "95%", "99%", "MAX", "RU/MSG");
        headers = false;
    }

    printf("%10ld %4u %4zu %9ld %9ld %8lu %8.2lf %6.1lf %6.1lf %6.1lf %6.1lf %6.1lf %6.1lf %7.1lf %7.2lf\n",
           time(NULL), jobs, msglag, iters, usecs, (iters * 1000000) / usecs,
           (double)bytes / usecs, first / 10.0, (avglat / n) / 10.0,
           pct50 / 10.0, pct90 / 10.0, pct95 / 10.0, pct99 / 10.0, last / 10.0,
           (double)ru_usecs / iters);

    if (itermax-- > 1)
        goto again;

    munmap(tdargv, tdargvsz);
    munmap(rxbuf, rxbufsz);
    auth_destroy(auth);
    free(host);

    return 0;
}


/* Debug print.  Usually called indirectly via the dprint() macro.
 */
void
dprint_func(int lvl, const char *func, int line, const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (verbosity > 2)
        fprintf(dprint_fp, "%s: %16s %4d:  %s", progname, func, line, msg);
    else
        fprintf(dprint_fp, "%s", msg);
}


/* Error print.
 */
void
eprint(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(eprint_fp, "%s: %s", progname, msg);
}
