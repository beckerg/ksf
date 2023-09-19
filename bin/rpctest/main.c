/*
 * Copyright (c) 2001-2006,2011,2014-2017,2019-2020 Greg Becker.  All rights reserved.
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

#if __linux__
#define _GNU_SOURCE
#endif

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
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpc.h>

#if __FreeBSD__
#include <pthread_np.h>
#include <sys/endian.h>
#include <rpcsvc/nfs_prot.h>
#include <sys/sysctl.h>
#include <sys/cpuset.h>

#elif __linux__

#include <sched.h>
#include <endian.h>
#include <linux/nfs.h>

#define MAP_ALIGNED_SUPER   MAP_HUGETLB
#define CACHE_LINE_SIZE     (64)
#define cpuset_t            cpu_set_t

#if HAVE_TSC
#define __rdtsc()           __builtin_ia32_rdtsc()
#endif

#define CPU_COPY(_src, _dst)        \
do {                                \
    CPU_ZERO((_dst));               \
    CPU_OR((_dst), (_src), (_src)); \
} while (0)

size_t __attribute__((__weak__))
strlcat(char *dst, const char *src, size_t dstsize)
{
    return strlen(strcat(dst, src)); // TODO...
}
#endif

/* SPALIGN     Superpage alignment
 * BKTV_MAX    Max buckets in latency histogram
 * MSGINF_MAX  Max messages in flight per thread
 * MSGSZ_MAX   Max rx/tx message size
 */
#define SPALIGN             (1024 * 1024 * 2ul)
#define BKTV_MAX            (1024 * 1024 * 8ul)
#define MSGINF_MAX          (1024)
#define MSGSZ_MAX           (128)
#define NFS3_NULL           (0)

#define NELEM(_a)           (sizeof(_a) / sizeof((_a)[0]))

#ifndef __read_mostly
#define __read_mostly       __attribute__((__section__(".read_mostly")))
#endif

#ifndef likely
#define likely(_expr)       __builtin_expect(!!(_expr), 1)
#endif

#ifndef __aligned
#define __aligned(_sz)      __attribute__((__aligned__(_sz)))
#endif

#include "main.h"
#include "clp.h"
#include "ksf.h"

/* Time-stamp interval type...
 */
#if HAVE_TSC
typedef uint64_t            tsi_t;
#else
typedef struct timespec     tsi_t;
#endif

char version[] = PROG_VERSION;
char *progname;
int verbosity;

FILE *dprint_fp;
FILE *eprint_fp;

pthread_barrier_t bar_start;
pthread_barrier_t bar_end;
long duration = 600;
u_int itermax = 99;
u_int jobs = 1;
bool headers = true;
bool fragged = false;
bool xstats = false;
bool runavg = false;
in_port_t port = 62049;
enum_t auth_flavor;
char *auth_type = "none";
AUTH *auth;
char *host;
bool udp;
char *datadir;

double nsecspercycle;
double quantilev[16];
char *quantiles;
int quantilec;

size_t msglen __read_mostly;
size_t msginf __read_mostly;
u_long msgcnt __read_mostly;
uint tsc_scale __read_mostly;
uint64_t tsc_freq __read_mostly;

struct tdargs {
    struct sockaddr_in faddr;
    pthread_t td;
    int job;
    int cpu;
    long iters;
    uint64_t elapsed;
    size_t spbufsz;
    char *spbuf;
    char *rxbuf;
    uint32_t *bktv;
    tsi_t *startv;

    __aligned(CACHE_LINE_SIZE)
    size_t bytes;
    long tx_eagain;
    long rx_eagain;
    uint64_t latmax;
};

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
    CLP_OPTION(size_t, 'a', msginf, NULL, NULL, "max number of inflight RPCs (per thread)"),
    CLP_OPTION(u_long, 'c', msgcnt, NULL, NULL, "max messages to send (per thread)"),
    CLP_OPTION(bool, 'f', fragged, NULL, NULL, "break each RPC into three records"),
    CLP_OPTION(string, 'd', datadir, NULL, NULL, "latency data output directory"),
    CLP_OPTION(bool, 'H', headers, NULL, NULL, "suppress headers"),
    CLP_OPTION(u_int, 'i', itermax, NULL, NULL, "max iterations"),
    CLP_OPTION(u_int, 'j', jobs, NULL, NULL, "max number of threads/connections"),
    CLP_OPTION(bool, 'm', runavg, NULL, NULL, "show running average rather than running median"),
    CLP_OPTION(string, 'q', quantiles, NULL, NULL, "comma-separated list of quantiles"),
    CLP_OPTION(bool, 'u', udp, NULL, NULL, "use UDP"),
    CLP_OPTION(bool, 'x', xstats, NULL, NULL, "show extended statistics"),
    CLP_OPTION_END
};

static uint64_t
cycles2nsecs(uint64_t cycles)
{
    return cycles * nsecspercycle;
}

/* Record the start time for a time stamp interval measurement.
 */
static inline void
tsi_start(tsi_t *start)
{
#if HAVE_TSC
    *start = __rdtsc();
#else
    clock_gettime(CLOCK_MONOTONIC, start);
#endif
}

/* Return the difference in time between the current time
 * and the given earlier time stamp.  Always returns "cycles"
 * which can be converted to nanoseconds via cycles2nsecs().
 */
static inline uint64_t
tsi_delta(tsi_t *start)
{
#if HAVE_TSC
    return __rdtsc() - *start;
#else
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    timespecsub(&now, start, &now);

    return now.tv_sec * 1000000000ul + now.tv_nsec;
#endif
}


/* Allocate one or more superpages.  Falls back to normal
 * pages if superpages cannot be allocated.
 */
void *
spalloc(size_t sz)
{
    int flags = MAP_SHARED | MAP_ANON;
    int prot = PROT_READ | PROT_WRITE;
    int super = MAP_ALIGNED_SUPER;
    void *mem;

    sz = roundup(sz, 1024 * 1024 * 2);

  again:
    mem = mmap(NULL, sz, prot, flags, -1, 0);

    if (mem == MAP_FAILED) {
        if (super) {
            super = 0;
            goto again;
        }
    }

    if (!super)
        dprint(1, "unable to mmap %zu superpages\n", sz / SPALIGN);

    return (mem == MAP_FAILED) ? NULL : mem;
}

int
spfree(void *mem, size_t sz)
{
    return munmap(mem, roundup(sz, 1024 * 1024 * 2));
}

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

/* Asynchronous send/recv loop.  Note that the sender can race ahead
 * of the receiver by at most msginf messages.
 */
int
nullproc_async(int fd, struct tdargs *tdargs)
{
    tsi_t *startv;
    uint32_t *bktv;

    __aligned(CACHE_LINE_SIZE) // separate from read-mostly vars, above...
    ssize_t rxlen, txlen, txfrag, txfragmax, cc;
    uint32_t rxmax, rxoff, rmlen;
    int rxflags, txflags;
    u_long msgrx, msgtx;
    char *rxbuf, *txbuf;
    uint64_t stop;
    bool last;
    int rc;

    rxbuf = tdargs->rxbuf;
    txbuf = rxbuf + roundup(MSGSZ_MAX, 4096);
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
        if (msgtx < msgcnt && msgtx - msgrx < msginf) {
            if (txlen == 0) {
                tsi_start(&startv[msgtx % MSGINF_MAX]);

                txlen = rpc_encode(msgtx, NFS3_NULL, auth, txbuf, MSGSZ_MAX);

                txfragmax = 8192;
                if (txfragmax > txlen)
                    txfragmax = txlen;
                txfrag = txfragmax;
            }

            cc = send(fd, txbuf + (txfragmax - txfrag), txfrag, txflags);
            if (cc == -1) {
                if (errno != EAGAIN) {
                    eprint(rc = errno, "send: cc %ld", cc);
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

        rxflags = (msgtx - msgrx < msginf) ? MSG_DONTWAIT : 0;

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

                eprint(rc = errno, "recv: cc %ld", cc);
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

            eprint(rc = errno, "recv: cc %ld", cc);
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
                    eprint(0, "invalid record mark: %ld %u %u %u %u %lu %lu",
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
                    eprint(0, "invalid rpc reply: %ld %u %u %u %u %lu %lu %u: %s",
                           rxlen, rxmax, rmlen, rxoff, rmlen2, msgrx, msgtx, stat,
                           clnt_sperrno(stat));
                    break;
                }

                stop = tsi_delta(&startv[msg.rm_xid % MSGINF_MAX]);
                stop >>= tsc_scale;

                if (likely( stop < BKTV_MAX ))
                    ++bktv[stop];
                else if (stop > tdargs->latmax)
                    tdargs->latmax = stop;

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
    tsi_t *startv;
    uint64_t stop;
    char *rxbuf, *txbuf;
    u_int *bktv;
    ssize_t cc;
    long msgrx;
    int rc;

    rxbuf = tdargs->rxbuf;
    txbuf = rxbuf + roundup(MSGSZ_MAX, 4096);
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

        tsi_start(&startv[msgrx % MSGINF_MAX]);

        rpclen = rpc_encode(msgrx, NFS3_NULL, auth, txbuf, MSGSZ_MAX);
        if (rpclen == -1) {
            eprint(0, "rpc_encode: len %d, msgrx %ld", rpclen, msgrx);
            abort();
        }

        cc = send(fd, txbuf, rpclen, 0);

        if (cc != rpclen) {
            if (cc == -1) {
                eprint(rc = errno, "send: cc %ld", cc);
                break;
            }

            eprint(0, "send: cc %ld: short write", cc);
            rc = EIO;
            break;
        }

        /* Peek at the RPC record mark so that we can get the
         * size of the record fragment.
         */
        cc = recv(fd, rxbuf, RPC_RECMARK_SZ, MSG_WAITALL);

        if (cc < RPC_RECMARK_SZ) {
            if (cc == -1) {
                eprint(rc = errno, "recv: recmark cc %ld", cc);
                break;
            }

            eprint(EIO, "recv: recmark cc %ld short read", cc);
            rc = EIO;
            break;
        }

        rpc_recmark_get(rxbuf, &rmlen, &last);

        cc = recv(fd, rxbuf, rmlen, MSG_WAITALL);

        if (cc != rmlen) {
            if (cc == -1) {
                eprint(rc = errno, "recv: cc %ld, expected %u", cc, rmlen);
                break;
            }

            eprint(EIO, "recv: cc %ld short read, expected %u", cc, rmlen);
            rc = EIO;
            break;
        }

        xdrmem_create(&xdr, rxbuf, rmlen, XDR_DECODE);

        stat = rpc_decode(&xdr, &rmsg, &rerr);

        if (stat != RPC_SUCCESS) {
            eprint(EINVAL, "recv: msgrx %ld, stat %d", msgrx, stat);
            break;
        }

        if (rmsg.rm_xid != msgrx) {
            eprint(EINVAL, "recv: invalid xid %u, msgrx %ld", rmsg.rm_xid, msgrx);
            break;
        }

        stop = tsi_delta(&startv[rmsg.rm_xid % MSGINF_MAX]);
        stop >>= tsc_scale;

        if (likely( stop < BKTV_MAX ))
            ++bktv[stop];
        else if (stop > tdargs->latmax)
            tdargs->latmax = stop;

        tdargs->bytes += cc + rpclen + RPC_RECMARK_SZ;
        ++msgrx;
    }

    tdargs->iters = msgrx;

    return rc;
}

void *
run(void *arg)
{
    size_t rxbufsz, startvsz, bktvsz;
    struct rusage ru_start, ru_stop;
    struct tdargs *tdargs = arg;
    long majflt, minflt;
    int fd, rc;
    tsi_t tsi;

    if (jobs < 16 /* fixme */) {
        cpuset_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(tdargs->cpu, &cpuset);

        rc = pthread_setaffinity_np(tdargs->td, sizeof(cpuset), &cpuset);
        if (rc) {
            eprint(errno, "pthread_setaffinity_np (cpu %d)", tdargs->cpu);
            abort();
        }
    }

    /* Reschedule to ensure we awaken on the desired CPU...
     */
    usleep(10000);

    fd = socket(PF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd == -1) {
        eprint(errno, "socket");
        abort();
    }

    rc = connect(fd, (struct sockaddr *)&tdargs->faddr, sizeof(tdargs->faddr));
    if (rc) {
        eprint(errno, "connect");
        abort();
    }

    if (msginf == 1) {
        int optval = 1;

        rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
        if (rc)
            eprint(errno, "setsockopt(TCP_NODELAY)");
    }

    rxbufsz = roundup(MSGSZ_MAX, 4096) * 2;
    startvsz = sizeof(tdargs->startv[0]) * MSGINF_MAX;
    bktvsz = sizeof(tdargs->bktv[0]) * BKTV_MAX;
    tdargs->spbufsz = rxbufsz + startvsz + bktvsz;

    tdargs->spbuf = spalloc(tdargs->spbufsz);
    if (!tdargs->spbuf) {
        eprint(errno, "spalloc spbuf %zu", tdargs->spbufsz);
        abort();
    }

    memset(tdargs->spbuf, 0, tdargs->spbufsz);
    tdargs->rxbuf = tdargs->spbuf;
    tdargs->startv = (tsi_t *)(tdargs->spbuf + rxbufsz);
    tdargs->bktv = (uint32_t *)(tdargs->spbuf + rxbufsz + startvsz);

    /* Wait until all other workers have finished initializing...
     */
    pthread_barrier_wait(&bar_start);

    getrusage(RUSAGE_THREAD, &ru_start);
    tsi_start(&tsi);

    if (msginf > 0)
        rc = nullproc_async(fd, tdargs);
    else
        rc = nullproc_sync(fd, tdargs);

    tdargs->elapsed = tsi_delta(&tsi);
    getrusage(RUSAGE_THREAD, &ru_stop);

    /* Reqlinquish the cpu until all other workers have finished.
     */
    pthread_barrier_wait(&bar_end);

    majflt = ru_stop.ru_majflt - ru_start.ru_majflt;
    minflt = ru_stop.ru_minflt - ru_start.ru_minflt;

    if (majflt > 0 || minflt > 2) {
        eprint(0, "job %2d: unexpected maj/min faults: maj %ld, min %ld",
               tdargs->job, majflt, minflt);
    }

    close(fd);
    pthread_exit(NULL);
}

static int
doublecmp(const void *lhs, const void *rhs)
{
    if (*(const double *)lhs < *(const double *)rhs)
        return -1;
    if (*(const double *)lhs > *(const double *)rhs)
        return 1;
    return 0;
}

static int
uint64cmp(const void *lhs, const void *rhs)
{
    if (*(const uint64_t *)lhs < *(const uint64_t *)rhs)
        return -1;
    if (*(const uint64_t *)lhs > *(const uint64_t *)rhs)
        return 1;
    return 0;
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
    struct sockaddr_in faddr;
    struct tdargs *tdargv;
    struct tdargs *accum;
    struct hostent *hent;
    char *server, *user;
    u_int loops;
    int latprec;
    long nsecs;
    int i;

    cpuset_t cpuset;

    uint64_t *elapsedv, *latencyv;
    char *quantilebase;
    char errbuf[128];
    char state[256];
    int optind;
    char *pc;
    int rc;

    progname = strrchr(argv[0], '/');
    progname = (progname ? progname + 1 : argv[0]);

    initstate((u_long)time(NULL), state, sizeof(state));
    quantilebase = strdup(".3, 4.6, 31.7, 50, 68.3, 95.4, 99.7");
    quantiles = quantilebase;
    dprint_fp = stderr;
    eprint_fp = stderr;
    tsc_scale = 4;
    tsc_freq = 0;
    msgcnt = 1000000;
    msginf = 1;

#if HAVE_TSC
#if __FreeBSD__
    uint64_t val = 0;
    size_t valsz = sizeof(val);

    rc = sysctlbyname("kern.timecounter.smp_tsc", (void *)&val, &valsz, NULL, 0);
    if (rc) {
        eprint(errno, "sysctlbyname(kern.timecounter.smp_tsc)");
    } else if (val) {
        valsz = sizeof(val);
        val = 0;

        rc = sysctlbyname("machdep.tsc_freq", (void *)&val, &valsz, NULL, 0);
        if (rc) {
            eprint(errno, "sysctlbyname(machdep.tsc_freq)");
        } else {
            tsc_freq = val;
        }
    }
#elif __linux__
    const char cmd[] = "lscpu | sed -En 's/^Model name.*([0-9]\\.[0-9][0-9])GHz$/\\1/p'";
    char line[32];
    FILE *fp;

    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            tsc_freq = strtod(line, NULL) * 1000000000;
        }
        pclose(fp);
    }
#endif

    if (tsc_freq < 1000000) {
        eprint(0, "unable to determine TSC frequency, disable HAVE_TSC in GNUmakefile to use clock_gettime()");
        exit(EX_UNAVAILABLE);
    }

#else
    tsc_freq = 1000000000;
#endif

    rc = clp_parsev(argc, argv, optionv, posparamv, errbuf, sizeof(errbuf), &optind);
    if (rc) {
        eprint(0, "%s", errbuf);
        exit(rc);
    }

    if (given('h') || given('V'))
        return 0;

    nsecspercycle = 1000000000.0 / tsc_freq;
    tsc_scale += (tsc_freq / 1000000000) + (jobs > 2);

    nsecs = cycles2nsecs(1u << tsc_scale);
    latprec = (nsecs < 10) ? 2 : (nsecs < 100 ? 1 : 0);

    dprint(1, "tsc_freq %lu, tsc_scale %u, nsecs/cycle %lf, histres %luns\n",
           tsc_freq, tsc_scale, nsecspercycle, nsecs);

    if (quantiles) {
        char *buf = quantiles;
        char *tok, *end;
        int n;

        for (n = 0; buf && n < NELEM(quantilev); ++n, ++quantilec) {
            while (isspace(*buf))
                ++buf;

            tok = strsep(&buf, ",");
            if (!tok || !tok[0])
                break;

            errno = 0;
            quantilev[n] = strtod(tok, &end);
            if (errno) {
                eprint(errno, "unable to convert percentile `%s'", tok);
                exit(EX_DATAERR);
            }

            while (end && isspace(*end))
                ++end;

            if ((quantilev[n] == 0 && end == tok) || (end && *end)) {
                eprint(EINVAL, "unable to convert percentile `%s'", tok);
                exit(EX_DATAERR);
            }
            if (quantilev[n] < 0 || quantilev[n] > 100) {
                eprint(EINVAL, "percentile %lf is less than 0 or greater than 100",
                       quantilev[n]);
                exit(EX_DATAERR);
            }
        }

        qsort(quantilev, quantilec, sizeof(quantilev[0]), doublecmp);
    }

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
        eprint(0, "invalid host name %s", server);
        exit(1);
    }

    faddr.sin_family = AF_INET;
    faddr.sin_port = htons(port);

    hent = gethostbyname(server);
    if (!hent) {
        eprint(0, "gethostbyname(%s) failed: %s", server, hstrerror(h_errno));
        exit(1);
    }

    if (hent->h_addrtype != AF_INET) {
        eprint(0, "host %s does not have an AF_INET address", server);
        exit(1);
    }

    if (!inet_ntop(AF_INET, hent->h_addr_list[0],
                   serverip, sizeof(serverip))) {
        eprint(errno, "unable to convert server address %s to dotted quad notation",
               server);
        exit(1);
    }

    serverip[sizeof(serverip) - 1] = '\000';
    faddr.sin_addr.s_addr = inet_addr(serverip);

    elapsedv = malloc(sizeof(elapsedv[0]) * itermax * jobs);
    latencyv = malloc(sizeof(latencyv[0]) * itermax);
    if (!elapsedv || !latencyv) {
        eprint(errno, "malloc elapsedv/latencyv");
        exit(1);
    }

    if (msgcnt < 1)
        msgcnt = 1;
    if (msginf >= MSGINF_MAX)
        msginf = MSGINF_MAX - 1;

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
        eprint(0, "invalid auth type %s, use -h for help", auth_type);
        exit(EX_USAGE);
    }

    if (1) {
        char msgbuf[128];

        rc = rpc_encode(msgcnt, NFS3_NULL, auth, msgbuf, sizeof(msgbuf));
        dprint(1, "sizeof(rpc_msg) %zu, sizeof(call_body) %zu, authtype auth%s, rpclen %d\n",
               sizeof(struct rpc_msg), sizeof(struct call_body), auth_type, rc);

        msglen = roundup(rc, 32);
    }

    rc = pthread_barrier_init(&bar_start, NULL, jobs + 1);
    if (rc)
        abort();

    rc = pthread_barrier_init(&bar_end, NULL, jobs);
    if (rc)
        abort();

    rc = setpriority(PRIO_PROCESS, 0, -20);
    if (rc && errno != EACCES) {
        eprint(errno, "unable to set priority");
    }

    uint64_t elapsed_min, elapsed_max, elapsed_med;
    uint64_t elapsed_medv[jobs];

    char latmaxbuf[jobs * 16 + 32], *latmaxcomma;
    int msgcntwidth, maxwidth;
    u_long jmax, j;

    msgcntwidth = snprintf(NULL, 0, "%lu", msgcnt * jobs);
    if (msgcntwidth < 8)
        msgcntwidth = 8;

    maxwidth = 8;
    loops = 0;

  again:
    rc = pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    if (rc) {
        eprint(errno, "pthread_getaffinity_np");
        abort();
    }

    tdargv = calloc(jobs + 1, sizeof(*tdargv));
    if (!tdargv) {
        eprint(errno, "malloc tdargv %d", jobs);
        abort();
    }

    accum = tdargv + jobs;
    latmaxbuf[0] = '\000';
    latmaxcomma = "  ";
    elapsed_min = UINT64_MAX;
    elapsed_max = 0;
    jmax = 0;

    /* Allocate storage for the accumulator's histogram...
     */
    accum->spbufsz = sizeof(accum->bktv[0]) * BKTV_MAX;
    accum->spbuf = spalloc(accum->spbufsz);
    if (!accum->spbuf) {
        eprint(errno, "spalloc accum");
        abort();
    }
    accum->bktv = (uint32_t *)accum->spbuf;

    /* Start worker threads...
     */
    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;

        memcpy(&tdargs->faddr, &faddr, sizeof(tdargs->faddr));
        tdargs->job = i;

        if (CPU_COUNT(&cpuset) > 0) {
            tdargs->cpu = CPU_FFS(&cpuset) - 1;
            CPU_CLR(tdargs->cpu, &cpuset);
        }

        rc = pthread_create(&tdargs->td, NULL, run, tdargs);
        if (rc) {
            eprint(rc, "pthread_create (job %u of %u)", i, jobs);
            abort();
        }
    }

    /* Release the hounds!
     */
    rc = pthread_barrier_wait(&bar_start);
    if (rc > 0) {
        eprint(rc, "pthread_barrier_wait");
        abort();
    }

    /* Wait for all worker threads to complete...
     */
    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;
        u_long jlast;
        void *val;

        rc = pthread_join(tdargs->td, &val);
        if (rc) {
            eprint(rc, "pthread_join thread %u of %u", i, jobs);
            abort();
        }

        /* If the max latency of this job overflowed the latency
         * hash table then append it (in msecs) to the list.
         */
        if (tdargs->latmax > 0) {
            size_t len = strlen(latmaxbuf);

            nsecs = cycles2nsecs(tdargs->latmax << tsc_scale);

            if (tdargs->latmax > accum->latmax)
                accum->latmax = tdargs->latmax;

            snprintf(latmaxbuf + len, sizeof(latmaxbuf) - len, "%s%ld",
                     latmaxcomma, nsecs / 1000000);
            latmaxcomma = ",";
        }

        if (tdargs->elapsed < elapsed_min)
            elapsed_min = tdargs->elapsed;
        if (tdargs->elapsed > elapsed_max)
            elapsed_max = tdargs->elapsed;
        elapsed_medv[i] = cycles2nsecs(tdargs->elapsed);
        elapsedv[loops * jobs + i] = elapsed_medv[i];

        /* Accumulate results from all workers into tdargv[jobs]...
         */
        accum->bytes += tdargs->bytes;
        accum->iters += tdargs->iters;
        accum->elapsed += tdargs->elapsed;
        accum->rx_eagain += tdargs->rx_eagain;
        accum->tx_eagain += tdargs->tx_eagain;

        for (j = jlast = 0; j < BKTV_MAX; ++j) {
            if (tdargs->bktv[j] > 0) {
                accum->bktv[j] += tdargs->bktv[j];
                jlast = j;
            }
        }

        if (jlast > jmax)
            jmax = jlast;
    }

    char buf[quantilec * 16 + 128];
    u_long qcyclesv[quantilec], q999cycles, q50cycles;
    u_long qhitsv[quantilec], q999hits, q50hits;
    u_long first, last, n;
    int qcyclesvmin;

    /* Set qhitsv[i] to the percent of total hits required to reach quantilev[i]..
     */
    for (i = 0; i < quantilec; ++i) {
        qhitsv[i] = (accum->iters * quantilev[i]) / 100;
        qcyclesv[i] = 0;
    }

    q999hits = (accum->iters * 999) / 1000;
    q50hits = (accum->iters * 50) / 100;
    q999cycles = q50cycles = 0;
    first = last = n = 0;
    qcyclesvmin = 0;

    /* Find quantiles...
     */
    for (j = 0; j < jmax + 1; ++j) {
        if (accum->bktv[j] == 0)
            continue;

        n += accum->bktv[j];

        if (n >= q999hits) {
            q999hits = ULONG_MAX;
            q999cycles = j;
        }
        if (n >= q50hits) {
            q50hits = ULONG_MAX;
            q50cycles = j;
        }

        if (first == 0)
            first = j;
        last = j;

        for (i = quantilec - 1; i >= qcyclesvmin; --i) {
            if (qcyclesv[i] == 0) {
                if (n >= qhitsv[i]) {
                    if (i == qcyclesvmin)
                        ++qcyclesvmin;
                    qcyclesv[i] = j;
                }
            }
        }
    }

    elapsed_min = cycles2nsecs(elapsed_min);
    elapsed_max = cycles2nsecs(elapsed_max);

    qsort(elapsed_medv, jobs, sizeof(elapsed_medv[0]), uint64cmp);
    elapsed_med = elapsed_medv[jobs / 2];

    latencyv[loops] = cycles2nsecs(q50cycles << tsc_scale);
    qsort(latencyv, loops + 1, sizeof(latencyv[0]), uint64cmp);
    qsort(elapsedv, (loops + 1) * jobs, sizeof(elapsedv[0]), uint64cmp);

    if (headers) {
        n = snprintf(buf, sizeof(buf),
                     "%10s %3s %4s %8s %6s %7s %7s",
                     "Date", "TD", "INF",
                     runavg ? "AvgRPC" : "MedRPC",
                     runavg ? "AvgLat" : "MedLat",
                     "Mbps", "MinLat");

        for (i = 0; i < quantilec; ++i) {
            const char *fmt = " %7.1lf";

            if ((long)(quantilev[i] * 1000) % 1000 == 0)
                fmt = " %7.0lf";

            n += snprintf(buf + n, sizeof(buf) - n, fmt, quantilev[i]);
        }

        printf("%s %*s ", buf, maxwidth, "MaxLat");

        if (xstats) {
            printf(" %*s %8s %8s %8s %8s %8s %8s",
                   msgcntwidth + 1, "TotalRPC",
                   "MinTime", "MedTime", "MaxTIme",
                   "MinRPC", "MedRPC", "MaxRPC");
        }

        printf("\n");
        headers = false;
    }

    /* Use the cumulative median elapsed/latency values by default.
     * Use the cumulative average if requested by the -A option.
     */
    uint64_t elapsed_ns = elapsedv[(loops + 1) * jobs / 2];
    uint64_t latency_ns = latencyv[loops / 2];

    if (runavg) {
        elapsed_ns = latency_ns = 0;
        for (i = 0; i < (loops + 1) * jobs; ++i)
            elapsed_ns += elapsedv[i];
        elapsed_ns /= (loops + 1) * jobs;

        for (i = 0; i < (loops + 1); ++i)
            latency_ns += latencyv[i];
        latency_ns /= (loops + 1);
    }

    n = snprintf(buf, sizeof(buf),
                 "%10ld %3u %4zu %8lu %6.*lf %7.1lf %7.*lf",
                 time(NULL), jobs, msginf,
                 (accum->iters * 1000000000ul) / elapsed_ns,
                 latprec, latency_ns / 1000.0,
                 (accum->bytes * 8 * 1000.0) / elapsed_med,
                 latprec, cycles2nsecs(first << tsc_scale) / 1000.0);

    for (i = 0; i < quantilec; ++i)
        n += snprintf(buf + n, sizeof(buf) - n, " %7.*lf",
                      latprec, cycles2nsecs(qcyclesv[i] << tsc_scale) / 1000.0);

    printf("%s %*.*lf%s",
           buf, maxwidth, latprec,
           cycles2nsecs(last << tsc_scale) / 1000.0,
           latmaxbuf[0] ? "*" : " ");

    if (xstats) {
        printf(" %*ld %8.3lf %8.3lf %8.3lf %8lu %8lu %8lu",
               msgcntwidth + 1, accum->iters,
               elapsed_min / 1000000000.0,
               elapsed_med / 1000000000.0,
               elapsed_max / 1000000000.0,
               (accum->iters * 1000000000ul) / elapsed_min,
               (accum->iters * 1000000000ul) / elapsed_med,
               (accum->iters * 1000000000ul) / elapsed_max);
    }

    printf(" %s\n", latmaxbuf);
    fflush(stdout);

    if (datadir) {
        char datafile[1024], gplotfile[1024], pngfile[1024];
        char cmd[1024 + 32];
        FILE *fp;

        snprintf(gplotfile, sizeof(gplotfile), "%s/%s.%u.gnuplot", datadir, progname, loops);
        snprintf(datafile, sizeof(datafile), "%s/%s.%u.data", datadir, progname, loops);
        snprintf(pngfile, sizeof(pngfile), "%s/%s.%u.png", datadir, progname, loops);

        mkdir(datadir, 0755);

        fp = fopen(datafile, "w");
        if (fp) {
            fprintf(fp, "#%10s %10s", "CYCLES", "NSECS");
            for (i = 0; i < jobs ; ++i)
                fprintf(fp, " %*s%u", (i < 10) ? 8 : 7, "JOB", i);
            fprintf(fp, " %9s\n", "TOTAL");

            for (j = 0; j < jmax; ++j) {
                if (accum->bktv[j] > 0) {
                    fprintf(fp, " %10lu %10lu",
                            j << tsc_scale, cycles2nsecs(j << tsc_scale));

                    for (i = 0; i < jobs + 1; ++i)
                        fprintf(fp, " %9u", tdargv[i].bktv[j]);

                    fprintf(fp, "\n");
                }
            }
            fclose(fp);

            fp = fopen(gplotfile, "w");
            if (fp) {
                const char *xlabel = "microseconds";
                const char *ylabel = "hits";
                const char *color = "orange";
                const char *term = "png";
                u_long xmin, xmax;

                /* Clip the left x-axis to the first sample,
                 * and the right x-axis to the 99.9 percentile.
                 */
                xmin = cycles2nsecs(first << tsc_scale) / 1000;
                xmax = cycles2nsecs(q999cycles << tsc_scale) / 1000;
                if (xmax - xmin > 1000)
                    xmax = xmin + 1000;

                fprintf(fp, "set title \"%s -j%u -a%zu -c%lu (loop %u)\"\n",
                        progname, jobs, msginf, msgcnt, loops);
                fprintf(fp, "set output '%s'\n", pngfile);
                fprintf(fp, "set term %s size 2560,768\n", term);
                fprintf(fp, "set autoscale\n");
                fprintf(fp, "set grid\n");
                fprintf(fp, "set xlabel \"%s\"\n", xlabel);
                fprintf(fp, "set xtics autofreq\n");
                fprintf(fp, "set xrange [%ld:%ld]\n", xmin, xmax);
                fprintf(fp, "set ylabel \"%s\"\n", ylabel);
                fprintf(fp, "set ytics autofreq\n");
                fprintf(fp, "set tics front\n");

                fprintf(fp, "plot \"%s\" using ($2 / 1000.0):($%u) "
                        "with impulses lc rgbcolor \"%s\" "
                        "title \"latency %u\"\n",
                        datafile, jobs + 3, color, loops);

                fclose(fp);

                snprintf(cmd, sizeof(cmd), "gnuplot %s", gplotfile);
                fp = popen(cmd, "r");
                if (!fp) {
                    eprint(errno, "[%s] failed\n", cmd);
                } else {
                    pclose(fp);
                }
            }
        }
    }

    for (i = 0; i < jobs; ++i)
        spfree(tdargv[i].spbuf, tdargv[i].spbufsz);

    free(tdargv);

    if (++loops < itermax)
        goto again;

    auth_destroy(auth);
    free(host);
    free(quantilebase);

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
eprint(int err, const char *fmt, ...)
{
    char msg[256];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (err && n >= 0 && n < sizeof(msg) - 2) {
        strlcat(msg, ": ", sizeof(msg) - n);
        strerror_r(err, msg + n + 2, sizeof(msg) - n - 2);
    }

    fprintf(eprint_fp, "%s: %s\n", progname, msg);
}
