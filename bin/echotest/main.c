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
u_int itermax = UINT_MAX;
unsigned int jobs = 1;
in_port_t port = 60007;
size_t msglen = 1;
char *host;
bool headers = true;
bool async;
bool udp;

double nsecspercycle;

u_long msgcnt __read_mostly;
size_t msginf __read_mostly;
uint tsc_scale __read_mostly;
uint64_t tsc_freq __read_mostly;

struct tdargs {
    struct sockaddr_in faddr;
    pthread_t td;
    size_t spbufsz;
    size_t rxbufsz;
    char *spbuf;
    char *rxbuf;
    tsi_t *startv;
    long iters;
    long usecs;
    long cpu;
    long tx_eagain;
    long rx_eagain;
    long latency;
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

    CLP_OPTION(size_t, 'a', msginf, NULL, NULL, "max number of inflight msgs (per thread)"),
    CLP_OPTION(u_long, 'c', msgcnt, NULL, NULL, "max messages to send (per thread)"),
    CLP_OPTION(bool, 'H', headers, NULL, NULL, "suppress headers"),
    CLP_OPTION(u_int, 'i', itermax, NULL, NULL, "max iterations"),
    CLP_OPTION(u_int, 'j', jobs, NULL, NULL, "max number of threads/connections"),
    CLP_OPTION(size_t, 'l', msglen, NULL, NULL, "message length"),
    CLP_OPTION(uint16_t, 'p', port, NULL, NULL, "remote port"),
    CLP_OPTION(bool, 'u', udp, NULL, NULL, "use UDP"),

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

/* Asynchronous send/recv loop.  Note that the send can race ahead
 * of the receiver by at most msginf messages.
 */
int
test_async(int fd, struct tdargs *tdargs)
{
    ssize_t rxlen, txlen, txfrag, txfragmax, cc;
    int rxflags, txflags;
    char *rxbuf, *txbuf;
    long msgrx, msgtx;
    tsi_t *startv;
    int rc;

    startv = tdargs->startv;
    rxbuf = tdargs->rxbuf;
    txbuf = rxbuf + roundup(msglen, 4096);
    txflags = MSG_DONTWAIT;
    rxflags = MSG_DONTWAIT;
    msgrx = msgtx = 0;
    rxlen = msglen;
    txlen = msglen;
    rc = 0;

    txfragmax = 16 * 1024;
    txfragmax = msglen;
    if (txfragmax > msglen)
        txfragmax = msglen;
    txfrag = txfragmax;

    while (msgrx < msgcnt) {
        if (msgtx < msgcnt && msgtx - msgrx < msginf) {
            if (txlen == msglen)
                tsi_start(&startv[msgtx % MSGINF_MAX]);

            cc = send(fd, txbuf + (txfragmax - txfrag), txfrag, txflags);
            if (cc == -1) {
                if (errno != EAGAIN) {
                    eprint(rc = errno, "send: cc %ld", cc);
                    break;
                }

                ++tdargs->tx_eagain;
            }
            else {
                txlen -= cc;
                if (txlen == 0) {
                    txlen = msglen;
                    ++msgtx;
                }

                txfrag -= cc;
                if (txfrag == 0) {
                    txfrag = txfragmax;
                    if (txfrag > txlen)
                        txfrag = txlen;
                }
            }
        }

        rxflags = (msgtx < msgcnt && msgtx - msgrx < msginf) ? MSG_DONTWAIT : MSG_WAITALL;

        cc = recv(fd, rxbuf + (msglen - rxlen), rxlen, rxflags);
        if (cc == -1) {
            if (errno != EAGAIN) {
                eprint(rc = errno, "recv: cc %ld", cc);
                break;
            }

            ++tdargs->rx_eagain;
            continue;
        }

        rxlen -= cc;
        if (rxlen == 0) {
            tdargs->latency += tsi_delta(&startv[msgrx % MSGINF_MAX]);
            rxlen = msglen;
            ++msgrx;
        }
    }

    tdargs->iters = msgrx;

    return rc;
}

/* Synchronous send/recv loop...
 */
int
test_sync(int fd, struct tdargs *tdargs)
{
    char *rxbuf, *txbuf, errbuf[128];
    ssize_t cc;
    long msgrx;
    int rc;

    rxbuf = tdargs->rxbuf;
    txbuf = rxbuf + roundup(msglen, 4096);
    msgrx = 0;
    rc = 0;

    while (msgrx++ < msgcnt) {

        cc = send(fd, txbuf, msglen, 0);

        if (cc != msglen) {
            if (cc == -1) {
                strerror_r(rc = errno, errbuf, sizeof(errbuf));
                eprint(rc = errno, "send: cc %ld", cc);
                break;
            }

            eprint(EIO, "sendto: cc %ld: short write", cc);
            rc = EIO;
            break;
        }

        cc = recv(fd, rxbuf, msglen, MSG_WAITALL);

        if (cc != msglen) {
            if (cc == -1) {
                eprint(rc = errno, "recv: cc %ld", cc);
                break;
            }

            eprint(EIO, "recvfrom: cc %ld short read", cc);
            rc = EIO;
            break;
        }
    }

    tdargs->iters = msgrx;
    return rc;
}

void *
run(void *arg)
{
    struct timeval ru_utime, ru_stime, ru_total;
    struct rusage ru_start, ru_stop;
    struct tdargs *tdargs = arg;
    double bytespersec;
    long usecs;
    int fd, rc;
    int optval;
    tsi_t tsi;

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

    optval = msglen;
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &optval, sizeof(optval));
    if (rc) {
        eprint(errno, "setsockopt(SO_RCVLOWAT)");
        abort();
    }

    /* Make the send buffer large enough so that send() wont block..
     */
    if (msglen * msginf > 16 * 1024) {
        optval = roundup(msglen * msginf, 4096);

        rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval));
        if (rc) {
            eprint(errno, "setsockopt(SO_SNDBUF)");
            abort();
        }
    }

    if (msglen > 16 * 1024) {
        optval = roundup(msglen * 2, 4096);

        rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
        if (rc) {
            eprint(errno, "setsockopt(SO_RCVBUF)");
            abort();
        }
    }

    if (msginf == 1) {
        optval = 1;

        rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
        if (rc)
            eprint(errno, "setsockopt(TCP_NODELAY)");
    }

    tdargs->rxbufsz = roundup(msglen, 4096) * 2;
    tdargs->spbufsz += sizeof(tdargs->startv[0]) * MSGINF_MAX;

    tdargs->spbuf = spalloc(tdargs->spbufsz);
    if (!tdargs->spbuf) {
        eprint(errno, "spalloc spbuf %zu", tdargs->spbufsz);
        abort();
    }

    memset(tdargs->spbuf, 0, tdargs->spbufsz);
    tdargs->rxbuf = tdargs->spbuf;
    tdargs->startv = (tsi_t *)(tdargs->spbuf + tdargs->rxbufsz);

    errno = 0;
    rc = pthread_barrier_wait(&bar_start);
    if (rc && errno)
        abort();

    getrusage(RUSAGE_SELF, &ru_start);
    tsi_start(&tsi);

    if (msginf > 0)
        rc = test_async(fd, tdargs);
    else
        rc = test_sync(fd, tdargs);

    usecs = cycles2nsecs(tsi_delta(&tsi)) / 1000;
    getrusage(RUSAGE_SELF, &ru_stop);

    pthread_barrier_wait(&bar_end);

    bytespersec = (msglen * tdargs->iters * 1000000) / usecs;
    tdargs->usecs = usecs;

    timersub(&ru_stop.ru_utime, &ru_start.ru_utime, &ru_utime);
    timersub(&ru_stop.ru_stime, &ru_start.ru_stime, &ru_stime);
    timeradd(&ru_utime, &ru_stime, &ru_total);
    tdargs->cpu = ru_total.tv_sec * 1000000 + ru_total.tv_usec;

    dprint(1, "%p, fd %2d, usecs %ld, cpu %ld %.2lf, msgs/sec %ld, MBps %.2lf, Gbps %.2lf, %ld %ld\n",
           (void *)tdargs->td, fd, usecs,
           tdargs->cpu, (double)tdargs->cpu / tdargs->iters,
           (tdargs->iters * 1000000) / usecs,
           bytespersec / (1ul << 20),
           (bytespersec * 8) / 1000000000,
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
    struct sockaddr_in faddr;
    long iters, usecs, cpu;
    struct tdargs *tdargv;
    struct hostent *hent;
    char *server, *user;
    double bytespersec;
    uint64_t latency;
    long nsecs;
    u_int loops;
    int i;

    char errbuf[128];
    char state[256];
    int optind;
    char *pc;
    int rc;

    progname = strrchr(argv[0], '/');
    progname = (progname ? progname + 1 : argv[0]);

    initstate((u_long)time(NULL), state, sizeof(state));
    dprint_fp = stderr;
    eprint_fp = stderr;
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
    //latprec = (nsecs < 10) ? 2 : (nsecs < 100 ? 1 : 0);

    dprint(1, "tsc_freq %lu, tsc_scale %u, nsecs/cycle %lf, histres %luns\n",
           tsc_freq, tsc_scale, nsecspercycle, nsecs);

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
        eprint(h_errno, "gethostbyname(%s) failed", server);
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


    if (msgcnt < 1)
        msgcnt = 1;
    if (msglen < 1)
        msglen = 1;
    if (msginf > MSGINF_MAX)
        msginf = MSGINF_MAX;

    rc = pthread_barrier_init(&bar_start, NULL, jobs);
    if (rc)
        abort();

    rc = pthread_barrier_init(&bar_end, NULL, jobs);
    if (rc)
        abort();

    rc = setpriority(PRIO_PROCESS, 0, -15);
    if (rc && errno != EACCES) {
        eprint(errno, "unable to set priority");
    }

    loops = 0;

  again:
    tdargv = calloc(jobs, sizeof(tdargv[0]));
    if (!tdargv) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint(errno, "spalloc tdargv");
        abort();
    }

    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;

        memcpy(&tdargs->faddr, &faddr, sizeof(tdargs->faddr));

        rc = pthread_create(&tdargs->td, NULL, run, tdargs);
        if (rc) {
            eprint(rc, "pthread_create %d of %u", i, jobs);
            abort();
        }
    }

    usecs = iters = cpu = 0;
    latency = 0;

    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;
        void *val;

        rc = pthread_join(tdargs->td, &val);

        iters += tdargs->iters;
        usecs += tdargs->usecs;
        cpu += tdargs->cpu;
        latency += tdargs->latency;

        spfree(tdargs->spbuf, tdargs->spbufsz);
    }

    latency = cycles2nsecs(latency) / iters;

    usecs /= jobs;
    bytespersec = (msglen * iters * 1000000.0) / usecs;

    if (headers) {
        printf("%10s %10s %10s %7s %7s %7s\n",
               "totmsgs", "totusecs", "msgs/sec", "avglat", "Mbps", "cpu/msg");
        headers = false;
    }

    printf("%10ld %10ld %10ld %7.1lf %7.2lf %7.2lf\n",
           iters, usecs,
           (iters * 1000000) / usecs,
           latency / 1000.0,
           (bytespersec * 8) / 1000000,
           (double)cpu / iters);
    fflush(stdout);

    free(tdargv);

    if (++loops < itermax)
        goto again;

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
