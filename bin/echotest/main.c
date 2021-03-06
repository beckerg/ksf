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
#include <arpa/inet.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpc.h>

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif

#include "main.h"
#include "clp.h"

#define MSGLAG_MAX  (1024)

char version[] = PROG_VERSION;
char *progname;
int verbosity;

FILE *dprint_fp;
FILE *eprint_fp;

pthread_barrier_t bar_start;
pthread_barrier_t bar_end;
unsigned int jobs = 1;
in_port_t port = 60007;
u_long msgcnt = 1000000;
size_t msglag = 1;
size_t msglen = 1;
char *host;
bool async;
bool udp;

struct tdargs {
    struct sockaddr_in faddr;
    pthread_t td;
    char *rxbuf;
    long iters;
    long usecs;
    long cpu;
    long tx_eagain;
    long rx_eagain;
    uint64_t latency;
    uint64_t startv[MSGLAG_MAX];
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

    CLP_OPTION(size_t, 'a', msglag, NULL, NULL, "max number of inflight msgs (per thread)"),
    CLP_OPTION(u_long, 'c', msgcnt, NULL, NULL, "max messages to send (per thread)"),
    CLP_OPTION(u_int, 'j', jobs, NULL, NULL, "max number of threads/connections"),
    CLP_OPTION(size_t, 'l', msglen, NULL, NULL, "message length"),
    CLP_OPTION(uint16_t, 'p', port, NULL, NULL, "remote port"),
    CLP_OPTION(bool, 'u', udp, NULL, NULL, "use UDP"),

    CLP_OPTION_END
};


/* Asynchronous send/recv loop.  Note that the send can race ahead
 * of the receiver by at most msglag messages.
 */
int
test_async(int fd, struct tdargs *tdargs)
{
    char *rxbuf, *txbuf, errbuf[128];
    ssize_t rxlen, txlen, txfrag, txfragmax, cc;
    int rxflags, txflags;
    long msgrx, msgtx;
    int rc;

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
        if (msgtx < msgcnt && msgtx - msgrx < msglag) {
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

        rxflags = (msgtx < msgcnt && msgtx - msgrx < msglag) ? MSG_DONTWAIT : MSG_WAITALL;

        cc = recv(fd, rxbuf + (msglen - rxlen), rxlen, rxflags);
        if (cc == -1) {
            if (errno != EAGAIN) {
                strerror_r(rc = errno, errbuf, sizeof(errbuf));
                eprint("recv: cc %ld %s\n", cc, errbuf);
                break;
            }

            ++tdargs->rx_eagain;
            continue;
        }

        rxlen -= cc;
        if (rxlen == 0) {
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
                eprint("send: cc %ld: %s\n", cc, errbuf);
                break;
            }

            eprint("sendto: cc %ld: short write\n", cc);
            rc = EIO;
            break;
        }

        cc = recv(fd, rxbuf, msglen, MSG_WAITALL);

        if (cc != msglen) {
            if (cc == -1) {
                strerror_r(rc = errno, errbuf, sizeof(errbuf));
                eprint("recv: cc %ld %s\n", cc, errbuf);
                break;
            }

            eprint("recvfrom: cc %ld short read\n", cc);
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
    char errbuf[128];
    struct timeval tv_start, tv_stop, tv_diff;
    struct timeval ru_utime, ru_stime, ru_total;
    struct rusage ru_start, ru_stop;
    struct tdargs *tdargs = arg;
    double bytespersec;
    long usecs;
    int optval;
    int fd, rc;

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

    optval = msglen;
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &optval, sizeof(optval));
    if (rc) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint("setsockopt(SO_RCVLOWAT): %s\n", errbuf);
        abort();
    }

    /* Make the send buffer large enough so that send() wont block..
     */
    if (msglen * msglag > 16 * 1024) {
        optval = msglen * msglag;
        rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval));
        if (rc) {
            strerror_r(errno, errbuf, sizeof(errbuf));
            eprint("setsockopt(SO_SNDBUF): %s\n", errbuf);
            abort();
        }
    }

    if (msglen > 16 * 1024) {
        optval = msglen * 2;
        rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
        if (rc) {
            strerror_r(errno, errbuf, sizeof(errbuf));
            eprint("setsockopt(SO_RCVBUF): %s\n", errbuf);
            abort();
        }
    }

    errno = 0;
    rc = pthread_barrier_wait(&bar_start);
    if (rc && errno)
        abort();

    getrusage(RUSAGE_SELF, &ru_start);
    gettimeofday(&tv_start, NULL);

    if (msglag > 0)
        rc = test_async(fd, tdargs);
    else
        rc = test_sync(fd, tdargs);

    gettimeofday(&tv_stop, NULL);
    getrusage(RUSAGE_SELF, &ru_stop);

    pthread_barrier_wait(&bar_end);

    timersub(&tv_stop, &tv_start, &tv_diff);
    usecs = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
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
    size_t tdargvsz;
    size_t rxbufsz;
    char *rxbuf;
    long *prxbuf;
    int i;

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


#ifdef USE_TSC
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
#endif

    if (msgcnt < 1)
        msgcnt = 1;
    if (msglen < 1)
        msglen = 1;
    if (msglag > MSGLAG_MAX)
        msglag = MSGLAG_MAX;

    rxbufsz = roundup(msglen, 4096) * 2 * jobs;
    rxbufsz = roundup(rxbufsz, 1024 * 1024 * 2);

    rxbuf = mmap(NULL, rxbufsz, PROT_READ | PROT_WRITE,
                 MAP_ALIGNED_SUPER | MAP_SHARED | MAP_ANON, -1, 0);
    if (rxbuf == MAP_FAILED) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        eprint("mmap: %s\n", errbuf);
        abort();
    }

    prxbuf = (long *)rxbuf;
    for (i = 0; i < rxbufsz / sizeof(*prxbuf); i += sizeof(*prxbuf))
        *prxbuf++ = (long)(rxbuf + i);

    tdargvsz = roundup(sizeof(*tdargv) * jobs, 4096);
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

    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;

        memset(tdargs, 0, sizeof(*tdargs));
        memcpy(&tdargs->faddr, &faddr, sizeof(tdargs->faddr));
        tdargs->rxbuf = rxbuf + roundup(msglen, 4096) * 2 * i;

        rc = pthread_create(&tdargs->td, NULL, run, tdargs);
        if (rc) {
            eprint("pthread_create() failed: %s\n", strerror(errno));
            abort();
        }
    }

    usecs = iters = cpu = 0;

    for (i = 0; i < jobs; ++i) {
        struct tdargs *tdargs = tdargv + i;
        void *val;

        rc = pthread_join(tdargs->td, &val);

        iters += tdargs->iters;
        usecs += tdargs->usecs;
        cpu += tdargs->cpu;
    }

    usecs /= jobs;
    bytespersec = (msglen * iters * 1000000.0) / usecs;

    dprint(0, "total: iters %ld, usecs %ld, cpu %ld, msgs/sec %ld, avglat %.1lf, MBps %.2lf, Gbps %.2lf, cpu/msg %.2lf\n",
           iters, usecs, cpu,
           (iters * 1000000) / usecs,
           (double)usecs * jobs / iters,
           bytespersec / (1ul << 20),
           (bytespersec * 8) / 1000000000,
           (double)cpu / iters);

    munmap(tdargv, tdargvsz);
    munmap(rxbuf, rxbufsz);
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

    if (verbosity > 1)
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
