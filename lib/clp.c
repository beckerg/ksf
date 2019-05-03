/*
 * Copyright (c) 2015-2016 Greg Becker.  All rights reserved.
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
 *
 * $Id: clp.c 386 2016-01-27 13:25:47Z greg $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <inttypes.h>
#include <float.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sysexits.h>
#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <sys/file.h>
#include <sys/param.h>

#include "clp.h"

#define CLP_DEBUG

struct clp_suftab {
    const char *list;
    double mult[];
};

#if 0
static struct clp_suftab clp_suftab_iec = {
    .list = "kmgtpezy",
    .mult = { 0x1p10, 0x1p20, 0x1p30, 0x1p40, 0x1p50, 0x1p60, 0x1p70, 0x1p80 }
};

static struct clp_suftab clp_suftab_si = {
    .list = "KMGTPEZY",
    .mult = { 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1e21, 1e24 }
};
#endif

static struct clp_suftab clp_suftab_combo = {
    .list = "kmgtpezyKMGTPEZYbw",
    .mult = { 0x1p10, 0x1p20, 0x1p30, 0x1p40, 0x1p50, 0x1p60, 0x1p70, 0x1p80,
              1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1e21, 1e24,
              512, sizeof(int) }
};

static struct clp_suftab clp_suftab_time_t = {
    .list = "smhdwyc",
    .mult = { 1, 60, 3600, 86400, 86400 * 7, 86400 * 365, 86400 * 365 * 100ul }
};


clp_posparam_t clp_posparam_none[] = {
    { .name = NULL }
};


static int clp_debug;

#ifdef CLP_DEBUG
/* dprint() prints a debug message to stdout if (clp_debug >= lvl).
 */
#define dprint(lvl, ...)                                                \
do {                                                                    \
    if (clp_debug >= (lvl)) {                                           \
        dprint_impl(__FILE__, __LINE__, __func__, stdout, __VA_ARGS__); \
    }                                                                   \
} while (0);

/* Called via the dprint() macro..
 */
static void
dprint_impl(const char *file, int line, const char *func, FILE *fp, const char *fmt, ...)
{
    va_list ap;

    if (!fp)
        fp = stderr;

    if (file && func)
        fprintf(fp, "  +%-4d %-6s %-12s  ", line, file, func);

    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
}

#else

#define dprint(lvl, ...)
#endif /* CLP_DEBUG */

/* Format and save an error message for retrieval by the caller
 * of clp_parse().
 */
static void
eprint(clp_t *clp, const char *fmt, ...)
{
    va_list ap;

    if (clp->errbuf) {
        va_start(ap, fmt);
        vsnprintf(clp->errbuf, clp->errbufsz, fmt, ap);
        va_end(ap);
    }
}


clp_option_t *
clp_option_find(clp_option_t *optionv, int optopt)
{
    if (optionv && optopt > 0) {
        while (optionv->optopt > 0) {
            if (optionv->optopt == optopt) {
                return optionv;
            }
            ++optionv;
        }
    }

    return NULL;
}

void
clp_option_priv_set(clp_option_t *option, void *priv)
{
    if (option) {
        option->priv = priv;
    }
}

/* An option's conversion procedure is called each time the
 * option is seen on the command line.
 *
 * Note:  These functions are not type safe.
 */
int
clp_cvt_bool(const char *optarg, int flags, void *parms, void *dst)
{
    bool *result = dst;

    *result = ! *result;

    return 0;
}

int
clp_cvt_string(const char *optarg, int flags, void *parms, void *dst)
{
    char **result = dst;

    if (!result) {
        errno = EINVAL;
        return EX_DATAERR;
    }

    *result = strdup(optarg);

    return *result ? 0 : EX_OSERR;
}

int
clp_cvt_open(const char *optarg, int flags, void *parms, void *dst)
{
    int *result = dst;

    if (!result) {
        errno = EINVAL;
        return EX_DATAERR;
    }

    *result = open(optarg, flags ? flags : O_RDONLY, 0644);

    return (*result >= 0) ? 0 : EX_NOINPUT;
}

int
clp_cvt_fopen(const char *optarg, int flags, void *parms, void *dst)
{
    const char *mode = parms ? parms : "r";
    FILE **result = dst;

    if (!result) {
        errno = EINVAL;
        return EX_DATAERR;
    }

    *result = fopen(optarg, mode);

    return *result ? 0 : EX_NOINPUT;
}

int
clp_cvt_incr(const char *optarg, int flags, void *parms, void *dst)
{
    int *result = dst;

    if (!result) {
        errno = EINVAL;
        return EX_DATAERR;
    }

    ++(*result);

    return 0;
}

/* This template produces type-specific functions to convert a string
 * of one or more delimited numbers to a single/vector of integers.
 *
 * Each string to be converted may end in a single character suffix
 * from suftab which modifies the result.
 *
 * Note that we use strtold() to parse each number in order to allow
 * the caller maximum flexibility when specifying number formats.
 * There is the possibility for loss of precision if long double
 * on the target platform doesn't have at least as many bits in the
 * significand as the widest integer type for which this function
 * may be called.
 */
#define CLP_CVT_XX(_xsuffix, _xtype, _xmin, _xmax, _suftab)             \
int                                                                     \
clp_cvt_ ## _xsuffix(const char *optarg, int flags, void *parms, void *dst) \
{                                                                       \
    const struct clp_suftab *suftab = &(_suftab);                       \
    CLP_VECTOR(vectorbuf, _xtype, 1, "");                               \
    clp_vector_t *vector;                                               \
    char *str, *strbase;                                                \
    _xtype *result;                                                     \
    bool rangechk;                                                      \
    int nrange;                                                         \
    int n;                                                              \
                                                                        \
    if (!optarg || !dst) {                                              \
        errno = EINVAL;                                                 \
        return EX_DATAERR;                                              \
    }                                                                   \
                                                                        \
    vector = (void *)&vectorbuf;                                        \
    if (parms) {                                                        \
        vector = parms;                                                 \
    }                                                                   \
                                                                        \
    /* Only call strdup if there are delimiters in optarg.              \
     */                                                                 \
    str = (char *)optarg;                                               \
    strbase = strpbrk(str, vector->delim);                              \
    if (strbase) {                                                      \
        strbase = strdup(optarg);                                       \
        if (!strbase) {                                                 \
            errno = ENOMEM;                                             \
            return EX_DATAERR;                                          \
        }                                                               \
        str = strbase;                                                  \
    }                                                                   \
                                                                        \
    rangechk = (_xmin) < (_xmax);                                       \
    result = dst;                                                       \
    nrange = 0;                                                         \
    errno = 0;                                                          \
                                                                        \
    for (n = 0; n < vector->size && str; ++n, ++result) {               \
        char *tok, *end;                                                \
        long double val;                                                \
                                                                        \
        if (strbase) {                                                  \
            tok = strsep(&str, vector->delim);                          \
            if (tok && *tok == '\000') {                                \
                *result = 0;                                            \
                continue;                                               \
            }                                                           \
        } else {                                                        \
            tok = str;                                                  \
            str = NULL;                                                 \
        }                                                               \
                                                                        \
        errno = 0;                                                      \
        val = strtold(tok, &end);                                       \
                                                                        \
        if (errno) {                                                    \
            if (errno != ERANGE) {                                      \
                *result = (_xtype)val;                                  \
                break;                                                  \
            }                                                           \
            ++nrange;                                                   \
        }                                                               \
                                                                        \
        if (end == tok) {                                               \
            errno = EINVAL;                                             \
            *result = 0;                                                \
            break;                                                      \
        }                                                               \
                                                                        \
        if (*end) {                                                     \
            const char *pc;                                             \
                                                                        \
            pc = strchr(suftab->list, *end);                            \
            if (!pc) {                                                  \
                errno = EINVAL;                                         \
                *result = 0;                                            \
                break;                                                  \
            }                                                           \
                                                                        \
            val *= *(suftab->mult + (pc - suftab->list));               \
        }                                                               \
                                                                        \
        if (isinf(val) || isnan(val))                                   \
            ;                                                           \
        else if (rangechk && (val < (_xmin) || val > (_xmax))) {        \
            val = (val < (_xmin)) ? (_xmin) : (_xmax);                  \
            ++nrange;                                                   \
        }                                                               \
                                                                        \
        *result = (_xtype)val;                                          \
    }                                                                   \
                                                                        \
    vector->len = n;                                                    \
    if (str && vector->len >= vector->size) {                           \
        errno = E2BIG;                                                  \
    }                                                                   \
                                                                        \
    if (nrange > 0 && !errno) {                                         \
        errno = ERANGE;                                                 \
    }                                                                   \
                                                                        \
    if (strbase) {                                                      \
        int save = errno;                                               \
                                                                        \
        free(strbase);                                                  \
        errno = save;                                                   \
    }                                                                   \
                                                                        \
    return errno ? EX_DATAERR : 0;                                      \
}

CLP_CVT_XX(char,        char,       CHAR_MIN,   CHAR_MAX,   clp_suftab_combo);
CLP_CVT_XX(u_char,      u_char,     0,          UCHAR_MAX,  clp_suftab_combo);

CLP_CVT_XX(short,       short,      SHRT_MIN,   SHRT_MAX,   clp_suftab_combo);
CLP_CVT_XX(u_short,     u_short,    0,          USHRT_MAX,  clp_suftab_combo);

CLP_CVT_XX(int,         int,        INT_MIN,    INT_MAX,    clp_suftab_combo);
CLP_CVT_XX(u_int,       u_int,      0,          UINT_MAX,   clp_suftab_combo);

CLP_CVT_XX(long,        long,       LONG_MIN,   LONG_MAX,   clp_suftab_combo);
CLP_CVT_XX(u_long,      u_long,     0,          ULONG_MAX,  clp_suftab_combo);

CLP_CVT_XX(float,       float,      -FLT_MAX,   FLT_MAX,    clp_suftab_combo);
CLP_CVT_XX(double,      double,     -DBL_MAX,   DBL_MAX,    clp_suftab_combo);

CLP_CVT_XX(int8_t,      int8_t,     INT8_MIN,   INT8_MAX,   clp_suftab_combo);
CLP_CVT_XX(uint8_t,     uint8_t,    0,          UINT8_MAX,  clp_suftab_combo);

CLP_CVT_XX(int16_t,     int16_t,    INT16_MIN,  INT16_MAX,  clp_suftab_combo);
CLP_CVT_XX(uint16_t,    uint16_t,   0,          UINT16_MAX, clp_suftab_combo);

CLP_CVT_XX(int32_t,     int32_t,    INT32_MIN,  INT32_MAX,  clp_suftab_combo);
CLP_CVT_XX(uint32_t,    uint32_t,   0,          UINT32_MAX, clp_suftab_combo);

CLP_CVT_XX(int64_t,     int64_t,    INT64_MIN,  INT64_MAX,  clp_suftab_combo);
CLP_CVT_XX(uint64_t,    uint64_t,   0,          UINT64_MAX, clp_suftab_combo);

CLP_CVT_XX(intmax_t,    intmax_t,   INTMAX_MIN, INTMAX_MAX, clp_suftab_combo);
CLP_CVT_XX(uintmax_t,   uintmax_t,  0,          UINTMAX_MAX,clp_suftab_combo);

CLP_CVT_XX(intptr_t,    intptr_t,   INTPTR_MIN, INTPTR_MAX, clp_suftab_combo);
CLP_CVT_XX(uintptr_t,   uintptr_t,  0,          UINTPTR_MAX,clp_suftab_combo);

CLP_CVT_XX(size_t,      size_t,     0,          SIZE_MAX,   clp_suftab_combo);
CLP_CVT_XX(time_t,      time_t,     0,          LONG_MAX,   clp_suftab_time_t);


/* Return true if the two specified options are mutually exclusive.
 */
int
clp_excludes2(const clp_option_t *l, const clp_option_t *r)
{
    if (l && r) {
        if (l->excludes) {
            if (l->excludes[0] == '^') {
                if (!strchr(l->excludes, r->optopt)) {
                    return true;
                }
            } else {
                if (l->excludes[0] == '*' || strchr(l->excludes, r->optopt)) {
                    return true;
                }
            }
        }
        if (r->excludes) {
            if (r->excludes[0] == '^') {
                if (!strchr(r->excludes, l->optopt)) {
                    return true;
                }
            } else {
                if (r->excludes[0] == '*' || strchr(r->excludes, l->optopt)) {
                    return true;
                }
            }
        }
        if (l->paramv && r->paramv && l->paramv != r->paramv) {
            return true;
        }
    }

    return false;
}

/* Return the opt letter of any option that is mutually exclusive
 * with the specified option and which appeared on the command line
 * at least the specified number of times.
 */
clp_option_t *
clp_excludes(clp_option_t *first, const clp_option_t *option, int given)
{
    clp_option_t *o;

    for (o = first; o->optopt > 0; ++o) {
        if (o->given >= given && clp_excludes2(option, o)) {
            return o;
        }
    }

    return NULL;
}

/* Option after() procedures are called after option processing
 * for each option that was given on the command line.
 */
void
clp_version(clp_option_t *option)
{
    printf("%s\n", (char *)option->cvtdst);
}

/* Return the count of leading open brackets, and the given
 * name stripped of white space and brackets in buf[].
 */
int
clp_unbracket(const char *name, char *buf, size_t bufsz)
{
    int nbrackets = 0;

    if (!name || !buf || bufsz < 1) {
        abort();
    }

    // Eliminate white space around open brackets
    while (isspace(*name) || *name == '[') {
        if (*name == '[') {
            ++nbrackets;
        }
        ++name;
    }

    strncpy(buf, name, bufsz - 1);
    buf[bufsz - 1] = '\000';

    // Terminate buf at first white space or bracket
    while (*buf && !isspace(*buf) && *buf != ']' && *buf != '[') {
        ++buf;
    }
    *buf = '\000';

    return nbrackets;
}

/* Lexical string comparator for qsort (e.g., AaBbCcDd...)
 */
static int
clp_string_cmp(const void *lhs, const void *rhs)
{
    const char *l = (const char *)lhs;
    const char *r = (const char *)rhs;

    int lc = tolower(*l);
    int rc = tolower(*r);

    if (lc == rc) {
        return (isupper(*l) ? -1 : 1);
    }

    return (lc - rc);
}

/* Print just the usage line, i.e., lines of the general form
 *   "usage: progname [options] args..."
 */
void
clp_usage(clp_t *clp, const clp_option_t *limit, FILE *fp)
{
    clp_posparam_t *paramv = clp->paramv;
    char excludes_buf[clp->optionc + 1];
    char optarg_buf[clp->optionc * 16];
    char opt_buf[clp->optionc + 1];
    clp_posparam_t *param;
    char *pc_excludes;
    clp_option_t *o;
    char *pc_optarg;
    char *pc_opt;
    char *pc;

    if (limit) {
        if (!limit->paramv) {
            return;
        }
        paramv = limit->paramv;
    }

    pc_excludes = excludes_buf;
    pc_optarg = optarg_buf;
    pc_opt = opt_buf;

    /* Build three lists of option characters:
     *
     * 1) excludes_buf[] contains all the options that might exclude
     * or be excluded by another option.
     *
     * 2) optarg_buf[] contains all the options not in (1) that require
     * an argument.
     *
     * 3) opt_buf[] contains all the rest not covered by (1) or (2).
     *
     * Note: if 'limit' is not NULL, then only options that share
     * the same paramv or have a NULL paramv may appear in one of
     * the three lists.
     */
    for (o = clp->optionv; o->optopt > 0; ++o) {
        if (limit) {
            if (clp_excludes2(limit, o)) {
                continue;
            }
        } else if (o->paramv) {
            continue;
        }

        if (o != limit) {
            if (isprint(o->optopt)) {
                if (o->excludes) {
                    *pc_excludes++ = o->optopt;
                } else if (o->argname) {
                    *pc_optarg++ = o->optopt;
                } else {
                    *pc_opt++ = o->optopt;
                }
            }
        }
    }

    *pc_excludes = '\000';
    *pc_optarg = '\000';
    *pc_opt = '\000';

    qsort(opt_buf, strlen(opt_buf), 1, clp_string_cmp);
    qsort(optarg_buf, strlen(optarg_buf), 1, clp_string_cmp);
    qsort(excludes_buf, strlen(excludes_buf), 1, clp_string_cmp);

    dprint(1, "option -%c:\n", limit ? limit->optopt : '?');
    dprint(1, "  excludes: %s\n", excludes_buf);
    dprint(1, "  optarg:   %s\n", optarg_buf);
    dprint(1, "  opt:      %s\n", opt_buf);

    /* Now print out the usage line in the form of:
     *
     * usage: basename [mandatory-opt] [bool-opts] [opts-with-args] [excl-opts] [posparams...]
     */

    /* [mandatory-opt]
     */
    fprintf(fp, "usage: %s", clp->basename);
    if (limit) {
        fprintf(fp, " -%c", limit->optopt);
    }

    /* [bool-opts]
     */
    if (opt_buf[0]) {
        fprintf(fp, " [-%s]", opt_buf);
    }

    /* [opts-with-args]
     */
    for (pc = optarg_buf; *pc; ++pc) {
        clp_option_t *o = clp_option_find(clp->optionv, *pc);

        if (o) {
            fprintf(fp, " [-%c %s]", o->optopt, o->argname);
        }
    }

    /* Generate the mutually exclusive option usage message...
     * [excl-args]
     */
    if (excludes_buf[0]) {
        char *listv[clp->optionc + 1];
        int listc = 0;
        char *cur;
        int i;

        /* Build a vector of strings where each string contains
         * mutually exclusive options.
         */
        for (cur = excludes_buf; *cur; ++cur) {
            clp_option_t *l = clp_option_find(clp->optionv, *cur);
            char buf[1024], *pc_buf;

            pc_buf = buf;

            for (pc = excludes_buf; *pc; ++pc) {
                if (cur == pc) {
                    *pc_buf++ = *pc;
                } else {
                    clp_option_t *r = clp_option_find(clp->optionv, *pc);

                    if (clp_excludes2(l, r)) {
                        *pc_buf++ = *pc;
                    }
                }
            }

            *pc_buf = '\000';

            listv[listc++] = strdup(buf);
        }

        /* Eliminate duplicate strings.
         */
        for (i = 0; i < listc; ++i) {
            int j;

            for (j = i + 1; j < listc; ++j) {
                if (listv[i] && listv[j]) {
                    if (0 == strcmp(listv[i], listv[j])) {
                        free(listv[j]);
                        listv[j] = NULL;
                    }
                }
            }
        }

        /* Ensure that all options within a list are mutually exclusive.
         */
        for (i = 0; i < listc; ++i) {
            if (listv[i]) {
                for (pc = listv[i]; *pc; ++pc) {
                    clp_option_t *l = clp_option_find(clp->optionv, *pc);
                    char *pc2;

                    for (pc2 = listv[i]; *pc2; ++pc2) {
                        if (pc2 != pc) {
                            clp_option_t *r = clp_option_find(clp->optionv, *pc2);

                            if (!clp_excludes2(l, r)) {
                                free(listv[i]);
                                listv[i] = NULL;
                                goto next;
                            }
                        }
                    }
                }
            }

          next:
            continue;
        }

        /* Now, print out the remaining strings of mutually exclusive options.
         */
        for (i = 0; i < listc; ++i) {
            if (listv[i]) {
                char *bar = "";

                fprintf(fp, " [");

                for (pc = listv[i]; *pc; ++pc) {
                    fprintf(fp, "%s-%c", bar, *pc);
                    bar = " | ";
                }

                fprintf(fp, "]");
            }
        }
    }

    /* Finally, print out all the positional parameters.
     * [posparams...]
     */
    if (paramv) {
        int noptional = 0;

        for (param = paramv; param->name; ++param) {
            char namebuf[128];
            int isopt;

            isopt = clp_unbracket(param->name, namebuf, sizeof(namebuf));

            if (isopt) {
                ++noptional;
            }

            fprintf(fp, "%s%s", isopt ? " [" : " ", namebuf);

            if (param[1].name) {
                isopt = clp_unbracket(param[1].name, namebuf, sizeof(namebuf));
            }

            /* If we're at the end of the list or the next parameter
             * is not optional then print all the closing brackets.
             */
            if (!param[1].name || !isopt) {
                for (; noptional > 0; --noptional) {
                    fputc(']', fp);
                }
            }
        }
    }

    fprintf(fp, "\n");
}

/* Lexical option comparator for qsort (e.g., AaBbCcDd...)
 */
static int
clp_help_cmp(const void *lhs, const void *rhs)
{
    clp_option_t const *l = *(clp_option_t * const *)lhs;
    clp_option_t const *r = *(clp_option_t * const *)rhs;

    int lc = tolower(l->optopt);
    int rc = tolower(r->optopt);

    if (lc == rc) {
        return (isupper(l->optopt) ? -1 : 1);
    }

    return (lc - rc);
}

/* Print the entire help message, for example:
 *
 * usage: prog [-v] [-i intarg] src... dst
 * usage: prog -h [-v]
 * usage: prog -V
 * -h         print this help list
 * -i intarg  specify an integer argument
 * -V         print version
 * -v         increase verbosity
 * dst     specify destination directory
 * src...  specify one or more source files
 */
void
clp_help(clp_option_t *opthelp)
{
    const clp_posparam_t *param;
    const clp_option_t *option;
    clp_posparam_t *paramv;
    int longhelp;
    int optionc;
    clp_t *clp;
    int width;
    FILE *fp;
    int i;

    /* opthelp is the option that triggered clp into calling clp_help().
     * Ususally -h, but the user could have changed it...
     */
    if (!opthelp) {
        return;
    }

    fp = opthelp->priv ? opthelp->priv : stdout;
    longhelp = (opthelp->longidx >= 0);

    clp = opthelp->clp;
    optionc = clp->optionc;
    paramv = clp->paramv;

    /* Create an array of pointers to options and sort it.
     */
    clp_option_t *optionv[optionc];

    for (i = 0; i < optionc; ++i) {
        optionv[i] = clp->optionv + i;
    }
    qsort(optionv, optionc, sizeof(optionv[0]), clp_help_cmp);

    /* Print the default usage line.
     */
    clp_usage(clp, NULL, fp);

    /* Print usage lines for each option that has positional parameters
     * different than the default usage.
     * Also, determine the width of the longest combination of option
     * argument and long option names.
     */
    width = 0;
    for (i = 0; i < optionc; ++i) {
        int len = 0;

        option = optionv[i];

        if (!option->help) {
            continue;
        }

        clp_usage(clp, option, fp);

        if (option->argname) {
            len += strlen(option->argname) + 1;
        }
        if (longhelp && option->longopt) {
            len += strlen(option->longopt) + 4;
        }
        if (len > width) {
            width = len;
        }
    }

    /* Print a line of help for each option.
     */
    for (i = 0; i < optionc; ++i) {
        char buf[width + 8];

        option = optionv[i];

        if (!option->help) {
            continue;
        }

        if (!isprint(option->optopt) && !longhelp) {
            continue;
        }

        buf[0] = '\000';

        if (longhelp && option->longopt) {
            if (isprint(option->optopt)) {
                strcat(buf, ",");
            }
            strcat(buf, " --");
            strcat(buf, option->longopt);
        }
        if (option->argname) {
            strcat(buf, " ");
            strcat(buf, option->argname);
        }

        if (isprint(option->optopt)) {
            fprintf(fp, "-%c%-*s  %s\n", option->optopt, width, buf, option->help);
        } else {
            fprintf(fp, "   %-*s  %s\n", width, buf, option->help);
        }
    }

    /* Determine the wdith of the longest positional parameter name.
     */
    if (paramv) {
        width = 0;

        for (param = paramv; param->name; ++param) {
            char namebuf[32];
            int namelen;

            clp_unbracket(param->name, namebuf, sizeof(namebuf));
            namelen = strlen(namebuf);

            if (namelen > width) {
                width = namelen;
            }
        }

        /* Print a line of help for each positional paramter.
         */
        for (param = paramv; param->name; ++param) {
            char namebuf[32];

            clp_unbracket(param->name, namebuf, sizeof(namebuf));

            fprintf(fp, "%-*s  %s\n",
                    width, namebuf, param->help ? param->help : "");
        }
    }

    /* Print detailed help if -v was given.
     */
    option = clp_option_find(clp->optionv, 'v');

    if (option && option->given == 0) {
#if 0
        fprintf(fp, "\nUse -%c for more detail", option->optopt);
        if (!longhelp && opthelp->longopt) {
            fprintf(fp, ", use --%s for long help", opthelp->longopt);
        }
        fprintf(fp, "\n");
#endif
    }

    fprintf(fp, "\n");
}

/* Determine the minimum and maximum number of arguments that the
 * given posparam vector could consume.
 */
void
clp_posparam_minmax(clp_posparam_t *paramv, int *posminp, int *posmaxp)
{
    clp_posparam_t *param;

    if (!paramv || !posminp || !posmaxp) {
        assert(0);
        return;
    }

    *posminp = 0;
    *posmaxp = 0;

    for (param = paramv; param->name; ++param) {
        char namebuf[128];
        int isopt;
        int len;

        isopt = clp_unbracket(param->name, namebuf, sizeof(namebuf));

        param->posmin = isopt ? 0 : 1;

        len = strlen(namebuf);
        if (len >= 3 && 0 == strncmp(namebuf + len - 3, "...", 3)) {
            param->posmax = 1024;
        } else {
            param->posmax = 1;
        }

        *posminp += param->posmin;
        *posmaxp += param->posmax;
    }
}

static int
clp_parsev_impl(clp_t *clp, int argc, char **argv, int *optindp)
{
    struct option *longopt;
    clp_posparam_t *paramv;
    size_t optstringsz;
    clp_option_t *o;
    int posmin;
    int posmax;
    char *env;
    char *pc;
    int rc;

    env = getenv("CLP_DEBUG");
    if (env) {
        clp_debug = strtol(env, NULL, 0);
    }

    clp->longopts = calloc(clp->optionc + 1, sizeof(*clp->longopts));
    if (!clp->longopts) {
        eprint(clp, "+%d %s: unable to calloc longopts (%zu bytes)",
               __LINE__, __FILE__, sizeof(*clp->longopts) * (clp->optionc + 1));
        return EX_OSERR;
    }
    longopt = clp->longopts;

    optstringsz = clp->optionc * 3 + 3;

    clp->optstring = calloc(1, optstringsz);
    if (!clp->optstring) {
        eprint(clp, "+%d %s: unable to calloc optstring (%zu bytes)",
               __LINE__, __FILE__, optstringsz);
        return EX_OSERR;
    }

    pc = clp->optstring;

    *pc++ = '+';    // Enable POSIXLY_CORRECT sematics
    *pc++ = ':';    // Disable getopt error reporting

    /* Generate the optstring and the long options table from the options vector.
     */
    if (clp->optionv) {
        for (o = clp->optionv; o->optopt > 0; ++o) {
            if (isprint(o->optopt)) {
                *pc++ = o->optopt;

                if (o->argname) {
                    *pc++ = ':';
                }
            }

            if (o->longopt) {
                longopt->name = o->longopt;
                longopt->has_arg = no_argument;
                longopt->val = o->optopt;

                if (o->argname) {
                    longopt->has_arg = required_argument;
                }

                ++longopt;
            }
        }

        /* Call each option's before() procedure before option processing.
         */
        for (o = clp->optionv; o->optopt > 0; ++o) {
            if (o->before) {
                o->before(o);
            }
        }
    }

    paramv = clp->paramv;

    char usehelp[] = ", use -h for help";
    if (clp->opthelp > 0) {
        usehelp[7] = clp->opthelp;
    } else {
        usehelp[0] = '\000';
    }

    /* Reset getopt_long().
     * TODO: Create getopt_long_r() for MT goodness.
     */
#ifdef optreset
    optreset = 1; // FreeBSD
#else
    optind = 1; // GNU
#endif

    while (1) {
        int curind = optind;
        int longidx = -1;
        clp_option_t *x;
        int c;

        c = getopt_long(argc, argv, clp->optstring, clp->longopts, &longidx);

        if (-1 == c) {
            break;
        } else if ('?' == c) {
            eprint(clp, "invalid option %s%s", argv[curind], usehelp);
            return EX_USAGE;
        } else if (':' == c) {
            eprint(clp, "option %s requires a parameter%s", argv[curind], usehelp);
            return EX_USAGE;
        }

        /* Look up the option.  This should not fail unless someone perturbs
         * the option vector that was passed in to us.
         */
        o = clp_option_find(clp->optionv, c);
        if (!o) {
            eprint(clp, "+%d %s: program error: unexpected option %s",
                   __LINE__, __FILE__, argv[curind]);
            return EX_SOFTWARE;
        }

        /* See if this option is excluded by any other option given so far...
         */
        x = clp_excludes(clp->optionv, o, 1);
        if (x) {
            eprint(clp, "option -%c excludes -%c%s", x->optopt, c, usehelp);
            return EX_USAGE;
        }

        o->longidx = longidx;
        o->optarg = optarg;
        ++o->given;

        if (o->paramv) {
            paramv = o->paramv;
        }

        if (o->convert) {
            if (o->given > 1 && o->cvtdst) {
                if (o->convert == clp_cvt_string) {
                    free(*(void **)o->cvtdst);
                    *(void **)o->cvtdst = NULL;
                }
            }

            rc = o->convert(optarg, o->cvtflags, o->cvtparms, o->cvtdst);

            if (rc) {
                char optbuf[] = { o->optopt, '\000' };

                eprint(clp, "unable to convert '%s%s %s'%s%s",
                       (longidx >= 0) ? "--" : "-",
                       (longidx >= 0) ? o->longopt : optbuf,
                       optarg,
                       errno ? ": " : "",
                       errno ? strerror(errno) : "");

                return rc;
            }
        }
    }

    if (optindp) {
        *optindp = optind;
    }
    argc -= optind;
    argv += optind;

    posmin = 0;
    posmax = 0;

    /* Only check positional parameter counts if paramv is not NULL.
     * This allows the caller to prevent parameter processing by clp
     * and handle it themselves.
     */
    if (paramv) {
        clp_posparam_minmax(paramv, &posmin, &posmax);

        if (argc < posmin) {
            eprint(clp, "mandatory positional parameters required%s", usehelp);
            return EX_USAGE;
        } else if (argc > posmax) {
            eprint(clp, "extraneous positional parameters detected%s", usehelp);
            return EX_USAGE;
        }
    }

    /* Call each given option's after() procedure after all options have
     * been processed.
     */
    if (clp->optionv) {
        for (o = clp->optionv; o->optopt > 0; ++o) {
            if (o->given && o->after) {
                o->after(o);
            }
        }
    }

    if (paramv) {
        clp_posparam_t *param;
        int i;

        /* Call each parameter's before() procedure before positional parameter processing.
         */
        for (param = paramv; param->name; ++param) {
            if (param->before) {
                param->before(param);
            }
        }

        /* Distribute the given positional arguments to the positional parameters
         * using a greedy approach.
         */
        for (param = paramv; param->name && argc > 0; ++param) {
            param->argv = argv;
            param->argc = 0;

            if (param->posmin == 1) {
                param->argc = 1;
                if (param->posmax > 1) {
                    param->argc += argc - posmin;
                }
                --posmin;
            }
            else if (argc > posmin) {
                if (param->posmax > 1) {
                    param->argc = argc - posmin;
                } else {
                    param->argc = 1;
                }
            }

            dprint(1, "argc=%d posmin=%d argv=%s param=%s %d,%d,%d\n",
                   argc, posmin, *argv, param->name, param->posmin,
                   param->posmax, param->argc);

            argv += param->argc;
            argc -= param->argc;
        }

        if (argc > 0) {
            dprint(0, "args left over: argc=%d posmin=%d argv=%s\n",
                   argc, posmin, *argv);
        }

        /* Call each parameter's convert() procedure for each given argument.
         */
        for (param = paramv; param->name; ++param) {
            if (param->convert) {
                for (i = 0; i < param->argc; ++i) {
                    param->convert(param->argv[i], param->cvtflags,
                                   param->cvtparms, param->cvtdst);
                }
            }
        }

        /* Call each filled parameter's after() procedure.
         */
        for (param = paramv; param->name; ++param) {
            if (param->argc > 0 && param->after) {
                param->after(param);
            }
        }
    }

    return 0;
}

/* Like clp_parsev(), but takes a string instead of a vector.
 * Uses strsep() to break the line up by the given delimiters.
 */
int
clp_parsel(const char *line, const char *delim,
           clp_option_t *optionv, clp_posparam_t *paramv,
           char *errbuf, size_t errbufsz)
{
    char **argv;
    int optind;
    int argc;
    int rc;

    rc = clp_breakargs(line, delim, errbuf, errbufsz, &argc, &argv);
    if (rc)
        return rc;

    rc = clp_parsev(argc, argv, optionv, paramv, errbuf, errbufsz, &optind);

    free(argv);

    return rc;
}

/* Parse a vector of strings as specified by the given option and
 * param vectors (either or both which may be nil).
 *
 * If successful, returns zero and if optindp is not nil returns
 * the index into argv[] at which processng stopped.
 *
 * On error, returns a suggested exit code from sysexits.h, and
 * an error message in errbuf.  If errbuf is nil, prints the error
 * message to stderr.
 */
int
clp_parsev(int argc, char **argv,
           clp_option_t *optionv, clp_posparam_t *paramv,
           char *errbuf, size_t errbufsz, int *optindp)
{
    char _errbuf[128];
    clp_t clp;
    int rc;

    if (argc < 1)
        return 0;

    memset(&clp, 0, sizeof(clp));

    clp.optionv = optionv;
    clp.paramv = paramv;

    clp.errbuf = errbuf ?: _errbuf;
    clp.errbufsz = errbuf ? errbufsz : sizeof(_errbuf);

    clp.basename = __func__;
    if (argc > 0) {
        clp.basename = strrchr(argv[0], '/');
        clp.basename = (clp.basename ? clp.basename + 1 : argv[0]);
    }

    /* Validate options and initialize/reset from previous run.
     */
    if (optionv) {
        clp_option_t *o;

        for (o = optionv; o->optopt > 0; ++o) {
            o->clp = &clp;
            o->given = 0;
            o->optarg = NULL;

            if (o->convert == clp_cvt_bool || o->convert == clp_cvt_incr) {
                o->argname = NULL;
            }

            if (o->argname && !o->convert) {
                eprint(&clp, "option -%c requires an argument"
                       " but has no conversion function", o->optopt);
                return EX_DATAERR;
            }

            if (o->convert && !o->cvtdst) {
                eprint(&clp, "option -%c has a conversion function but no cvtdst ptr",
                       o->optopt);
                return EX_DATAERR;
            }

            if (o->after == clp_help) {
                clp.opthelp = o->optopt;
            }

            ++clp.optionc;
        }
    }

    /* Validate positional parameters.
     */
    if (paramv) {
        clp_posparam_t *param;

        for (param = paramv; param->name > 0; ++param) {
            if (param->convert && !param->cvtdst) {
                eprint(&clp, "parameter %s has a conversion function but no cvtdst ptr",
                       param->name);
                return EX_DATAERR;
            }

        }
    }

    rc = clp_parsev_impl(&clp, argc, argv, optindp);

    if (rc && !errbuf) {
        fprintf(stderr, "%s: %s\n", clp.basename, clp.errbuf);
    }

    if (clp.optstring) {
        free(clp.optstring);
    }
    if (clp.longopts) {
        free(clp.longopts);
    }

    return rc;
}

/* Create a vector of strings from words in src.
 *
 * Words are delimited by any character from delim (or isspace()
 * if delim is nil) and delimiters are elided.  Delimiters that are
 * escaped by a backslash and/or occur within quoted strings lose
 * their significance as delimiters and hence are retained with the
 * word in which they appear.
 *
 * If sep is nil, then all whitespace between words is elided, which
 * is to say that zero-length strings between delimiters are always
 * elided.  If sep is not nil, then zero-length strings between
 * delimiters are always preserved.
 *
 * For example:
 *
 *    src = :one\, two,, , "four,five" :
 *    delim = ,:
 *
 *    argc = 6;
 *    argv[0] = ""
 *    argv[1] = "one two"
 *    argv[2] = ""
 *    argv[3] = " "
 *    argv[4] = " four,five "
 *    argv[5] = ""
 *    argv[6] = NULL
 *
 * On success, argc and argv are returned via *argcp and *argvp
 * respectively if not nil, and argv[argc] is always set to NULL.
 * If argvp is not nil then *argvp must always be freed by the
 * caller, even if *argcp is zero.
 *
 * On failue, errno is set and an exit code from sysexits.h
 * is returned.  *argvp is not set and must not be freed
 * in this case.
 *
 * Note:  If delim is nil, then all white space surrounding
 * each word is elided.
 */
int
clp_breakargs(const char *src, const char *delim,
              char *errbuf, size_t errbufsz,
              int *argcp, char ***argvp)
{
    char _errbuf[128];
    bool backslash = false;
    bool dquote = false;
    bool squote = false;
    size_t argvsz;
    int argcmax;
    char **argv;
    int srclen;
    char *prev;
    char *dst;
    int argc;

    errbufsz = errbuf ? errbufsz : sizeof(_errbuf);
    errbuf = errbuf ?: _errbuf;

    if (!src) {
        snprintf(errbuf, errbufsz, "+%d %s: src may not be NULL", __LINE__, __FILE__);
        errno = EINVAL;
        return EX_SOFTWARE;
    }

    /* Allocate enough space to hold the maximum needed pointers plus
     * a copy of the entire source string.  This will generally waste
     * a bit of space, but it greatly simplifies cleanup.
     */
    srclen = strlen(src);
    argcmax = srclen + 2;
    argvsz = sizeof(*argv) * argcmax + (srclen + 1);

    argv = malloc(argvsz);
    if (!argv) {
        snprintf(errbuf, errbufsz, "+%d %s: unable to allocate %zu bytes",
                 __LINE__, __FILE__, argvsz);
        errno = ENOMEM;
        return EX_OSERR;
    }

    dst = (char *)(argv + argcmax);
    prev = dst;
    argc = 0;

    while (1) {
        if (backslash) {
            backslash = false;

            /* TODO: Not sure if we should convert printf escapes
             * or leave them unconverted in dst.
             */
            switch (*src) {
            case 'a': *dst++ = '\a'; break;
            case 'b': *dst++ = '\b'; break;
            case 'f': *dst++ = '\f'; break;
            case 'n': *dst++ = '\n'; break;
            case 'r': *dst++ = '\r'; break;
            case 't': *dst++ = '\t'; break;
            case 'v': *dst++ = '\v'; break;

            default:
                if (isdigit(*src)) {
                    char *end;

                    *dst++ = strtoul(src, &end, 8); // TODO: Test me...
                    src = end;
                    continue;
                }

                *dst++ = *src;
                break;
            }
        }
        else if (*src == '\\') {
            backslash = true;
        }
        else if (*src == '"') {
            if (squote) {
                *dst++ = *src;
            } else {
                dquote = !dquote;
            }
        }
        else if (*src == '\'') {
            if (dquote) {
                *dst++ = *src;
            } else {
                squote = !squote;
            }
        }
        else if (dquote || squote) {
            *dst++ = *src;
        }
        else if (!delim && (!*src || isspace(*src))) {
            if (dst > prev) {
                argv[argc++] = prev;
                *dst++ = '\000';
                prev = dst;
            }
            // else elides leading whitespace and NUL characters...
        } else if (delim && strchr(delim, *src)) {
            argv[argc++] = prev;
            *dst++ = '\000';
            prev = dst;
        } else {
            *dst++ = *src;
        }

        if (!*src++)
            break;
    }

    if (dquote || squote) {
        snprintf(errbuf, errbufsz, "unterminated %s quote",
                 dquote ? "double" : "single");
        free(argv);
        errno = EINVAL;
        return EX_DATAERR;
    }

    if (dst > prev) {
        argv[argc++] = prev;
        *dst++ = '\000';
    }

    argv[argc] = NULL;

    if (argcp) {
        *argcp = argc;
    }
    if (argvp) {
        *argvp = argv;
    } else {
        free(argv);
    }

    return 0;
}
