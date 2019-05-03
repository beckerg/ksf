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
 * $Id: clp.h 384 2016-01-25 11:48:25Z greg $
 */
#ifndef CLP_H
#define CLP_H

#include <sys/types.h>

#define CLP_OPTION_END      { .optopt = 0 }
#define CLP_PARAM_END       { .name = NULL }

/* List of conversion routines provided by clp.
 *
 * xtype        .cvtdst         .cvtflags       .cvtparms
 *
 * bool         bool *
 * char         char *
 * u_char       u_char *
 * short        short *
 * u_short      u_short *
 * int          int *
 * u_int        u_int *
 * long         long *
 * u_long       u_long *
 * intXX_t      intXX_t *
 * uintXX_t     uintXX_t *
 *
 * intmax_t     intmax_t *
 * uintmax_t    uintmax_t *
 *
 * intptr_t     intptr_t *
 * uintptr_t    uintptr_t *
 *
 * size_t       size_t *
 * time_t       time_t *
 *
 * The above conversion functions accept an clp_cvtparms_t pointer
 * in the cvtparms parameter in order to process a list of integers.
 *
 * string       char *
 * fopen        FILE **         -               fopen() mode arg
 * open         int *           open() flags    -
 */

#define CLP_OPTION(xtype, xoptopt, xargname, xlongopt, xexcl, xhelp) \
    { CLP_OPTION_TMPL((xoptopt), #xargname, (xexcl), (xlongopt),     \
                      clp_cvt_ ## xtype, 0, NULL, &(xargname),       \
                      NULL, NULL, NULL, (xhelp)) }

#define CLP_OPTION_VERBOSE(xverbose)                                \
    CLP_OPTION(incr, 'v', xverbose, NULL, NULL, "increase verbosity")

#define CLP_OPTION_HELP                                             \
    { CLP_OPTION_TMPL('h', NULL, "^v", "help",                      \
                      NULL, 0, NULL, NULL,                          \
                      NULL, clp_help, clp_posparam_none,            \
                      "print this help list") }

#define CLP_OPTION_VERSION(xversion)                                \
    { CLP_OPTION_TMPL('V', NULL, "*", #xversion,                    \
                      NULL, 0, NULL, &(xversion),                   \
                      NULL, clp_version, clp_posparam_none,         \
                      "print version") }

#define CLP_OPTION_DRYRUN(xdryrun)                                  \
    { CLP_OPTION_TMPL('n', NULL, NULL, #xdryrun,                    \
                      clp_cvt_incr, 0, NULL, &(xdryrun),            \
                      NULL, NULL, NULL,                             \
                      "trace execution but do not change anything") }

#define CLP_OPTION_CONF(xconf)                                      \
    { CLP_OPTION_TMPL('C', #xconf, NULL, #xconf,                    \
                      clp_cvt_fopen, 0, NULL, &(xconf),             \
                      NULL, NULL, NULL,                             \
                      "specify a configuration file") }

#define CLP_OPTION_TMPL(xoptopt, xargname, xexcludes, xlongopt,     \
                        xconvert, xcvtflags, xcvtparms, xcvtdst,    \
                        xbefore, xafter, xparamv, xhelp)            \
    .optopt = (xoptopt),                                            \
    .argname = (xargname),                                          \
    .excludes = (xexcludes),                                        \
    .longopt = (xlongopt),                                          \
    .convert = (xconvert),                                          \
    .cvtflags = (xcvtflags),                                        \
    .cvtparms = (xcvtparms),                                        \
    .cvtdst = (xcvtdst),                                            \
    .before = (xbefore),                                            \
    .after = (xafter),                                              \
    .paramv = (xparamv),                                            \
    .help = (xhelp),                                                \



struct clp_s;
struct clp_option_s;
struct clp_posparam_s;

typedef int clp_cvt_t(const char *optarg, int flags, void *parms, void *dst);

typedef void clp_option_cb_t(struct clp_option_s *option);

typedef void clp_posparam_cb_t(struct clp_posparam_s *param);

typedef struct clp_posparam_s {
    const char         *name;           // Name shown by help for the parameter
    const char         *help;           // One line that descibes this parameter
    clp_cvt_t          *convert;        // Called for each positional argument
    int                 cvtflags;       // Arg 2 to convert()
    void               *cvtparms;       // Arg 3 to convert()
    void               *cvtdst;         // Where convert() stores its output
    clp_posparam_cb_t  *before;         // Called before positional argument distribution
    clp_posparam_cb_t  *after;          // Called after positional argument distribution
    void               *priv;           // Free for use by caller of clp_parse()

    /* The following fields are used by the option parser, whereas the above
     * fields are supplied by the user.
     */
    struct clp_s       *clp;
    int                 posmin;         // Min number of positional parameters
    int                 posmax;         // Max number of positional parameters
    int                 argc;           // Number of arguments assigned to this parameter
    char              **argv;           // Ptr to arguments assigned to this parameter
} clp_posparam_t;

typedef struct clp_option_s {
    const int           optopt;         // Option letter for getopt optstring
    const char         *argname;        // Name of option argument (if any)
    const char         *excludes;       // List of options excluded by optopt
    const char         *longopt;        // Long option name for getopt
    const char         *help;           // One line that describes this option
    clp_cvt_t          *convert;        // Function to convert optarg
    int                 cvtflags;       // Arg 2 to convert()
    void               *cvtparms;       // Arg 3 to convert()
    void               *cvtdst;         // Where convert() stores its result
    clp_option_cb_t    *before;         // Called before getopt processing
    clp_option_cb_t    *after;          // Called after getopt processing
    clp_posparam_t     *paramv;         // Option specific positional parameters
    void               *priv;           // Free for use by caller of clp_parse()

    /* The following fields are used by the option parser, whereas the above
     * fields are supplied by the user.
     */
    struct clp_s       *clp;            // Not valid when parser returns
    int                 given;          // Count of times this option was given
    const char         *optarg;         // optarg from getopt()
    int                 longidx;        // Index into cli->longopts[]
} clp_option_t;

typedef struct clp_s {
    const char         *basename;       // From argv[0] of clp_parsev()
    clp_option_t       *optionv;        // Argument from clp_parsev()
    clp_posparam_t     *paramv;         // Argument from clp_parsev()
    int                 optionc;        // Count of elements in optionv[]
    char               *optstring;      // The optstring for getopt
    struct option      *longopts;       // Table of long options for getopt_long()
    int                 opthelp;        // The option tied to opt_help()
    char               *errbuf;
    size_t              errbufsz;
} clp_t;


/* Declare a type-specific vector.
 */
#define CLP_VECTOR_DECL(_xname, _xtype, _xsize)                         \
    struct _xname {                                                     \
        u_int            len;                                           \
        u_int            size;                                          \
        const char      *delim;                                         \
        void            *priv;                                          \
        _xtype           data[(_xsize)];                                \
    }

/* Declare, define, and initialize a vector.
 */
#define CLP_VECTOR(_xname, _xtype, _xsize, _xdelim)                    \
    CLP_VECTOR_DECL(_xname, _xtype, _xsize) _xname = {                 \
        .size = (_xsize),                                              \
        .delim = (_xdelim),                                            \
    }

typedef CLP_VECTOR_DECL(clp_vector, char, 0) clp_vector_t;

extern clp_posparam_t clp_posparam_none[];

extern clp_option_t *clp_option_find(clp_option_t *optionv, int optopt);

extern void clp_option_priv1_set(clp_option_t *option, void *priv1);

extern clp_cvt_t clp_cvt_bool;

extern clp_cvt_t clp_cvt_string;
extern clp_cvt_t clp_cvt_fopen;
extern clp_cvt_t clp_cvt_open;
extern clp_cvt_t clp_cvt_incr;

extern clp_cvt_t clp_cvt_char;
extern clp_cvt_t clp_cvt_uchar;
extern clp_cvt_t clp_cvt_u_char;

extern clp_cvt_t clp_cvt_int;
extern clp_cvt_t clp_cvt_uint;
extern clp_cvt_t clp_cvt_u_int;

extern clp_cvt_t clp_cvt_long;
extern clp_cvt_t clp_cvt_ulong;
extern clp_cvt_t clp_cvt_u_long;

extern clp_cvt_t clp_cvt_float;
extern clp_cvt_t clp_cvt_double;

extern clp_cvt_t clp_cvt_int8;
extern clp_cvt_t clp_cvt_int8_t;

extern clp_cvt_t clp_cvt_uint8;
extern clp_cvt_t clp_cvt_uint8_t;

extern clp_cvt_t clp_cvt_int16;
extern clp_cvt_t clp_cvt_int16_t;

extern clp_cvt_t clp_cvt_uint16;
extern clp_cvt_t clp_cvt_uint16_t;

extern clp_cvt_t clp_cvt_int32;
extern clp_cvt_t clp_cvt_int32_t;

extern clp_cvt_t clp_cvt_uint32;
extern clp_cvt_t clp_cvt_uint32_t;

extern clp_cvt_t clp_cvt_int64;
extern clp_cvt_t clp_cvt_int64_t;

extern clp_cvt_t clp_cvt_uint64;
extern clp_cvt_t clp_cvt_uint64_t;

extern clp_cvt_t clp_cvt_intmax_t;
extern clp_cvt_t clp_cvt_uintmax_t;

extern clp_cvt_t clp_cvt_intptr_t;
extern clp_cvt_t clp_cvt_uintptr_t;

extern clp_cvt_t clp_cvt_size_t;
extern clp_cvt_t clp_cvt_time_t;


extern clp_option_cb_t clp_help;
extern clp_option_cb_t clp_version;

extern int clp_breakargs(const char *src, const char *delim,
                         char *errbuf, size_t errbufsz,
                         int *argcp, char ***argvp);

extern int clp_parsev(int argc, char **argv,
                      clp_option_t *optionv,
                      clp_posparam_t *paramv,
                      char *errbuf, size_t errbufsz,
                      int *optindp);

extern int clp_parsel(const char *line, const char *delim,
                      clp_option_t *optionv,
                      clp_posparam_t *paramv,
                      char *errbuf, size_t errbufsz);

#endif /* CLP_H */
