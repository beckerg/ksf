/*
 * Copyright (c) 2001-2006,2011,2014-2016,2019 Greg Becker.  All rights reserved.
 */
#ifndef XX_MAIN_H
#define XX_MAIN_H

typedef void *start_t(void *);

/* The command line parser set the following global variables:
 */
extern char version[];
extern char *progname;      // The programe name (i.e., the basename of argv[0])
extern int verbosity;       // The number of times -v appeared on the command line

/* By default dprint() and eprint() print to stderr.  You can change that
 * behavior by simply setting these variables to a different stream.
 */
extern FILE *dprint_stream;
extern FILE *eprint_stream;

/* dprint() prints a message if (lvl >= verbosity).  'verbosity' is increased
 * by one each time the -v option is given on the command line.
 * Each message is preceded by: "progname(pid): func:line"
 */
#define dprint(lvl, ...)                                            \
do {                                                                \
    if ((lvl) <= verbosity) {                                       \
        dprint_func((lvl), __func__, __LINE__, __VA_ARGS__);        \
    }                                                               \
} while (0);

extern void dprint_func(int lvl, const char *func, int line, const char *fmt, ...)
    __attribute__((format (printf, 4, 5)));


/* You should call eprint() to print error messages that should always be shown.
 * It simply prints the given message preceded by the program name.
 */
extern void eprint(const char *fmt, ...)
    __attribute__((format (printf, 1, 2)));

#endif /* XX_MAIN_H */
