/*
 * Copyright (c) 2019 Greg Becker.  All rights reserved.
 */

#ifndef XX_H
#define XX_H

#include <sys/module.h>

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#define dprint(...)     xx_dprint(xx_debug, __func__, __LINE__, __VA_ARGS__)
#define eprint(...)     xx_dprint(8, __func__, __LINE__, __VA_ARGS__)

extern u_int xx_debug;

void xx_dprint(u_int lvl, const char *func, int line, const char *fmt, ...)
    __printflike(4, 5);

#endif /* XX_H */
