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

#ifndef KSF_MOD_H
#define KSF_MOD_H

#include <sys/module.h>

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#define dprint(...)     xx_dprint(xx_debug, __func__, __LINE__, __VA_ARGS__)
#define eprint(...)     xx_dprint(8, __func__, __LINE__, __VA_ARGS__)

#define PCAT(_arg, ...)     _arg ## __VA_ARGS__
#define CAT(_arg, ...)      PCAT(_arg, __VA_ARGS__)

#define KSF_MODEVENT_PROTO(_module, _func) \
    extern int CAT(_module, _func)(module_t, int, void *)

KSF_MODEVENT_PROTO(KSF_MOD, _mod_load);
KSF_MODEVENT_PROTO(KSF_MOD, _mod_unload);

extern u_int xx_debug;

void xx_dprint(u_int lvl, const char *func, int line, const char *fmt, ...)
    __printflike(4, 5);

int xx_sosetopt(struct socket *so, int name, void *val, size_t valsz);

#endif /* KSF_MOD_H */
