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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/unistd.h>
#include <sys/sysctl.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <machine/stdarg.h>

#include "xx.h"

#define KSF_MODEVENT_FUNC(_module, _func, _mod, _cmd, _data)    \
    CAT(_module, _func)((_mod), (_cmd), (_data))

static moduledata_t xx_mod;

u_int xx_debug = 0;

void
xx_dprint(u_int lvl, const char *func, int line, const char *fmt, ...)
{
    char msg[128];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (lvl > 1)
        printf("%s: %2d %16s %4d:  %s", xx_mod.name, curcpu, func, line, msg);
    else if (lvl > 0)
        printf("%s: %2d %s", xx_mod.name, curcpu, msg);
}

int
xx_sosetopt(struct socket *so, int name, void *val, size_t valsz)
{
    struct sockopt sopt;

    bzero(&sopt, sizeof(sopt));
    sopt.sopt_dir = SOPT_SET;
    sopt.sopt_level = SOL_SOCKET;
    sopt.sopt_name = name;
    sopt.sopt_val = val;
    sopt.sopt_valsize = valsz;

    return sosetopt(so, &sopt);
}

static int
xx_modevent(module_t mod, int cmd, void *data)
{
    int rc;

    switch (cmd) {
    case MOD_LOAD:
        rc = KSF_MODEVENT_FUNC(KSF_MOD, _mod_load, mod, cmd, data);
        break;

    case MOD_UNLOAD:
        rc = KSF_MODEVENT_FUNC(KSF_MOD, _mod_unload, mod, cmd, data);
        break;

    default:
        rc = EOPNOTSUPP;
        break;
    }

    return rc;
}

static moduledata_t xx_mod = {
    KSF_MOD_NAME,
    xx_modevent,
    NULL,
};

DECLARE_MODULE(KSF_MOD, xx_mod, SI_SUB_EXEC, SI_ORDER_ANY);
//MODULE_VERSION(KSF_MOD, 1);
