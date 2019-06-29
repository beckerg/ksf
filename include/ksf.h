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

#ifndef KNSF_H
#define KNSF_H

#ifndef ntohll
#define ntohll(_x)      be64toh((_x))
#endif

#ifndef htonll
#define htonll(_x)      htobe64((_x))
#endif

#ifndef likely
#define likely(_x)      __builtin_expect(!!(_x), 1)
#endif

#ifndef unlikely
#define unlikely(_x)    __builtin_expect(!!(_x), 0)
#endif

/* Record marking for RPC message framing.
 */
#define RPC_RECMARK_SZ  (4)

static inline void
rpc_recmark_get(const void *ptr, uint32_t *msglenp, bool *lastp)
{
    uint32_t mark;

    memcpy(&mark, ptr, sizeof(mark));
    mark = ntohl(mark);

    *msglenp = mark & ~0x80000000u;
    *lastp = mark & 0x80000000u;
}

static inline void
rpc_recmark_set(void *ptr, uint32_t msglen, bool last)
{
    uint32_t mark = msglen;

    if (last)
        mark |= 0x80000000u;

    mark = htonl(mark);
    memcpy(ptr, &mark, sizeof(mark));
}

#endif /* KNSF_H */
