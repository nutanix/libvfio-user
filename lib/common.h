/*
 * Copyright (c) 2019 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
 *          Swapnil Ingle <swapnil.ingle@nutanix.com>
 *          Felipe Franciosi <felipe@nutanix.com>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Nutanix nor the names of its contributors may be
 *        used to endorse or promote products derived from this software without
 *        specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>

#define PAGE_SIZE           sysconf(_SC_PAGE_SIZE)
#define PAGE_ALIGNED(x)		(((x) & ((typeof(x))(PAGE_SIZE) - 1)) == 0)

#define BIT(nr)             (1UL << (nr))

#define ARRAY_SIZE(array)   (sizeof(array) / sizeof((array)[0]))

#define likely(e)   __builtin_expect(!!(e), 1)
#define unlikely(e) __builtin_expect(e, 0)

#define ROUND_DOWN(x, a)    ((x) & ~((a)-1))
#define ROUND_UP(x,a)       ROUND_DOWN((x)+(a)-1, a)

void
lm_log(lm_ctx_t *lm_ctx, lm_log_lvl_t lvl, const char *fmt, ...);

#ifdef DEBUG
void
dump_buffer(lm_ctx_t *lm_ctx, const char *prefix,
            const char *buf, uint32_t count);
#else
#define dump_buffer(lm_ctx, prefix, buf, count)
#endif

#endif /* __COMMON_H__ */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
