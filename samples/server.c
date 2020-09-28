/*
 * Sample server to be tested with samples/client.c
 *
 * Copyright (c) 2020, Nutanix Inc. All rights reserved.
 *     Author: Thanos Makatos <thanos@nutanix.com>
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

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include "../lib/muser.h"

static void
_log(void *pvt, lm_log_lvl_t lvl __attribute__((unused)), char const *msg)
{
    fprintf(stderr, "server: %s\n", msg);
}

/* returns time in seconds since Epoch */
ssize_t
bar0_access(void *pvt, char * const buf, size_t count, loff_t offset,
            const bool is_write)
{
    time_t t = time(NULL);

    if (count != sizeof(time_t) || offset != 0) {
        errno = EINVAL;
        return -1;
    }

    memcpy(buf, &t, count);

    return count;
}

lm_ctx_t *lm_ctx;

bool irq_triggered = false;
static void _sa_handler(int signum)
{
    int _errno = errno;
    if (signum == SIGUSR1) {
        /*
         * FIXME not async-signal-safe becasue lm_irq_trigger prints to the log
         */
        lm_irq_trigger(lm_ctx, 0);
        irq_triggered = true;
    }
    errno = _errno;
}

static int
unmap_dma(void *pvt __attribute__((unused)),
          uint64_t iova __attribute__((unused)))
{
}

int main(int argc, char *argv[])
{
    int ret;
    bool trans_sock = false, verbose = false;
    char opt;
    struct sigaction act = {.sa_handler = _sa_handler};
    lm_ctx_t **_lm_ctx;

    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-d] <IOMMU group>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        err(EXIT_FAILURE, "missing MUSER device UUID");
    }

    lm_dev_info_t dev_info = {
        .trans = LM_TRANS_SOCK,
        .log = verbose ? _log : NULL,
        .log_lvl = LM_DBG,
        .pci_info = {
            .reg_info[LM_DEV_BAR0_REG_IDX] = {
                .flags = LM_REG_FLAG_RW,
                .size = sizeof(time_t),
                .fn = &bar0_access
            },
            .irq_count[LM_DEV_INTX_IRQ_IDX] = 1,
        },
        .uuid = argv[optind],
        .unmap_dma = unmap_dma,
        .pvt = &_lm_ctx
    };

    sigemptyset(&act.sa_mask);
    if (sigaction(SIGUSR1, &act, NULL) == -1) {
        fprintf(stderr, "warning: failed to register signal handler: %m\n");
    }

    lm_ctx = lm_ctx_create(&dev_info);
    if (lm_ctx == NULL) {
        if (errno == EINTR) {
            goto out;
        }
        fprintf(stderr, "failed to initialize device emulation: %m\n");
        return -1;
    }
    _lm_ctx = &lm_ctx;
    do {
        ret = lm_ctx_drive(lm_ctx);
        if (ret == -EINTR) {
            if (irq_triggered) {
                ret = 0;
                irq_triggered = false;
            }            
        }
    } while (ret == 0);
    if (ret != -ENOTCONN && ret != -EINTR) {
        fprintf(stderr, "failed to realize device emulation: %m\n");
    }
out:
    lm_ctx_destroy(lm_ctx);
    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
