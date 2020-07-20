/*
 * Userspace mediated device sample application
 *
 * Copyright (c) 2019, Nutanix Inc. All rights reserved.
 *     Author: Thanos Makatos <thanos@nutanix.com>
 *             Swapnil Ingle <swapnil.ingle@nutanix.com>
 *             Felipe Franciosi <felipe@nutanix.com>
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

/* gpio-pci-idio-16 */

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "../lib/muser.h"

static void
_log(void *pvt, lm_log_lvl_t lvl __attribute__((unused)), char const *msg)
{
    fprintf(stderr, "gpio: %s", msg);
}

ssize_t
bar2_access(void *pvt, char * const buf, size_t count, loff_t offset,
           const bool is_write)
{
    static char n;

    if (offset == 0 && !is_write)
        buf[0] = n++ / 3;

    return count;
}

static void _sa_handler(int signum __attribute__((unused)))
{
}

int main(int argc, char *argv[])
{
    int ret;
    bool trans_sock = false, verbose = false;
    char opt;
    struct sigaction act = {.sa_handler = _sa_handler};
    lm_ctx_t *lm_ctx;

    while ((opt = getopt(argc, argv, "sv")) != -1) {
        switch (opt) {
            case 's':
                trans_sock = true;
                break;
            case 'v':
                verbose = true;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-s] [-d] <IOMMU group>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        err(EXIT_FAILURE, "missing MUSER device UUID");
    }

    lm_dev_info_t dev_info = {
        .trans = trans_sock ? LM_TRANS_SOCK : LM_TRANS_KERNEL,
        .log = verbose ? _log : NULL,
        .log_lvl = LM_DBG,
        .pci_info = {
            .id = {.vid = 0x494F, .did = 0x0DC8 },
            .reg_info[LM_DEV_BAR2_REG_IDX] = {
                .flags = LM_REG_FLAG_RW,
                .size = 0x100,
                .fn = &bar2_access
            },
            .irq_count[LM_DEV_INTX_IRQ_IDX] = 1,
        },
        .uuid = argv[optind],
    };

    sigemptyset(&act.sa_mask);
    if (sigaction(SIGINT, &act, NULL) == -1) {
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
    ret = lm_ctx_drive(lm_ctx);
    if (ret != 0 && errno != EINTR) {
        fprintf(stderr, "failed to realize device emulation: %m\n");
    }
out:
    lm_ctx_destroy(lm_ctx);
    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
