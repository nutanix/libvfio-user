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

/* null PCI device, doesn't do anything */

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "../lib/muser.h"
#include "../lib/muser_priv.h"

static void
null_log(UNUSED void *pvt, UNUSED lm_log_lvl_t lvl, char const *msg)
{
	fprintf(stderr, "muser: %s", msg);
}


static void* null_drive(void *arg)
{
    lm_ctx_t *lm_ctx = (lm_ctx_t*)arg;
    int ret = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (ret != 0) {
        fprintf(stderr, "failed to enable cancel state: %s\n", strerror(ret));
        return NULL;
    }
    ret = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    if (ret != 0) {
        fprintf(stderr, "failed to enable cancel type: %s\n", strerror(ret));
        return NULL;
    }
    printf("starting device emulation\n");
    lm_ctx_drive(lm_ctx);
    return NULL;
}

int main(int argc, char **argv)
{
    int ret;
    pthread_t thread;

    if (argc != 2) {
        err(EXIT_FAILURE, "missing MUSER device UUID");
    }

    lm_dev_info_t dev_info = {.uuid = argv[1], .log = null_log, .log_lvl = LM_DBG };

    lm_ctx_t *lm_ctx = lm_ctx_create(&dev_info);
    if (lm_ctx == NULL) {
        err(EXIT_FAILURE, "failed to create libmuser context");
    }

    ret = pthread_create(&thread, NULL, null_drive, lm_ctx);
    if (ret != 0) {
        errno = ret;
        err(EXIT_FAILURE, "failed to create pthread");
    }

    printf("press enter to stop device emulation and clean up\n");
    getchar();

    ret = pthread_cancel(thread);
    if (ret != 0) {
        errno = ret;
        err(EXIT_FAILURE, "failed to create pthread");
    }
    lm_ctx_destroy(lm_ctx);

    printf("device emulation stopped and cleaned up, press enter to exit\n");
    getchar();

    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
