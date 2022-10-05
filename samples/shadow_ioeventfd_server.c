/*
 * Copyright (c) 2022, Nutanix Inc. All rights reserved.
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

/*
 * shadow_ioeventfd_server.c: an example of how to use a shadow ioeventfd.
 * There is no Linux kernel driver, use samples/shadow_ioeventfd_speed_test.c
 * in the guest instead.
 */

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/poll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "libvfio-user.h"
#include "common.h"

static void
_log(vfu_ctx_t *vfu_ctx UNUSED, int level UNUSED, char const *msg)
{
    fprintf(stderr, "%s\n", msg);
}

static ssize_t
bar0_cb(vfu_ctx_t *vfu_ctx UNUSED, char * const buf UNUSED,
        size_t count UNUSED, loff_t offset UNUSED,
        const bool is_write UNUSED)
{
    return count;
}

int
main(int argc, char *argv[])
{
    int ret;
    vfu_ctx_t *vfu_ctx;
    struct pollfd fds[2]; /* one for vfu_ctx, one for shadow_ioeventfd */
    int fd, bar0_fd;

    if (argc != 2) {
        errx(EXIT_FAILURE, "missing vfio-user socket path");
    }

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, argv[1],
                             LIBVFIO_USER_FLAG_ATTACH_NB, NULL,
                             VFU_DEV_TYPE_PCI);

    if (vfu_ctx == NULL) {
        err(EXIT_FAILURE, "failed to initialize device emulation");
    }

    ret = vfu_setup_log(vfu_ctx, _log, LOG_ERR);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup log");
    }

    ret = vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_CONVENTIONAL,
                       PCI_HEADER_TYPE_NORMAL, 0);
    if (ret < 0) {
        err(EXIT_FAILURE, "vfu_pci_init() failed");
    }

    vfu_pci_set_id(vfu_ctx, 0x4e58, 0, 0x0, 0x0);

    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX,
                           sysconf(_SC_PAGE_SIZE), &bar0_cb,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, NULL, 0,
                           -1, 0);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup region");
    }

    ret = vfu_realize_ctx(vfu_ctx);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to realize device");
    }

    fds[0] = (struct pollfd) {
        .fd = vfu_get_poll_fd(vfu_ctx),
        .events = POLLIN | POLLOUT
    };
    ret = poll(fds, 1, -1);
    assert(ret == 1);
    ret = vfu_attach_ctx(vfu_ctx);
    if (ret < 0) {
         err(EXIT_FAILURE, "failed to attach device");
    }

    fd = eventfd(0, 0);
    if (fd == -1) {
        err(EXIT_FAILURE, "failed to create eventfd");
    }
    bar0_fd = syscall(SYS_memfd_create, "BAR0", 0);
    if (bar0_fd == -1) {
        err(EXIT_FAILURE, "failed to create BAR0 file");
    }
    ret = ftruncate(bar0_fd, sysconf(_SC_PAGESIZE));
    if (ret == -1) {
        err(EXIT_FAILURE, "failed to truncate BAR0 file");
    }
    ret = vfu_create_ioeventfd(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX,
                               fd, 0, 4,
                               0, false, bar0_fd, 0);
    if (ret == -1) {
        err(EXIT_FAILURE, "failed to create shadow ioeventfd");
    }

    fds[0] = (struct pollfd) {
        .fd = vfu_get_poll_fd(vfu_ctx),
        .events = POLLIN
    };
    fds[1] = (struct pollfd) {
        .fd = fd,
        .events = POLLIN
    };

    do {
        ret = poll(fds, 2, -1);
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to poll(2)");
        }
        assert(ret > 0);
        if (fds[0].revents & (POLLIN)) {
            ret = vfu_run_ctx(vfu_ctx);
            if (ret < 0) {
                if (errno == EAGAIN) {
                    continue;
                }
                if (errno == ENOTCONN) {
                    return 0;
                }
                err(EXIT_FAILURE, "vfu_run_ctx() failed");
            }
        }
        if (fds[1].revents & POLLIN) {
            eventfd_t value;
            eventfd_read(fd, &value);
            bar0_cb(vfu_ctx, NULL, 4, 0, true);
        }
    } while (true);
    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
