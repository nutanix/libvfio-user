/*
 * Copyright (c) 2020 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
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

// for RTLD_NEXT
#define _GNU_SOURCE

#include <dlfcn.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <cmocka.h>

#include "mocks.h"
#include "dma.h"
#include "migration.h"
#include "../lib/private.h"
#include "../lib/tran_sock.h"

struct function
{
    const char *name;
    bool patched;
};
;
static int (*__real_close)(int);

static struct function funcs[] = {
    /* mocked internal funcs */
    { .name = "_dma_controller_do_remove_region" },
    { .name = "cmd_allowed_when_stopped_and_copying" },
    { .name = "device_is_stopped_and_copying" },
    { .name = "device_is_stopped" },
    { .name = "dma_controller_add_region" },
    { .name = "dma_controller_remove_region" },
    { .name = "dma_map_region" },
    { .name = "exec_command" },
    { .name = "get_next_command" },
    { .name = "handle_dirty_pages" },
    { .name = "process_request" },
    { .name = "should_exec_command" },
    { .name = "tran_sock_send_iovec" },
    /* system libs */
    { .name = "bind" },
    { .name = "close" },
    { .name = "listen" },
};

static struct function *
find(const char *name)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(funcs); i++) {
        if (strcmp(name, funcs[i].name) == 0) {
            return &funcs[i];
        }
    }
    assert(false);
}

void
patch(const char *name)
{
    struct function *func = find(name);
    func->patched = true;
}

static bool
is_patched(const char *name)
{
    return find(name)->patched;
}

void
unpatch_all(void)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(funcs); i++) {
        funcs[i].patched = false;
    }
}

int
dma_controller_add_region(dma_controller_t *dma, dma_addr_t dma_addr,
                          size_t size, int fd, off_t offset,
                          uint32_t prot)
{
    if (!is_patched("dma_controller_add_region")) {
        return __real_dma_controller_add_region(dma, dma_addr, size, fd, offset,
                                                prot);
    }

    check_expected_ptr(dma);
    check_expected(dma_addr);
    check_expected(size);
    check_expected(fd);
    check_expected(offset);
    check_expected(prot);
    return mock();
}

int
dma_controller_remove_region(dma_controller_t *dma,
                             dma_addr_t dma_addr, size_t size,
                             vfu_unmap_dma_cb_t *unmap_dma, void *data)
{
    if (!is_patched("dma_controller_remove_region")) {
        return __real_dma_controller_remove_region(dma, dma_addr, size,
                                                   unmap_dma, data);
    }

    check_expected(dma);
    check_expected(dma_addr);
    check_expected(size);
    check_expected(unmap_dma);
    check_expected(data);
    return mock();
}

void *
dma_map_region(dma_memory_region_t *region, int prot, size_t offset,
               size_t len)
{
    check_expected_ptr(region);
    check_expected(prot);
    check_expected(offset);
    check_expected(len);
    return mock_ptr_type(void*);
}

void
_dma_controller_do_remove_region(dma_controller_t *dma,
                                 dma_memory_region_t *region)
{
    check_expected(dma);
    check_expected(region);
}

bool
device_is_stopped(struct migration *migration)
{
    if (!is_patched("device_is_stopped")) {
        return __real_device_is_stopped(migration);
    }
    check_expected(migration);
    return mock();
}

int
get_next_command(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr,
                 int *fds, size_t *nr_fds)
{
    check_expected(vfu_ctx);
    check_expected(hdr);
    check_expected(fds);
    check_expected(nr_fds);
    return mock();
}

int
exec_command(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr,
             size_t size, int *fds, size_t nr_fds, int **fds_out,
             size_t *nr_fds_out, struct iovec *_iovecs,
             struct iovec **iovecs, size_t *nr_iovecs,
             bool *free_iovec_data)
{
    if (!is_patched("exec_command")) {
        return __real_exec_command(vfu_ctx, hdr, size, fds, nr_fds, fds_out,
                                   nr_fds_out, _iovecs, iovecs, nr_iovecs,
                                   free_iovec_data);
    }
    check_expected(vfu_ctx);
    check_expected(hdr);
    check_expected(size);
    check_expected(fds);
    check_expected(nr_fds);
    check_expected(fds_out);
    check_expected(nr_fds_out);
    check_expected(_iovecs);
    check_expected(iovecs);
    check_expected(nr_iovecs);
    check_expected(free_iovec_data);
    return mock();
}

int
tran_sock_send_iovec(int sock, uint16_t msg_id, bool is_reply,
                     enum vfio_user_command cmd,
                     struct iovec *iovecs, size_t nr_iovecs,
                     int *fds, int count, int err)
{
    check_expected(sock);
    check_expected(msg_id);
    check_expected(is_reply);
    check_expected(cmd);
    check_expected(iovecs);
    check_expected(nr_iovecs);
    check_expected(fds);
    check_expected(count);
    check_expected(err);
    return mock();
}

int
process_request(vfu_ctx_t *vfu_ctx)
{

    if (!is_patched("process_request")) {
        return __real_process_request(vfu_ctx);
    }
    check_expected(vfu_ctx);

    return mock();
}

bool
device_is_stopped_and_copying(struct migration *migration)
{
    if (!is_patched("device_is_stopped_and_copying")) {
        return __real_device_is_stopped_and_copying(migration);
    }
    check_expected(migration);
    return mock();
}

bool
cmd_allowed_when_stopped_and_copying(uint16_t cmd)
{
    if (!is_patched("cmd_allowed_when_stopped_and_copying")) {
        return __real_cmd_allowed_when_stopped_and_copying(cmd);
    }
    check_expected(cmd);
    return mock();
}

bool
should_exec_command(vfu_ctx_t *vfu_ctx, uint16_t cmd)
{
    if (!is_patched("should_exec_command")) {
        return __real_should_exec_command(vfu_ctx, cmd);
    }
    check_expected(vfu_ctx);
    check_expected(cmd);
    return mock();
}

int
handle_dirty_pages(vfu_ctx_t *vfu_ctx, uint32_t size,
                   struct iovec **iovecs, size_t *nr_iovecs,
                   struct vfio_iommu_type1_dirty_bitmap *dirty_bitmap)
{
    if (!is_patched("handle_dirty_pages")) {
        return __real_handle_dirty_pages(vfu_ctx, size, iovecs, nr_iovecs,
                                         dirty_bitmap);
    }
    check_expected(vfu_ctx);
    check_expected(size);
    check_expected(iovecs);
    check_expected(nr_iovecs);
    check_expected(dirty_bitmap);
    return mock();
}

/* Always mocked. */
int
mock_unmap_dma(vfu_ctx_t *vfu_ctx, uint64_t iova, uint64_t len)
{
    check_expected(vfu_ctx);
    check_expected(iova);
    check_expected(len);
    return mock();
}

/* System-provided funcs. */

int
bind(int sockfd UNUSED, const struct sockaddr *addr UNUSED,
     socklen_t addrlen UNUSED)
{
    return 0;
}

int
close(int fd)
{
    if (!is_patched("close")) {
        if (__real_close == NULL) {
            __real_close = dlsym(RTLD_NEXT, "close");
        }

        return __real_close(fd);
    }

    check_expected(fd);
    return mock();
}

int
listen(int sockfd UNUSED, int backlog UNUSED)
{
    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
