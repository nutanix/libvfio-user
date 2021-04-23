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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <alloca.h>
#include <string.h>
#include <linux/pci_regs.h>
#include <sys/param.h>

#include "dma.h"
#include "libvfio-user.h"
#include "pci.h"
#include "private.h"
#include "migration.h"
#include "mocks.h"
#include "tran_sock.h"
#include "migration_priv.h"

static void
test_dma_map_without_dma(void **state UNUSED)
{
    vfu_ctx_t vfu_ctx = { 0 };
    size_t size = sizeof(struct vfio_user_dma_region);
    struct vfio_user_dma_region dma_region = {
        .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
    };
    int fd;

    assert_int_equal(0, handle_dma_map_or_unmap(&vfu_ctx, size, true, &fd, 1, &dma_region));
}

static void
test_dma_map_mappable_without_fd(void **state UNUSED)
{
    dma_controller_t dma = { 0 };
    vfu_ctx_t vfu_ctx = { .dma = &dma };
    size_t size = sizeof(struct vfio_user_dma_region);
    struct vfio_user_dma_region dma_region = {
        .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
    };
    int fd;

    assert_int_equal(-1, handle_dma_map_or_unmap(&vfu_ctx, size, true, &fd, 0, &dma_region));
    assert_int_equal(errno, EINVAL);
}

static void
test_dma_map_without_fd(void **state UNUSED)
{
    dma_controller_t dma = { 0 };
    vfu_ctx_t vfu_ctx = { .dma = &dma };
    dma.vfu_ctx = &vfu_ctx;
    size_t size = sizeof(struct vfio_user_dma_region);

    struct vfio_user_dma_region r = {
        .addr = 0xdeadbeef,
        .size = 0xcafebabe,
        .offset = 0x8badf00d,
        .prot = PROT_NONE
    };
    int fd;

    patch("dma_controller_add_region");
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 0);
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r.addr);
    expect_value(dma_controller_add_region, size, r.size);
    expect_value(dma_controller_add_region, fd, -1);
    expect_value(dma_controller_add_region, offset, r.offset);
    expect_value(dma_controller_add_region, prot, r.prot);
    assert_int_equal(0, handle_dma_map_or_unmap(&vfu_ctx, size, true, &fd, 0, &r));
}

static int
check_dma_info(const LargestIntegralType value,
               const LargestIntegralType cvalue)
{
    vfu_dma_info_t *info = (vfu_dma_info_t *)value;
    vfu_dma_info_t *cinfo = (vfu_dma_info_t *)cvalue;

    return info->iova.iov_base == cinfo->iova.iov_base &&
        info->iova.iov_len == cinfo->iova.iov_len &&
        info->vaddr == cinfo->vaddr &&
        info->mapping.iov_base == cinfo->mapping.iov_base &&
        info->mapping.iov_len == cinfo->mapping.iov_len &&
        info->page_size == cinfo->page_size &&
        info->prot == cinfo->prot;
}

/*
 * Tests that adding multiple DMA regions that not all of them are mappable
 * results in only the mappable one being memory mapped.
 * FIXME this test no longer tests what it's supposed to be testing, since
 * checking that a non-mappable DMA region doesn't get mmap'ed can only be done
 * in dma_controller_add_region. We don't have such a test (we only have
 * test_dma_controller_add_region_no_fd), we should add it.
 */
static void
test_dma_add_regions_mixed(void **state UNUSED)
{
    dma_controller_t *dma = alloca(sizeof(*dma) + sizeof(dma_memory_region_t) * 2);
    size_t count = 0;
    vfu_ctx_t vfu_ctx = { .dma = dma , .dma_register = mock_dma_register,
                          .pvt = &count };
    dma->vfu_ctx = &vfu_ctx;
    struct vfio_user_dma_region r[2] = {
        [0] = {
            .addr = 0xdeadbeef,
            .size = 0x1000,
            .offset = 0,
            .prot = PROT_NONE
        },
        [1] = {
            .addr = 0xcafebabe,
            .size = 0x1000,
            .offset = 0x1000,
            .flags = VFIO_USER_F_DMA_REGION_MAPPABLE,
            .prot = PROT_READ | PROT_WRITE
        }
    };
    int fd = 0x0badf00d;

    memset(dma, 0, sizeof(*dma) + sizeof(dma_memory_region_t) * 2);
    dma->nregions = 2;
    dma->regions[0].info.mapping.iov_base = (void *)0x123456789;
    dma->regions[0].info.prot = r[0].prot;
    dma->regions[1].info.mapping.iov_base = (void *)0x987654321;
    dma->regions[1].info.vaddr = (void *)0x987654321;
    dma->regions[1].info.prot = r[1].prot;

    patch("dma_controller_add_region");
    /* 1st region */
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 0);
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[0].addr);
    expect_value(dma_controller_add_region, size, r[0].size);
    expect_value(dma_controller_add_region, fd, -1);
    expect_value(dma_controller_add_region, offset, r[0].offset);
    expect_value(dma_controller_add_region, prot, r[0].prot);
    expect_value(mock_dma_register, vfu_ctx, &vfu_ctx);
    expect_check(mock_dma_register, info, check_dma_info,
                 &dma->regions[0].info);
    /* 2nd region */
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 1);
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(dma_controller_add_region, size, r[1].size);
    expect_value(dma_controller_add_region, fd, fd);
    expect_value(dma_controller_add_region, offset, r[1].offset);
    expect_value(dma_controller_add_region, prot, r[1].prot);
    expect_value(mock_dma_register, vfu_ctx, &vfu_ctx);
    expect_check(mock_dma_register, info, check_dma_info,
                 &dma->regions[1].info);

    assert_int_equal(0, handle_dma_map_or_unmap(&vfu_ctx, sizeof(r), true, &fd, 1, r));
}

/*
 * Tests that handle_dma_map_or_unmap closes unconsumed file descriptors when
 * failing halfway through.
 */
static void
test_dma_add_regions_mixed_partial_failure(void **state UNUSED)
{
    dma_controller_t dma = { 0 };
    vfu_ctx_t vfu_ctx = { .dma = &dma };
    dma.vfu_ctx = &vfu_ctx;
    struct vfio_user_dma_region r[3] = {
        [0] = {
            .addr = 0xdeadbeef,
            .size = 0x1000,
            .offset = 0
        },
        [1] = {
            .addr = 0xcafebabe,
            .size = 0x1000,
            .offset = 0x1000,
            .flags = VFIO_USER_F_DMA_REGION_MAPPABLE,
            .prot = PROT_READ
        },
        [2] = {
            .addr = 0xbabecafe,
            .size = 0x1000,
            .offset = 0x2000,
            .flags = VFIO_USER_F_DMA_REGION_MAPPABLE,
            .prot = PROT_READ|PROT_WRITE
        }
    };
    int fds[] = {0xa, 0xb};

    patch("dma_controller_add_region");

    /* 1st region */
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[0].addr);
    expect_value(dma_controller_add_region, size, r[0].size);
    expect_value(dma_controller_add_region, fd, -1);
    expect_value(dma_controller_add_region, offset, r[0].offset);
    expect_value(dma_controller_add_region, prot, r[0].prot);
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 0);

    /* 2nd region */
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(dma_controller_add_region, size, r[1].size);
    expect_value(dma_controller_add_region, fd, fds[0]);
    expect_value(dma_controller_add_region, offset, r[1].offset);
    expect_value(dma_controller_add_region, prot, r[1].prot);
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 0);

    /* 3rd region */
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[2].addr);
    expect_value(dma_controller_add_region, size, r[2].size);
    expect_value(dma_controller_add_region, fd, fds[1]);
    expect_value(dma_controller_add_region, offset, r[2].offset);
    expect_value(dma_controller_add_region, prot, r[2].prot);
    will_return(dma_controller_add_region, EREMOTEIO);
    will_return(dma_controller_add_region, -1);

    patch("close");
    expect_value(close, fd, 0xb);
    will_return(close, 0);

    assert_int_equal(-1,
                     handle_dma_map_or_unmap(&vfu_ctx,
                                             ARRAY_SIZE(r) * sizeof(struct vfio_user_dma_region),
                                             true, fds, 2, r));
    assert_int_equal(EREMOTEIO, errno);
}

/*
 * Checks that handle_dma_map_or_unmap returns 0 when dma_controller_add_region
 * succeeds.
 */
static void
test_dma_map_return_value(void **state UNUSED)
{
    dma_controller_t dma = { 0 };
    vfu_ctx_t vfu_ctx = { .dma = &dma };
    dma.vfu_ctx = &vfu_ctx;
    struct vfio_user_dma_region r = { 0 };
    int fd = 0;

    patch("dma_controller_add_region");
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r.addr);
    expect_value(dma_controller_add_region, size, r.size);
    expect_value(dma_controller_add_region, fd, -1);
    expect_value(dma_controller_add_region, offset, r.offset);
    expect_value(dma_controller_add_region, prot, r.prot);
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 2);

    assert_int_equal(0,
        handle_dma_map_or_unmap(&vfu_ctx, sizeof(struct vfio_user_dma_region),
            true, &fd, 0, &r));
}

/*
 * Tests that handle_dma_map_or_unmap correctly removes a region.
 */
static void
test_handle_dma_unmap(void **state UNUSED)
{
    size_t size = sizeof(dma_controller_t) * sizeof(dma_memory_region_t) * 3;
    dma_controller_t *d = alloca(size);
    vfu_ctx_t v = {
        .dma = d,
    };
    struct vfio_user_dma_region r = {
        .addr = 0x1000, .size = 0x1000
    };
    int ret;

    memset(d, 0, size);

    d->nregions = 3;
    d->regions[0].info.iova.iov_base = (void *)0x1000;
    d->regions[0].info.iova.iov_len = 0x1000;
    d->regions[0].fd = -1;
    d->regions[1].info.iova.iov_base = (void *)0x4000;
    d->regions[1].info.iova.iov_len = 0x2000;
    d->regions[1].fd = -1;
    d->regions[2].info.iova.iov_base = (void *)0x8000;
    d->regions[2].info.iova.iov_len = 0x3000;
    d->regions[2].fd = -1;

    v.dma_unregister = mock_dma_unregister;

    expect_value(mock_dma_unregister, vfu_ctx, &v);
    expect_check(mock_dma_unregister, info, check_dma_info,
                 &d->regions[0].info);
    will_return(mock_dma_unregister, 0);

    ret = handle_dma_map_or_unmap(&v, sizeof(r), false, NULL, 0, &r);

    assert_int_equal(0, ret);
    assert_int_equal(2, d->nregions);
    assert_int_equal(0x4000, d->regions[0].info.iova.iov_base);
    assert_int_equal(0x2000, d->regions[0].info.iova.iov_len);
    assert_int_equal(0x8000, d->regions[1].info.iova.iov_base);
    assert_int_equal(0x3000, d->regions[1].info.iova.iov_len);
}

static void
test_dma_controller_add_region_no_fd(void **state UNUSED)
{
    vfu_ctx_t vfu_ctx = { 0 };
    dma_controller_t *dma = alloca(sizeof(*dma) + sizeof(dma_memory_region_t));
    void *dma_addr = (void *)0xdeadbeef;
    size_t size = 0;
    int fd = -1;
    off_t offset = 0;
    dma_memory_region_t *r;

    memset(dma, 0, sizeof(*dma) + sizeof(dma_memory_region_t));

    dma->vfu_ctx = &vfu_ctx;
    dma->max_regions = 1;

    assert_int_equal(0,
                     dma_controller_add_region(dma, dma_addr, size, fd,
                        offset, PROT_NONE));

    assert_int_equal(1, dma->nregions);
    r = &dma->regions[0];
    assert_ptr_equal(NULL, r->info.vaddr);
    assert_ptr_equal(NULL, r->info.mapping.iov_base);
    assert_int_equal(0, r->info.mapping.iov_len);
    assert_ptr_equal(dma_addr, r->info.iova.iov_base);
    assert_int_equal(size, r->info.iova.iov_len);
    assert_int_equal(0x1000, r->info.page_size);
    assert_int_equal(offset, r->offset);
    assert_int_equal(fd, r->fd);
    assert_int_equal(0, r->refcnt);
    assert_int_equal(PROT_NONE, r->info.prot);
}

static void
test_dma_controller_remove_region_mapped(void **state UNUSED)
{
    vfu_ctx_t v = { 0 };
    size_t size = sizeof(dma_controller_t) + sizeof(dma_memory_region_t);
    dma_controller_t *d = alloca(size);
    memset(d, 0, size);

    d->vfu_ctx = &v;
    d->max_regions = d->nregions = 1;
    d->regions[0].info.iova.iov_base = (void *)0xdeadbeef;
    d->regions[0].info.iova.iov_len = 0x100;
    d->regions[0].info.mapping.iov_base = (void *)0xcafebabe;
    d->regions[0].info.mapping.iov_len = 0x1000;
    d->regions[0].info.vaddr = (void *)0xcafebabe;
    expect_value(mock_dma_unregister, vfu_ctx, &v);
    expect_check(mock_dma_unregister, info, check_dma_info,
                 &d->regions[0].info);
    /* FIXME add unit test when dma_unregister fails */
    will_return(mock_dma_unregister, 0);
    patch("dma_controller_unmap_region");
    expect_value(dma_controller_unmap_region, dma, d);
    expect_value(dma_controller_unmap_region, region, &d->regions[0]);
    assert_int_equal(0,
        dma_controller_remove_region(d, (void *)0xdeadbeef, 0x100,
            mock_dma_unregister, &v));
}

static void
test_dma_controller_remove_region_unmapped(void **state UNUSED)
{
    vfu_ctx_t v = { 0 };
    size_t size = sizeof(dma_controller_t) + sizeof(dma_memory_region_t);
    dma_controller_t *d = alloca(size);
    memset(d, 0, size);

    d->vfu_ctx = &v;
    d->max_regions = d->nregions = 1;
    d->regions[0].info.iova.iov_base = (void *)0xdeadbeef;
    d->regions[0].info.iova.iov_len = 0x100;
    d->regions[0].fd = -1;
    expect_value(mock_dma_unregister, vfu_ctx, &v);
    expect_check(mock_dma_unregister, info, check_dma_info,
                 &d->regions[0].info);
    will_return(mock_dma_unregister, 0);
    patch("dma_controller_unmap_region");
    assert_int_equal(0,
        dma_controller_remove_region(d, (void *)0xdeadbeef, 0x100,
            mock_dma_unregister, &v));
}

static int fds[] = { 0xab, 0xcd };

static int
set_fds(const long unsigned int value, const long unsigned int data)
{
    assert(value != 0);
    if ((void*)data == &get_next_command) {
        memcpy((int*)value, fds, ARRAY_SIZE(fds) * sizeof(int));
    } else if ((void*)data == &exec_command) {
        ((int*)value)[0] = -1;
    }
    return 1;
}

static int
set_nr_fds(const long unsigned int value,
           const long unsigned int data UNUSED)
{
    int *nr_fds = (int*)value;
    assert(nr_fds != NULL);
    *nr_fds = ARRAY_SIZE(fds);
    return 1;
}

typedef struct {
    int fd;
    int conn_fd;
} tran_sock_t;

/*
 * Tests that if if exec_command fails then process_request frees passed file
 * descriptors.
 */
static void
test_process_command_free_passed_fds(void **state UNUSED)
{
    tran_sock_t ts = { .fd = 23, .conn_fd = 24 };
    vfu_ctx_t vfu_ctx = {
        .client_max_fds = ARRAY_SIZE(fds),
        .migration = (struct migration *)0x8badf00d,
        .tran = &tran_sock_ops,
        .tran_data = &ts
    };

    patch("get_next_command");
    expect_value(get_next_command, vfu_ctx, &vfu_ctx);
    expect_any(get_next_command, hdr);
    expect_check(get_next_command, fds, &set_fds, &get_next_command);
    expect_check(get_next_command, nr_fds, &set_nr_fds, NULL);
    will_return(get_next_command, 0x0000beef);

    patch("exec_command");
    expect_value(exec_command, vfu_ctx, &vfu_ctx);
    expect_any(exec_command, hdr);
    expect_value(exec_command, size, 0x0000beef);
    expect_check(exec_command, fds, &set_fds, &exec_command);
    expect_any(exec_command, nr_fds);
    expect_any(exec_command, fds_out);
    expect_any(exec_command, nr_fds_out);
    expect_any(exec_command, _iovecs);
    expect_any(exec_command, iovecs);
    expect_any(exec_command, nr_iovecs);
    expect_any(exec_command, free_iovec_data);
    will_return(exec_command, -0x1234);

    patch("close");
    expect_value(close, fd, 0xcd);
    will_return(close, 0);

    patch("tran_sock_send_iovec");
    expect_value(tran_sock_send_iovec, sock, ts.conn_fd);
    expect_any(tran_sock_send_iovec, msg_id);
    expect_value(tran_sock_send_iovec, is_reply, true);
    expect_any(tran_sock_send_iovec, cmd);
    expect_any(tran_sock_send_iovec, iovecs);
    expect_any(tran_sock_send_iovec, nr_iovecs);
    expect_any(tran_sock_send_iovec, fds);
    expect_any(tran_sock_send_iovec, count);
    expect_any(tran_sock_send_iovec, err);
    will_return(tran_sock_send_iovec, 0);

    assert_int_equal(0, process_request(&vfu_ctx));
}

static void
test_realize_ctx(void **state UNUSED)
{
    vfu_reg_info_t *cfg_reg;
    vfu_reg_info_t reg_info[VFU_PCI_DEV_NUM_REGIONS + 1] = { { 0 } };
    vfu_ctx_t vfu_ctx = {
        .reg_info = reg_info,
        .nr_regions = VFU_PCI_DEV_NUM_REGIONS + 1
    };

    assert_int_equal(0, vfu_realize_ctx(&vfu_ctx));
    assert_true(vfu_ctx.realized);
    cfg_reg = &vfu_ctx.reg_info[VFU_PCI_DEV_CFG_REGION_IDX];
    assert_int_equal(VFU_REGION_FLAG_RW, cfg_reg->flags);
    assert_int_equal(PCI_CFG_SPACE_SIZE, cfg_reg->size);
    assert_non_null(vfu_ctx.pci.config_space);
    assert_non_null(vfu_ctx.irqs);
    assert_int_equal(0, vfu_ctx.pci.nr_caps);
    assert_int_equal(0, vfu_ctx.pci.nr_ext_caps);

    free(vfu_ctx.irqs);
    free(vfu_ctx.pci.config_space);
}

static int
dummy_attach(vfu_ctx_t *vfu_ctx)
{
    assert(vfu_ctx != NULL);

    return 0;
}

static void
test_attach_ctx(void **state UNUSED)
{
    struct transport_ops transport_ops = {
        .attach = &dummy_attach,
    };
    vfu_ctx_t vfu_ctx = {
        .tran = &transport_ops,
    };

    assert_int_equal(0, vfu_attach_ctx(&vfu_ctx));
}

static void
test_run_ctx(UNUSED void **state)
{
    vfu_ctx_t vfu_ctx = {
        .realized = false,
    };

    // device un-realized
    assert_int_equal(-1, vfu_run_ctx(&vfu_ctx));

    // device realized, with NB vfu_ctx
    vfu_ctx.realized = true;
    vfu_ctx.flags = LIBVFIO_USER_FLAG_ATTACH_NB;

    patch("process_request");
    expect_value(process_request, vfu_ctx, &vfu_ctx);
    will_return(process_request, 0);
    assert_int_equal(0, vfu_run_ctx(&vfu_ctx));

    // device realized, with blocking vfu_ctx
    vfu_ctx.flags = 0;
    expect_value(process_request, vfu_ctx, &vfu_ctx);
    will_return(process_request, 0);

    expect_value(process_request, vfu_ctx, &vfu_ctx);
    will_return(process_request, -1);
    assert_int_equal(-1, vfu_run_ctx(&vfu_ctx));
}

static void
test_get_region_info(UNUSED void **state)
{
    struct iovec iov = { .iov_base = (void*)0x8badf00, .iov_len = 0x0d15ea5e };
    vfu_reg_info_t reg_info[VFU_PCI_DEV_NUM_REGIONS] = {
        {
            .size = 0xcadebabe
        },
        {
            .flags = VFU_REGION_FLAG_RW,
            .size = 0xdeadbeef,
            .fd = 0x12345
        },
        [VFU_PCI_DEV_MIGR_REGION_IDX] = {
            .flags = VFU_REGION_FLAG_RW,
            .size = 0x1000,
            .fd = -1
        }
    };
    vfu_ctx_t vfu_ctx = {
        .client_max_fds = 1,
        .nr_regions = ARRAY_SIZE(reg_info),
        .reg_info = reg_info,
    };
    uint32_t index = 0;
    uint32_t argsz = 0;
    struct vfio_region_info *vfio_reg;
    int *fds = NULL;
    size_t nr_fds;

    /* bad argsz */
    assert_int_equal(-1,
                     dev_get_reginfo(&vfu_ctx, index, argsz, &vfio_reg,
                                     &fds, &nr_fds));
    assert_int_equal(EINVAL, errno);

    /* bad region */
    index = vfu_ctx.nr_regions;
    argsz = sizeof(struct vfio_region_info);
    assert_int_equal(-1,
                     dev_get_reginfo(&vfu_ctx, index, argsz, &vfio_reg,
                                     &fds, &nr_fds));
    assert_int_equal(EINVAL, errno);

    /* no region caps */
    index = 1;
    assert_int_equal(0,
                     dev_get_reginfo(&vfu_ctx, index, argsz, &vfio_reg,
                                     &fds, &nr_fds));
    assert_int_equal(sizeof(struct vfio_region_info), vfio_reg->argsz);
    assert_int_equal(VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE |
                     VFIO_REGION_INFO_FLAG_MMAP, vfio_reg->flags);
    assert_int_equal(1, vfio_reg->index);
    assert_int_equal(0x10000000000, vfio_reg->offset);
    assert_int_equal(0xdeadbeef, vfio_reg->size);
    assert_int_equal(0, nr_fds);

    free(vfio_reg);

    /* regions caps (sparse mmap) but argsz too small */
    vfu_ctx.reg_info[1].mmap_areas = &iov;
    vfu_ctx.reg_info[1].nr_mmap_areas = 1;

    assert_int_equal(0,
                     dev_get_reginfo(&vfu_ctx, index, argsz, &vfio_reg,
                                     &fds, &nr_fds));
    assert_int_equal(argsz + sizeof(struct vfio_region_info_cap_sparse_mmap) + sizeof(struct vfio_region_sparse_mmap_area),
                     vfio_reg->argsz);
    assert_int_equal(VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE |
                     VFIO_REGION_INFO_FLAG_MMAP | VFIO_REGION_INFO_FLAG_CAPS,
                     vfio_reg->flags);
    assert_int_equal(0, nr_fds);

    free(vfio_reg);

    /* region caps and argsz large enough */
    argsz += sizeof(struct vfio_region_info_cap_sparse_mmap) + sizeof(struct vfio_region_sparse_mmap_area);
    assert_int_equal(0,
                     dev_get_reginfo(&vfu_ctx, index, argsz, &vfio_reg,
                                     &fds, &nr_fds));
    struct vfio_region_info_cap_sparse_mmap *sparse = (struct vfio_region_info_cap_sparse_mmap*)(vfio_reg + 1);
    assert_int_equal(VFIO_REGION_INFO_CAP_SPARSE_MMAP, sparse->header.id);
    assert_int_equal(1, sparse->header.version);
    assert_int_equal(0, sparse->header.next);
    assert_int_equal(1, sparse->nr_areas);
    assert_non_null(fds);
    assert_int_equal(1, nr_fds);
    assert_int_equal(0x12345, fds[0]);

    free(vfio_reg);
    free(fds);

    /* migration cap */
    fds = NULL;
    vfu_ctx.reg_info[1].mmap_areas = NULL;
    vfu_ctx.reg_info[1].nr_mmap_areas = 0;
    argsz = sizeof(struct vfio_region_info) + sizeof(struct vfio_region_info_cap_type);
    assert_int_equal(0,
                     dev_get_reginfo(&vfu_ctx, VFU_PCI_DEV_MIGR_REGION_IDX,
                                     argsz, &vfio_reg, &fds, &nr_fds));
    assert_int_equal(VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE |
                     VFIO_REGION_INFO_FLAG_CAPS,
                     vfio_reg->flags);
    struct vfio_region_info_cap_type *type = (struct vfio_region_info_cap_type*)(vfio_reg + 1);
    assert_int_equal(VFIO_REGION_INFO_CAP_TYPE, type->header.id);
    assert_int_equal(VFIO_REGION_TYPE_MIGRATION , type->type);
    assert_int_equal(VFIO_REGION_SUBTYPE_MIGRATION, type->subtype);
    assert_null(fds);
    assert_int_equal(0, nr_fds);
    free(vfio_reg);

    /* FIXME add check  for multiple sparse areas */
}

static void
test_vfu_ctx_create(void **state UNUSED)
{
    vfu_ctx_t *vfu_ctx = NULL;
    struct pmcap pm = { { 0 } };

    pm.hdr.id = PCI_CAP_ID_PM;
    pm.pmcs.nsfrst = 0x1;

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK + 1, "", 0, NULL, VFU_DEV_TYPE_PCI);
    assert_null(vfu_ctx);
    assert_int_equal(ENOTSUP, errno);

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, "", 0, NULL, VFU_DEV_TYPE_PCI + 4);
    assert_null(vfu_ctx);
    assert_int_equal(ENOTSUP, errno);

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, "", 999, NULL, VFU_DEV_TYPE_PCI);
    assert_null(vfu_ctx);
    assert_int_equal(EINVAL, errno);

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, "", LIBVFIO_USER_FLAG_ATTACH_NB,
                             NULL, VFU_DEV_TYPE_PCI);
    assert_non_null(vfu_ctx);

    assert_int_equal(1, vfu_ctx->irq_count[VFU_DEV_ERR_IRQ]);
    assert_int_equal(1, vfu_ctx->irq_count[VFU_DEV_REQ_IRQ]);
    assert_int_equal(0, vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_CONVENTIONAL,
                        PCI_HEADER_TYPE_NORMAL, 0));
    assert_int_equal(PCI_STD_HEADER_SIZEOF,
                     vfu_pci_add_capability(vfu_ctx, 0, 0, &pm));
    assert_int_equal(0, vfu_realize_ctx(vfu_ctx));

    patch("close");
    expect_value(close, fd, ((tran_sock_t *)vfu_ctx->tran_data)->fd);
    will_return(close, 0);

    vfu_destroy_ctx(vfu_ctx);

    /* Test "bare" vfu_create_ctx(). */
    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, "", LIBVFIO_USER_FLAG_ATTACH_NB,
                             NULL, VFU_DEV_TYPE_PCI);
    assert_non_null(vfu_ctx);

    assert_int_equal(0, vfu_realize_ctx(vfu_ctx));

    expect_value(close, fd, ((tran_sock_t *)vfu_ctx->tran_data)->fd);
    will_return(close, 0);

    vfu_destroy_ctx(vfu_ctx);
}

bool pci_caps_writing = true;

static ssize_t
test_pci_caps_region_cb(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                        loff_t offset, bool is_write)
{
    uint8_t *ptr = pci_config_space_ptr(vfu_ctx, offset);

    if (!pci_caps_writing) {
        assert_int_equal(is_write, false);
        memcpy(buf, ptr, count);
        return count;
    }

    assert_int_equal(is_write, true);
    assert_int_equal(offset, PCI_STD_HEADER_SIZEOF + PCI_PM_SIZEOF + 8 +
                             offsetof(struct vsc, data));
    assert_int_equal(count, 10);
    assert_memory_equal(ptr, "Hello world.", 10);
    memcpy(ptr, buf, count);
    return count;
}

static void
test_pci_caps(void **state UNUSED)
{
    vfu_pci_config_space_t config_space;
    vfu_reg_info_t reg_info[VFU_PCI_DEV_NUM_REGIONS] = {
        [VFU_PCI_DEV_CFG_REGION_IDX] = { .size = PCI_CFG_SPACE_SIZE },
    };
    vfu_ctx_t vfu_ctx = { .pci.config_space = &config_space,
                          .reg_info = reg_info,
    };
    struct vsc *vsc1 = alloca(sizeof(*vsc1) + 3);
    struct vsc *vsc2 = alloca(sizeof(*vsc2) + 13);
    struct vsc *vsc3 = alloca(sizeof(*vsc3) + 13);
    struct vsc *vsc4 = alloca(sizeof(*vsc4) + 13);
    struct pmcap pm = { { 0 } };
    size_t expoffsets[] = {
        PCI_STD_HEADER_SIZEOF,
        PCI_STD_HEADER_SIZEOF + PCI_PM_SIZEOF,
        /* NB: note 4-byte alignment of vsc2. */
        PCI_STD_HEADER_SIZEOF + PCI_PM_SIZEOF + 8,
        0x80,
        0x90
    };
    size_t offset;
    ssize_t ret;
    char buf[256];

    memset(&config_space, 0, sizeof(config_space));

    vfu_ctx.reg_info = calloc(VFU_PCI_DEV_NUM_REGIONS,
                              sizeof(*vfu_ctx.reg_info));

    pm.hdr.id = PCI_CAP_ID_PM;
    pm.pmcs.raw = 0xef01;

    vsc1->hdr.id = PCI_CAP_ID_VNDR;
    vsc1->size = 6;
    memcpy(vsc1->data, "abc", 3);

    vsc2->hdr.id = PCI_CAP_ID_VNDR;
    vsc2->size = 16;
    memcpy(vsc2->data, "Hello world.", 13);

    vsc3->hdr.id = PCI_CAP_ID_VNDR;
    vsc3->size = 16;
    memcpy(vsc3->data, "Hello world.", 13);

    vsc4->hdr.id = PCI_CAP_ID_VNDR;
    vsc4->size = 16;
    memcpy(vsc4->data, "Hello world.", 13);

    offset = vfu_pci_add_capability(&vfu_ctx, 0, VFU_CAP_FLAG_CALLBACK, &pm);
    assert_int_equal(-1, offset);
    assert_int_equal(EINVAL, errno);

    offset = vfu_pci_add_capability(&vfu_ctx, 256, 0, &pm);
    assert_int_equal(-1, offset);
    assert_int_equal(EINVAL, errno);

    vfu_ctx.reg_info[VFU_PCI_DEV_CFG_REGION_IDX].cb = test_pci_caps_region_cb;
    vfu_ctx.reg_info[VFU_PCI_DEV_CFG_REGION_IDX].size = PCI_CFG_SPACE_SIZE;

    offset = vfu_pci_add_capability(&vfu_ctx, 0, 0, &pm);
    assert_int_equal(expoffsets[0], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, 0, VFU_CAP_FLAG_READONLY, vsc1);
    assert_int_equal(expoffsets[1], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, 0, VFU_CAP_FLAG_CALLBACK, vsc2);
    assert_int_equal(expoffsets[2], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, expoffsets[3], 0, vsc3);
    assert_int_equal(expoffsets[3], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, expoffsets[4], 0, vsc4);
    assert_int_equal(expoffsets[4], offset);

    offset = vfu_pci_find_capability(&vfu_ctx, false, PCI_CAP_ID_PM);
    assert_int_equal(expoffsets[0], offset);
    assert_int_equal(PCI_CAP_ID_PM, config_space.raw[offset]);
    assert_int_equal(expoffsets[1],
                     config_space.raw[offset + PCI_CAP_LIST_NEXT]);

    offset = vfu_pci_find_next_capability(&vfu_ctx, false, offset,
                                          PCI_CAP_ID_PM);
    assert_int_equal(0, offset);

    offset = vfu_pci_find_capability(&vfu_ctx, false, PCI_CAP_ID_VNDR);
    assert_int_equal(expoffsets[1], offset);
    assert_int_equal(PCI_CAP_ID_VNDR, config_space.raw[offset]);
    assert_int_equal(expoffsets[2],
                     config_space.raw[offset + PCI_CAP_LIST_NEXT]);

    offset = vfu_pci_find_next_capability(&vfu_ctx, false, offset,
                                          PCI_CAP_ID_PM);
    assert_int_equal(0, offset);

    offset = vfu_pci_find_next_capability(&vfu_ctx, false, 0, PCI_CAP_ID_VNDR);
    assert_int_equal(expoffsets[1], offset);
    assert_int_equal(PCI_CAP_ID_VNDR, config_space.raw[offset]);
    assert_int_equal(expoffsets[2],
                     config_space.raw[offset + PCI_CAP_LIST_NEXT]);

    offset = vfu_pci_find_next_capability(&vfu_ctx, false,
                                          offset, PCI_CAP_ID_VNDR);
    assert_int_equal(expoffsets[2], offset);
    assert_int_equal(PCI_CAP_ID_VNDR, config_space.raw[offset]);
    assert_int_equal(expoffsets[3],
                     config_space.raw[offset + PCI_CAP_LIST_NEXT]);

    offset = vfu_pci_find_next_capability(&vfu_ctx, false,
                                          offset, PCI_CAP_ID_VNDR);
    assert_int_equal(expoffsets[3], offset);
    offset = vfu_pci_find_next_capability(&vfu_ctx, false,
                                          offset, PCI_CAP_ID_VNDR);
    assert_int_equal(expoffsets[4], offset);
    offset = vfu_pci_find_next_capability(&vfu_ctx, false,
                                          offset, PCI_CAP_ID_VNDR);
    assert_int_equal(0, offset);

    /* check for invalid offsets */

    offset = vfu_pci_find_next_capability(&vfu_ctx, false, 8192, PCI_CAP_ID_PM);
    assert_int_equal(0, offset);
    assert_int_equal(EINVAL, errno);
    offset = vfu_pci_find_next_capability(&vfu_ctx, false, 256, PCI_CAP_ID_PM);
    assert_int_equal(0, offset);
    assert_int_equal(EINVAL, errno);
    offset = vfu_pci_find_next_capability(&vfu_ctx, false, 255, PCI_CAP_ID_PM);
    assert_int_equal(0, offset);
    assert_int_equal(EINVAL, errno);

    offset = vfu_pci_find_next_capability(&vfu_ctx, false,
                                          PCI_STD_HEADER_SIZEOF +
                                          PCI_PM_SIZEOF + 1,
                                          PCI_CAP_ID_VNDR);
    assert_int_equal(0, offset);
    assert_int_equal(ENOENT, errno);

    /* check writing PMCS */

    pm.pmcs.raw = 0xffff;

    ret = pci_config_space_access(&vfu_ctx, (char *)&pm.pmcs,
                                  sizeof(struct pmcs), expoffsets[0] +
                                  offsetof(struct pmcap, pmcs), true);

    assert_int_equal(sizeof(struct pmcs), ret);

    assert_memory_equal(pci_config_space_ptr(&vfu_ctx, expoffsets[0] +
                                             offsetof(struct pmcap, pmcs)),
                        &pm.pmcs, sizeof(struct pmcs));

    /* check read only capability */

    ret = pci_config_space_access(&vfu_ctx, (char *)vsc1->data, 3,
                                  expoffsets[1] + offsetof(struct vsc, data),
                                  false);
    assert_int_equal(ret, 3);
    assert_memory_equal(vsc1->data, "abc", 3);

    ret = pci_config_space_access(&vfu_ctx, "ced", 3,
                                  expoffsets[1] + offsetof(struct vsc, data),
                                  true);
    assert_int_equal(-1, ret);
    assert_int_equal(EPERM, errno);

    /* check capability callback */

    ret = pci_config_space_access(&vfu_ctx, "Bye world.", 10,
                                  expoffsets[2] + offsetof(struct vsc, data),
                                  true);

    assert_int_equal(ret, 10);
    assert_memory_equal(pci_config_space_ptr(&vfu_ctx,
                        expoffsets[2] + offsetof(struct vsc, data)),
                        "Bye world.", 10);

    /* check straddling read */

    pci_caps_writing = false;

    ret = pci_config_space_access(&vfu_ctx, buf, sizeof (buf), 0, false);

    assert_int_equal(ret, sizeof (buf));
    assert_memory_equal(pci_config_space_ptr(&vfu_ctx, 0), buf, sizeof (buf));

    free(vfu_ctx.reg_info);
}

static bool pci_ext_caps_writing = true;

static ssize_t
test_pci_ext_caps_region_cb(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                            loff_t offset, bool is_write)
{
    uint8_t *ptr = pci_config_space_ptr(vfu_ctx, offset);

    if (!pci_ext_caps_writing) {
        assert_int_equal(is_write, false);
        memcpy(buf, ptr, count);
        return count;
    }

    assert_int_equal(is_write, true);
    assert_int_equal(offset, PCI_CFG_SPACE_SIZE + sizeof(struct dsncap) +
                     sizeof(struct pcie_ext_cap_vsc_hdr) + 8 +
                     sizeof(struct pcie_ext_cap_vsc_hdr));
    assert_int_equal(count, 10);
    assert_memory_equal(ptr, "Hello world.", 10);
    memcpy(ptr, buf, count);
    return count;
}

static void
test_pci_ext_caps(void **state UNUSED)
{
    uint8_t config_space[PCI_CFG_SPACE_EXP_SIZE] = { 0, };
    vfu_reg_info_t reg_info[VFU_PCI_DEV_NUM_REGIONS] = {
        [VFU_PCI_DEV_CFG_REGION_IDX] = { .size = PCI_CFG_SPACE_EXP_SIZE },
    };
    vfu_ctx_t vfu_ctx = { .pci.config_space = (void *)&config_space,
                          .reg_info = reg_info,
    };

    struct pcie_ext_cap_hdr *hdr;
    size_t explens[] = {
        sizeof(struct pcie_ext_cap_vsc_hdr) + 5,
        sizeof(struct pcie_ext_cap_vsc_hdr) + 13,
        sizeof(struct pcie_ext_cap_vsc_hdr) + 13,
        sizeof(struct pcie_ext_cap_vsc_hdr) + 13,
    };
    struct pcie_ext_cap_vsc_hdr *vsc1 = alloca(explens[0]);
    struct pcie_ext_cap_vsc_hdr *vsc2 = alloca(explens[1]);
    struct pcie_ext_cap_vsc_hdr *vsc3 = alloca(explens[2]);
    struct pcie_ext_cap_vsc_hdr *vsc4 = alloca(explens[3]);
    size_t expoffsets[] = {
        PCI_CFG_SPACE_SIZE,
        PCI_CFG_SPACE_SIZE + sizeof(struct dsncap),
        PCI_CFG_SPACE_SIZE + sizeof(struct dsncap) + sizeof(*vsc1) + 8,
        512,
        600
    };
    struct dsncap dsn;
    size_t offset;
    ssize_t ret;
    char buf[512];

    vfu_ctx.pci.type = VFU_PCI_TYPE_EXPRESS;

    vfu_ctx.reg_info = calloc(VFU_PCI_DEV_NUM_REGIONS,
                              sizeof(*vfu_ctx.reg_info));

    vfu_ctx.reg_info[VFU_PCI_DEV_CFG_REGION_IDX].cb = test_pci_ext_caps_region_cb;
    vfu_ctx.reg_info[VFU_PCI_DEV_CFG_REGION_IDX].size = PCI_CFG_SPACE_EXP_SIZE;

    memset(&dsn, 0, sizeof (dsn));

    dsn.hdr.id = PCI_EXT_CAP_ID_DSN;
    dsn.sn_lo = 0x4;
    dsn.sn_hi = 0x8;

    memset(vsc1, 0, explens[0]);
    vsc1->len = explens[0];
    vsc1->hdr.id = PCI_EXT_CAP_ID_VNDR;
    memcpy(vsc1->data, "abcde", 5);

    memset(vsc2, 0, explens[1]);
    vsc2->len = explens[1];
    vsc2->hdr.id = PCI_EXT_CAP_ID_VNDR;
    memcpy(vsc2->data, "Hello world.", 13);

    memset(vsc3, 0, explens[2]);
    vsc3->len = explens[2];
    vsc3->hdr.id = PCI_EXT_CAP_ID_VNDR;
    memcpy(vsc3->data, "Hello world.", 13);

    memset(vsc4, 0, explens[3]);
    vsc4->len = explens[3];
    vsc4->hdr.id = PCI_EXT_CAP_ID_VNDR;
    memcpy(vsc4->data, "Hello world.", 13);

    offset = vfu_pci_add_capability(&vfu_ctx, 4096, VFU_CAP_FLAG_EXTENDED, &dsn);
    assert_int_equal(-1, offset);
    assert_int_equal(EINVAL, errno);

    /* First cap must be at 256 */
    offset = vfu_pci_add_capability(&vfu_ctx, 512, VFU_CAP_FLAG_EXTENDED, &dsn);
    assert_int_equal(-1, offset);
    assert_int_equal(EINVAL, errno);

    offset = vfu_pci_add_capability(&vfu_ctx, 0, VFU_CAP_FLAG_EXTENDED, &dsn);
    assert_int_equal(expoffsets[0], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, 0, VFU_CAP_FLAG_EXTENDED |
                                    VFU_CAP_FLAG_READONLY, vsc1);
    assert_int_equal(expoffsets[1], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, 0, VFU_CAP_FLAG_EXTENDED |
                                    VFU_CAP_FLAG_CALLBACK, vsc2);
    assert_int_equal(expoffsets[2], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, expoffsets[3],
                                    VFU_CAP_FLAG_EXTENDED, vsc3);
    assert_int_equal(expoffsets[3], offset);
    offset = vfu_pci_add_capability(&vfu_ctx, expoffsets[4],
                                    VFU_CAP_FLAG_EXTENDED, vsc4);
    assert_int_equal(expoffsets[4], offset);

    offset = vfu_pci_find_capability(&vfu_ctx, true, PCI_EXT_CAP_ID_DSN);
    assert_int_equal(expoffsets[0], offset);
    hdr = (struct pcie_ext_cap_hdr *)&config_space[offset];
    assert_int_equal(PCI_EXT_CAP_ID_DSN, hdr->id);
    assert_int_equal(expoffsets[1], hdr->next);

    offset = vfu_pci_find_next_capability(&vfu_ctx, true, offset,
                                          PCI_EXT_CAP_ID_DSN);
    assert_int_equal(0, offset);

    offset = vfu_pci_find_capability(&vfu_ctx, true, PCI_EXT_CAP_ID_VNDR);
    assert_int_equal(expoffsets[1], offset);
    hdr = (struct pcie_ext_cap_hdr *)&config_space[offset];
    assert_int_equal(PCI_EXT_CAP_ID_VNDR, hdr->id);
    assert_int_equal(expoffsets[2], hdr->next);

    offset = vfu_pci_find_next_capability(&vfu_ctx, true, offset,
                                          PCI_EXT_CAP_ID_DSN);
    assert_int_equal(0, offset);

    offset = vfu_pci_find_next_capability(&vfu_ctx, true, 0, PCI_EXT_CAP_ID_VNDR);
    assert_int_equal(expoffsets[1], offset);
    hdr = (struct pcie_ext_cap_hdr *)&config_space[offset];
    assert_int_equal(PCI_EXT_CAP_ID_VNDR, hdr->id);
    assert_int_equal(expoffsets[2], hdr->next);

    offset = vfu_pci_find_next_capability(&vfu_ctx, true,
                                          offset, PCI_EXT_CAP_ID_VNDR);
    assert_int_equal(expoffsets[2], offset);
    hdr = (struct pcie_ext_cap_hdr *)&config_space[offset];
    assert_int_equal(PCI_EXT_CAP_ID_VNDR, hdr->id);
    assert_int_equal(expoffsets[3], hdr->next);

    offset = vfu_pci_find_next_capability(&vfu_ctx, true,
                                          offset, PCI_EXT_CAP_ID_VNDR);
    assert_int_equal(expoffsets[3], offset);
    offset = vfu_pci_find_next_capability(&vfu_ctx, true,
                                          offset, PCI_EXT_CAP_ID_VNDR);
    assert_int_equal(expoffsets[4], offset);
    offset = vfu_pci_find_next_capability(&vfu_ctx, true,
                                          offset, PCI_EXT_CAP_ID_VNDR);
    assert_int_equal(0, offset);

    /* check for invalid offsets */

    offset = vfu_pci_find_next_capability(&vfu_ctx, true, 8192,
                                          PCI_EXT_CAP_ID_DSN);
    assert_int_equal(0, offset);
    assert_int_equal(EINVAL, errno);
    offset = vfu_pci_find_next_capability(&vfu_ctx, true, 4096,
                                          PCI_EXT_CAP_ID_DSN);
    assert_int_equal(0, offset);
    assert_int_equal(EINVAL, errno);
    offset = vfu_pci_find_next_capability(&vfu_ctx, true, 4095,
                                          PCI_EXT_CAP_ID_DSN);
    assert_int_equal(0, offset);
    assert_int_equal(EINVAL, errno);

    offset = vfu_pci_find_next_capability(&vfu_ctx, true,
                                          expoffsets[1] + 1,
                                          PCI_EXT_CAP_ID_DSN);
    assert_int_equal(0, offset);
    assert_int_equal(ENOENT, errno);

    /* check read only capability */

    ret = pci_config_space_access(&vfu_ctx, (char *)vsc1->data, 5,
                                  expoffsets[1] + offsetof(struct pcie_ext_cap_vsc_hdr, data),
                                  false);
    assert_int_equal(ret, 5);
    assert_memory_equal(vsc1->data, "abcde", 5);

    ret = pci_config_space_access(&vfu_ctx, "ced", 3,
                                  expoffsets[1] + offsetof(struct pcie_ext_cap_vsc_hdr, data),
                                  true);
    assert_int_equal(-1, ret);
    assert_int_equal(EPERM, errno);

    /* check capability callback */

    ret = pci_config_space_access(&vfu_ctx, "Bye world.", 10,
                                  expoffsets[2] + offsetof(struct pcie_ext_cap_vsc_hdr, data),
                                  true);

    assert_int_equal(ret, 10);
    assert_memory_equal(pci_config_space_ptr(&vfu_ctx,
                        expoffsets[2] + offsetof(struct pcie_ext_cap_vsc_hdr, data)),
                        "Bye world.", 10);

    /* check straddling read */

    pci_ext_caps_writing = false;

    ret = pci_config_space_access(&vfu_ctx, buf, sizeof (buf), 0, false);

    assert_int_equal(ret, sizeof (buf));
    assert_memory_equal(pci_config_space_ptr(&vfu_ctx, 0), buf, sizeof (buf));

    free(vfu_ctx.reg_info);
}

static void
test_device_get_info(void **state UNUSED)
{
    vfu_ctx_t vfu_ctx = { .nr_regions = 0xdeadbeef };
    struct vfio_user_device_info d_in = { .argsz = sizeof(d_in) };
    struct vfio_user_device_info d_out;

    assert_int_equal(0, handle_device_get_info(&vfu_ctx, sizeof(d_in),
                                               &d_in, &d_out));
    assert_int_equal(sizeof(d_out), d_out.argsz);
    assert_int_equal(VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET,
                     d_out.flags);
    assert_int_equal(vfu_ctx.nr_regions, d_out.num_regions);
    assert_int_equal(VFU_DEV_NUM_IRQS, d_out.num_irqs);
}

/*
 * Checks that handle_device_get_info handles correctly struct
 * vfio_user_device_info with more fields.
 */
static void
test_device_get_info_compat(void **state UNUSED)
{
    vfu_ctx_t vfu_ctx = { .nr_regions = 0xdeadbeef };
    struct vfio_user_device_info d_in = { .argsz = sizeof(d_in) + 1 };
    struct vfio_user_device_info d_out;

    assert_int_equal(0, handle_device_get_info(&vfu_ctx, sizeof(d_in) + 1,
                                               &d_in, &d_out));
    assert_int_equal(sizeof(d_out), d_out.argsz);
    assert_int_equal(VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET,
                     d_out.flags);
    assert_int_equal(vfu_ctx.nr_regions, d_out.num_regions);
    assert_int_equal(VFU_DEV_NUM_IRQS, d_out.num_irqs);

    /* fewer fields */
    assert_int_equal(-1,
                     handle_device_get_info(&vfu_ctx, (sizeof(d_in)) - 1,
                                            &d_in, &d_out));
    assert_int_equal(EINVAL, errno);
}


/*
 * Performs various checks when adding sparse memory regions.
 */
static void
test_setup_sparse_region(void **state UNUSED)
{
    vfu_reg_info_t reg_info;
    vfu_ctx_t vfu_ctx = { .reg_info = &reg_info };
    struct iovec mmap_areas[2] = {
        [0] = {
            .iov_base = (void*)0x0,
            .iov_len = 0x1000
        },
        [1] = {
            .iov_base = (void*)0x1000,
            .iov_len = 0x1000
        }
    };
    int ret;

    /* invalid mappable settings */
    ret = vfu_setup_region(&vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX,
                           0x2000, NULL, 0, mmap_areas, 2, -1);
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    ret = vfu_setup_region(&vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX,
                           0x2000, NULL, 0, mmap_areas, 0, 1);
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* default mmap area if not given */
    ret = vfu_setup_region(&vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX,
                           0x2000, NULL, 0, NULL, 0, 1);
    assert_int_equal(0, ret);

    free(reg_info.mmap_areas);

    /* sparse region exceeds region size */
    mmap_areas[1].iov_len = 0x1001;
    ret = vfu_setup_region(&vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX,
                            0x2000, NULL, 0, mmap_areas, 2, 0);
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* sparse region within region size */
    mmap_areas[1].iov_len = 0x1000;
    ret = vfu_setup_region(&vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX,
                           0x2000, NULL, 0, mmap_areas, 2, 0);
    assert_int_equal(0, ret);

    free(reg_info.mmap_areas);
}

static void
test_dma_map_sg(void **state UNUSED)
{
    vfu_ctx_t vfu_ctx = { 0 };
    size_t size = sizeof(dma_controller_t) + sizeof(dma_memory_region_t);
    dma_controller_t *dma = alloca(size);
    dma_sg_t sg = { .region = 1 };
    struct iovec iovec = { 0 };

    memset(dma, 0, size);
    dma->vfu_ctx = &vfu_ctx;
    dma->nregions = 1;

    /* bad region */
    assert_int_equal(-1, dma_map_sg(dma, &sg, &iovec, 1));
    assert_int_equal(EINVAL, errno);

    /* w/o fd */
    sg.region = 0;
    assert_int_equal(-1, dma_map_sg(dma, &sg, &iovec, 1));
    assert_int_equal(EFAULT, errno);

    /* w/ fd */
    dma->regions[0].info.vaddr = (void *)0xdead0000;
    sg.offset = 0x0000beef;
    sg.length = 0xcafebabe;
    assert_int_equal(0, dma_map_sg(dma, &sg, &iovec, 1));
    assert_int_equal(0xdeadbeef, iovec.iov_base);
    assert_int_equal((int)0x00000000cafebabe, iovec.iov_len);

}

static void
test_dma_addr_to_sg(void **state UNUSED)
{
    dma_controller_t *dma = alloca(sizeof(dma_controller_t) + sizeof(dma_memory_region_t));
    dma_sg_t sg;
    dma_memory_region_t *r;

    dma->nregions = 1;
    r = &dma->regions[0];
    r->info.iova.iov_base = (void *)0x1000;
    r->info.iova.iov_len = 0x4000;
    r->info.vaddr = (void *)0xdeadbeef;

    /* fast path, region hint hit */
    r->info.prot = PROT_WRITE;
    assert_int_equal(1,
        dma_addr_to_sg(dma, (vfu_dma_addr_t)0x2000, 0x400, &sg, 1, PROT_READ));
    assert_int_equal(r->info.iova.iov_base, sg.dma_addr);
    assert_int_equal(0, sg.region);
    assert_int_equal(0x2000 - (unsigned long long)r->info.iova.iov_base, sg.offset);
    assert_int_equal(0x400, sg.length);
    assert_true(sg.mappable);

    errno = 0;
    r->info.prot = PROT_WRITE;
    assert_int_equal(-1,
        dma_addr_to_sg(dma, (vfu_dma_addr_t)0x6000, 0x400, &sg, 1, PROT_READ));
    assert_int_equal(ENOENT, errno);

    r->info.prot = PROT_READ;
    assert_int_equal(-1,
        dma_addr_to_sg(dma, (vfu_dma_addr_t)0x2000, 0x400, &sg, 1, PROT_WRITE));
    assert_int_equal(EACCES, errno);

    r->info.prot = PROT_READ|PROT_WRITE;
    assert_int_equal(1,
        dma_addr_to_sg(dma, (vfu_dma_addr_t)0x2000, 0x400, &sg, 1, PROT_READ));

    /* TODO test more scenarios */
}

static void
test_vfu_setup_device_dma(void **state UNUSED)
{
    vfu_ctx_t vfu_ctx = { 0 };

    assert_int_equal(0, vfu_setup_device_dma(&vfu_ctx, NULL, NULL));
    assert_non_null(vfu_ctx.dma);
    free(vfu_ctx.dma);
}

static void
test_migration_state_transitions(void **state UNUSED)
{
    bool (*f)(uint32_t, uint32_t) = vfio_migr_state_transition_is_valid;
    uint32_t i, j;

    /* from stopped (000b): all transitions are invalid */
    assert_true(f(0, 0));
    for (i = 1; i < 8; i++) {
        assert_false(f(0, i));
    }

    /* from running (001b) */
    assert_true(f(1, 0));
    assert_true(f(1, 1));
    assert_true(f(1, 2));
    assert_true(f(1, 3));
    assert_true(f(1, 4));
    assert_false(f(1, 5));
    assert_true(f(1, 6));
    assert_false(f(1, 5));

    /* from stop-and-copy (010b) */
    assert_true(f(2, 0));
    assert_false(f(2, 1));
    assert_true(f(2, 2));
    assert_false(f(2, 3));
    assert_false(f(2, 4));
    assert_false(f(2, 5));
    assert_true(f(2, 6));
    assert_false(f(2, 7));

    /* from pre-copy (011b) */
    assert_true(f(3, 0));
    assert_true(f(3, 1));
    assert_true(f(3, 2));
    assert_false(f(3, 3));
    assert_false(f(3, 4));
    assert_false(f(3, 5));
    assert_true(f(3, 6));
    assert_false(f(3, 7));

    /* from resuming (100b) */
    assert_false(f(4, 0));
    assert_true(f(4, 1));
    assert_false(f(4, 2));
    assert_false(f(4, 3));
    assert_true(f(4, 4));
    assert_false(f(4, 5));
    assert_true(f(4, 6));
    assert_false(f(4, 7));

    /*
     * Transitioning to any other state from the remaining 3 states
     * (101b - invalid, 110b - error, 111b - invalid)  is invalid.
     * Transitioning from the error state to the stopped state is possible but
     * that requires a device reset, so we don't consider it a valid state
     * transition.
     */
    for (i = 5; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            assert_false(f(i, j));
        }
    }
}

/*
 * FIXME we shouldn't have to specify a setup function explicitly for each unit
 * test, cmocka should provide that. E.g. cmocka_run_group_tests enables us to
 * run a function before/after ALL unit tests have finished, we can extend it
 * and provide a function to execute before and after each unit test.
 */
static int
setup(void **state UNUSED)
{
    unpatch_all();
    return 0;
}

static struct test_setup_migr_reg_dat {
    vfu_ctx_t *v;
    size_t rs; /* migration registers size */
    size_t ds; /* migration data size */
    size_t s; /* migration region size*/
    const vfu_migration_callbacks_t c;
} migr_reg_data = {
    .c = {
        .version = VFU_MIGR_CALLBACKS_VERS,
        .transition = (void *)0x1,
        .get_pending_bytes = (void *)0x2,
        .prepare_data = (void *)0x3,
        .read_data = (void *)0x4,
        .write_data = (void *)0x5,
        .data_written = (void *)0x6
    }
};

static int
setup_test_setup_migration_region(void **state)
{
    struct test_setup_migr_reg_dat *p = &migr_reg_data;
    p->v = vfu_create_ctx(VFU_TRANS_SOCK, "test", 0, NULL,
        VFU_DEV_TYPE_PCI);
    if (p->v == NULL) {
        return -1;
    }
    p->rs = ROUND_UP(sizeof(struct vfio_device_migration_info), sysconf(_SC_PAGE_SIZE));
    p->ds = sysconf(_SC_PAGE_SIZE);
    p->s = p->rs + p->ds;
    *state = p;
    return setup(state);
}

static vfu_ctx_t *
get_vfu_ctx(void **state)
{
    return (*((struct test_setup_migr_reg_dat **)(state)))->v;
}

static int
teardown_test_setup_migration_region(void **state)
{
    struct test_setup_migr_reg_dat *p = *state;
    vfu_destroy_ctx(p->v);
    return 0;
}

static void
test_setup_migration_region_too_small(void **state)
{
    vfu_ctx_t *v = get_vfu_ctx(state);
    int r = vfu_setup_region(v, VFU_PCI_DEV_MIGR_REGION_IDX,
        vfu_get_migr_register_area_size() - 1, NULL,
        VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE, NULL, 0, -1);
    assert_int_equal(-1, r);
    assert_int_equal(EINVAL, errno);
}

static void
test_setup_migration_region_size_ok(void **state)
{
    vfu_ctx_t *v = get_vfu_ctx(state);
    int r = vfu_setup_region(v, VFU_PCI_DEV_MIGR_REGION_IDX,
        vfu_get_migr_register_area_size(), NULL,
        VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE, NULL, 0, -1);
    assert_int_equal(0, r);
}

static void
test_setup_migration_region_fully_mappable(void **state)
{
    struct test_setup_migr_reg_dat *p = *state;
    int r = vfu_setup_region(p->v, VFU_PCI_DEV_MIGR_REGION_IDX, p->s,
        NULL, VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE, NULL, 0,
        0xdeadbeef);
    assert_int_equal(-1, r);
    assert_int_equal(EINVAL, errno);
}

static void
test_setup_migration_region_sparsely_mappable_over_migration_registers(void **state)
{
    struct test_setup_migr_reg_dat *p = *state;
    struct iovec mmap_areas[] = {
        [0] = {
            .iov_base = 0,
            .iov_len = p->rs
        }
    };
    int r = vfu_setup_region(p->v, VFU_PCI_DEV_MIGR_REGION_IDX, p->s, NULL,
        VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE, mmap_areas, 1, 0xdeadbeef);
    assert_int_equal(-1, r);
    assert_int_equal(EINVAL, errno);
}

static void
test_setup_migration_region_sparsely_mappable_valid(void **state)
{
    struct test_setup_migr_reg_dat *p = *state;
    struct iovec mmap_areas[] = {
        [0] = {
            .iov_base = (void *)p->rs,
            .iov_len = p->ds
        }
    };
    int r = vfu_setup_region(p->v, VFU_PCI_DEV_MIGR_REGION_IDX, p->s, NULL,
        VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE, mmap_areas, 1,
        0xdeadbeef);
    assert_int_equal(0, r);
}

static void
test_setup_migration_callbacks_without_migration_region(void **state)
{
    struct test_setup_migr_reg_dat *p = *state;
    assert_int_equal(-1, vfu_setup_device_migration_callbacks(p->v, &p->c, 0));
    assert_int_equal(EINVAL, errno);
}

static void
test_setup_migration_callbacks_bad_data_offset(void **state)
{
    struct test_setup_migr_reg_dat *p = *state;
    int r = vfu_setup_region(p->v, VFU_PCI_DEV_MIGR_REGION_IDX, p->s, NULL,
        VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE, NULL, 0, -1);
    assert_int_equal(0, r);
    r = vfu_setup_device_migration_callbacks(p->v, &p->c,
        vfu_get_migr_register_area_size() - 1);
    assert_int_equal(-1, r);
}

static void
test_setup_migration_callbacks(void **state)
{
    struct test_setup_migr_reg_dat *p = *state;
    int r = vfu_setup_region(p->v, VFU_PCI_DEV_MIGR_REGION_IDX, p->s, NULL,
        VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE, NULL, 0, -1);
    assert_int_equal(0, r);
    r = vfu_setup_device_migration_callbacks(p->v, &p->c,
        vfu_get_migr_register_area_size());
    assert_int_equal(0, r);
    assert_non_null(p->v->migration);
    /* FIXME can't validate p->v->migration because it's a private strcut, need to move it out of lib/migration.c */
}

static void
test_device_is_stopped_and_copying(UNUSED void **state)
{
    vfu_ctx_t vfu_ctx = { .migration = NULL };

    assert_false(device_is_stopped_and_copying(vfu_ctx.migration));
    assert_false(device_is_stopped(vfu_ctx.migration));

    size_t i;
    struct migration migration;
    vfu_ctx.migration = &migration;
    for (i = 0; i < ARRAY_SIZE(migr_states); i++) {
        if (migr_states[i].name == NULL) {
            continue;
        }
        migration.info.device_state = i;
        bool r = device_is_stopped_and_copying(vfu_ctx.migration);
        if (i == VFIO_DEVICE_STATE_SAVING) {
            assert_true(r);
        } else {
            assert_false(r);
        }
        r = device_is_stopped(vfu_ctx.migration);
        if (i == VFIO_DEVICE_STATE_STOP) {
            assert_true(r);
        } else {
            assert_false(r);
        }
    }
}

static void
test_cmd_allowed_when_stopped_and_copying(UNUSED void **state)
{
    size_t i;

    for (i = 0; i < VFIO_USER_MAX; i++) {
        bool r = cmd_allowed_when_stopped_and_copying(i);
        if (i == VFIO_USER_REGION_READ || i == VFIO_USER_REGION_WRITE ||
            i == VFIO_USER_DIRTY_PAGES) {
            assert_true(r);
        } else {
            assert_false(r);
        }
    }
}

static void
test_should_exec_command(UNUSED void **state)
{
    struct migration migration = { { 0 } };
    vfu_ctx_t vfu_ctx = { .migration = &migration };

    patch("device_is_stopped_and_copying");
    patch("cmd_allowed_when_stopped_and_copying");
    patch("device_is_stopped");

    /* XXX stopped and copying, command allowed */
    will_return(device_is_stopped_and_copying, true);
    expect_value(device_is_stopped_and_copying, migration, &migration);
    will_return(cmd_allowed_when_stopped_and_copying, true);
    expect_value(cmd_allowed_when_stopped_and_copying, cmd, 0xbeef);
    assert_true(should_exec_command(&vfu_ctx, 0xbeef));

    /* XXX stopped and copying, command not allowed */
    will_return(device_is_stopped_and_copying, true);
    expect_any(device_is_stopped_and_copying, migration);
    will_return(cmd_allowed_when_stopped_and_copying, false);
    expect_any(cmd_allowed_when_stopped_and_copying, cmd);
    assert_false(should_exec_command(&vfu_ctx, 0xbeef));

    /* XXX stopped */
    will_return(device_is_stopped_and_copying, false);
    expect_any(device_is_stopped_and_copying, migration);
    will_return(device_is_stopped, true);
    expect_value(device_is_stopped, migration, &migration);
    assert_false(should_exec_command(&vfu_ctx, 0xbeef));

    /* XXX none of the above */
    will_return(device_is_stopped_and_copying, false);
    expect_any(device_is_stopped_and_copying, migration);
    will_return(device_is_stopped, false);
    expect_any(device_is_stopped, migration);
    assert_true(should_exec_command(&vfu_ctx, 0xbeef));
}

static int
recv_body(UNUSED vfu_ctx_t *vfu_ctx, UNUSED const struct vfio_user_header *hdr,
          UNUSED void **datap)
{
    /* hack to avoid having to refactor the rest of exec_command */
    errno = ENOBUFS;
    return -1;
}

static void
test_exec_command(UNUSED void **state)
{
    vfu_ctx_t vfu_ctx = { 0 };
    struct vfio_user_header hdr = {
        .cmd = 0xbeef,
        .flags.type = VFIO_USER_F_TYPE_COMMAND,
        .msg_size = sizeof(hdr) + 1
    };
    size_t size = sizeof(hdr);
    int fds = 0;
    struct iovec _iovecs = { 0 };
    struct iovec *iovecs = NULL;
    size_t nr_iovecs = 0;
    bool free_iovec_data = false;
    int r;

    /* XXX should NOT execute command */
    patch("should_exec_command");
    will_return(should_exec_command, false);
    expect_value(should_exec_command, vfu_ctx, &vfu_ctx);
    expect_value(should_exec_command, cmd, 0xbeef);
    r = exec_command(&vfu_ctx, &hdr, size, &fds, 0, NULL, NULL, &_iovecs,
                     &iovecs, &nr_iovecs, &free_iovec_data);
    assert_int_equal(-1, r);
    assert_int_equal(EINVAL, errno);

    /* XXX should execute command */
    struct transport_ops tran = { .recv_body = recv_body };
    vfu_ctx.tran = &tran;
    will_return(should_exec_command, true);
    expect_value(should_exec_command, vfu_ctx, &vfu_ctx);
    expect_value(should_exec_command, cmd, 0xbeef);
    r = exec_command(&vfu_ctx, &hdr, size, &fds, 0, NULL, NULL, &_iovecs,
                     &iovecs, &nr_iovecs, &free_iovec_data);
    assert_int_equal(-1, r);
    assert_int_equal(ENOBUFS, errno);
}

static void
test_dirty_pages_without_dma(UNUSED void **state)
{
    vfu_ctx_t vfu_ctx = { .migration = NULL };
    struct vfio_user_header hdr = {
        .cmd = VFIO_USER_DIRTY_PAGES,
        .flags = {
            .type = VFIO_USER_F_TYPE_COMMAND
        },
        .msg_size = sizeof(hdr)
    };
    size_t size = sizeof(hdr);
    int fds = 0;
    struct iovec _iovecs = { 0 };
    struct iovec *iovecs = NULL;
    size_t nr_iovecs = 0;
    bool free_iovec_data = false;
    int r;


    patch("handle_dirty_pages");

    /* XXX w/o DMA controller */
    r = exec_command(&vfu_ctx, &hdr, size, &fds, 0, NULL, NULL,
                     &_iovecs, &iovecs, &nr_iovecs, &free_iovec_data);
    assert_int_equal(0, r);

    /* XXX w/ DMA controller */
    vfu_ctx.dma = (void*)0xdeadbeef;
    expect_value(handle_dirty_pages, vfu_ctx, &vfu_ctx);
    expect_value(handle_dirty_pages, size, 0);
    expect_value(handle_dirty_pages, iovecs, &iovecs);
    expect_value(handle_dirty_pages, nr_iovecs, &nr_iovecs);
    expect_value(handle_dirty_pages, dirty_bitmap, NULL);
    will_return(handle_dirty_pages, 0xabcd);
    r = exec_command(&vfu_ctx, &hdr, size, &fds, 0, NULL, NULL,
                     &_iovecs, &iovecs, &nr_iovecs, &free_iovec_data);
    assert_int_equal(0xabcd, r);
}

static void
test_device_set_irqs(UNUSED void **state)
{
    vfu_irqs_t *irqs = alloca(sizeof (*irqs) + sizeof (int));
    struct vfio_irq_set irq_set = { 0, };
    vfu_ctx_t vfu_ctx = { 0, };
    int fd = 0xdead;
    int ret;

    vfu_ctx.irq_count[VFU_DEV_MSIX_IRQ] = 2048;
    vfu_ctx.irq_count[VFU_DEV_ERR_IRQ] = 1;
    vfu_ctx.irq_count[VFU_DEV_REQ_IRQ] = 1;
    vfu_ctx.irqs = irqs;

    /* validation tests */

    irq_set.argsz = sizeof (irq_set);

    ret = handle_device_set_irqs(&vfu_ctx, 0, NULL, 0, &irq_set);
    /* bad message size */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.argsz = 3;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad .argsz */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.argsz = sizeof (irq_set);
    irq_set.index = VFU_DEV_NUM_IRQS;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad .index */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.index = VFU_DEV_MSIX_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_ACTION_UNMASK;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad flags, MASK and UNMASK */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_DATA_NONE |
                    VFIO_IRQ_SET_DATA_BOOL;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad flags, DATA_NONE and DATA_BOOL */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_DATA_NONE;
    irq_set.start = 2047;
    irq_set.count = 2;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad start, count range */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.start = 2049;
    irq_set.count = 1;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad start, count range */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.start = 0;
    irq_set.count = 1;
    irq_set.index = VFU_DEV_ERR_IRQ;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad action for err irq */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.index = VFU_DEV_REQ_IRQ;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad action for req irq */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.start = 1;
    irq_set.count = 0;
    irq_set.index = VFU_DEV_MSIX_IRQ;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad start for count == 0 */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_DATA_NONE;
    irq_set.count = 0;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad action for count == 0 */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_BOOL;
    irq_set.count = 0;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    /* bad action and data type for count == 0 */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_BOOL;
    irq_set.count = 1;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), &fd, 1, &irq_set);
    /* bad fds for DATA_BOOL */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE;
    irq_set.count = 1;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), &fd, 1, &irq_set);
    /* bad fds for DATA_NONE */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_EVENTFD;
    irq_set.count = 2;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), &fd, 1, &irq_set);
    /* bad fds for count == 2 */
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irqs->err_efd = irqs->req_efd = -1;

    /* Basic disable functionality. */

    irq_set.index = VFU_DEV_REQ_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE;
    irq_set.count = 0;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    assert_int_equal(0, ret);

    irq_set.index = VFU_DEV_REQ_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_EVENTFD;
    irq_set.count = 1;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), NULL, 0, &irq_set);
    assert_int_equal(0, ret);

    /* Basic enable. */

    irq_set.index = VFU_DEV_MSIX_IRQ;
    vfu_ctx.irq_count[VFU_DEV_MSIX_IRQ] = 1;
    irqs->efds[0] = -1;
    fd = 0xbeef;

    irq_set.index = VFU_DEV_MSIX_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_EVENTFD;
    irq_set.count = 1;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, sizeof (irq_set), &fd, 1, &irq_set);
    assert_int_equal(0, ret);
    assert_int_equal(0xbeef, irqs->efds[0]);

}

int
main(void)
{
   const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_dma_map_without_dma, setup),
        cmocka_unit_test_setup(test_dma_map_mappable_without_fd, setup),
        cmocka_unit_test_setup(test_dma_map_without_fd, setup),
        cmocka_unit_test_setup(test_dma_add_regions_mixed, setup),
        cmocka_unit_test_setup(test_dma_add_regions_mixed_partial_failure, setup),
        cmocka_unit_test_setup(test_dma_controller_add_region_no_fd, setup),
        cmocka_unit_test_setup(test_dma_controller_remove_region_mapped, setup),
        cmocka_unit_test_setup(test_dma_controller_remove_region_unmapped, setup),
        cmocka_unit_test_setup(test_handle_dma_unmap, setup),
        cmocka_unit_test_setup(test_process_command_free_passed_fds, setup),
        cmocka_unit_test_setup(test_realize_ctx, setup),
        cmocka_unit_test_setup(test_attach_ctx, setup),
        cmocka_unit_test_setup(test_run_ctx, setup),
        cmocka_unit_test_setup(test_vfu_ctx_create, setup),
        cmocka_unit_test_setup(test_pci_caps, setup),
        cmocka_unit_test_setup(test_pci_ext_caps, setup),
        cmocka_unit_test_setup(test_device_get_info, setup),
        cmocka_unit_test_setup(test_device_get_info_compat, setup),
        cmocka_unit_test_setup(test_get_region_info, setup),
        cmocka_unit_test_setup(test_setup_sparse_region, setup),
        cmocka_unit_test_setup(test_dma_map_return_value, setup),
        cmocka_unit_test_setup(test_dma_map_sg, setup),
        cmocka_unit_test_setup(test_dma_addr_to_sg, setup),
        cmocka_unit_test_setup(test_vfu_setup_device_dma, setup),
        cmocka_unit_test_setup(test_migration_state_transitions, setup),
        cmocka_unit_test_setup_teardown(test_setup_migration_region_too_small,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup_teardown(test_setup_migration_region_size_ok,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup_teardown(test_setup_migration_region_fully_mappable,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup_teardown(test_setup_migration_region_sparsely_mappable_over_migration_registers,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup_teardown(test_setup_migration_region_sparsely_mappable_valid,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup_teardown(test_setup_migration_callbacks_without_migration_region,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup_teardown(test_setup_migration_callbacks_bad_data_offset,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup_teardown(test_setup_migration_callbacks,
            setup_test_setup_migration_region,
            teardown_test_setup_migration_region),
        cmocka_unit_test_setup(test_device_is_stopped_and_copying, setup),
        cmocka_unit_test_setup(test_cmd_allowed_when_stopped_and_copying, setup),
        cmocka_unit_test_setup(test_should_exec_command, setup),
        cmocka_unit_test_setup(test_exec_command, setup),
        cmocka_unit_test_setup(test_dirty_pages_without_dma, setup),
        cmocka_unit_test_setup(test_device_set_irqs, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
