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
#include "irq.h"
#include "libvfio-user.h"
#include "migration.h"
#include "migration_priv.h"
#include "mocks.h"
#include "pci.h"
#include "private.h"
#include "tran_sock.h"

#define DMACSIZE (sizeof(dma_controller_t) + sizeof(dma_memory_region_t) * 5)

/*
 * These globals are used in the unit tests; they're re-initialized each time by
 * setup(), but having them as globals makes for significantly less
 * boiler-plate.
 */
static char dmacbuf[DMACSIZE];
static vfu_ctx_t vfu_ctx;
static vfu_msg_t msg;
static size_t nr_fds;
static int fds[2];
static int ret;

static vfu_msg_t *
mkmsg(enum vfio_user_command cmd, void *data, size_t size)
{
    msg.hdr.cmd = cmd;
    msg.in_data = data;
    msg.in_size = size;

    if (nr_fds != 0) {
        msg.in_fds = fds;
        msg.nr_in_fds = nr_fds;
    } else {
        msg.in_fds = NULL;
        msg.nr_in_fds = 0;
    }

    return &msg;
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
    memset(&vfu_ctx, 0, sizeof(vfu_ctx));

    vfu_ctx.client_max_fds = 10;

    memset(dmacbuf, 0, DMACSIZE);

    vfu_ctx.dma = (void *)dmacbuf;
    vfu_ctx.dma->max_regions = 10;
    vfu_ctx.dma->vfu_ctx = &vfu_ctx;

    memset(&msg, 0, sizeof(msg));

    msg.hdr.flags.type = VFIO_USER_F_TYPE_COMMAND;
    msg.hdr.msg_size = sizeof(msg.hdr);

    fds[0] = fds[1] = -1;
    nr_fds = 0;
    ret = 0;

    unpatch_all();
    return 0;
}

static void
test_dma_map_without_dma(void **state UNUSED)
{
    struct vfio_user_dma_region dma_region = {
        .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
    };

    vfu_ctx.dma = NULL;

    ret = handle_dma_map_or_unmap(&vfu_ctx, mkmsg(VFIO_USER_DMA_MAP,
                                  &dma_region, sizeof(dma_region)));
    assert_int_equal(0, ret);
}

static void
test_dma_map_mappable_without_fd(void **state UNUSED)
{
    struct vfio_user_dma_region dma_region = {
        .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
    };

    ret = handle_dma_map_or_unmap(&vfu_ctx, mkmsg(VFIO_USER_DMA_MAP,
                                  &dma_region, sizeof(dma_region)));
    assert_int_equal(-1, ret);
    assert_int_equal(errno, EINVAL);
}

static void
test_dma_map_without_fd(void **state UNUSED)
{
    struct vfio_user_dma_region r = {
        .addr = 0xdeadbeef,
        .size = 0xcafebabe,
        .offset = 0x8badf00d,
        .prot = PROT_NONE
    };

    patch("dma_controller_add_region");
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 0);
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r.addr);
    expect_value(dma_controller_add_region, size, r.size);
    expect_value(dma_controller_add_region, fd, -1);
    expect_value(dma_controller_add_region, offset, r.offset);
    expect_value(dma_controller_add_region, prot, r.prot);
    ret = handle_dma_map_or_unmap(&vfu_ctx, mkmsg(VFIO_USER_DMA_MAP,
                                  &r, sizeof(r)));
    assert_int_equal(0, ret);
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
    size_t count = 0;
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

    vfu_ctx.dma_register = mock_dma_register;
    vfu_ctx.pvt = &count;

    fds[0] = 0x0badf00d;
    nr_fds = 1;

    vfu_ctx.dma->regions[0].info.iova.iov_base = (void *)r[0].addr;
    vfu_ctx.dma->regions[0].info.iova.iov_len = r[0].size;
    vfu_ctx.dma->regions[0].info.prot = r[0].prot;
    vfu_ctx.dma->regions[1].info.iova.iov_base = (void *)r[1].addr;
    vfu_ctx.dma->regions[1].info.iova.iov_len = r[1].size;
    vfu_ctx.dma->regions[1].info.prot = r[1].prot;
    vfu_ctx.dma->nregions = 2;

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
                 &vfu_ctx.dma->regions[0].info);
    /* 2nd region */
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 1);
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(dma_controller_add_region, size, r[1].size);
    expect_value(dma_controller_add_region, fd, fds[0]);
    expect_value(dma_controller_add_region, offset, r[1].offset);
    expect_value(dma_controller_add_region, prot, r[1].prot);
    expect_value(mock_dma_register, vfu_ctx, &vfu_ctx);
    expect_check(mock_dma_register, info, check_dma_info,
                 &vfu_ctx.dma->regions[1].info);

    ret = handle_dma_map_or_unmap(&vfu_ctx, mkmsg(VFIO_USER_DMA_MAP,
                                  r, sizeof(r)));
    assert_int_equal(0, ret);
    assert_int_equal(-1, fds[0]);
}

/*
 * Tests that handle_dma_map_or_unmap closes unconsumed file descriptors when
 * failing halfway through.
 */
static void
test_dma_add_regions_mixed_partial_failure(void **state UNUSED)
{
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

    fds[0] = 0xa;
    fds[1] = 0xb;
    nr_fds = 2;

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

    /* 2nd region */
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 1);
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(dma_controller_add_region, size, r[1].size);
    expect_value(dma_controller_add_region, fd, fds[0]);
    expect_value(dma_controller_add_region, offset, r[1].offset);
    expect_value(dma_controller_add_region, prot, r[1].prot);

    /* 3rd region */
    will_return(dma_controller_add_region, EREMOTEIO);
    will_return(dma_controller_add_region, -1);
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r[2].addr);
    expect_value(dma_controller_add_region, size, r[2].size);
    expect_value(dma_controller_add_region, fd, fds[1]);
    expect_value(dma_controller_add_region, offset, r[2].offset);
    expect_value(dma_controller_add_region, prot, r[2].prot);

    patch("close");
    expect_value(close, fd, 0xb);
    will_return(close, 0);

    ret = handle_dma_map_or_unmap(&vfu_ctx, mkmsg(VFIO_USER_DMA_MAP,
                                  r, sizeof(r)));
    assert_int_equal(-1, ret);
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

    patch("dma_controller_add_region");
    expect_value(dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_add_region, dma_addr, r.addr);
    expect_value(dma_controller_add_region, size, r.size);
    expect_value(dma_controller_add_region, fd, -1);
    expect_value(dma_controller_add_region, offset, r.offset);
    expect_value(dma_controller_add_region, prot, r.prot);
    will_return(dma_controller_add_region, 0);
    will_return(dma_controller_add_region, 2);

    assert_int_equal(0, handle_dma_map_or_unmap(&vfu_ctx,
                     mkmsg(VFIO_USER_DMA_MAP, &r, sizeof(r))));
}

/*
 * Tests that handle_dma_map_or_unmap correctly removes a region.
 */
static void
test_handle_dma_unmap(void **state UNUSED)
{
    struct vfio_user_dma_region r = {
        .addr = 0x1000, .size = 0x1000
    };

    vfu_ctx.dma->nregions = 3;
    vfu_ctx.dma->regions[0].info.iova.iov_base = (void *)0x1000;
    vfu_ctx.dma->regions[0].info.iova.iov_len = 0x1000;
    vfu_ctx.dma->regions[0].fd = -1;
    vfu_ctx.dma->regions[1].info.iova.iov_base = (void *)0x4000;
    vfu_ctx.dma->regions[1].info.iova.iov_len = 0x2000;
    vfu_ctx.dma->regions[1].fd = -1;
    vfu_ctx.dma->regions[2].info.iova.iov_base = (void *)0x8000;
    vfu_ctx.dma->regions[2].info.iova.iov_len = 0x3000;
    vfu_ctx.dma->regions[2].fd = -1;

    vfu_ctx.dma_unregister = mock_dma_unregister;

    expect_value(mock_dma_unregister, vfu_ctx, &vfu_ctx);
    expect_check(mock_dma_unregister, info, check_dma_info,
                 &vfu_ctx.dma->regions[0].info);
    will_return(mock_dma_unregister, 0);

    ret = handle_dma_map_or_unmap(&vfu_ctx, mkmsg(VFIO_USER_DMA_UNMAP,
                                  &r, sizeof(r)));

    assert_int_equal(0, ret);
    assert_int_equal(2, vfu_ctx.dma->nregions);
    assert_int_equal(0x4000, vfu_ctx.dma->regions[0].info.iova.iov_base);
    assert_int_equal(0x2000, vfu_ctx.dma->regions[0].info.iova.iov_len);
    assert_int_equal(0x8000, vfu_ctx.dma->regions[1].info.iova.iov_base);
    assert_int_equal(0x3000, vfu_ctx.dma->regions[1].info.iova.iov_len);
}

static void
test_dma_controller_add_region_no_fd(void **state UNUSED)
{
    vfu_dma_addr_t dma_addr = (void *)0xdeadbeef;
    dma_memory_region_t *r;
    off_t offset = 0;
    size_t size = 0;
    int fd = -1;

    assert_int_equal(0, dma_controller_add_region(vfu_ctx.dma, dma_addr,
                                                  size, fd, offset, PROT_NONE));
    assert_int_equal(1, vfu_ctx.dma->nregions);
    r = &vfu_ctx.dma->regions[0];
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
    vfu_ctx.dma->nregions = 1;
    vfu_ctx.dma->regions[0].info.iova.iov_base = (void *)0xdeadbeef;
    vfu_ctx.dma->regions[0].info.iova.iov_len = 0x100;
    vfu_ctx.dma->regions[0].info.mapping.iov_base = (void *)0xcafebabe;
    vfu_ctx.dma->regions[0].info.mapping.iov_len = 0x1000;
    vfu_ctx.dma->regions[0].info.vaddr = (void *)0xcafebabe;

    expect_value(mock_dma_unregister, vfu_ctx, &vfu_ctx);
    expect_check(mock_dma_unregister, info, check_dma_info,
                 &vfu_ctx.dma->regions[0].info);
    /* FIXME add unit test when dma_unregister fails */
    will_return(mock_dma_unregister, 0);
    patch("dma_controller_unmap_region");
    expect_value(dma_controller_unmap_region, dma, vfu_ctx.dma);
    expect_value(dma_controller_unmap_region, region, &vfu_ctx.dma->regions[0]);
    assert_int_equal(0,
        dma_controller_remove_region(vfu_ctx.dma, (void *)0xdeadbeef, 0x100,
            mock_dma_unregister, &vfu_ctx));
}

static void
test_dma_controller_remove_region_unmapped(void **state UNUSED)
{
    vfu_ctx.dma->nregions = 1;
    vfu_ctx.dma->regions[0].info.iova.iov_base = (void *)0xdeadbeef;
    vfu_ctx.dma->regions[0].info.iova.iov_len = 0x100;
    vfu_ctx.dma->regions[0].fd = -1;

    expect_value(mock_dma_unregister, vfu_ctx, &vfu_ctx);
    expect_check(mock_dma_unregister, info, check_dma_info,
                 &vfu_ctx.dma->regions[0].info);
    will_return(mock_dma_unregister, 0);
    patch("dma_controller_unmap_region");
    assert_int_equal(0,
        dma_controller_remove_region(vfu_ctx.dma, (void *)0xdeadbeef, 0x100,
            mock_dma_unregister, &vfu_ctx));
}

static void
test_dma_map_sg(void **state UNUSED)
{
    dma_sg_t sg = { .region = 1 };
    struct iovec iovec = { 0 };

    /* bad region */
    assert_int_equal(-1, dma_map_sg(vfu_ctx.dma, &sg, &iovec, 1));
    assert_int_equal(EINVAL, errno);

    vfu_ctx.dma->nregions = 1;

    /* w/o fd */
    sg.region = 0;
    assert_int_equal(-1, dma_map_sg(vfu_ctx.dma, &sg, &iovec, 1));
    assert_int_equal(EFAULT, errno);

    /* w/ fd */
    vfu_ctx.dma->regions[0].info.vaddr = (void *)0xdead0000;

    sg.offset = 0x0000beef;
    sg.length = 0xcafebabe;
    assert_int_equal(0, dma_map_sg(vfu_ctx.dma, &sg, &iovec, 1));
    assert_int_equal(0xdeadbeef, iovec.iov_base);
    assert_int_equal((int)0x00000000cafebabe, iovec.iov_len);
}

static void
test_dma_addr_to_sg(void **state UNUSED)
{
    dma_memory_region_t *r;
    dma_sg_t sg;
    int ret;

    vfu_ctx.dma->nregions = 1;
    r = &vfu_ctx.dma->regions[0];
    r->info.iova.iov_base = (void *)0x1000;
    r->info.iova.iov_len = 0x4000;
    r->info.vaddr = (void *)0xdeadbeef;

    /* fast path, region hint hit */
    r->info.prot = PROT_WRITE;
    ret = dma_addr_to_sg(vfu_ctx.dma, (vfu_dma_addr_t)0x2000,
                         0x400, &sg, 1, PROT_READ);
    assert_int_equal(1, ret);
    assert_int_equal(r->info.iova.iov_base, sg.dma_addr);
    assert_int_equal(0, sg.region);
    assert_int_equal(0x2000 - (unsigned long long)r->info.iova.iov_base,
                     sg.offset);
    assert_int_equal(0x400, sg.length);
    assert_true(sg.mappable);

    errno = 0;
    r->info.prot = PROT_WRITE;
    ret = dma_addr_to_sg(vfu_ctx.dma, (vfu_dma_addr_t)0x6000,
                         0x400, &sg, 1, PROT_READ);
    assert_int_equal(-1, ret);
    assert_int_equal(ENOENT, errno);

    r->info.prot = PROT_READ;
    ret = dma_addr_to_sg(vfu_ctx.dma, (vfu_dma_addr_t)0x2000,
                         0x400, &sg, 1, PROT_WRITE);
    assert_int_equal(-1, ret);
    assert_int_equal(EACCES, errno);

    r->info.prot = PROT_READ|PROT_WRITE;
    ret = dma_addr_to_sg(vfu_ctx.dma, (vfu_dma_addr_t)0x2000,
                         0x400, &sg, 1, PROT_READ);
    assert_int_equal(1, ret);

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

typedef struct {
    int fd;
    int conn_fd;
} tran_sock_t;

static void
test_get_region_info(UNUSED void **state)
{
    struct iovec iov = { .iov_base = (void *)0x8badf00, .iov_len = 0x0d15ea5e };
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
    struct vfio_region_info_cap_sparse_mmap *sparse;
    struct vfio_region_info_cap_type *type;
    struct vfio_region_info in_info = {
        .index = 0
    };
    struct vfio_region_info *out_info;
    int ret;

    vfu_ctx.nr_regions = ARRAY_SIZE(reg_info);
    vfu_ctx.reg_info = reg_info;

    /* bad argsz */
    ret = handle_device_get_region_info(&vfu_ctx,
                                        mkmsg(VFIO_USER_DEVICE_GET_REGION_INFO,
                                        &in_info, 0));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad region */
    in_info.index = vfu_ctx.nr_regions;
    in_info.argsz = sizeof(struct vfio_region_info);

    ret = handle_device_get_region_info(&vfu_ctx,
                                        mkmsg(VFIO_USER_DEVICE_GET_REGION_INFO,
                                        &in_info, in_info.argsz));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* no region caps */
    in_info.index = 1;

    ret = handle_device_get_region_info(&vfu_ctx,
                                        mkmsg(VFIO_USER_DEVICE_GET_REGION_INFO,
                                        &in_info, in_info.argsz));
    assert_int_equal(0, ret);

    out_info = msg.out_data;

    assert_int_equal(sizeof(struct vfio_region_info), out_info->argsz);
    assert_int_equal(VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE |
                     VFIO_REGION_INFO_FLAG_MMAP, out_info->flags);
    assert_int_equal(1, out_info->index);
    assert_int_equal(0x10000000000, out_info->offset);
    assert_int_equal(0xdeadbeef, out_info->size);
    assert_int_equal(0, msg.nr_out_fds);

    free(msg.out_data);
    msg.out_data = NULL;

    /* regions caps (sparse mmap) but argsz too small */
    vfu_ctx.reg_info[1].mmap_areas = &iov;
    vfu_ctx.reg_info[1].nr_mmap_areas = 1;

    ret = handle_device_get_region_info(&vfu_ctx,
                                        mkmsg(VFIO_USER_DEVICE_GET_REGION_INFO,
                                        &in_info, in_info.argsz));
    assert_int_equal(0, ret);

    out_info = msg.out_data;

    assert_int_equal(in_info.argsz +
                     sizeof(struct vfio_region_info_cap_sparse_mmap) +
                     sizeof(struct vfio_region_sparse_mmap_area),
                     out_info->argsz);
    assert_int_equal(VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE |
                     VFIO_REGION_INFO_FLAG_MMAP | VFIO_REGION_INFO_FLAG_CAPS,
                     out_info->flags);

    free(msg.out_data);
    msg.out_data = NULL;

    /* region caps and argsz large enough */
    in_info.argsz += sizeof(struct vfio_region_info_cap_sparse_mmap) +
                     sizeof(struct vfio_region_sparse_mmap_area);

    ret = handle_device_get_region_info(&vfu_ctx,
                                        mkmsg(VFIO_USER_DEVICE_GET_REGION_INFO,
                                        &in_info, in_info.argsz));
    assert_int_equal(0, ret);

    out_info = msg.out_data;

    sparse = (struct vfio_region_info_cap_sparse_mmap *)(out_info + 1);
    assert_int_equal(VFIO_REGION_INFO_CAP_SPARSE_MMAP, sparse->header.id);
    assert_int_equal(1, sparse->header.version);
    assert_int_equal(0, sparse->header.next);
    assert_int_equal(1, sparse->nr_areas);

    assert_int_equal(1, msg.nr_out_fds);
    assert_int_equal(0x12345, msg.out_fds[0]);

    free(msg.out_fds);
    msg.out_fds = NULL;
    msg.nr_out_fds = 0;

    free(msg.out_data);
    msg.out_data = NULL;

    /* migration cap */
    vfu_ctx.reg_info[1].mmap_areas = NULL;
    vfu_ctx.reg_info[1].nr_mmap_areas = 0;

    in_info.index = VFU_PCI_DEV_MIGR_REGION_IDX;
    in_info.argsz = sizeof(in_info) + sizeof(struct vfio_region_info_cap_type);

    ret = handle_device_get_region_info(&vfu_ctx,
                                        mkmsg(VFIO_USER_DEVICE_GET_REGION_INFO,
                                        &in_info, in_info.argsz));
    assert_int_equal(0, ret);

    out_info = msg.out_data;

    assert_int_equal(VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE |
                     VFIO_REGION_INFO_FLAG_CAPS, out_info->flags);
    type = (struct vfio_region_info_cap_type *)(out_info + 1);
    assert_int_equal(VFIO_REGION_INFO_CAP_TYPE, type->header.id);
    assert_int_equal(VFIO_REGION_TYPE_MIGRATION , type->type);
    assert_int_equal(VFIO_REGION_SUBTYPE_MIGRATION, type->subtype);
    assert_null(msg.out_fds);
    assert_int_equal(0, msg.nr_out_fds);

    free(msg.out_data);
    msg.out_data = NULL;

    /* FIXME add check  for multiple sparse areas */
}

static bool pci_caps_writing = true;

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

    vfu_ctx.pci.config_space = &config_space;

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

    vfu_ctx.pci.config_space = (void *)&config_space;
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
    struct vfio_user_device_info d_in = { .argsz = sizeof(d_in) + 1 };
    struct vfio_user_device_info *d_out;
    int ret;

    vfu_ctx.nr_regions = 0xdeadbeef;

    ret = handle_device_get_info(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_GET_INFO,
                                 &d_in, sizeof (d_in)));

    assert_int_equal(0, ret);


    d_out = msg.out_data;
    assert_int_equal(sizeof(*d_out), d_out->argsz);
    assert_int_equal(VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET,
                     d_out->flags);
    assert_int_equal(vfu_ctx.nr_regions, d_out->num_regions);
    assert_int_equal(VFU_DEV_NUM_IRQS, d_out->num_irqs);

    free(msg.out_data);
    msg.out_data = NULL;
    msg.out_size = 0;

    /* bad size */
    ret = handle_device_get_info(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_GET_INFO,
                                 &d_in, sizeof (d_in) - 1));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);
    assert_ptr_equal(NULL, msg.out_data);
    assert_ptr_equal(0, msg.out_size);
}

/*
 * Performs various checks when adding sparse memory regions.
 */
static void
test_setup_sparse_region(void **state UNUSED)
{
    vfu_reg_info_t reg_info = { 0 };
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

    vfu_ctx.reg_info = &reg_info;

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
test_dirty_pages_without_dma(UNUSED void **state)
{
    int ret;

    /* with DMA controller */

    patch("handle_dirty_pages");

    expect_value(handle_dirty_pages, vfu_ctx, &vfu_ctx);
    expect_any(handle_dirty_pages, msg);
    will_return(handle_dirty_pages, EREMOTEIO);
    will_return(handle_dirty_pages, -1);

    ret = exec_command(&vfu_ctx, mkmsg(VFIO_USER_DIRTY_PAGES, NULL, 0));
    assert_int_equal(-1, ret);
    assert_int_equal(EREMOTEIO, errno);

    /* without DMA controller */

    vfu_ctx.dma = NULL;

    ret = exec_command(&vfu_ctx, mkmsg(VFIO_USER_DIRTY_PAGES, NULL, 0));
    assert_int_equal(0, ret);

}

static void
test_device_set_irqs(UNUSED void **state)
{
    vfu_irqs_t *irqs = alloca(sizeof (*irqs) + sizeof (int));
    struct vfio_irq_set irq_set = { 0, };
    //int fd = 0xdead;

    vfu_ctx.irq_count[VFU_DEV_MSIX_IRQ] = 2048;
    vfu_ctx.irq_count[VFU_DEV_ERR_IRQ] = 1;
    vfu_ctx.irq_count[VFU_DEV_REQ_IRQ] = 1;
    vfu_ctx.irqs = irqs;

    memset(irqs, 0, sizeof (*irqs) + sizeof (int));

    irq_set.argsz = sizeof (irq_set);

    /*
     * Validation tests.
     */

    /* bad message size */
    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, 0));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad .argsz */
    irq_set.argsz = 3;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad .index */
    irq_set.argsz = sizeof (irq_set);
    irq_set.index = VFU_DEV_NUM_IRQS;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad flags, MASK and UNMASK */
    irq_set.index = VFU_DEV_MSIX_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_ACTION_UNMASK;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad flags, DATA_NONE and DATA_BOOL */
    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_DATA_NONE |
                    VFIO_IRQ_SET_DATA_BOOL;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad start, count range */
    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_DATA_NONE;
    irq_set.start = 2047;
    irq_set.count = 2;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad start, count range */
    irq_set.start = 2049;
    irq_set.count = 1;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad action for err irq */
    irq_set.start = 0;
    irq_set.count = 1;
    irq_set.index = VFU_DEV_ERR_IRQ;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad action for req irq */
    irq_set.index = VFU_DEV_REQ_IRQ;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad start for count == 0 */
    irq_set.start = 1;
    irq_set.count = 0;
    irq_set.index = VFU_DEV_MSIX_IRQ;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad action for count == 0 */
    irq_set.flags = VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_DATA_NONE;
    irq_set.count = 0;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad action and data type for count == 0 */
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_BOOL;
    irq_set.count = 0;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad fds for DATA_BOOL */
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_BOOL;
    irq_set.count = 1;
    irq_set.start = 0;
    nr_fds = 1;
    fds[0] = 0xbeef;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad fds for DATA_NONE */
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE;
    irq_set.count = 1;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    /* bad fds for count == 2 */
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_EVENTFD;
    irq_set.count = 2;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(-1, ret);
    assert_int_equal(EINVAL, errno);

    irqs->err_efd = irqs->req_efd = -1;

    /*
     * Basic disable functionality.
     */

    nr_fds = 0;

    irq_set.index = VFU_DEV_REQ_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_NONE;
    irq_set.count = 0;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(0, ret);

    irq_set.index = VFU_DEV_REQ_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_EVENTFD;
    irq_set.count = 1;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(0, ret);

    /*
     * Basic enable functionality.
     */

    irq_set.index = VFU_DEV_MSIX_IRQ;
    vfu_ctx.irq_count[VFU_DEV_MSIX_IRQ] = 1;
    irqs->efds[0] = -1;

    nr_fds = 1;
    fds[0] = 0xbeef;

    irq_set.index = VFU_DEV_MSIX_IRQ;
    irq_set.flags = VFIO_IRQ_SET_ACTION_TRIGGER | VFIO_IRQ_SET_DATA_EVENTFD;
    irq_set.count = 1;
    irq_set.start = 0;

    ret = handle_device_set_irqs(&vfu_ctx, mkmsg(VFIO_USER_DEVICE_SET_IRQS,
                                 &irq_set, sizeof (irq_set)));
    assert_int_equal(0, ret);
    assert_int_equal(0xbeef, irqs->efds[0]);

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

    vfu_ctx.migration = &migration;

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
check_request_header_msg(const LargestIntegralType value,
                         const LargestIntegralType cvalue UNUSED)
{
    vfu_msg_t **msgp = (vfu_msg_t **)value;

    *msgp = malloc(sizeof(msg));

    assert_non_null(*msgp);

    memcpy(*msgp, &msg, sizeof(msg));

    return 1;
}

static int
check_exec_command_msg(const LargestIntegralType value,
                       const LargestIntegralType cvalue UNUSED)
{
    vfu_msg_t *cmsg = (vfu_msg_t *)value;

    int ret = cmsg->nr_in_fds == ARRAY_SIZE(fds) &&
              cmsg->in_fds[0] == fds[0] &&
              cmsg->in_fds[1] == fds[1] &&
              cmsg->in_data == NULL &&
              cmsg->in_size == 0 &&
              memcmp(&cmsg->hdr, &msg.hdr, sizeof (msg.hdr)) == 0;

    consume_fd(cmsg->in_fds, cmsg->nr_in_fds, 0);

    return ret;
}

/*
 * Tests that if if exec_command fails then process_request() frees passed file
 * descriptors.
 */
static void
test_process_request_free_passed_fds(void **state UNUSED)
{
    tran_sock_t ts = { .fd = 23, .conn_fd = 24 };

    mkmsg(VFIO_USER_DMA_MAP, NULL, 0);

    fds[0] = 0xab;
    fds[1] = 0xcd;
    msg.nr_in_fds = 2;
    msg.in_fds = malloc(sizeof(int) * msg.nr_in_fds);
    assert_non_null(msg.in_fds);
    msg.in_fds[0] = fds[0];
    msg.in_fds[1] = fds[1];

    vfu_ctx.tran = &tran_sock_ops;
    vfu_ctx.tran_data = &ts;

    patch("get_request_header");
    expect_value(get_request_header, vfu_ctx, &vfu_ctx);
    expect_check(get_request_header, msgp, check_request_header_msg, NULL);
    will_return(get_request_header, 0);

    patch("exec_command");
    expect_value(exec_command, vfu_ctx, &vfu_ctx);
    expect_check(exec_command, msg, check_exec_command_msg, NULL);
    will_return(exec_command, -1);
    will_return(exec_command, EREMOTEIO);

    patch("close");
    expect_value(close, fd, fds[1]);
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

int
main(void)
{
   const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_dma_map_without_dma, setup),
        cmocka_unit_test_setup(test_dma_map_mappable_without_fd, setup),
        cmocka_unit_test_setup(test_dma_map_without_fd, setup),
        cmocka_unit_test_setup(test_dma_add_regions_mixed, setup),
        cmocka_unit_test_setup(test_dma_add_regions_mixed_partial_failure, setup),
        cmocka_unit_test_setup(test_dma_map_return_value, setup),
        cmocka_unit_test_setup(test_handle_dma_unmap, setup),
        cmocka_unit_test_setup(test_dma_controller_add_region_no_fd, setup),
        cmocka_unit_test_setup(test_dma_controller_remove_region_mapped, setup),
        cmocka_unit_test_setup(test_dma_controller_remove_region_unmapped, setup),
        cmocka_unit_test_setup(test_dma_map_sg, setup),
        cmocka_unit_test_setup(test_dma_addr_to_sg, setup),
        cmocka_unit_test_setup(test_vfu_setup_device_dma, setup),
        cmocka_unit_test_setup(test_get_region_info, setup),
        cmocka_unit_test_setup(test_pci_caps, setup),
        cmocka_unit_test_setup(test_pci_ext_caps, setup),
        cmocka_unit_test_setup(test_device_get_info, setup),
        cmocka_unit_test_setup(test_setup_sparse_region, setup),
        cmocka_unit_test_setup(test_dirty_pages_without_dma, setup),
        cmocka_unit_test_setup(test_device_set_irqs, setup),
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
        cmocka_unit_test_setup(test_process_request_free_passed_fds, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
