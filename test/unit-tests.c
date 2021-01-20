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

#include "dma.h"
#include "libvfio-user.h"
#include "pci.h"
#include "private.h"
#include "migration.h"
#include "tran_sock.h"

static void
test_dma_map_without_dma(void **state __attribute__((unused)))
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
test_dma_map_mappable_without_fd(void **state __attribute__((unused)))
{
    dma_controller_t dma = { 0 };
    vfu_ctx_t vfu_ctx = { .dma = &dma };
    size_t size = sizeof(struct vfio_user_dma_region);
    struct vfio_user_dma_region dma_region = {
        .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
    };
    int fd;

    assert_int_equal(-EINVAL, handle_dma_map_or_unmap(&vfu_ctx, size, true, &fd, 0, &dma_region));
}

static void
test_dma_map_without_fd(void **state __attribute__((unused)))
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

    patch(dma_controller_add_region);
    will_return(__wrap_dma_controller_add_region, 0);
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r.addr);
    expect_value(__wrap_dma_controller_add_region, size, r.size);
    expect_value(__wrap_dma_controller_add_region, fd, -1);
    expect_value(__wrap_dma_controller_add_region, offset, r.offset);
    expect_value(__wrap_dma_controller_add_region, prot, r.prot);
    assert_int_equal(0, handle_dma_map_or_unmap(&vfu_ctx, size, true, &fd, 0, &r));
}

/*
 * Tests that adding multiple DMA regions that not all of them are mappable
 * results in only the mappable one being memory mapped.
 */
static void
test_dma_add_regions_mixed(void **state __attribute__((unused)))
{
    dma_controller_t dma = { 0 };
    vfu_ctx_t vfu_ctx = { .dma = &dma };
    dma.vfu_ctx = &vfu_ctx;
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
            .prot = PROT_READ|PROT_WRITE
        }
    };
    int fd = 0x0badf00d;

    patch(dma_controller_add_region);
    will_return(__wrap_dma_controller_add_region, 0);
    will_return(__wrap_dma_controller_add_region, 0);
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[0].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[0].size);
    expect_value(__wrap_dma_controller_add_region, fd, -1);
    expect_value(__wrap_dma_controller_add_region, offset, r[0].offset);
    expect_value(__wrap_dma_controller_add_region, prot, r[0].prot);
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[1].size);
    expect_value(__wrap_dma_controller_add_region, fd, fd);
    expect_value(__wrap_dma_controller_add_region, offset, r[1].offset);
    expect_value(__wrap_dma_controller_add_region, prot, r[1].prot);

    assert_int_equal(0, handle_dma_map_or_unmap(&vfu_ctx, sizeof r, true, &fd, 1, r));
}

/*
 * Tests that handle_dma_map_or_unmap closes unconsumed file descriptors when
 * failing halfway through.
 */
static void
test_dma_add_regions_mixed_partial_failure(void **state __attribute__((unused)))
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

    patch(dma_controller_add_region);

    /* 1st region */
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[0].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[0].size);
    expect_value(__wrap_dma_controller_add_region, fd, -1);
    expect_value(__wrap_dma_controller_add_region, offset, r[0].offset);
    expect_value(__wrap_dma_controller_add_region, prot, r[0].prot);
    will_return(__wrap_dma_controller_add_region, 0);

    /* 2nd region */
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[1].size);
    expect_value(__wrap_dma_controller_add_region, fd, fds[0]);
    expect_value(__wrap_dma_controller_add_region, offset, r[1].offset);
    expect_value(__wrap_dma_controller_add_region, prot, r[1].prot);
    will_return(__wrap_dma_controller_add_region, 0);

    /* 3rd region */
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[2].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[2].size);
    expect_value(__wrap_dma_controller_add_region, fd, fds[1]);
    expect_value(__wrap_dma_controller_add_region, offset, r[2].offset);
    expect_value(__wrap_dma_controller_add_region, prot, r[2].prot);
    will_return(__wrap_dma_controller_add_region, -0x1234);

    patch(close);
    expect_value(__wrap_close, fd, 0xb);
    will_return(__wrap_close, 0);

    assert_int_equal(-0x1234,
                     handle_dma_map_or_unmap(&vfu_ctx,
                                             ARRAY_SIZE(r) * sizeof(struct vfio_user_dma_region),
                                             true, fds, 2, r));
}

/*
 * Checks that handle_dma_map_or_unmap returns 0 when dma_controller_add_region 
 * succeeds.
 */
static void
test_dma_map_return_value(void **state __attribute__((unused)))
{
    dma_controller_t dma = { 0 };
    vfu_ctx_t vfu_ctx = { .dma = &dma };
    dma.vfu_ctx = &vfu_ctx;
    struct vfio_user_dma_region r = { 0 };
    int fd = 0;

    patch(dma_controller_add_region);
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r.addr);
    expect_value(__wrap_dma_controller_add_region, size, r.size);
    expect_value(__wrap_dma_controller_add_region, fd, -1);
    expect_value(__wrap_dma_controller_add_region, offset, r.offset);
    expect_value(__wrap_dma_controller_add_region, prot, r.prot);
    will_return(__wrap_dma_controller_add_region, 2);

    assert_int_equal(0,
        handle_dma_map_or_unmap(&vfu_ctx, sizeof(struct vfio_user_dma_region),
            true, &fd, 0, &r));
}

static void
test_dma_controller_add_region_no_fd(void **state __attribute__((unused)))
{
    vfu_ctx_t vfu_ctx = { 0 };
    dma_controller_t dma = { .vfu_ctx = &vfu_ctx, .max_regions = 1 };
    dma_addr_t dma_addr = 0xdeadbeef;
    size_t size = 0;
    int fd = -1;
    off_t offset = 0;
    dma_memory_region_t *r;

    assert_int_equal(0, dma_controller_add_region(&dma, dma_addr, size, fd,
                     offset, PROT_NONE));
    assert_int_equal(1, dma.nregions);
    r = &dma.regions[0];
    assert_ptr_equal(NULL, r->virt_addr);
    assert_ptr_equal(dma_addr, r->dma_addr);
    assert_int_equal(size, r->size);
    assert_int_equal(0x1000, r->page_size);
    assert_int_equal(offset, r->offset);
    assert_int_equal(fd, r->fd);
    assert_int_equal(0, r->refcnt);
    assert_int_equal(PROT_NONE, r->prot);
}

static void
test_dma_controller_remove_region_no_fd(void **state __attribute__((unused)))
{
    dma_memory_region_t r = {
        .dma_addr = 0xdeadbeef,
        .size = 0x100,
        .fd = -1,
        .virt_addr = NULL
    };
    vfu_ctx_t vfu_ctx = { 0 };
    dma_controller_t *dma = alloca(sizeof(*dma) + sizeof(r));
    dma->vfu_ctx = &vfu_ctx;
    dma->nregions = 1;
    dma->max_regions = 1;
    dma->regions[0] = r;
    patch(_dma_controller_do_remove_region);
    expect_value(__wrap__dma_controller_do_remove_region, dma, dma);
    expect_value(__wrap__dma_controller_do_remove_region, region, &dma->regions[0]);
    assert_int_equal(0, dma_controller_remove_region(dma, r.dma_addr, r.size, NULL, NULL));
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
           const long unsigned int data __attribute__((unused)))
{
    int *nr_fds = (int*)value;
    assert(nr_fds != NULL);
    *nr_fds = ARRAY_SIZE(fds);
    return 1;
}

/*
 * Tests that if if exec_command fails then process_request frees passed file
 * descriptors.
 */
static void
test_process_command_free_passed_fds(void **state __attribute__((unused)))
{
    vfu_ctx_t vfu_ctx = {
        .conn_fd = 0xcafebabe,
        .migration = (struct migration*)0x8badf00d
    };

    patch(device_is_stopped);
    expect_value(__wrap_device_is_stopped, migr, vfu_ctx.migration);
    will_return(__wrap_device_is_stopped, false);

    patch(get_next_command);
    expect_value(__wrap_get_next_command, vfu_ctx, &vfu_ctx);
    expect_any(__wrap_get_next_command, hdr);
    expect_check(__wrap_get_next_command, fds, &set_fds, &get_next_command);
    expect_check(__wrap_get_next_command, nr_fds, &set_nr_fds, NULL);
    will_return(__wrap_get_next_command, 0x0000beef);

    patch(exec_command);
    expect_value(__wrap_exec_command, vfu_ctx, &vfu_ctx);
    expect_any(__wrap_exec_command, hdr);
    expect_value(__wrap_exec_command, size, 0x0000beef);
    expect_check(__wrap_exec_command, fds, &set_fds, &exec_command);
    expect_any(__wrap_exec_command, nr_fds);
    expect_any(__wrap_exec_command, fds_out);
    expect_any(__wrap_exec_command, nr_fds_out);
    expect_any(__wrap_exec_command, _iovecs);
    expect_any(__wrap_exec_command, iovecs);
    expect_any(__wrap_exec_command, nr_iovecs);
    expect_any(__wrap_exec_command, free_iovec_data);
    will_return(__wrap_exec_command, -0x1234);

    patch(close);
    expect_value(__wrap_close, fd, 0xcd);
    will_return(__wrap_close, 0);

    patch(vfu_send_iovec);
    expect_value(__wrap_vfu_send_iovec, sock, vfu_ctx.conn_fd);
    expect_any(__wrap_vfu_send_iovec, msg_id);
    expect_value(__wrap_vfu_send_iovec, is_reply, true);
    expect_any(__wrap_vfu_send_iovec, cmd);
    expect_any(__wrap_vfu_send_iovec, iovecs);
    expect_any(__wrap_vfu_send_iovec, nr_iovecs);
    expect_any(__wrap_vfu_send_iovec, fds);
    expect_any(__wrap_vfu_send_iovec, count);
    expect_any(__wrap_vfu_send_iovec, err);
    will_return(__wrap_vfu_send_iovec, 0);

    assert_int_equal(0, process_request(&vfu_ctx));
}

static void
test_realize_ctx(void **state __attribute__((unused)))
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
}

static int
dummy_attach(vfu_ctx_t *vfu_ctx)
{
    assert(vfu_ctx != NULL);

    return 222;
}

static void
test_attach_ctx(void **state __attribute__((unused)))
{
    struct transport_ops transport_ops = {
        .attach = &dummy_attach,
    };
    vfu_ctx_t vfu_ctx = {
        .trans = &transport_ops,
    };

    assert_int_equal(222, vfu_attach_ctx(&vfu_ctx));
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

    patch(process_request);
    expect_value(__wrap_process_request, vfu_ctx, &vfu_ctx);
    will_return(__wrap_process_request, 0);
    assert_int_equal(0, vfu_run_ctx(&vfu_ctx));

    // device realized, with blocking vfu_ctx
    vfu_ctx.flags = 0;
    expect_value(__wrap_process_request, vfu_ctx, &vfu_ctx);
    will_return(__wrap_process_request, 0);

    expect_value(__wrap_process_request, vfu_ctx, &vfu_ctx);
    will_return(__wrap_process_request, -1);
    assert_int_equal(-1, vfu_run_ctx(&vfu_ctx));
}

static void
test_get_region_info(UNUSED void **state)
{
    struct iovec iov = { .iov_base = (void*)0x8badf00, .iov_len = 0x0d15ea5e };
    vfu_reg_info_t reg_info[] = {
        {
            .size = 0xcadebabe
        },
        {
            .flags = VFU_REGION_FLAG_RW,
            .size = 0xdeadbeef,
            .fd = 0x12345
        }
    };
    vfu_ctx_t vfu_ctx = {
        .client_max_fds = 1,
        .nr_regions = 2,
        .reg_info = reg_info
    };
    uint32_t index = 0;
    uint32_t argsz = 0;
    struct vfio_region_info *vfio_reg;
    int *fds = NULL;
    size_t nr_fds;

    /* bad argsz */
    assert_int_equal(-EINVAL,
                     dev_get_reginfo(&vfu_ctx, index, argsz, &vfio_reg,
                                     &fds, &nr_fds));

    /* bad region */
    index = vfu_ctx.nr_regions;
    argsz = sizeof(struct vfio_region_info);
    assert_int_equal(-EINVAL,
                     dev_get_reginfo(&vfu_ctx, index, argsz, &vfio_reg,
                                     &fds, &nr_fds));

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

    /* FIXME add check for migration region and for multiple sparse areas */
}

/*
 * FIXME expand and validate
 */
static void
test_vfu_ctx_create(void **state __attribute__((unused)))
{
    vfu_ctx_t *vfu_ctx = NULL;
    struct pmcap pm = { { 0 } };

    pm.hdr.id = PCI_CAP_ID_PM;
    pm.pmcs.nsfrst = 0x1;

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
}

static ssize_t
test_pci_caps_region_cb(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                        loff_t offset, bool is_write)
{
    uint8_t *ptr = pci_config_space_ptr(vfu_ctx, offset);

    assert_int_equal(is_write, true);
    assert_int_equal(offset, PCI_STD_HEADER_SIZEOF + PCI_PM_SIZEOF + 8 +
                             offsetof(struct vsc, data));
    assert_int_equal(count, 10);
    assert_memory_equal(ptr, "Hello world.", 10);
    memcpy(ptr, buf, count);
    return count;
}

static void
test_pci_caps(void **state __attribute__((unused)))
{
    vfu_pci_config_space_t config_space;
    vfu_reg_info_t reg_info[VFU_PCI_DEV_NUM_REGIONS] = {
        [VFU_PCI_DEV_CFG_REGION_IDX] = { .size = PCI_CFG_SPACE_SIZE },
    };
    vfu_ctx_t vfu_ctx = { .pci.config_space = &config_space,
                          .reg_info = reg_info,
    };
    struct vsc *vsc1 = alloca(sizeof (*vsc1) + 3);
    struct vsc *vsc2 = alloca(sizeof (*vsc2) + 13);
    struct vsc *vsc3 = alloca(sizeof (*vsc3) + 13);
    struct vsc *vsc4 = alloca(sizeof (*vsc4) + 13);
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

    memset(&config_space, 0, sizeof (config_space));

    vfu_ctx.reg_info = calloc(VFU_PCI_DEV_NUM_REGIONS,
                              sizeof (*vfu_ctx.reg_info));

    pm.hdr.id = PCI_CAP_ID_PM;
    pm.pmcs.raw = 0xef01;

    vsc1->hdr.id = PCI_CAP_ID_VNDR;
    vsc1->size = 6;
    memcpy(vsc1->data, "abc", 3);

    vsc2->hdr.id = PCI_CAP_ID_VNDR;
    vsc2->size = 16;
    memcpy(vsc2->data, "Hello world.", 12);

    vsc3->hdr.id = PCI_CAP_ID_VNDR;
    vsc3->size = 16;
    memcpy(vsc3->data, "Hello world.", 12);

    vsc4->hdr.id = PCI_CAP_ID_VNDR;
    vsc4->size = 16;
    memcpy(vsc4->data, "Hello world.", 12);

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
                                  sizeof (struct pmcs), expoffsets[0] +
                                  offsetof(struct pmcap, pmcs), true);

    assert_int_equal(sizeof (struct pmcs), ret);

    assert_memory_equal(pci_config_space_ptr(&vfu_ctx, expoffsets[0] +
                                             offsetof(struct pmcap, pmcs)),
                        &pm.pmcs, sizeof (struct pmcs));

    /* check read only capability */

    ret = pci_config_space_access(&vfu_ctx, (char *)vsc1->data, 3,
                                  expoffsets[1] + offsetof(struct vsc, data),
                                  false);
    assert_int_equal(ret, 3);
    assert_memory_equal(vsc1->data, "abc", 3);

    ret = pci_config_space_access(&vfu_ctx, "ced", 3,
                                  expoffsets[1] + offsetof(struct vsc, data),
                                  true);
    assert_int_equal(ret, -EPERM);

    /* check capability callback */

    ret = pci_config_space_access(&vfu_ctx, "Bye world.", 10,
                                  expoffsets[2] + offsetof(struct vsc, data),
                                  true);

    assert_int_equal(ret, 10);
    assert_memory_equal(pci_config_space_ptr(&vfu_ctx,
                        expoffsets[2] + offsetof(struct vsc, data)),
                        "Bye world.", 10);
}

static ssize_t
test_pci_ext_caps_region_cb(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                            loff_t offset, bool is_write)
{
    uint8_t *ptr = pci_config_space_ptr(vfu_ctx, offset);

    assert_int_equal(is_write, true);
    assert_int_equal(offset, PCI_CFG_SPACE_SIZE + sizeof (struct dsncap) +
                     sizeof (struct pcie_ext_cap_vsc_hdr) + 8 +
                     sizeof (struct pcie_ext_cap_vsc_hdr));
    assert_int_equal(count, 10);
    assert_memory_equal(ptr, "Hello world.", 10);
    memcpy(ptr, buf, count);
    return count;
}

static void
test_pci_ext_caps(void **state __attribute__((unused)))
{
    uint8_t config_space[PCI_CFG_SPACE_EXP_SIZE] = { 0, };
    vfu_reg_info_t reg_info[VFU_PCI_DEV_NUM_REGIONS] = {
        [VFU_PCI_DEV_CFG_REGION_IDX] = { .size = PCI_CFG_SPACE_EXP_SIZE },
    };
    vfu_ctx_t vfu_ctx = { .pci.config_space = (void *)&config_space,
                          .reg_info = reg_info,
    };

    struct pcie_ext_cap_vsc_hdr *vsc1 = alloca(sizeof (*vsc1) + 5);
    struct pcie_ext_cap_vsc_hdr *vsc2 = alloca(sizeof (*vsc2) + 13);
    struct pcie_ext_cap_vsc_hdr *vsc3 = alloca(sizeof (*vsc3) + 13);
    struct pcie_ext_cap_vsc_hdr *vsc4 = alloca(sizeof (*vsc4) + 13);
    struct pcie_ext_cap_hdr *hdr;
    size_t expoffsets[] = {
        PCI_CFG_SPACE_SIZE,
        PCI_CFG_SPACE_SIZE + sizeof (struct dsncap),
        PCI_CFG_SPACE_SIZE + sizeof (struct dsncap) + sizeof (*vsc1) + 8,
        512,
        600
    };
    struct dsncap dsn;
    size_t offset;
    ssize_t ret;

    vfu_ctx.pci.type = VFU_PCI_TYPE_EXPRESS;

    vfu_ctx.reg_info = calloc(VFU_PCI_DEV_NUM_REGIONS,
                              sizeof (*vfu_ctx.reg_info));

    vfu_ctx.reg_info[VFU_PCI_DEV_CFG_REGION_IDX].cb = test_pci_ext_caps_region_cb;
    vfu_ctx.reg_info[VFU_PCI_DEV_CFG_REGION_IDX].size = PCI_CFG_SPACE_EXP_SIZE;

    dsn.hdr.id = PCI_EXT_CAP_ID_DSN;
    dsn.sn_lo = 0x4;
    dsn.sn_hi = 0x8;

    vsc1->hdr.id = PCI_EXT_CAP_ID_VNDR;
    vsc1->len = sizeof (*vsc1) + 5;
    memcpy(vsc1->data, "abcde", 5);
    vsc2->hdr.id = PCI_EXT_CAP_ID_VNDR;
    vsc2->len = sizeof (*vsc2) + 13;
    memcpy(vsc2->data, "Hello world.", 12);
    vsc3->hdr.id = PCI_EXT_CAP_ID_VNDR;
    vsc3->len = sizeof (*vsc3) + 13;
    memcpy(vsc3->data, "Hello world.", 12);
    vsc4->hdr.id = PCI_EXT_CAP_ID_VNDR;
    vsc4->len = sizeof (*vsc4) + 13;
    memcpy(vsc4->data, "Hello world.", 12);

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
    assert_int_equal(ret, -EPERM);

    /* check capability callback */

    ret = pci_config_space_access(&vfu_ctx, "Bye world.", 10,
                                  expoffsets[2] + offsetof(struct pcie_ext_cap_vsc_hdr, data),
                                  true);

    assert_int_equal(ret, 10);
    assert_memory_equal(pci_config_space_ptr(&vfu_ctx,
                        expoffsets[2] + offsetof(struct pcie_ext_cap_vsc_hdr, data)),
                        "Bye world.", 10);
}

static void
test_device_get_info(void **state __attribute__((unused)))
{
    vfu_ctx_t vfu_ctx = { .nr_regions = 0xdeadbeef};
    struct vfio_device_info d = { 0 };

    assert_int_equal(0, handle_device_get_info(&vfu_ctx, sizeof d, &d));
    assert_int_equal(sizeof d, d.argsz);
    assert_int_equal(VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET, d.flags);
    assert_int_equal(vfu_ctx.nr_regions, d.num_regions);
    assert_int_equal(VFU_DEV_NUM_IRQS, d.num_irqs);
}

/*
 * Checks that handle_device_get_info handles correctly struct vfio_device_info
 * with more fields.
 */
static void
test_device_get_info_compat(void **state __attribute__((unused)))
{
    vfu_ctx_t vfu_ctx = { .nr_regions = 0xdeadbeef};
    struct vfio_device_info d = { 0 };

    /* more fields */
    assert_int_equal(0, handle_device_get_info(&vfu_ctx, (sizeof d) + 1, &d));
    assert_int_equal(sizeof d, d.argsz);
    assert_int_equal(VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET, d.flags);
    assert_int_equal(vfu_ctx.nr_regions, d.num_regions);
    assert_int_equal(VFU_DEV_NUM_IRQS, d.num_irqs);

    /* fewer fields */
    assert_int_equal(-EINVAL, handle_device_get_info(&vfu_ctx, (sizeof d) - 1, &d));
}


/*
 * Performs various checks when adding sparse memory regions.
 */
static void
test_setup_sparse_region(void **state __attribute__((unused)))
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
}

static void
test_dma_map_sg(void **state __attribute__((unused)))
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
    assert_int_equal(-EINVAL, dma_map_sg(dma, &sg, &iovec, 1));

    /* w/o fd */
    sg.region = 0;
    assert_int_equal(-EFAULT, dma_map_sg(dma, &sg, &iovec, 1));

    /* w/ fd */
    dma->regions[0].virt_addr = (void*)0xdead0000;
    sg.offset = 0x0000beef;
    sg.length = 0xcafebabe;
    assert_int_equal(0, dma_map_sg(dma, &sg, &iovec, 1));
    assert_int_equal(0xdeadbeef, iovec.iov_base);
    assert_int_equal((int)0x00000000cafebabe, iovec.iov_len);

}

static void
test_dma_addr_to_sg(void **state __attribute__((unused)))
{
    dma_controller_t *dma = alloca(sizeof(dma_controller_t) + sizeof(dma_memory_region_t));
    dma_sg_t sg;
    dma_memory_region_t *r;

    dma->nregions = 1;
    r = &dma->regions[0];
    r->dma_addr = 0x1000;
    r->size = 0x4000;
    r->virt_addr = (void*)0xdeadbeef;

    /* fast path, region hint hit */
    assert_int_equal(1,
        dma_addr_to_sg(dma, 0x2000, 0x400, &sg, 1, PROT_NONE));
    assert_int_equal(r->dma_addr, sg.dma_addr);
    assert_int_equal(0, sg.region);
    assert_int_equal(0x2000 - r->dma_addr, sg.offset);
    assert_int_equal(0x400, sg.length);
    assert_true(sg.mappable);

    /* TODO test more scenarios */
}

static void
test_vfu_setup_device_dma_cb(void **state __attribute__((unused)))
{
    vfu_ctx_t vfu_ctx = { 0 };

    assert_int_equal(0, vfu_setup_device_dma_cb(&vfu_ctx, NULL, NULL));
    assert_non_null(vfu_ctx.dma);
}

/*
 * FIXME we shouldn't have to specify a setup function explicitly for each unit
 * test, cmocka should provide that. E.g. cmocka_run_group_tests enables us to
 * run a function before/after ALL unit tests have finished, we can extend it
 * and provide a function to execute before and after each unit test.
 */
static int
setup(void **state __attribute__((unused))) {
    unpatch_all();
    return 0;
}

int main(void)
{
   const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_dma_map_without_dma, setup),
        cmocka_unit_test_setup(test_dma_map_mappable_without_fd, setup),
        cmocka_unit_test_setup(test_dma_map_without_fd, setup),
        cmocka_unit_test_setup(test_dma_add_regions_mixed, setup),
        cmocka_unit_test_setup(test_dma_add_regions_mixed_partial_failure, setup),
        cmocka_unit_test_setup(test_dma_controller_add_region_no_fd, setup),
        cmocka_unit_test_setup(test_dma_controller_remove_region_no_fd, setup),
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
        cmocka_unit_test_setup(test_vfu_setup_device_dma_cb, setup)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
