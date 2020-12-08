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

#include "dma.h"
#include "libvfio-user.h"
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
        .offset = 0x8badf00d
    };
    int fd;

    patch(dma_controller_add_region);
    will_return(__wrap_dma_controller_add_region, 0);
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r.addr);
    expect_value(__wrap_dma_controller_add_region, size, r.size);
    expect_value(__wrap_dma_controller_add_region, fd, -1);
    expect_value(__wrap_dma_controller_add_region, offset, r.offset);
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
            .offset = 0
        },
        [1] = {
            .addr = 0xcafebabe,
            .size = 0x1000,
            .offset = 0x1000,
            .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
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
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[1].size);
    expect_value(__wrap_dma_controller_add_region, fd, fd);
    expect_value(__wrap_dma_controller_add_region, offset, r[1].offset);

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
            .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
        },
        [2] = {
            .addr = 0xbabecafe,
            .size = 0x1000,
            .offset = 0x2000,
            .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
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
    will_return(__wrap_dma_controller_add_region, 0);

    /* 2nd region */
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[1].size);
    expect_value(__wrap_dma_controller_add_region, fd, fds[0]);
    expect_value(__wrap_dma_controller_add_region, offset, r[1].offset);
    will_return(__wrap_dma_controller_add_region, 0);

    /* 3rd region */
    expect_value(__wrap_dma_controller_add_region, dma, vfu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[2].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[2].size);
    expect_value(__wrap_dma_controller_add_region, fd, fds[1]);
    expect_value(__wrap_dma_controller_add_region, offset, r[2].offset);
    will_return(__wrap_dma_controller_add_region, -0x1234);

    patch(close);
    expect_value(__wrap_close, fd, 0xb);
    will_return(__wrap_close, 0);

    assert_int_equal(-0x1234,
                     handle_dma_map_or_unmap(&vfu_ctx,
                                             ARRAY_SIZE(r) * sizeof(struct vfio_user_dma_region),
                                             true, fds, 2, r));
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

    assert_int_equal(0, dma_controller_add_region(&dma, dma_addr, size, fd, offset));
    assert_int_equal(1, dma.nregions);
    r = &dma.regions[0];
    assert_ptr_equal(NULL, r->virt_addr);
    assert_ptr_equal(dma_addr, r->dma_addr);
    assert_int_equal(size, r->size);
    assert_int_equal(0x1000, r->page_size);
    assert_int_equal(offset, r->offset);
    assert_int_equal(fd, r->fd);
    assert_int_equal(0, r->refcnt);
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

/*
 * Tests that if if exec_command fails then process_request frees passed file
 * descriptors.
 */
static void
test_process_command_free_passed_fds(void **state __attribute__((unused)))
{
    int fds[] = {0xab, 0xcd};
    int set_fds(const long unsigned int value,
                const long unsigned int data)
    {
        assert(value != 0);
        if ((void*)data == &get_next_command) {
            memcpy((int*)value, fds, ARRAY_SIZE(fds) * sizeof(int));
        } else if ((void*)data == &exec_command) {
            ((int*)value)[0] = -1;
        }
        return 1;
    }
    int set_nr_fds(const long unsigned int value,
                   const long unsigned int data __attribute__((unused)))
    {
        int *nr_fds = (int*)value;
        assert(nr_fds != NULL);
        *nr_fds = ARRAY_SIZE(fds);
        return 1;
    }

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
    vfu_reg_info_t reg_info[VFU_PCI_DEV_NUM_REGIONS + 1] = { 0 };
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
    assert_null(vfu_ctx.pci.caps);
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
        .fd = 111
    };

    assert_int_equal(222, vfu_attach_ctx(&vfu_ctx));
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
