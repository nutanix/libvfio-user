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

#include "dma.h"
#include "libvfio-user.h"
#include "private.h"

static void
test_dma_map_without_dma(void **state __attribute__((unused)))
{
    vu_ctx_t vu_ctx = { 0 };
    size_t size = sizeof(struct vfio_user_dma_region);
    struct vfio_user_dma_region dma_region = {
        .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
    };
    int fd;

    assert_int_equal(0, handle_dma_map_or_unmap(&vu_ctx, size, true, &fd, 1, &dma_region));
}

static void
test_dma_map_mappable_without_fd(void **state __attribute__((unused)))
{
    dma_controller_t dma = { 0 };
    vu_ctx_t vu_ctx = { .dma = &dma };
    size_t size = sizeof(struct vfio_user_dma_region);
    struct vfio_user_dma_region dma_region = {
        .flags = VFIO_USER_F_DMA_REGION_MAPPABLE
    };
    int fd;
    assert_int_equal(-EINVAL, handle_dma_map_or_unmap(&vu_ctx, size, true, &fd, 0, &dma_region));
}

static void
test_dma_map_without_fd(void **state __attribute__((unused)))
{
    dma_controller_t dma = { 0 };
    vu_ctx_t vu_ctx = { .dma = &dma };
    dma.vu_ctx = &vu_ctx;
    size_t size = sizeof(struct vfio_user_dma_region);

    struct vfio_user_dma_region r = {
        .addr = 0xdeadbeef,
        .size = 0xcafebabe,
        .offset = 0x8badf00d
    };
    int fd;

    patch(dma_controller_add_region);
    expect_value(__wrap_dma_controller_add_region, dma, vu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r.addr);
    expect_value(__wrap_dma_controller_add_region, size, r.size);
    expect_value(__wrap_dma_controller_add_region, fd, -1);
    expect_value(__wrap_dma_controller_add_region, offset, r.offset);
    assert_int_equal(0, handle_dma_map_or_unmap(&vu_ctx, size, true, &fd, 0, &r));
}

/*
 * Tests that adding multiple DMA regions where not all of them are mappable
 * results in only the mappable one being memory mapped.
 */
static void
test_dma_add_regions_mixed(void **state __attribute__((unused)))
{
    dma_controller_t dma = { 0 };
    vu_ctx_t vu_ctx = { .dma = &dma };
    dma.vu_ctx = &vu_ctx;
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
    int fd = 0x8badf00d;

    patch(dma_controller_add_region);
    expect_value(__wrap_dma_controller_add_region, dma, vu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[0].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[0].size);
    expect_value(__wrap_dma_controller_add_region, fd, -1);
    expect_value(__wrap_dma_controller_add_region, offset, r[0].offset);
    expect_value(__wrap_dma_controller_add_region, dma, vu_ctx.dma);
    expect_value(__wrap_dma_controller_add_region, dma_addr, r[1].addr);
    expect_value(__wrap_dma_controller_add_region, size, r[1].size);
    expect_value(__wrap_dma_controller_add_region, fd, fd);
    expect_value(__wrap_dma_controller_add_region, offset, r[1].offset);

    assert_int_equal(0, handle_dma_map_or_unmap(&vu_ctx, sizeof r, true, &fd, 1, r));
}


static void
test_dma_controller_add_region_no_fd(void **state __attribute__((unused)))
{
    vu_ctx_t vu_ctx = { 0 };
    dma_controller_t dma = { .vu_ctx = &vu_ctx, .max_regions = 1 };
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
    vu_ctx_t vu_ctx = { 0 };
    dma_controller_t *dma = alloca(sizeof(*dma) + sizeof(r));
    dma->vu_ctx = &vu_ctx;
    dma->nregions = 1;
    dma->max_regions = 1;
    dma->regions[0] = r;
    patch(_dma_controller_do_remove_region);
    expect_value(__wrap__dma_controller_do_remove_region, dma, dma);
    expect_value(__wrap__dma_controller_do_remove_region, region, &dma->regions[0]);
    assert_int_equal(0, dma_controller_remove_region(dma, r.dma_addr, r.size, NULL, NULL));
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
        cmocka_unit_test_setup(test_dma_controller_add_region_no_fd, setup),
        cmocka_unit_test_setup(test_dma_controller_remove_region_no_fd, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
