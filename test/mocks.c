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
#include <stdio.h>

#include "mocks.h"
#include "dma.h"

struct function
{
    void *addr;
    bool patched;
};

int
__wrap_dma_controller_add_region(dma_controller_t *dma, dma_addr_t dma_addr,
                                 size_t size, int fd, off_t offset)
{
    if (!is_patched(dma_controller_add_region)) {
        return __real_dma_controller_add_region(dma, dma_addr, size, fd, offset);
    }

    check_expected_ptr(dma);
    check_expected(dma_addr);
    check_expected(size);
    check_expected(fd);
    check_expected(offset);
    return 0;
}

void *
__wrap_dma_map_region(dma_memory_region_t *region, int prot, size_t offset,
                      size_t len)
{
    check_expected_ptr(region);
    check_expected(prot);
    check_expected(offset);
    check_expected(len);
    return 0;
}

void
__wrap__dma_controller_do_remove_region(dma_controller_t *dma,
                                       dma_memory_region_t *region)
{
    check_expected(dma);
    check_expected(region);
}

/* FIXME should be something faster than unsorted array, look at tsearch(3). */
static struct function funcs[] = {
    {.addr = &__wrap_dma_controller_add_region},
    {.addr = &__wrap_dma_map_region},
    {.addr = &__wrap__dma_controller_do_remove_region},
};

static struct function*
find(void *addr)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(funcs); i++) {
        if (addr == funcs[i].addr) {
            return &funcs[i];
        }
    }
    assert(false);
}

void
patch(void *addr)
{
    struct function *func = find(addr);
    func->patched = true;
}

bool
is_patched(void *addr)
{
    return find(addr)->patched;
}

void
unpatch_all(void)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(funcs); i++) {
        funcs[i].patched = false;
    }
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
