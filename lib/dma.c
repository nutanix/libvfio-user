/*
 * Copyright (c) 2019 Nutanix Inc. All rights reserved.
 *
 * Authors: Mike Cui <cui@nutanix.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/param.h>

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include "dma.h"
#include "fd_cache.h"
#include "private.h"

EXPORT size_t
dma_sg_size(void)
{
    return sizeof(dma_sg_t);
}

bool
dma_sg_is_mappable(const dma_sg_t *sg) {
    return sg->region->info.vaddr != NULL;
}

static inline ssize_t
fd_get_blocksize(int fd)
{
    struct stat st;

    if (fstat(fd, &st) != 0)
        return -1;

    return st.st_blksize;
}

static int
dirty_page_logging_start_on_region(dma_memory_region_t *region, size_t pgsize)
{
    assert(region->fd != -1);

    ssize_t size = get_bitmap_size(region->info.iova.iov_len, pgsize);
    if (size < 0) {
        return size;
    }

    region->dirty_bitmap = calloc(size, 1);
    if (region->dirty_bitmap == NULL) {
        return ERROR_INT(errno);
    }
    return 0;
}

static void
dirty_page_logging_stop_on_region(dma_memory_region_t *region)
{
    if (region->dirty_bitmap != NULL) {
        free(region->dirty_bitmap);
        region->dirty_bitmap = NULL;
    }
}

dma_controller_t *
dma_controller_create(vfu_ctx_t *vfu_ctx, size_t max_regions, size_t max_size)
{
    dma_controller_t *dma;

    dma = calloc(1, sizeof(*dma));
    if (dma == NULL) {
        return dma;
    }

    dma->vfu_ctx = vfu_ctx;
    dma->max_regions = (int)max_regions;
    dma->max_size = max_size;
    dma->dirty_pgsize = 0;
    btree_init(&dma->regions);
    dma->regions_generation = 1;

    return dma;
}

static inline void
dma_controller_increment_regions_generation(dma_controller_t *dma)
{
    /*
     * DMA region generation identifier: Incremented whenever the shape of the
     * DMA address space (i.e. the regions tree in a DMA controller) changes due
     * to a client adding or removing target regions. This is used to invalidate
     * thread-local cached region pointers belonging to previous generations.
     *
     * This global supplies identifiers for all DMA controller instances. This
     * makes sure that even with multiple DMA controllers, each generation
     * identifier will be unique. Otherwise, we could get identifier collisions
     * between DMA controller instances, and failing to ignore caches after DMA
     * address space changes.
     */
    static uint64_t dma_regions_generation = 1;

    dma->regions_generation =
        __atomic_add_fetch(&dma_regions_generation, 1, __ATOMIC_RELEASE);

    /*
     * The generations counter is wide enough such that it will not overflow in
     * practice: Even if we were to perform 2^32 region updates per second
     * (which is completely unrealistic given that updates are performed via
     * IPC), it would still take more than 136 years to burn through the
     * higher-order 32 bits.
     */
    assert(dma->regions_generation != UINT64_MAX);
}

void
MOCK_DEFINE(dma_controller_unmap_region)(dma_controller_t *dma,
                                         dma_memory_region_t *region)
{
    int err;

    assert(dma != NULL);
    assert(region != NULL);

    err = munmap(region->info.mapping.iov_base, region->info.mapping.iov_len);
    if (err != 0) {
        vfu_log(dma->vfu_ctx, LOG_DEBUG, "failed to unmap fd=%d "
                "mapping=[%p, %p): %m",
                region->fd, region->info.mapping.iov_base,
                iov_end(&region->info.mapping));
    }

    assert(region->fd != -1);

    dirty_page_logging_stop_on_region(region);

    err = fd_cache_put(&region->fd);
    assert(err == 0);
}

/* FIXME not thread safe */
int
MOCK_DEFINE(dma_controller_remove_region)(dma_controller_t *dma,
                                          vfu_dma_addr_t dma_addr, size_t size,
                                          vfu_dma_unregister_cb_t *dma_unregister,
                                          void *data)
{
    dma_memory_region_t *region;
    btree_iter_t iter;

    assert(dma != NULL);

    btree_iter_init(&dma->regions, (uintptr_t)dma_addr, &iter);
    region = btree_iter_get(&iter, NULL);
    if (region == NULL) {
        return ERROR_INT(ENOENT);
    }

    if (region->info.iova.iov_base != dma_addr ||
        region->info.iova.iov_len != size) {
        return ERROR_INT(ENOENT);
    }

    if (dma_unregister != NULL) {
        dma->vfu_ctx->in_cb = CB_DMA_UNREGISTER;
        dma_unregister(data, &region->info);
        dma->vfu_ctx->in_cb = CB_NONE;
    }

    if (region->info.vaddr != NULL) {
        dma_controller_unmap_region(dma, region);
    } else {
        assert(region->fd == -1);
    }

    btree_iter_remove(&iter);
    dma_controller_increment_regions_generation(dma);
    free(region);

    return 0;
}

void
dma_controller_remove_all_regions(dma_controller_t *dma,
                                  vfu_dma_unregister_cb_t *dma_unregister,
                                  void *data)
{
    dma_memory_region_t *region = NULL;
    btree_iter_t iter;

    assert(dma != NULL);

    btree_iter_init(&dma->regions, 0, &iter);
    while ((region = btree_iter_remove(&iter)) != NULL) {
        vfu_log(dma->vfu_ctx, LOG_DEBUG,
                "removing DMA region "
                "iova=[%p, %p) vaddr=%p mapping=[%p, %p)",
                region->info.iova.iov_base, iov_end(&region->info.iova),
                region->info.vaddr, region->info.mapping.iov_base,
                iov_end(&region->info.mapping));

        if (dma_unregister != NULL) {
            dma->vfu_ctx->in_cb = CB_DMA_UNREGISTER;
            dma_unregister(data, &region->info);
            dma->vfu_ctx->in_cb = CB_NONE;
        }

        if (region->info.vaddr != NULL) {
            dma_controller_unmap_region(dma, region);
        } else {
            assert(region->fd == -1);
        }

        free(region);
    }
}

void
dma_controller_destroy(dma_controller_t *dma)
{
    assert(btree_size(&dma->regions) == 0);
    btree_destroy(&dma->regions);
    free(dma);
}

static int
dma_map_region(dma_controller_t *dma, dma_memory_region_t *region)
{
    void *mmap_base;
    size_t mmap_len;
    off_t offset;

    offset = ROUND_DOWN(region->offset, region->info.page_size);
    mmap_len = ROUND_UP(region->info.iova.iov_len, region->info.page_size);

    mmap_base = mmap(NULL, mmap_len, region->info.prot, MAP_SHARED,
                     region->fd, offset);

    if (mmap_base == MAP_FAILED) {
        return -1;
    }

    // Do not dump.
    madvise(mmap_base, mmap_len, MADV_DONTDUMP);

    region->info.mapping.iov_base = mmap_base;
    region->info.mapping.iov_len = mmap_len;
    region->info.vaddr = mmap_base + (region->offset - offset);

    vfu_log(dma->vfu_ctx, LOG_DEBUG, "mapped DMA region iova=[%p, %p) "
            "vaddr=%p page_size=%zx mapping=[%p, %p)",
            region->info.iova.iov_base, iov_end(&region->info.iova),
            region->info.vaddr, region->info.page_size,
            region->info.mapping.iov_base, iov_end(&region->info.mapping));


    return 0;
}

dma_memory_region_t *
MOCK_DEFINE(dma_controller_add_region)(dma_controller_t *dma,
                                       vfu_dma_addr_t dma_addr, uint64_t size,
                                       int fd, off_t offset, uint32_t prot)
{
    dma_memory_region_t *existing = NULL;
    dma_memory_region_t *region = NULL;
    btree_iter_t iter;
    int page_size = 0;
    char rstr[1024];
    int ret = 0;
    int err;

    assert(dma != NULL);

    snprintf(rstr, sizeof(rstr), "[%p, %p) fd=%d offset=%#llx prot=%#x",
             dma_addr, dma_addr + size, fd, (ull_t)offset, prot);

    if (size > dma->max_size) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "DMA region size %llu > max %zu",
                (unsigned long long)size, dma->max_size);
        return ERROR_PTR(ENOSPC);
    }

    btree_iter_init(&dma->regions, (uintptr_t)dma_addr, &iter);
    existing = btree_iter_get(&iter, NULL);
    if (existing != NULL) {
        /* First check if this is the same exact region. */
        if (existing->info.iova.iov_base == dma_addr &&
            existing->info.iova.iov_len == size) {
            if (offset != existing->offset) {
                vfu_log(dma->vfu_ctx, LOG_ERR, "bad offset for new DMA region "
                        "%s; existing=%#llx", rstr,
                        (ull_t)existing->offset);
                return ERROR_PTR(EINVAL);
            }
            if (fd_cache_is_same_file(existing->fd, fd) != 0) {
                vfu_log(dma->vfu_ctx, LOG_ERR, "bad fd for new DMA region %s; "
                        "existing=%d", rstr, existing->fd);
                return ERROR_PTR(EINVAL);
            }
            if (existing->info.prot != prot) {
                vfu_log(dma->vfu_ctx, LOG_ERR, "bad prot for new DMA region "
                        "%s; existing=%#x", rstr, existing->info.prot);
                return ERROR_PTR(EINVAL);
            }
            close_safely(&fd);
            return existing;
        }

        /* Check for overlap, i.e. start of one region is within another. */
        if ((dma_addr >= existing->info.iova.iov_base &&
             dma_addr < iov_end(&existing->info.iova)) ||
            (existing->info.iova.iov_base >= dma_addr &&
             existing->info.iova.iov_base < dma_addr + size)) {
            vfu_log(dma->vfu_ctx, LOG_INFO, "new DMA region %s overlaps with "
                    "DMA region [%p, %p)", rstr, existing->info.iova.iov_base,
                    iov_end(&existing->info.iova));
            return ERROR_PTR(EINVAL);
        }
    }

    if (btree_size(&dma->regions) == dma->max_regions) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "hit max regions %zu", dma->max_regions);
        return ERROR_PTR(EINVAL);
    }

    if (fd != -1) {
        page_size = fd_get_blocksize(fd);
        if (page_size < 0) {
            vfu_log(dma->vfu_ctx, LOG_ERR, "bad page size %d", page_size);
            return ERROR_PTR(EINVAL);
        }

        fd = fd_cache_get(fd);
        if (fd == -1) {
            vfu_log(dma->vfu_ctx, LOG_ERR,
                    "failed to de-duplicate fd for new DMA region %s: %m",
                    rstr);
            return NULL;
        }
    }
    page_size = MAX(page_size, getpagesize());

    region = calloc(1, sizeof(*region));
    if (region == NULL) {
        errno = ENOMEM;
        goto rollback;
    }

    region->info.iova.iov_base = (void *)dma_addr;
    region->info.iova.iov_len = size;
    region->info.page_size = page_size;
    region->info.prot = prot;
    region->offset = offset;
    region->fd = fd;

    if (fd != -1) {
        /*
         * TODO introduce a function that tells whether dirty page logging is
         * enabled
         */
        if (dma->dirty_pgsize != 0) {
            if (dirty_page_logging_start_on_region(region, dma->dirty_pgsize) < 0) {
                /*
                 * TODO We don't necessarily have to fail, we can continue
                 * and fail the get dirty page bitmap request later.
                 */
                goto rollback;
            }
        }

        ret = dma_map_region(dma, region);

        if (ret != 0) {
            vfu_log(dma->vfu_ctx, LOG_ERR,
                   "failed to memory map DMA region %s: %m", rstr);
            goto rollback;
        } else {
            /* Ownership of the fd is now with the region. */
            fd = -1;
        }
    }

    if (btree_iter_insert(&iter, (uintptr_t)dma_addr + size - 1, region) != 0) {
        goto rollback;
    }

    dma_controller_increment_regions_generation(dma);

    return region;

rollback:
    ret = errno;
    if (region != NULL) {
        if (region->info.vaddr != NULL) {
            dma_controller_unmap_region(dma, region);
        }
        dirty_page_logging_stop_on_region(region);
        free(region);
    }
    err = fd_cache_put(&fd);
    assert(err == 0);

    return ERROR_PTR(ret);
}

int
_dma_addr_sg_split(const dma_controller_t *dma,
                   vfu_dma_addr_t dma_addr, uint64_t len,
                   dma_sg_t *sg, int max_nr_sgs, int prot)
{
    dma_memory_region_t *region;
    btree_iter_t iter;
    int cnt = 0, ret;

    for (btree_iter_init((btree_t *)&dma->regions, (uintptr_t)dma_addr, &iter);
         len > 0 && (region = btree_iter_get(&iter, NULL)) != NULL;
         btree_iter_next(&iter)) {
        vfu_dma_addr_t region_start = region->info.iova.iov_base;
        vfu_dma_addr_t region_end = iov_end(&region->info.iova);

        if (dma_addr < region_start || dma_addr >= region_end) {
            return ERROR_INT(ENOENT);
        }

        size_t region_len = MIN((uint64_t)(region_end - dma_addr), len);

        if (cnt < max_nr_sgs) {
            ret =
                dma_init_sg(dma, &sg[cnt], dma_addr, region_len, prot, region);
            if (ret < 0) {
                return ret;
            }
        }

        cnt++;

        dma_addr += region_len;
        len -= region_len;
    }

    if (len > 0) {
        return ERROR_INT(ENOENT);
    } else if (cnt > max_nr_sgs) {
        cnt = -cnt - 1;
    }
    errno = 0;
    return cnt;
}

static void
dma_controller_dirty_page_logging_reset(dma_controller_t *dma)
{
    dma_memory_region_t *region;
    btree_iter_t iter;

    for (btree_iter_init(&dma->regions, 0, &iter);
         (region = btree_iter_get(&iter, NULL)) != NULL;
         btree_iter_next(&iter)) {
        dirty_page_logging_stop_on_region(region);
    }
    dma->dirty_pgsize = 0;
}

int
dma_controller_dirty_page_logging_start(dma_controller_t *dma, size_t pgsize)
{
    dma_memory_region_t *region;
    btree_iter_t iter;

    assert(dma != NULL);

    if (pgsize == 0) {
        return ERROR_INT(EINVAL);
    }

    if (dma->dirty_pgsize > 0) {
        if (dma->dirty_pgsize != pgsize) {
            return ERROR_INT(EINVAL);
        }
        return 0;
    }

    for (btree_iter_init(&dma->regions, 0, &iter);
         (region = btree_iter_get(&iter, NULL)) != NULL;
         btree_iter_next(&iter)) {
        if (region->fd == -1) {
            continue;
        }

        if (dirty_page_logging_start_on_region(region, pgsize) < 0) {
            int _errno = errno;
            dma_controller_dirty_page_logging_reset(dma);
            return ERROR_INT(_errno);
        }
    }
    dma->dirty_pgsize = pgsize;

    vfu_log(dma->vfu_ctx, LOG_DEBUG, "dirty pages: started logging");

    return 0;
}

void
dma_controller_dirty_page_logging_stop(dma_controller_t *dma)
{
    assert(dma != NULL);

    if (dma->dirty_pgsize == 0) {
        return;
    }

    dma_controller_dirty_page_logging_reset(dma);

    vfu_log(dma->vfu_ctx, LOG_DEBUG, "dirty pages: stopped logging");
}


#ifdef DEBUG
static void
log_dirty_bitmap(vfu_ctx_t *vfu_ctx, const dma_memory_region_t *region,
                 char *bitmap, size_t size, size_t pgsize)
{
    size_t i;
    size_t count;
    for (i = 0, count = 0; i < size; i++) {
        count += __builtin_popcount((uint8_t)bitmap[i]);
    }
    vfu_log(vfu_ctx, LOG_DEBUG,
            "dirty pages: get [%p, %p), %zu dirty pages of size %zu",
            region->info.iova.iov_base, iov_end(&region->info.iova),
            count, pgsize);
}
#endif

static void
dirty_page_exchange(uint8_t *outp, uint8_t *bitmap)
{
    /*
     * If no bits are dirty, avoid the atomic exchange. This is obviously
     * racy, but it's OK: if we miss a dirty bit being set, we'll catch it
     * the next time around.
     *
     * Otherwise, atomically exchange the dirty bits with zero: as we use
     * atomic or in _dma_mark_dirty(), this cannot lose set bits - we might
     * miss a bit being set after, but again, we'll catch that next time
     * around.
     */
    if (*bitmap == 0) {
        *outp = 0;
    } else {
        uint8_t zero = 0;
        __atomic_exchange(bitmap, &zero, outp, __ATOMIC_SEQ_CST);
    }
}

static void
dirty_page_get_same_pgsize(const dma_memory_region_t *region, char *bitmap,
                           size_t bitmap_size)
{
    for (size_t i = 0; i < bitmap_size; i++) {
        dirty_page_exchange((uint8_t *)&bitmap[i], &region->dirty_bitmap[i]);
    }
}

static void
dirty_page_get_extend(const dma_memory_region_t *region, char *bitmap,
                      size_t server_bitmap_size, size_t server_pgsize,
                      size_t client_bitmap_size, size_t client_pgsize)
{
    /*
     * The index of the bit in the client bitmap that we are currently
     * considering. By keeping track of this separately to the for loop, we
     * allow for one server bit to be repeated for multiple client bytes.
     */
    uint8_t client_bit_idx = 0;
    size_t server_byte_idx;
    int server_bit_idx;
    size_t factor = server_pgsize / client_pgsize;

    /*
     * Iterate through the bytes of the server bitmap.
     */
    for (server_byte_idx = 0; server_byte_idx < server_bitmap_size;
         server_byte_idx++) {

        if (client_bit_idx / CHAR_BIT >= client_bitmap_size) {
            break;
        }

        uint8_t out = 0;

        dirty_page_exchange(&out, &region->dirty_bitmap[server_byte_idx]);

        /*
         * Iterate through the bits of the server byte, repeating bits to reach
         * the desired page size.
         */
        for (server_bit_idx = 0; server_bit_idx < CHAR_BIT; server_bit_idx++) {
            uint8_t server_bit = (out >> server_bit_idx) & 1;

            /*
             * Repeat `factor` times the bit at index `j` of `out`.
             *
             * OR the same bit from the server bitmap (`server_bit`) with
             * `factor` bits in the client bitmap, from `client_bit_idx` to
             * `end_client_bit_idx`.
             */
            for (size_t end_client_bit_idx = client_bit_idx + factor;
                 client_bit_idx < end_client_bit_idx;
                 client_bit_idx++) {

                bitmap[client_bit_idx / CHAR_BIT] |=
                    server_bit << (client_bit_idx % CHAR_BIT);
            }
        }
    }
}

static void
dirty_page_get_combine(const dma_memory_region_t *region, char *bitmap,
                       size_t server_bitmap_size, size_t server_pgsize,
                       size_t client_bitmap_size, size_t client_pgsize)
{
    /*
     * The index of the bit in the client bitmap that we are currently
     * considering. By keeping track of this separately to the for loop, we
     * allow multiple bytes' worth of server bits to be OR'd together to
     * calculate one client bit.
     */
    uint8_t client_bit_idx = 0;
    size_t server_byte_idx;
    int server_bit_idx;
    size_t factor = client_pgsize / server_pgsize;

    /*
     * Iterate through the bytes of the server bitmap.
     */
    for (server_byte_idx = 0; server_byte_idx < server_bitmap_size;
         server_byte_idx++) {

        if (client_bit_idx / CHAR_BIT >= client_bitmap_size) {
            break;
        }
            
        uint8_t out = 0;

        dirty_page_exchange(&out, &region->dirty_bitmap[server_byte_idx]);

        /*
         * Iterate through the bits of the server byte, combining bits to reach
         * the desired page size.
         */
        for (server_bit_idx = 0; server_bit_idx < CHAR_BIT; server_bit_idx++) {
            uint8_t server_bit = (out >> server_bit_idx) & 1;

            /*
             * OR `factor` bits of the server bitmap with the same bit at
             * index `client_bit_idx` in the client bitmap.
             */
            bitmap[client_bit_idx / CHAR_BIT] |=
                server_bit << (client_bit_idx % CHAR_BIT);

            /*
             * Only move onto the next bit in the client bitmap once we've
             * OR'd `factor` bits.
             */
            if (((server_byte_idx * CHAR_BIT) + server_bit_idx) % factor
                    == factor - 1) {
                client_bit_idx++;
                
                if (client_bit_idx / CHAR_BIT >= client_bitmap_size) {
                    return;
                }
            }
        }
    }
}

int
dma_controller_dirty_page_get(dma_controller_t *dma, vfu_dma_addr_t addr,
                              uint64_t len, size_t client_pgsize, size_t size,
                              char *bitmap)
{
    const dma_memory_region_t *region;
    ssize_t server_bitmap_size;
    ssize_t client_bitmap_size;
    dma_sg_t sg;
    int ret;

    assert(dma != NULL);
    assert(bitmap != NULL);

    /*
     * FIXME for now we support IOVAs that match exactly the DMA region. This
     * is purely for simplifying the implementation. We MUST allow arbitrary
     * IOVAs.
     */
    ret = dma_addr_to_sgl(dma, addr, len, &sg, 1, PROT_NONE);
    if (unlikely(ret != 1)) {
        vfu_log(dma->vfu_ctx, LOG_DEBUG, "failed to translate %#llx-%#llx: %m",
                (unsigned long long)(uintptr_t)addr,
		(unsigned long long)(uintptr_t)addr + len - 1);
        return ret;
    }

    if (unlikely(sg.dma_addr != addr || sg.length != len)) {
        return ERROR_INT(ENOTSUP);
    }

    /*
     * If dirty page logging is not enabled, the requested page size is zero,
     * or the requested page size is not a power of two, return an error.
     */
    if (dma->dirty_pgsize == 0) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "dirty page logging not enabled");
        return ERROR_INT(EINVAL);
    }
    if (client_pgsize == 0 || (client_pgsize & (client_pgsize - 1)) != 0) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "bad client page size %zu",
                client_pgsize);
        return ERROR_INT(EINVAL);
    }

    server_bitmap_size = get_bitmap_size(len, dma->dirty_pgsize);
    if (server_bitmap_size < 0) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "failed to get server bitmap size");
        return server_bitmap_size;
    }

    client_bitmap_size = get_bitmap_size(len, client_pgsize);
    if (client_bitmap_size < 0) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "bad client page size %zu",
                client_pgsize);
        return client_bitmap_size;
    }

    /*
     * They must be equal because this is how much data the client expects to
     * receive.
     */
    if (size != (size_t)client_bitmap_size) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "bad client bitmap size %zu != %zu",
                size, client_bitmap_size);
        return ERROR_INT(EINVAL);
    }

    region = sg.region;

    if (region->fd == -1) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "region [%p-%p] is not mapped",
                region->info.iova.iov_base, iov_end(&region->info.iova));
        return ERROR_INT(EINVAL);
    }

    if (client_pgsize == dma->dirty_pgsize) {
        dirty_page_get_same_pgsize(region, bitmap, client_bitmap_size);
    } else if (client_pgsize < dma->dirty_pgsize) {
        /*
         * If the requested page size is less than that used for logging by
         * the server, the bitmap will need to be extended, repeating bits.
         */
        dirty_page_get_extend(region, bitmap, server_bitmap_size,
                              dma->dirty_pgsize, client_bitmap_size,
                              client_pgsize);
    } else {
        /*
         * If the requested page size is larger than that used for logging by
         * the server, the bitmap will need to combine bits with OR, losing
         * accuracy.
         */
        dirty_page_get_combine(region, bitmap, server_bitmap_size,
                               dma->dirty_pgsize, client_bitmap_size,
                               client_pgsize);
    }

#ifdef DEBUG
    log_dirty_bitmap(dma->vfu_ctx, region, bitmap, size, client_pgsize);
#endif

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
