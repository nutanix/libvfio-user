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
#include <stdio.h>
#include <sys/param.h>

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include "dma.h"

static inline ssize_t
fd_get_blocksize(int fd)
{
    struct stat st;

    if (fstat(fd, &st) != 0)
        return -1;

    return st.st_blksize;
}

/* Returns true if 2 fds refer to the same file.
   If any fd is invalid, return false. */
static inline bool
fds_are_same_file(int fd1, int fd2)
{
    struct stat st1, st2;

    return (fstat(fd1, &st1) == 0 && fstat(fd2, &st2) == 0 &&
            st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino);
}

dma_controller_t *
dma_controller_create(int max_regions)
{
    dma_controller_t *dma;

    dma = malloc(offsetof(dma_controller_t, regions) +
                 max_regions * sizeof(dma->regions[0]));

    if (dma == NULL) {
        return dma;
    }

    dma->max_regions = max_regions;
    dma->nregions = 0;
    memset(dma->regions, 0, max_regions * sizeof(dma->regions[0]));

    return dma;
}

static void
_dma_controller_do_remove_region(dma_memory_region_t *region)
{
    assert(region);
#if DMA_MAP_FAST_IMPL
    dma_unmap_region(region, region->virt_addr, region->size);
#endif
    (void)close(region->fd);
}

/* FIXME not thread safe */
int
dma_controller_remove_region(dma_controller_t *dma, dma_addr_t dma_addr,
                             size_t size, int fd)
{
    int idx;
    dma_memory_region_t *region;

    assert(dma);

    for (idx = 0; idx < dma->nregions; idx++) {
        region = &dma->regions[idx];
        if (region->dma_addr == dma_addr && region->size == size &&
            fds_are_same_file(region->fd, fd)) {
            _dma_controller_do_remove_region(region);
            if (dma->nregions > 1)
                memcpy(region, &dma->regions[dma->nregions - 1],
                       sizeof *region);
            dma->nregions--;
            return 0;
        }
    }
    return -ENOENT;
}

static inline void
dma_controller_remove_regions(lm_ctx_t *ctx, dma_controller_t *dma)
{
    int i;

    assert(dma);

    for (i = 0; i < dma->nregions; i++) {
        dma_memory_region_t *region = &dma->regions[i];

        lm_log(ctx, LM_INF, "unmap vaddr=%lx IOVA=%lx\n",
               region->virt_addr, region->dma_addr);

        _dma_controller_do_remove_region(region);
    }
}

void
dma_controller_destroy(lm_ctx_t *lm_ctx, dma_controller_t *dma)
{
    dma_controller_remove_regions(lm_ctx, dma);
    free(dma);
}

int
dma_controller_add_region(lm_ctx_t *lm_ctx, dma_controller_t *dma,
                          dma_addr_t dma_addr, size_t size,
                          int fd, off_t offset)
{
    int idx;
    dma_memory_region_t *region;
    int page_size;

    for (idx = 0; idx < dma->nregions; idx++) {
        region = &dma->regions[idx];

        /* First check if this is the same exact region. */
        if (region->dma_addr == dma_addr && region->size == size) {
            if (offset != region->offset) {
                lm_log(lm_ctx, LM_ERR, "bad offset for new DMA region %lx+%lx, "
                       "want=%d, existing=%d\n",
                       dma_addr, size, offset, region->offset);
                goto err;
            }
            if (!fds_are_same_file(region->fd, fd)) {
                /*
                 * Printing the file descriptors here doesn't really make
                 * sense as they can be different but actually pointing to
                 * the same file, however in the majority of cases we'll be
                 * using a single fd.
                 */
                lm_log(lm_ctx, LM_ERR, "bad fd=%d for new DMA region %lx-%lx, "
                       "existing fd=%d\n", fd, region->fd);
                goto err;
            }
            return idx;
        }

        /* Check for overlap, i.e. start of one region is within another. */
        if ((dma_addr >= region->dma_addr &&
             dma_addr < region->dma_addr + region->size) ||
            (region->dma_addr >= dma_addr &&
             region->dma_addr < dma_addr + size)) {
            lm_log(lm_ctx, LM_INF, "new DMA region %lx+%lx overlaps with DMA "
                   "region %lx-%lx\n", dma_addr, size, region->dma_addr,
                   region->size);
            goto err;
        }
    }

    if (dma->nregions == dma->max_regions) {
        idx = dma->max_regions;
        lm_log(lm_ctx, LM_ERR, "reached maxed regions, recompile with higher number of DMA regions\n");
        goto err;
    }

    idx = dma->nregions;
    region = &dma->regions[idx];

    page_size = fd_get_blocksize(fd);
    if (page_size < 0) {
        lm_log(lm_ctx, LM_ERR, "bad page size %d\n", page_size);
        goto err;
    }
    page_size = MAX(page_size, getpagesize());

    region->dma_addr = dma_addr;
    region->size = size;
    region->page_size = page_size;
    region->offset = offset;

    region->fd = dup(fd);       // dup the fd to get our own private copy
    if (region->fd < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to duplicate file descriptor: %s\n",
               strerror(errno));
        goto err;
    }
#if DMA_MAP_FAST_IMPL
    region->virt_addr = dma_map_region(region, PROT_READ | PROT_WRITE,
                                       0, region->size);
    if (region->virt_addr == MAP_FAILED) {
        lm_log(lm_ctx, LM_ERR, "failed to memory map DMA region %lx-%lx: %s\n",
               dma_addr, dma_addr + size, strerror(errno));
        close(region->fd);
        goto err;
    }
#endif

    dma->nregions++;

    return idx;

err:
    return -idx - 1;
}

static inline void
mmap_round(size_t *offset, size_t *size, size_t page_size)
{
    size_t offset_orig = *offset;
    *offset = ROUND_DOWN(offset_orig, page_size);
    *size = ROUND_UP(offset_orig + *size, page_size) - *offset;
}

void *
dma_map_region(dma_memory_region_t *region, int prot, size_t offset, size_t len)
{
    size_t mmap_offset, mmap_size = len;
    char *mmap_base;

    if (offset >= region->size || offset + len > region->size) {
        return MAP_FAILED;
    }

    offset += region->offset;
    mmap_offset = offset;
    mmap_round(&mmap_offset, &mmap_size, region->page_size);

    // Do the mmap.
    mmap_base = mmap(NULL, mmap_size, prot, MAP_SHARED,
                     region->fd, mmap_offset);
    if (mmap_base == MAP_FAILED) {
        return mmap_base;
    }
    // Do not dump.
    madvise(mmap_base, mmap_size, MADV_DONTDUMP);

    return mmap_base + (offset - mmap_offset);
}

void
dma_unmap_region(dma_memory_region_t *region, void *virt_addr, size_t len)
{
    mmap_round((size_t *)&virt_addr, &len, region->page_size);
    munmap(virt_addr, len);
}

int
_dma_addr_sg_split(const dma_controller_t *dma,
                   dma_addr_t dma_addr, uint32_t len,
                   dma_sg_t *sg, int max_sg)
{
    int idx;
    int cnt = 0;
    bool found = true;          // Whether the current region is found.

    while (found && len > 0) {
        found = false;
        for (idx = 0; idx < dma->nregions; idx++) {
            const dma_memory_region_t *const region = &dma->regions[idx];
            const dma_addr_t region_end = region->dma_addr + region->size;

            while (dma_addr >= region->dma_addr && dma_addr < region_end) {
                size_t region_len = MIN(region_end - dma_addr, len);

                if (cnt < max_sg) {
                    sg[cnt].region = idx;
                    sg[cnt].offset = dma_addr - region->dma_addr;
                    sg[cnt].length = region_len;
                }

                cnt++;

                // dma_addr found, may need to start from the top for the
                // next dma_addr.
                found = true;
                dma_addr += region_len;
                len -= region_len;

                if (len == 0) {
                    goto out;
                }
            }
        }
    }

out:
    if (!found) {
        // There is still a region which was not found.
        assert(len > 0);
        cnt = -1;
    } else if (cnt > max_sg) {
        cnt = -cnt - 1;
    }
    return cnt;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
