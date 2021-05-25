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
#include "private.h"

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

    if (fd1 == fd2) {
        return true;
    }

    return (fstat(fd1, &st1) == 0 && fstat(fd2, &st2) == 0 &&
            st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino);
}

dma_controller_t *
dma_controller_create(vfu_ctx_t *vfu_ctx, int max_regions)
{
    dma_controller_t *dma;

    dma = malloc(offsetof(dma_controller_t, regions) +
                 max_regions * sizeof(dma->regions[0]));

    if (dma == NULL) {
        return dma;
    }

    dma->vfu_ctx = vfu_ctx;
    dma->max_regions = max_regions;
    dma->nregions = 0;
    memset(dma->regions, 0, max_regions * sizeof(dma->regions[0]));
    dma->dirty_pgsize = 0;

    return dma;
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

    if (close(region->fd) == -1) {
        vfu_log(dma->vfu_ctx, LOG_WARNING, "failed to close fd %d: %m",
                region->fd);
    }
}

static void
array_remove(void *array, size_t elem_size, size_t index, int *nr_elemsp)
{
    void *dest;
    void *src;
    size_t nr;

    assert((size_t)*nr_elemsp > index);

    nr = *nr_elemsp - (index + 1);
    dest = (char *)array + (index * elem_size);
    src = (char *)array + ((index + 1) * elem_size);

    memmove(dest, src, nr * elem_size);

    (*nr_elemsp)--;
}

/* FIXME not thread safe */
int
MOCK_DEFINE(dma_controller_remove_region)(dma_controller_t *dma,
                                          vfu_dma_addr_t dma_addr, size_t size,
                                          vfu_dma_unregister_cb_t *dma_unregister,
                                          void *data)
{
    int idx;
    dma_memory_region_t *region;
    int err;

    assert(dma != NULL);

    for (idx = 0; idx < dma->nregions; idx++) {
        region = &dma->regions[idx];
        if (region->info.iova.iov_base != dma_addr ||
            region->info.iova.iov_len != size) {
            continue;
        }

        err = dma_unregister == NULL ? 0 : dma_unregister(data, &region->info);
        if (err != 0) {
            err = errno;
            vfu_log(dma->vfu_ctx, LOG_ERR,
                   "failed to dma_unregister() DMA region [%p, %p): %m",
                   region->info.iova.iov_base, iov_end(&region->info.iova));
            return ERROR_INT(err);
        }

        assert(region->refcnt == 0);

        if (region->info.vaddr != NULL) {
            dma_controller_unmap_region(dma, region);
        } else {
            assert(region->fd == -1);
        }

        array_remove(&dma->regions, sizeof (*region), idx, &dma->nregions);
        return 0;
    }
    return ERROR_INT(ENOENT);
}

void
dma_controller_remove_all_regions(dma_controller_t *dma,
                                  vfu_dma_unregister_cb_t *dma_unregister,
                                  void *data)
{
    int i;

    assert(dma != NULL);

    for (i = 0; i < dma->nregions; i++) {
        dma_memory_region_t *region = &dma->regions[i];
        int err;

        vfu_log(dma->vfu_ctx, LOG_DEBUG, "removing DMA region "
                "iova=[%p, %p) vaddr=%p mapping=[%p, %p)",
                region->info.iova.iov_base, iov_end(&region->info.iova),
                region->info.vaddr,
                region->info.mapping.iov_base, iov_end(&region->info.mapping));

        err = dma_unregister == NULL ? 0 : dma_unregister(data, &region->info);
        if (err != 0) {
            err = errno;
            vfu_log(dma->vfu_ctx, LOG_ERR,
                   "failed to dma_unregister() DMA region [%p, %p): %m",
                   region->info.iova.iov_base, iov_end(&region->info.iova));
        }

        if (region->info.vaddr != NULL) {
            dma_controller_unmap_region(dma, region);
        } else {
            assert(region->fd == -1);
        }
    }

    memset(dma->regions, 0, dma->max_regions * sizeof(dma->regions[0]));
    dma->nregions = 0;
}

void
dma_controller_destroy(dma_controller_t *dma)
{
    assert(dma->nregions == 0);
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
            "vaddr=%p page_size=%#lx mapping=[%p, %p)",
            region->info.iova.iov_base, iov_end(&region->info.iova),
            region->info.vaddr, region->info.page_size,
            region->info.mapping.iov_base, iov_end(&region->info.mapping));


    return 0;
}

int
MOCK_DEFINE(dma_controller_add_region)(dma_controller_t *dma,
                                       vfu_dma_addr_t dma_addr, size_t size,
                                       int fd, off_t offset, uint32_t prot)
{
    dma_memory_region_t *region;
    int page_size = 0;
    char rstr[1024];
    int idx;

    assert(dma != NULL);

    snprintf(rstr, sizeof(rstr), "[%p, %p) fd=%d offset=%#lx prot=%#x",
             dma_addr, (char *)dma_addr + size, fd, offset, prot);

    for (idx = 0; idx < dma->nregions; idx++) {
        region = &dma->regions[idx];

        /* First check if this is the same exact region. */
        if (region->info.iova.iov_base == dma_addr &&
            region->info.iova.iov_len == size) {
            if (offset != region->offset) {
                vfu_log(dma->vfu_ctx, LOG_ERR, "bad offset for new DMA region "
                        "%s; existing=%#lx", rstr, region->offset);
                return ERROR_INT(EINVAL);
            }
            if (!fds_are_same_file(region->fd, fd)) {
                /*
                 * Printing the file descriptors here doesn't really make
                 * sense as they can be different but actually pointing to
                 * the same file, however in the majority of cases we'll be
                 * using a single fd.
                 */
                vfu_log(dma->vfu_ctx, LOG_ERR, "bad fd for new DMA region %s; "
                        "existing=%d", rstr, region->fd);
                return ERROR_INT(EINVAL);
            }
            if (region->info.prot != prot) {
                vfu_log(dma->vfu_ctx, LOG_ERR, "bad prot for new DMA region "
                        "%s; existing=%#x", rstr, region->info.prot);
                return ERROR_INT(EINVAL);
            }
            return idx;
        }

        /* Check for overlap, i.e. start of one region is within another. */
        if ((dma_addr >= region->info.iova.iov_base &&
             dma_addr < iov_end(&region->info.iova)) ||
            (region->info.iova.iov_base >= dma_addr &&
             region->info.iova.iov_base < dma_addr + size)) {
            vfu_log(dma->vfu_ctx, LOG_INFO, "new DMA region %s overlaps with "
                    "DMA region [%p, %p)", rstr, region->info.iova.iov_base,
                    iov_end(&region->info.iova));
            return ERROR_INT(EINVAL);
        }
    }

    if (dma->nregions == dma->max_regions) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "hit max regions %d", dma->max_regions);
        return ERROR_INT(EINVAL);
    }

    idx = dma->nregions;
    region = &dma->regions[idx];

    if (fd != -1) {
        page_size = fd_get_blocksize(fd);
        if (page_size < 0) {
            vfu_log(dma->vfu_ctx, LOG_ERR, "bad page size %d", page_size);
            return ERROR_INT(EINVAL);
        }
    }
    page_size = MAX(page_size, getpagesize());

    memset(region, 0, sizeof (*region));

    region->info.iova.iov_base = (void *)dma_addr;
    region->info.iova.iov_len = size;
    region->info.page_size = page_size;
    region->info.prot = prot;
    region->offset = offset;
    region->fd = fd;

    if (fd != -1) {
        int ret = dma_map_region(dma, region);

        if (ret != 0) {
            ret = errno;
            vfu_log(dma->vfu_ctx, LOG_ERR,
                   "failed to memory map DMA region %s: %m", rstr);

            if (close(region->fd) == -1) {
                vfu_log(dma->vfu_ctx, LOG_WARNING,
                        "failed to close fd %d: %m", region->fd);
            }

            return ERROR_INT(ret);
        }
    }

    dma->nregions++;
    return idx;
}

int
_dma_addr_sg_split(const dma_controller_t *dma,
                   vfu_dma_addr_t dma_addr, uint64_t len,
                   dma_sg_t *sg, int max_sg, int prot)
{
    int idx;
    int cnt = 0, ret;
    bool found = true;          // Whether the current region is found.

    while (found && len > 0) {
        found = false;
        for (idx = 0; idx < dma->nregions; idx++) {
            const dma_memory_region_t *const region = &dma->regions[idx];
            vfu_dma_addr_t region_start = region->info.iova.iov_base;
            vfu_dma_addr_t region_end = iov_end(&region->info.iova);

            while (dma_addr >= region_start && dma_addr < region_end) {
                size_t region_len = MIN((uint64_t)(region_end - dma_addr), len);

                if (cnt < max_sg) {
                    ret = dma_init_sg(dma, sg, dma_addr, region_len, prot, idx);
                    if (ret < 0) {
                        return ret;
                    }
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
        return ERROR_INT(ENOENT);
    } else if (cnt > max_sg) {
        cnt = -cnt - 1;
    }
    errno = 0;
    return cnt;
}

static ssize_t
get_bitmap_size(size_t region_size, size_t pgsize)
{
    if (pgsize == 0) {
        return ERROR_INT(EINVAL);
    }
    if (region_size < pgsize) {
        return ERROR_INT(EINVAL);
    }
    size_t nr_pages = (region_size / pgsize) + (region_size % pgsize != 0);
    return ROUND_UP(nr_pages, sizeof(uint64_t) * CHAR_BIT) / CHAR_BIT;
}

int dma_controller_dirty_page_logging_start(dma_controller_t *dma, size_t pgsize)
{
    size_t i;

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

    for (i = 0; i < (size_t)dma->nregions; i++) {
        dma_memory_region_t *region = &dma->regions[i];
        ssize_t bitmap_size;

        bitmap_size = get_bitmap_size(region->info.iova.iov_len, pgsize);

        if (bitmap_size < 0) {
            return bitmap_size;
        }
        region->dirty_bitmap = calloc(bitmap_size, sizeof(char));
        if (region->dirty_bitmap == NULL) {
            int ret = errno;
            size_t j;

            for (j = 0; j < i; j++) {
                region = &dma->regions[j];
                free(region->dirty_bitmap);
                region->dirty_bitmap = NULL;
            }
            return ERROR_INT(ret);
        }
    }
    dma->dirty_pgsize = pgsize;
    return 0;
}

void
dma_controller_dirty_page_logging_stop(dma_controller_t *dma)
{
    int i;

    assert(dma != NULL);

    if (dma->dirty_pgsize == 0) {
        return;
    }

    for (i = 0; i < dma->nregions; i++) {
        free(dma->regions[i].dirty_bitmap);
        dma->regions[i].dirty_bitmap = NULL;
    }
    dma->dirty_pgsize = 0;
}

int
dma_controller_dirty_page_get(dma_controller_t *dma, vfu_dma_addr_t addr,
                              uint64_t len, size_t pgsize, size_t size,
                              char **data)
{
    int ret;
    ssize_t bitmap_size;
    dma_sg_t sg;
    dma_memory_region_t *region;

    assert(dma != NULL);
    assert(data != NULL);

    /*
     * FIXME for now we support IOVAs that match exactly the DMA region. This
     * is purely for simplifying the implementation. We MUST allow arbitrary
     * IOVAs.
     */
    ret = dma_addr_to_sg(dma, addr, len, &sg, 1, PROT_NONE);
    if (ret != 1 || sg.dma_addr != addr || sg.length != len) {
        return ERROR_INT(ENOTSUP);
    }

    if (pgsize != dma->dirty_pgsize) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "bad page size %ld", pgsize);
        return ERROR_INT(EINVAL);
    }

    bitmap_size = get_bitmap_size(len, pgsize);
    if (bitmap_size < 0) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "failed to get bitmap size");
        return bitmap_size;
    }

    /*
     * FIXME they must be equal because this is how much data the client
     * expects to receive.
     */
    if (size != (size_t)bitmap_size) {
        vfu_log(dma->vfu_ctx, LOG_ERR, "bad bitmap size %ld != %ld", size,
                bitmap_size);
        return ERROR_INT(EINVAL);
    }

    region = &dma->regions[sg.region];

    *data = region->dirty_bitmap;

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
