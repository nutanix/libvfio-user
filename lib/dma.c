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
_dma_controller_do_remove_region(dma_controller_t *dma,
                                 dma_memory_region_t *region)
{
    int err;

    assert(dma != NULL);
    assert(region != NULL);

    err = dma_unmap_region(region, region->virt_addr, region->size);
    if (err != 0) {
        vfu_log(dma->vfu_ctx, LOG_DEBUG, "failed to unmap fd=%d vaddr=%p-%p\n",
               region->fd, region->virt_addr,
               region->virt_addr + region->size - 1);
    }
    if (region->fd != -1) {
        if (close(region->fd) == -1) {
            vfu_log(dma->vfu_ctx, LOG_DEBUG,
                    "failed to close fd %d: %m\n", region->fd);
        }
    }
}
UNIT_TEST_SYMBOL(_dma_controller_do_remove_region);

/*
 * FIXME super ugly, but without this functions within the same compilation
 * unit don't call the wrapped version, making unit testing impossible.
 * Ideally we'd like the UNIT_TEST_SYMBOL macro to solve this.
 */
#define _dma_controller_do_remove_region __wrap__dma_controller_do_remove_region

/*
 * FIXME no longer used. Also, it doesn't work for addresses that span two
 * DMA regions.
 */
bool
dma_controller_region_valid(dma_controller_t *dma, dma_addr_t dma_addr,
                            size_t size)
{
    dma_memory_region_t *region;
    int i;

    for (i = 0; i < dma->nregions; i++) {
        region = &dma->regions[i];
        if (dma_addr == region->dma_addr && size <= region->size) {
            return true;
        }
    }

    return false;
}

/* FIXME not thread safe */
int
dma_controller_remove_region(dma_controller_t *dma,
                             dma_addr_t dma_addr, size_t size,
                             vfu_unmap_dma_cb_t *unmap_dma, void *data)
{
    int idx;
    dma_memory_region_t *region;
    int err;

    assert(dma != NULL);

    for (idx = 0; idx < dma->nregions; idx++) {
        region = &dma->regions[idx];
        if (region->dma_addr == dma_addr && region->size == size) {
            if (region->refcnt > 0) {
                err = unmap_dma(data, region->dma_addr, region->size);
                if (err != 0) {
                    vfu_log(dma->vfu_ctx, LOG_ERR,
                           "failed to notify of removal of DMA region %#lx-%#lx: %s\n",
                           region->dma_addr, region->dma_addr + region->size,
                           strerror(-err));
                    return err;
                }
                assert(region->refcnt == 0);
            }
            _dma_controller_do_remove_region(dma, region);
            if (dma->nregions > 1)
                /*
                 * FIXME valgrind complains with 'Source and destination overlap in memcpy',
                 * check whether memmove eliminates this warning.
                 */
                memcpy(region, &dma->regions[dma->nregions - 1],
                       sizeof(*region));
            dma->nregions--;
            return 0;
        }
    }
    return -ENOENT;
}
UNIT_TEST_SYMBOL(dma_controller_remove_region);

static inline void
dma_controller_remove_regions(dma_controller_t *dma)
{
    int i;

    assert(dma);

    for (i = 0; i < dma->nregions; i++) {
        dma_memory_region_t *region = &dma->regions[i];

        vfu_log(dma->vfu_ctx, LOG_INFO, "unmap vaddr=%p IOVA=%lx",
               region->virt_addr, region->dma_addr);

        _dma_controller_do_remove_region(dma, region);
    }
}

void
dma_controller_destroy(dma_controller_t *dma)
{
    if (dma == NULL) {
        return;
    }

    dma_controller_remove_regions(dma);
    free(dma);
}

int
dma_controller_add_region(dma_controller_t *dma,
                          dma_addr_t dma_addr, size_t size,
                          int fd, off_t offset, uint32_t prot)
{
    int idx;
    dma_memory_region_t *region;
    int page_size = 0;

    assert(dma != NULL);

    for (idx = 0; idx < dma->nregions; idx++) {
        region = &dma->regions[idx];

        /* First check if this is the same exact region. */
        if (region->dma_addr == dma_addr && region->size == size) {
            if (offset != region->offset) {
                vfu_log(dma->vfu_ctx, LOG_ERR,
                       "bad offset for new DMA region %#lx-%#lx, want=%ld, existing=%ld\n",
                       dma_addr, dma_addr + size, offset, region->offset);
                goto err;
            }
            if (!fds_are_same_file(region->fd, fd)) {
                /*
                 * Printing the file descriptors here doesn't really make
                 * sense as they can be different but actually pointing to
                 * the same file, however in the majority of cases we'll be
                 * using a single fd.
                 */
                vfu_log(dma->vfu_ctx, LOG_ERR,
                       "bad fd=%d for new DMA region %#lx-%#lx, existing fd=%d\n",
                       fd, offset, offset + size - 1, region->fd);
                goto err;
            }
            if (region->prot != prot) {
                vfu_log(dma->vfu_ctx, LOG_ERR, "bad prot=%#x "
                        "for new DMA region %#lx-%#lx, existing prot=%#x\n",
                        prot, offset, offset + size - 1, region->prot);
                goto err;
            }
            return idx;
        }

        /* Check for overlap, i.e. start of one region is within another. */
        if ((dma_addr >= region->dma_addr &&
             dma_addr < region->dma_addr + region->size) ||
            (region->dma_addr >= dma_addr &&
             region->dma_addr < dma_addr + size)) {
            vfu_log(dma->vfu_ctx, LOG_INFO,
                   "new DMA region %#lx+%#lx overlaps with DMA region %#lx-%#lx\n",
                   dma_addr, size, region->dma_addr, region->size);
            goto err;
        }
    }

    if (dma->nregions == dma->max_regions) {
        idx = dma->max_regions;
        vfu_log(dma->vfu_ctx, LOG_ERR,
               "reached maxed regions, recompile with higher number of DMA regions\n");
        goto err;
    }

    idx = dma->nregions;
    region = &dma->regions[idx];

    if (fd != -1) {
        page_size = fd_get_blocksize(fd);
        if (page_size < 0) {
            vfu_log(dma->vfu_ctx, LOG_ERR, "bad page size %d\n", page_size);
            goto err;
        }
    }
    page_size = MAX(page_size, getpagesize());

    region->dma_addr = dma_addr;
    region->size = size;
    region->page_size = page_size;
    region->offset = offset;
    region->prot = prot;
    region->fd = fd;
    region->refcnt = 0;

    if (fd != -1) {
        region->virt_addr = dma_map_region(region, region->prot, 0,
                                           region->size);
        if (region->virt_addr == MAP_FAILED) {
            vfu_log(dma->vfu_ctx, LOG_ERR,
                   "failed to memory map DMA region %#lx-%#lx: %s\n",
                   dma_addr, dma_addr + size, strerror(errno));
            if (region->fd != -1) {
                if (close(region->fd) == -1) {
                    vfu_log(dma->vfu_ctx, LOG_DEBUG,
                            "failed to close fd %d: %m\n", region->fd);
                }
            }
            goto err;
        }
    } else {
        region->virt_addr = NULL;
    }
    dma->nregions++;

    return idx;

err:
    return -idx - 1;
}
UNIT_TEST_SYMBOL(dma_controller_add_region);

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
    // Note: As per mmap(2) manpage, on some hardware architectures
    //       (e.g., i386), PROT_WRITE implies PROT_READ
    mmap_base = mmap(NULL, mmap_size, prot, MAP_SHARED,
                     region->fd, mmap_offset);
    if (mmap_base == MAP_FAILED) {
        return mmap_base;
    }
    // Do not dump.
    madvise(mmap_base, mmap_size, MADV_DONTDUMP);

    return mmap_base + (offset - mmap_offset);
}
UNIT_TEST_SYMBOL(dma_map_region);

int
dma_unmap_region(dma_memory_region_t *region, void *virt_addr, size_t len)
{
    mmap_round((size_t *)&virt_addr, &len, region->page_size);
    return munmap(virt_addr, len);
}

int
_dma_addr_sg_split(const dma_controller_t *dma,
                   dma_addr_t dma_addr, uint32_t len,
                   dma_sg_t *sg, int max_sg, int prot)
{
    int idx;
    int cnt = 0, ret;
    bool found = true;          // Whether the current region is found.

    while (found && len > 0) {
        found = false;
        for (idx = 0; idx < dma->nregions; idx++) {
            const dma_memory_region_t *const region = &dma->regions[idx];
            const dma_addr_t region_end = region->dma_addr + region->size;

            while (dma_addr >= region->dma_addr && dma_addr < region_end) {
                size_t region_len = MIN(region_end - dma_addr, len);

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
        cnt = -1;
    } else if (cnt > max_sg) {
        cnt = -cnt - 1;
    }
    errno = 0;
    return cnt;
}

ssize_t _get_bitmap_size(size_t region_size, size_t pgsize)
{
    if (pgsize == 0) {
        return -EINVAL;
    }
    if (region_size < pgsize) {
        return -EINVAL;
    }
    size_t nr_pages = (region_size / pgsize) + (region_size % pgsize != 0);
    return (nr_pages / CHAR_BIT) + (nr_pages % CHAR_BIT != 0);
}

int dma_controller_dirty_page_logging_start(dma_controller_t *dma, size_t pgsize)
{
    int i;

    assert(dma != NULL);

    if (pgsize == 0) {
        return -EINVAL;
    }

    if (dma->dirty_pgsize > 0) {
        if (dma->dirty_pgsize != pgsize) {
            return -EINVAL;
        }
        return 0;
    }

    for (i = 0; i < dma->nregions; i++) {
        dma_memory_region_t *region = &dma->regions[i];
        ssize_t bitmap_size = _get_bitmap_size(region->size, pgsize);
        if (bitmap_size < 0) {
            return bitmap_size;
        }
        region->dirty_bitmap = calloc(bitmap_size, sizeof(char));
        if (region->dirty_bitmap == NULL) {
            int j, ret = -errno;
            for (j = 0; j < i; j++) {
                region = &dma->regions[j];
                free(region->dirty_bitmap);
                region->dirty_bitmap = NULL;
            }
            return ret;
        }
    }
    dma->dirty_pgsize = pgsize;
    return 0;
}

int dma_controller_dirty_page_logging_stop(dma_controller_t *dma)
{
    int i;

    assert(dma != NULL);

    if (dma->dirty_pgsize == 0) {
        return 0;
    }

    for (i = 0; i < dma->nregions; i++) {
        free(dma->regions[i].dirty_bitmap);
        dma->regions[i].dirty_bitmap = NULL;
    }
    dma->dirty_pgsize = 0;
    return 0;
}

int
dma_controller_dirty_page_get(dma_controller_t *dma, dma_addr_t addr, int len,
                              size_t pgsize, size_t size, char **data)
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
        return -ENOTSUP;
    }

    if (pgsize != dma->dirty_pgsize) {
        return -EINVAL;
    }

    bitmap_size = _get_bitmap_size(len, pgsize);
    if (bitmap_size < 0) {
        return bitmap_size;
    }

    /*
     * FIXME they must be equal because this is how much data the client
     * expects to receive.
     */
    if (size != (size_t)bitmap_size) {
        return -EINVAL;
    }

    region = &dma->regions[sg.region];

    *data = region->dirty_bitmap;

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
