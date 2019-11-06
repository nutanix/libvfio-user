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

#ifndef DMA_DMA_H
#define DMA_DMA_H

/*
 * This library emulates a DMA controller for a device emulation application to
 * perform DMA operations on a foreign memory space.
 *
 * Concepts:
 * - A DMA controller has its own 64-bit DMA address space.
 * - Foreign memory is made available to the DMA controller in linear chunks
 *   called memory regions.
 * - Each memory region is backed by a file descriptor and
 *   is registered with the DMA controllers at a unique, non-overlapping
 *   linear span of the DMA address space.
 * - To perform DMA, the application should first build a scatter-gather
 *   list (sglist) of dma_sg_t from DMA addresses. Then the sglist
 *   can be mapped using dma_map_sg() into the process's virtual address space
 *   as an iovec for direct access, and unmapped using dma_unmap_sg() when done.
 * - dma_map_addr() and dma_unmap_addr() helper functions are provided
 *   for mapping DMA regions that can fit into one scatter-gather entry.
 *
 * This library can be compiled to function in two modes as defined by the
 * following macros.
 * - DMA_MAP_FAST (default): Every region is mapped into the application's
 *   virtual address space at registration time with R/W permissions.
 *   dma_map_sg() ignores all protection bits and only does lookups and
 *   returns pointers to the previously mapped regions. dma_unmap_sg() is
 *   effectively a no-op.
 * - DMA_MAP_PROTECTED: Every call to dma_map_sg() does mmap()s and
 *   dma_unmap_sg() does munmap()s. All permission bits are honored. This mode
 *   is obviously much slower if used in the fast path. It may be useful to
 *   have the exta protection if the fast path does not need direct virtual
 *   memory access to foreign memory and data is accessed using a different
 *   method (e.g. RDMA, vfio-iommu). It can also be useful in debugging to
 *   make sure we are not writing to guest memory that's readonly for the
 *   device.
 */

#ifdef DMA_MAP_PROTECTED
#undef DMA_MAP_FAST
#define DMA_MAP_FAST_IMPL 0
#else
#define DMA_MAP_FAST_IMPL 1
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>

#include "muser.h"
#include "common.h"

typedef struct {
    dma_addr_t dma_addr;        // DMA address of this region
    size_t size;                // Size of this region
    int fd;                     // File descriptor to mmap
    int page_size;              // Page size of this fd
    off_t offset;               // File offset
#if DMA_MAP_FAST_IMPL
    void *virt_addr;            // Virtual address of this region
#endif
} dma_memory_region_t;

typedef struct {
    int max_regions;
    int nregions;
    dma_memory_region_t regions[0];
} dma_controller_t;

dma_controller_t *
dma_controller_create(int max_regions);

void
dma_controller_destroy(lm_ctx_t *ctx, dma_controller_t *dma);

/* Registers a new memory region.
 * Returns:
 * - On success, a non-negative region number
 * - On failure, a negative integer (-x - 1) where x is the region number
 *   where this region would have been mapped to if the call could succeed
 *   (e.g. due to conflict with existing region).
 */
int
dma_controller_add_region(lm_ctx_t *ctx, dma_controller_t *dma,
                          dma_addr_t dma_addr, size_t size,
                          int fd, off_t offset);

int
dma_controller_remove_region(dma_controller_t *dma, dma_addr_t dma_addr,
                             size_t size, int fd);

// Helper for dma_addr_to_sg() slow path.
int
_dma_addr_sg_split(const dma_controller_t *dma,
                   dma_addr_t dma_addr, uint32_t len,
                   dma_sg_t *sg, int max_sg);

/* Takes a linear dma address span and returns a sg list suitable for DMA.
 * A single linear dma address span may need to be split into multiple
 * scatter gather regions due to limitations of how memory can be mapped.
 *
 * Returns:
 * - On success, number of scatter gather entries created.
 * - On failure:
 *     -1 if the dma address span is invalid
 *     (-x - 1) if @max_sg is too small, where x is the number of sg entries
 *     necessary to complete this request.
 */
static inline int
dma_addr_to_sg(const dma_controller_t *dma,
               dma_addr_t dma_addr, uint32_t len,
               dma_sg_t *sg, int max_sg)
{
    static __thread int region_hint;
    int cnt;

    const dma_memory_region_t *const region = &dma->regions[region_hint];
    const dma_addr_t region_end = region->dma_addr + region->size;

    // Fast path: single region.
    if (likely(max_sg > 0 && len > 0 &&
               dma_addr >= region->dma_addr && dma_addr + len <= region_end)) {
        sg->region = region_hint;
        sg->offset = dma_addr - region->dma_addr;
        sg->length = len;
        return 1;
    }
    // Slow path: search through regions.
    cnt = _dma_addr_sg_split(dma, dma_addr, len, sg, max_sg);
    if (likely(cnt > 0)) {
        region_hint = sg->region;
    }
    return cnt;
}

void *
dma_map_region(dma_memory_region_t *region, int prot,
               size_t offset, size_t len);

void
dma_unmap_region(dma_memory_region_t *region, void *virt_addr, size_t len);

static inline int
dma_map_sg(dma_controller_t *dma,
#if DMA_MAP_FAST_IMPL
           int prot __attribute__((unused)),
#else
           int prot,
#endif
           const dma_sg_t *sg, struct iovec *iov, int cnt)
{
    int i;

    for (i = 0; i < cnt; i++) {
        dma_memory_region_t *const region = &dma->regions[sg[i].region];

#if DMA_MAP_FAST_IMPL
        iov[i].iov_base = (char *)region->virt_addr + sg[i].offset;
#else
        iov[i].iov_base = dma_map_region(region, prot,
                                         sg[i].offset, sg[i].length);
        if (iov[i].iov_base == MAP_FAILED) {
            return -1;
        }
#endif
        iov[i].iov_len = sg[i].length;
    }

    return 0;
}

static inline void
dma_unmap_sg(dma_controller_t *dma,
             const dma_sg_t *sg, struct iovec *iov, int cnt)
{
    int i;

    for (i = 0; i < cnt; i++) {
        dma_memory_region_t *const region = &dma->regions[sg[i].region];
        if (!DMA_MAP_FAST_IMPL) {
            dma_unmap_region(region, iov[i].iov_base, iov[i].iov_len);
        }
    }
}

static inline void *
dma_map_addr(dma_controller_t *dma, int prot,
             dma_addr_t dma_addr, uint32_t len)
{
    dma_sg_t sg;
    struct iovec iov;

    if (dma_addr_to_sg(dma, dma_addr, len, &sg, 1) == 1 &&
        dma_map_sg(dma, prot, &sg, &iov, 1) == 0) {
        return iov.iov_base;
    }

    return NULL;
}

static inline void
dma_unmap_addr(dma_controller_t *dma,
               dma_addr_t dma_addr, uint32_t len, void *addr)
{
    dma_sg_t sg;
    struct iovec iov = {
        .iov_base = addr,
        .iov_len = len,
    };
    int r;

    r = dma_addr_to_sg(dma, dma_addr, len, &sg, 1);
    assert(r == 1);

    dma_unmap_sg(dma, &sg, &iov, 1);
}

#endif /* DMA_DMA_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
