/*
 * Copyright (c) 2026 NVIDIA Corporation. All rights reserved.
 *
 * Authors: Ben Walker <ben@nvidia.com>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of NVIDIA nor the names of its contributors may be
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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "common.h"
#include "iommufd.h"
#include "libvfio-user.h"
#include "private.h"

iommufd_controller_t *
iommufd_controller_create(struct vfu_ctx *vfu_ctx)
{
    iommufd_controller_t *iommufd;

    assert(vfu_ctx != NULL);

    iommufd = calloc(1, sizeof(*iommufd));
    if (iommufd == NULL) {
        return NULL;
    }

    iommufd->vfu_ctx = vfu_ctx;
    iommufd->enabled = false;
    iommufd->device_bound = false;
    iommufd->bound_ioas_id = 0;
    iommufd->next_ioas_id = 1; /* Start IOAS IDs at 1 */
    TAILQ_INIT(&iommufd->ioas_list);

    return iommufd;
}

static void
iommufd_free_mapping(iommufd_mapping_t *mapping)
{
    if (mapping == NULL) {
        return;
    }

    if (mapping->vaddr != NULL && mapping->vaddr != MAP_FAILED) {
        munmap(mapping->vaddr, mapping->length);
    }

    if (mapping->fd >= 0) {
        close(mapping->fd);
    }

    free(mapping);
}

static void
iommufd_free_ioas(iommufd_ioas_t *ioas)
{
    iommufd_mapping_t *mapping;

    if (ioas == NULL) {
        return;
    }

    while (!TAILQ_EMPTY(&ioas->mappings)) {
        mapping = TAILQ_FIRST(&ioas->mappings);
        TAILQ_REMOVE(&ioas->mappings, mapping, link);
        iommufd_free_mapping(mapping);
    }

    free(ioas);
}

void
iommufd_controller_destroy(iommufd_controller_t *iommufd)
{
    iommufd_ioas_t *ioas;

    if (iommufd == NULL) {
        return;
    }

    while (!TAILQ_EMPTY(&iommufd->ioas_list)) {
        ioas = TAILQ_FIRST(&iommufd->ioas_list);
        TAILQ_REMOVE(&iommufd->ioas_list, ioas, link);
        iommufd_free_ioas(ioas);
    }

    free(iommufd);
}

static iommufd_ioas_t *
iommufd_find_ioas(iommufd_controller_t *iommufd, uint32_t ioas_id)
{
    iommufd_ioas_t *ioas;

    TAILQ_FOREACH(ioas, &iommufd->ioas_list, link) {
        if (ioas->ioas_id == ioas_id) {
            return ioas;
        }
    }

    return NULL;
}

/*
 * Find an iommufd mapping by IOVA.
 * Returns the mapping if found, NULL otherwise.
 * Optimized with thread-local hint (similar to DMA controller's region_hint).
 */
iommufd_mapping_t *
iommufd_find_mapping(iommufd_controller_t *iommufd, uint64_t iova, size_t len)
{
    static __thread iommufd_mapping_t *mapping_hint;
    iommufd_ioas_t *ioas;
    iommufd_mapping_t *mapping;

    if (iommufd == NULL || !iommufd->enabled) {
        return NULL;
    }

    /* Fast path: check hint first (similar to DMA controller's region_hint) */
    if (mapping_hint != NULL) {
        /* Check if hint matches the requested IOVA range */
        if (iova >= mapping_hint->iova &&
            iova + len <= mapping_hint->iova + mapping_hint->length) {
            return mapping_hint;
        }
        /* Hint doesn't match, clear it and continue to search */
        mapping_hint = NULL;
    }

    /* Fast path: check the bound IOAS first (where most mappings are) */
    if (iommufd->device_bound && iommufd->bound_ioas_id != 0) {
        ioas = iommufd_find_ioas(iommufd, iommufd->bound_ioas_id);
        if (ioas != NULL) {
            TAILQ_FOREACH(mapping, &ioas->mappings, link) {
                /* Check if the requested IOVA range overlaps with this mapping */
                if (iova >= mapping->iova && iova + len <= mapping->iova + mapping->length) {
                    mapping_hint = mapping; /* Update hint for next time */
                    return mapping;
                }
            }
        }
    }

    /* Slow path: search through other IOAS structures */
    TAILQ_FOREACH(ioas, &iommufd->ioas_list, link) {
        /* Skip the bound IOAS since we already checked it */
        if (iommufd->device_bound && ioas->ioas_id == iommufd->bound_ioas_id) {
            continue;
        }

        TAILQ_FOREACH(mapping, &ioas->mappings, link) {
            /* Check if the requested IOVA range overlaps with this mapping */
            if (iova >= mapping->iova && iova + len <= mapping->iova + mapping->length) {
                mapping_hint = mapping; /* Update hint for next time */
                return mapping;
            }
        }
    }

    return NULL;
}

int
iommufd_alloc_ioas(iommufd_controller_t *iommufd, uint32_t *ioas_id)
{
    iommufd_ioas_t *ioas;

    assert(iommufd != NULL);
    assert(ioas_id != NULL);

    if (!iommufd->enabled) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "iommufd not enabled");
        return ERROR_INT(EINVAL);
    }

    ioas = calloc(1, sizeof(*ioas));
    if (ioas == NULL) {
        return ERROR_INT(ENOMEM);
    }

    ioas->ioas_id = iommufd->next_ioas_id++;
    TAILQ_INIT(&ioas->mappings);
    TAILQ_INSERT_TAIL(&iommufd->ioas_list, ioas, link);

    *ioas_id = ioas->ioas_id;

    vfu_log(iommufd->vfu_ctx, LOG_DEBUG, "allocated IOAS id=%u", *ioas_id);

    return 0;
}

int
iommufd_destroy_ioas(iommufd_controller_t *iommufd, uint32_t ioas_id)
{
    iommufd_ioas_t *ioas;

    assert(iommufd != NULL);

    if (!iommufd->enabled) {
        return ERROR_INT(EINVAL);
    }

    ioas = iommufd_find_ioas(iommufd, ioas_id);
    if (ioas == NULL) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "IOAS id=%u not found", ioas_id);
        return ERROR_INT(ENOENT);
    }

    /* Cannot destroy IOAS that is currently attached */
    if (iommufd->device_bound && iommufd->bound_ioas_id == ioas_id) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "cannot destroy attached IOAS id=%u",
                ioas_id);
        return ERROR_INT(EBUSY);
    }

    TAILQ_REMOVE(&iommufd->ioas_list, ioas, link);
    iommufd_free_ioas(ioas);

    vfu_log(iommufd->vfu_ctx, LOG_DEBUG, "destroyed IOAS id=%u", ioas_id);

    return 0;
}

int
iommufd_bind_device(iommufd_controller_t *iommufd)
{
    assert(iommufd != NULL);

    if (!iommufd->enabled) {
        return ERROR_INT(EINVAL);
    }

    if (iommufd->device_bound) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "device already bound");
        return ERROR_INT(EEXIST);
    }

    iommufd->device_bound = true;
    iommufd->bound_ioas_id = 0;

    vfu_log(iommufd->vfu_ctx, LOG_DEBUG, "device bound to iommufd");

    return 0;
}

int
iommufd_attach_ioas(iommufd_controller_t *iommufd, uint32_t ioas_id)
{
    iommufd_ioas_t *ioas;

    assert(iommufd != NULL);

    if (!iommufd->enabled) {
        return ERROR_INT(EINVAL);
    }

    if (!iommufd->device_bound) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "device not bound");
        return ERROR_INT(EINVAL);
    }

    ioas = iommufd_find_ioas(iommufd, ioas_id);
    if (ioas == NULL) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "IOAS id=%u not found", ioas_id);
        return ERROR_INT(ENOENT);
    }

    iommufd->bound_ioas_id = ioas_id;

    vfu_log(iommufd->vfu_ctx, LOG_DEBUG, "device attached to IOAS id=%u", ioas_id);

    return 0;
}

int
iommufd_detach_ioas(iommufd_controller_t *iommufd)
{
    assert(iommufd != NULL);

    if (!iommufd->enabled) {
        return ERROR_INT(EINVAL);
    }

    if (!iommufd->device_bound) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "device not bound");
        return ERROR_INT(EINVAL);
    }

    if (iommufd->bound_ioas_id == 0) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "device not attached to any IOAS");
        return ERROR_INT(EINVAL);
    }

    vfu_log(iommufd->vfu_ctx, LOG_DEBUG, "device detached from IOAS id=%u",
            iommufd->bound_ioas_id);

    iommufd->bound_ioas_id = 0;

    return 0;
}

uint64_t
iommufd_map_iova(iommufd_controller_t *iommufd, uint32_t ioas_id,
                 uint64_t user_va, uint64_t length, uint64_t offset,
                 uint32_t flags, int fd)
{
    iommufd_ioas_t *ioas;
    iommufd_mapping_t *mapping;
    void *vaddr;
    uint32_t prot = 0;
    size_t page_size;

    assert(iommufd != NULL);

    if (!iommufd->enabled) {
        errno = EINVAL;
        return 0;
    }

    ioas = iommufd_find_ioas(iommufd, ioas_id);
    if (ioas == NULL) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "IOAS id=%u not found", ioas_id);
        errno = ENOENT;
        return 0;
    }

    /* Determine page size and round mmap parameters */
    page_size = getpagesize();
    off_t mmap_offset = (offset / page_size) * page_size;
    size_t offset_in_page = offset - mmap_offset;
    size_t mmap_length = length + offset_in_page;
    mmap_length = ((mmap_length + page_size - 1) / page_size) * page_size;

    /* Convert flags to prot */
    if (flags & VFIO_USER_IOMMUFD_MAP_READABLE) {
        prot |= PROT_READ;
    }
    if (flags & VFIO_USER_IOMMUFD_MAP_WRITEABLE) {
        prot |= PROT_WRITE;
    }

    /* mmap the memory */
    vaddr = mmap(NULL, mmap_length, prot, MAP_SHARED, fd, mmap_offset);
    if (vaddr == MAP_FAILED) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR,
                "failed to mmap fd=%d offset=%#llx length=%#zx: %m",
                fd, (unsigned long long)mmap_offset, mmap_length);
        errno = ENOMEM;
        return 0;
    }

    /* Allocate mapping structure */
    mapping = calloc(1, sizeof(*mapping));
    if (mapping == NULL) {
        munmap(vaddr, mmap_length);
        errno = ENOMEM;
        return 0;
    }

    /* The IOVA is the server's vaddr (offset-adjusted) */
    mapping->vaddr = vaddr;
    mapping->iova = (uint64_t)(uintptr_t)(vaddr + offset_in_page);
    mapping->length = length;
    mapping->user_va = user_va;
    mapping->offset = offset;
    mapping->fd = fd;
    mapping->flags = flags;

    TAILQ_INSERT_TAIL(&ioas->mappings, mapping, link);

    vfu_log(iommufd->vfu_ctx, LOG_DEBUG,
            "mapped IOAS id=%u: iova=%#llx length=%#llx user_va=%#llx",
            ioas_id, (unsigned long long)mapping->iova,
            (unsigned long long)length, (unsigned long long)user_va);

    /* Call the dma_register callback if set */
    if (iommufd->vfu_ctx->dma_register != NULL) {
        vfu_dma_info_t info = {
            .iova.iov_base = (void *)(uintptr_t)mapping->iova,
            .iova.iov_len = mapping->length,
            .vaddr = vaddr + offset_in_page,
            .mapping.iov_base = vaddr,
            .mapping.iov_len = mmap_length,
            .page_size = page_size,
            .prot = prot
        };
        iommufd->vfu_ctx->in_cb = CB_DMA_REGISTER;
        iommufd->vfu_ctx->dma_register(iommufd->vfu_ctx, &info);
        iommufd->vfu_ctx->in_cb = CB_NONE;
    }

    return mapping->iova;
}

int
iommufd_unmap_iova(iommufd_controller_t *iommufd, uint32_t ioas_id,
                   uint64_t iova, uint64_t length)
{
    iommufd_ioas_t *ioas;
    iommufd_mapping_t *mapping;

    assert(iommufd != NULL);

    if (!iommufd->enabled) {
        return ERROR_INT(EINVAL);
    }

    ioas = iommufd_find_ioas(iommufd, ioas_id);
    if (ioas == NULL) {
        vfu_log(iommufd->vfu_ctx, LOG_ERR, "IOAS id=%u not found", ioas_id);
        return ERROR_INT(ENOENT);
    }

    TAILQ_FOREACH(mapping, &ioas->mappings, link) {
        if (mapping->iova == iova && mapping->length == length) {
            /* Call dma_unregister callback if set */
            if (iommufd->vfu_ctx->dma_unregister != NULL) {
                vfu_dma_info_t info = {
                    .iova.iov_base = (void *)(uintptr_t)mapping->iova,
                    .iova.iov_len = mapping->length,
                    .vaddr = (void *)(uintptr_t)mapping->iova,
                    .mapping.iov_base = mapping->vaddr,
                    .mapping.iov_len = mapping->length,
                    .page_size = getpagesize(),
                    .prot = 0
                };
                iommufd->vfu_ctx->in_cb = CB_DMA_UNREGISTER;
                iommufd->vfu_ctx->dma_unregister(iommufd->vfu_ctx, &info);
                iommufd->vfu_ctx->in_cb = CB_NONE;
            }

            TAILQ_REMOVE(&ioas->mappings, mapping, link);
            iommufd_free_mapping(mapping);

            vfu_log(iommufd->vfu_ctx, LOG_DEBUG,
                    "unmapped IOAS id=%u: iova=%#llx length=%#llx",
                    ioas_id, (unsigned long long)iova, (unsigned long long)length);

            return 0;
        }
    }

    vfu_log(iommufd->vfu_ctx, LOG_ERR,
            "mapping not found in IOAS id=%u: iova=%#llx length=%#llx",
            ioas_id, (unsigned long long)iova, (unsigned long long)length);

    return ERROR_INT(ENOENT);
}

void
iommufd_enable(iommufd_controller_t *iommufd)
{
    assert(iommufd != NULL);
    iommufd->enabled = true;
    vfu_log(iommufd->vfu_ctx, LOG_INFO, "iommufd mode enabled");
}

bool
iommufd_is_enabled(iommufd_controller_t *iommufd)
{
    return iommufd != NULL && iommufd->enabled;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
