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

/*
 * iommufd support for libvfio-user
 */

#ifndef LIB_VFIO_USER_IOMMUFD_H
#define LIB_VFIO_USER_IOMMUFD_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/queue.h>

struct vfu_ctx;

/*
 * Represents a single IOVA mapping within an IOAS.
 * The IOVA is assigned to be equal to the server's vaddr.
 */
typedef struct iommufd_mapping {
    uint64_t            iova;           /* Server's vaddr, used as IOVA */
    uint64_t            length;
    uint64_t            user_va;        /* Client's vaddr (for tracking) */
    uint64_t            offset;         /* Offset in fd */
    int                 fd;
    uint32_t            flags;
    void                *vaddr;         /* Server's mapped address */
    TAILQ_ENTRY(iommufd_mapping) link;
} iommufd_mapping_t;

/*
 * Represents an IOAS (I/O Address Space).
 */
typedef struct iommufd_ioas {
    uint32_t            ioas_id;
    TAILQ_HEAD(, iommufd_mapping) mappings;
    TAILQ_ENTRY(iommufd_ioas) link;
} iommufd_ioas_t;

/*
 * iommufd controller state.
 * Stored per connection (in vfu_ctx), reset on client disconnect.
 */
typedef struct iommufd_controller {
    struct vfu_ctx      *vfu_ctx;
    bool                enabled;        /* iommufd mode negotiated */
    bool                device_bound;   /* Device bound to iommufd */
    uint32_t            bound_ioas_id;  /* Currently attached IOAS */
    uint32_t            next_ioas_id;   /* For allocating new IOAS IDs */
    TAILQ_HEAD(, iommufd_ioas) ioas_list;
} iommufd_controller_t;

/*
 * Create a new iommufd controller.
 */
iommufd_controller_t *
iommufd_controller_create(struct vfu_ctx *vfu_ctx);

/*
 * Destroy an iommufd controller and free all resources.
 */
void
iommufd_controller_destroy(iommufd_controller_t *iommufd);

/*
 * Allocate a new IOAS.
 * Returns the new IOAS ID on success, or -1 with errno set on failure.
 */
int
iommufd_alloc_ioas(iommufd_controller_t *iommufd, uint32_t *ioas_id);

/*
 * Destroy an IOAS and all its mappings.
 */
int
iommufd_destroy_ioas(iommufd_controller_t *iommufd, uint32_t ioas_id);

/*
 * Bind the device to iommufd.
 */
int
iommufd_bind_device(iommufd_controller_t *iommufd);

/*
 * Attach device to an IOAS (page table).
 */
int
iommufd_attach_ioas(iommufd_controller_t *iommufd, uint32_t ioas_id);

/*
 * Detach device from its current IOAS.
 */
int
iommufd_detach_ioas(iommufd_controller_t *iommufd);

/*
 * Map memory into an IOAS.
 * The server mmaps the fd and uses the resulting vaddr as the IOVA.
 * Returns the allocated IOVA on success, or 0 on failure with errno set.
 */
uint64_t
iommufd_map_iova(iommufd_controller_t *iommufd, uint32_t ioas_id,
                 uint64_t user_va, uint64_t length, uint64_t offset,
                 uint32_t flags, int fd);

/*
 * Unmap memory from an IOAS.
 */
int
iommufd_unmap_iova(iommufd_controller_t *iommufd, uint32_t ioas_id,
                   uint64_t iova, uint64_t length);

/*
 * Enable iommufd mode after successful capability negotiation.
 */
void
iommufd_enable(iommufd_controller_t *iommufd);

/*
 * Check if iommufd mode is enabled.
 */
bool
iommufd_is_enabled(iommufd_controller_t *iommufd);

/*
 * Find an iommufd mapping by IOVA.
 * Returns the mapping if found, NULL otherwise.
 */
iommufd_mapping_t *
iommufd_find_mapping(iommufd_controller_t *iommufd, uint64_t iova, size_t len);

#endif /* LIB_VFIO_USER_IOMMUFD_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
