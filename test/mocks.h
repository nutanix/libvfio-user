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

#include <stdbool.h>
#include "private.h"

void unpatch_all(void);

void patch(void *fn);

bool is_patched(void *fn);

int
handle_dirty_pages(vfu_ctx_t *vfu_ctx, uint32_t size,
                   struct iovec **iovecs, size_t *nr_iovecs,
                   struct vfio_iommu_type1_dirty_bitmap *dirty_bitmap);

int
__real_handle_dirty_pages(vfu_ctx_t *vfu_ctx, uint32_t size,
                          struct iovec **iovecs, size_t *nr_iovecs,
                          struct vfio_iommu_type1_dirty_bitmap *dirty_bitmap);

int
__real_dma_controller_add_region(dma_controller_t *dma, dma_addr_t dma_addr,
                                 size_t size, int fd, off_t offset,
                                 uint32_t prot);

bool
__real_device_is_stopped(struct migration *migr);

int
__real_exec_command(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr,
                    size_t size, int *fds, size_t *nr_fds, size_t **fds_out,
                    int *nr_fds_out, struct iovec *_iovecs, struct iovec **iovecs,
                    size_t *nr_iovecs, bool *free_iovec_data);
int
__real_close(int fd);

void
__real_free(void *ptr);

int
__real_process_request(vfu_ctx_t *vfu_ctx);


/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
