/*
 * Copyright (c) 2019 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
 *          Swapnil Ingle <swapnil.ingle@nutanix.com>
 *          Felipe Franciosi <felipe@nutanix.com>
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

#ifndef LIB_VFIO_USER_PRIVATE_H
#define LIB_VFIO_USER_PRIVATE_H

#include "pci_caps.h"
#include "dma.h"

static inline int
ERROR_INT(int err)
{
    errno = err;
    return -1;
}

static inline void *
ERROR_PTR(int err)
{
    errno = err;
    return NULL;
}

struct transport_ops {
    int (*init)(vfu_ctx_t *vfu_ctx);
    int (*attach)(vfu_ctx_t *vfu_ctx);

    int (*get_request)(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr,
                       int *fds, size_t *nr_fds);

    int (*recv_body)(vfu_ctx_t *vfu_ctx, const struct vfio_user_header *hdr,
                     void **datap);

    int (*reply)(vfu_ctx_t *vfu_ctx, uint16_t msg_id,
                 struct iovec *iovecs, size_t nr_iovecs,
                 int *fds, int count, int err);

    int (*send_msg)(vfu_ctx_t *vfu_ctx, uint16_t msg_id,
                    enum vfio_user_command cmd,
                    void *send_data, size_t send_len,
                    struct vfio_user_header *hdr,
                    void *recv_data, size_t recv_len);

    void (*detach)(vfu_ctx_t *vfu_ctx);
    void (*fini)(vfu_ctx_t *vfu_ctx);
};

typedef enum {
    IRQ_NONE = 0,
    IRQ_INTX,
    IRQ_MSI,
    IRQ_MSIX,
} irq_type_t;

typedef struct {
    irq_type_t  type;       /* irq type this device is using */
    int         err_efd;    /* eventfd for irq err */
    int         req_efd;    /* eventfd for irq req */
    uint32_t    max_ivs;    /* maximum number of ivs supported */
    int         efds[0];    /* XXX must be last */
} vfu_irqs_t;

struct migration;

typedef struct  {
    /* Region flags, see VFU_REGION_FLAG_READ and friends. */
    uint32_t            flags;
    /* Size of the region. */
    uint32_t            size;
    /* Callback that is called when the region is read or written. */
    vfu_region_access_cb_t  *cb;
    /* Sparse mmap areas if set. */
    struct iovec *mmap_areas;
    int nr_mmap_areas;
    /* fd for a mappable region, or -1. */
    int fd;
} vfu_reg_info_t;

struct pci_dev {
    vfu_pci_type_t          type;
    vfu_pci_config_space_t  *config_space;
    struct pci_cap          caps[VFU_MAX_CAPS];
    size_t                  nr_caps;
    struct pci_cap          ext_caps[VFU_MAX_CAPS];
    size_t                  nr_ext_caps;
};

struct vfu_ctx {
    void                    *pvt;
    dma_controller_t        *dma;
    int                     fd;
    int                     conn_fd;
    vfu_reset_cb_t          *reset;
    int           log_level;
    vfu_log_fn_t            *log;
    size_t                  nr_regions;
    vfu_reg_info_t          *reg_info;
    struct pci_dev          pci;
    struct transport_ops    *tran;
    uint64_t                flags;
    char                    *uuid;
    vfu_map_dma_cb_t        *map_dma;
    vfu_unmap_dma_cb_t      *unmap_dma;

    int                     client_max_fds;

    vfu_reg_info_t          *migr_reg;
    struct migration        *migration;

    uint32_t                irq_count[VFU_DEV_NUM_IRQS];
    vfu_irqs_t              *irqs;
    bool                    realized;
    vfu_dev_type_t          dev_type;
};

void
dump_buffer(const char *prefix, const char *buf, uint32_t count);

vfu_reg_info_t *
vfu_get_region_info(vfu_ctx_t *vfu_ctx);

int
handle_dma_map_or_unmap(vfu_ctx_t *vfu_ctx, uint32_t size, bool map,
                        int *fds, size_t nr_fds,
                        struct vfio_user_dma_region *dma_regions);

void
_dma_controller_do_remove_region(dma_controller_t *dma,
                                 dma_memory_region_t *region);

int
get_next_command(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr, int *fds,
                 size_t *nr_fds);

int
exec_command(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr, size_t size,
             int *fds, size_t nr_fds, int **fds_out, size_t *nr_fds_out,
             struct iovec *_iovecs, struct iovec **iovecs, size_t *nr_iovecs,
             bool *free_iovec_data);

int
process_request(vfu_ctx_t *vfu_ctx);

int
consume_fd(int *fds, size_t nr_fds, size_t index);

int
handle_device_get_info(vfu_ctx_t *vfu_ctx, uint32_t size,
                       struct vfio_device_info *dev_info);

long
dev_get_reginfo(vfu_ctx_t *vfu_ctx, uint32_t index, uint32_t argsz,
                struct vfio_region_info **vfio_reg, int **fds, size_t *nr_fds);

#endif /* LIB_VFIO_USER_PRIVATE_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
