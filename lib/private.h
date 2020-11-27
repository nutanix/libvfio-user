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

#include "dma.h"

#ifdef VU_VERBOSE_LOGGING
void
dump_buffer(const char *prefix, const char *buf, uint32_t count);
#else
#define dump_buffer(prefix, buf, count)
#endif

struct transport_ops {
    int (*init)(vu_ctx_t*);
    int (*attach)(vu_ctx_t*);
    int(*detach)(vu_ctx_t*);
    int (*get_request)(vu_ctx_t*, struct vfio_user_header*, int *fds, int *nr_fds);
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
} vu_irqs_t;

struct migration;

typedef struct  {

    /*
     * Region flags, see VU_REG_FLAG_XXX above.
     */
    uint32_t            flags;

    /*
     * Size of the region.
     */
    uint32_t            size;

    /*
     * Callback function that is called when the region is read or written.
     * Note that the memory of the region is owned by the user, except for the
     * standard header (first 64 bytes) of the PCI configuration space.
     */
    vu_region_access_cb_t  *fn;

    /*
     * Callback function that is called when the region is memory mapped.
     * Required if VU_REG_FLAG_MEM is set, otherwise ignored.
     */
    vu_map_region_cb_t     *map;
    struct vu_sparse_mmap_areas *mmap_areas; /* sparse mmap areas */
} vu_reg_info_t;

struct vu_ctx {
    void                    *pvt;
    dma_controller_t        *dma;
    int                     fd;
    int                     conn_fd;
    vu_reset_cb_t           *reset;
    vu_log_lvl_t            log_lvl;
    vu_log_fn_t             *log;
    size_t                  nr_regions;
    vu_reg_info_t           *reg_info;
    vu_pci_config_space_t   *pci_config_space;
    struct transport_ops    *trans;
    struct caps             *caps;
    uint64_t                flags;
    char                    *uuid;
    vu_map_dma_cb_t         *map_dma;
    vu_unmap_dma_cb_t       *unmap_dma;

    /* TODO there should be a void * variable to store transport-specific stuff */
    /* VU_TRANS_SOCK */
    int                     sock_flags;

    int                     client_max_fds;

    vu_reg_info_t           *migr_reg;
    struct migration        *migration;

    uint32_t                irq_count[VU_DEV_NUM_IRQS];
    vu_irqs_t               *irqs;
    int                     ready;
};

int
vu_pci_hdr_access(vu_ctx_t *vu_ctx, uint32_t *count,
                  uint64_t *pos, bool write, char *buf);

vu_reg_info_t *
vu_get_region_info(vu_ctx_t *vu_ctx);

uint64_t
region_to_offset(uint32_t region);

int
handle_dma_map_or_unmap(vu_ctx_t *vu_ctx, uint32_t size, bool map,
                        int *fds, int nr_fds,
                        struct vfio_user_dma_region *dma_regions);

void
_dma_controller_do_remove_region(dma_controller_t *dma,
                                 dma_memory_region_t *region);

#endif /* LIB_VFIO_USER_PRIVATE_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
