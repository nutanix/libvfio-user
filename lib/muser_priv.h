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

#ifndef MUSER_PRIV_H
#define MUSER_PRIV_H

#include "dma.h"

#ifdef LM_VERBOSE_LOGGING
void
dump_buffer(const char *prefix, const char *buf, uint32_t count);
#else
#define dump_buffer(prefix, buf, count)
#endif

struct transport_ops {
    int (*init)(lm_ctx_t*);
    int (*attach)(lm_ctx_t*);
    int(*detach)(lm_ctx_t*);
    int (*get_request)(lm_ctx_t*, struct vfio_user_header*, int *fds, int *nr_fds);
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
} lm_irqs_t;

struct migration;

struct lm_ctx {
    void                    *pvt;
    dma_controller_t        *dma;
    int                     fd;
    int                     conn_fd;
    int (*reset)            (void *pvt);
    lm_log_lvl_t            log_lvl;
    lm_log_fn_t             *log;
    uint32_t                irq_count[LM_DEV_NUM_IRQS];
    size_t                  nr_regions;
    lm_reg_info_t           *reg_info;
    lm_pci_config_space_t   *pci_config_space;
    struct transport_ops    *trans;
    struct caps             *caps;
    uint64_t                flags;
    char                    *uuid;
    void (*map_dma)         (void *pvt, uint64_t iova, uint64_t len);
    int (*unmap_dma)        (void *pvt, uint64_t iova);

    /* TODO there should be a void * variable to store transport-specific stuff */
    /* LM_TRANS_SOCK */
    int                     sock_flags;

    int                     client_max_fds;

    lm_reg_info_t           *migr_reg;
    struct migration        *migration;

    lm_irqs_t               irqs; /* XXX must be last */
};

int
muser_pci_hdr_access(lm_ctx_t *lm_ctx, uint32_t *count,
                     uint64_t *pos, bool write, char *buf);

lm_reg_info_t *
lm_get_region_info(lm_ctx_t *lm_ctx);

uint64_t
region_to_offset(uint32_t region);

/* FIXME copied from include/linux/stddef.h, is this OK license-wise? */
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define offsetofend(TYPE, MEMBER) \
       (offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))

static inline ssize_t get_minsz(unsigned int cmd)
{
	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return offsetofend(struct vfio_device_info, num_irqs);
	case VFIO_DEVICE_GET_REGION_INFO:
		return offsetofend(struct vfio_region_info, offset);
	case VFIO_DEVICE_GET_IRQ_INFO:
		return offsetofend(struct vfio_irq_info, count);
	case VFIO_DEVICE_SET_IRQS:
		return offsetofend(struct vfio_irq_set, count);
	case VFIO_GROUP_GET_STATUS:
		return offsetofend(struct vfio_group_status, flags);
	case VFIO_GET_API_VERSION:
		return 0;
	case VFIO_CHECK_EXTENSION:
	case VFIO_GROUP_SET_CONTAINER:
	case VFIO_GROUP_UNSET_CONTAINER:
	case VFIO_SET_IOMMU:
		return sizeof(int);
	case VFIO_IOMMU_GET_INFO:
		return offsetofend(struct vfio_iommu_type1_info, iova_pgsizes);
	case VFIO_IOMMU_MAP_DMA:
		return offsetofend(struct vfio_iommu_type1_dma_map, size);
	case VFIO_IOMMU_UNMAP_DMA:
		return offsetofend(struct vfio_iommu_type1_dma_unmap, size);
	case VFIO_GROUP_GET_DEVICE_FD:
	case VFIO_DEVICE_RESET:
		return 0;
	}
	return -EOPNOTSUPP;
}

static inline const char* vfio_cmd_to_str(int cmd) {
        switch (cmd) {
                case VFIO_GET_API_VERSION: return "VFIO_GET_API_VERSION";
                case VFIO_CHECK_EXTENSION: return "VFIO_CHECK_EXTENSION";
                case VFIO_SET_IOMMU: return "VFIO_SET_IOMMU";
                case VFIO_GROUP_GET_STATUS: return "VFIO_GROUP_GET_STATUS";
                case VFIO_GROUP_SET_CONTAINER: return "VFIO_GROUP_SET_CONTAINER";
                case VFIO_GROUP_UNSET_CONTAINER: return "VFIO_GROUP_UNSET_CONTAINER";
                case VFIO_GROUP_GET_DEVICE_FD: return "VFIO_GROUP_GET_DEVICE_FD";
                case VFIO_DEVICE_GET_INFO: return "VFIO_DEVICE_GET_INFO";
                case VFIO_DEVICE_GET_REGION_INFO: return "VFIO_DEVICE_GET_REGION_INFO";
                case VFIO_DEVICE_GET_IRQ_INFO: return "VFIO_DEVICE_GET_IRQ_INFO";
                case VFIO_DEVICE_SET_IRQS: return "VFIO_DEVICE_SET_IRQS";
                case VFIO_DEVICE_RESET: return "VFIO_DEVICE_RESET";
                case VFIO_IOMMU_GET_INFO: return "VFIO_IOMMU_GET_INFO/VFIO_DEVICE_GET_PCI_HOT_RESET_INFO/VFIO_IOMMU_SPAPR_TCE_GET_INFO";
                case VFIO_IOMMU_MAP_DMA: return "VFIO_IOMMU_MAP_DMA/VFIO_DEVICE_PCI_HOT_RESET";
                case VFIO_IOMMU_UNMAP_DMA: return "VFIO_IOMMU_UNMAP_DMA";
                case VFIO_IOMMU_ENABLE: return "VFIO_IOMMU_ENABLE";
                case VFIO_IOMMU_DISABLE: return "VFIO_IOMMU_DISABLE";
                case VFIO_EEH_PE_OP: return "VFIO_EEH_PE_OP";
                case VFIO_IOMMU_SPAPR_REGISTER_MEMORY: return "VFIO_IOMMU_SPAPR_REGISTER_MEMORY";
                case VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY: return "VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY";
                case VFIO_IOMMU_SPAPR_TCE_CREATE: return "VFIO_IOMMU_SPAPR_TCE_CREATE";
                case VFIO_IOMMU_SPAPR_TCE_REMOVE: return "VFIO_IOMMU_SPAPR_TCE_REMOVE";
        }
        return NULL;
}

#endif /* MUSER_PRIV_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
