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

#ifndef LIB_MUSER_H
#define LIB_MUSER_H

#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>

#include "pci.h"

typedef uint64_t dma_addr_t;

typedef struct {
    int region;
    int length;
    uint64_t offset;
} dma_scattergather_t;

typedef struct lm_ctx lm_ctx_t;
typedef struct lm_pci_config_space lm_pci_config_space_t;

typedef enum {
    LM_ERR,
    LM_INF,
    LM_DBG
} lm_log_lvl_t;

enum {
    LM_DEV_BAR0_REG_IDX,
    LM_DEV_BAR1_REG_IDX,
    LM_DEV_BAR2_REG_IDX,
    LM_DEV_BAR3_REG_IDX,
    LM_DEV_BAR4_REG_IDX,
    LM_DEV_BAR5_REG_IDX,
    LM_DEV_ROM_REG_IDX,
    LM_DEV_CFG_REG_IDX,
    LM_DEV_VGA_REG_IDX,
    LM_DEV_NUM_REGS = 9
};

// Region flags.
#define LM_REG_FLAG_READ    (1 << 0)
#define LM_REG_FLAG_WRITE   (1 << 1)
#define LM_REG_FLAG_MMAP    (1 << 2)    // TODO: how this relates to IO bar?
#define LM_REG_FLAG_RW      (LM_REG_FLAG_READ | LM_REG_FLAG_WRITE)
#define LM_REG_FLAG_MEM     (1 << 3)    // if unset, bar is IO

struct lm_mmap_area {
	uint64_t start;
	uint64_t size;
};

struct lm_sparse_mmap_areas {
    int nr_mmap_areas;
    struct lm_mmap_area areas[];
};

typedef ssize_t (lm_region_access_t) (void *pvt, char * const buf, size_t count,
                                      loff_t offset, const bool is_write);

typedef unsigned long (lm_map_region_t) (void *pvt, unsigned long pgoff,
                                         unsigned long len);

typedef struct  {
    uint32_t            flags;
    uint32_t            size;
    uint64_t            offset;
    lm_region_access_t  *fn;
    lm_map_region_t     *map;
    struct lm_sparse_mmap_areas *mmap_areas; /* sparse mmap areas */
} lm_reg_info_t;

enum {
    LM_DEV_INTX_IRQ_IDX,
    LM_DEV_MSI_IRQ_IDX,
    LM_DEV_MSIX_IRQ_IDX,
    LM_DEV_ERR_IRQ_IDX,
    LM_DEV_REQ_IRQ_IDX,
    LM_DEV_NUM_IRQS = 5
};

/*
 * Returns a pointer to the non-standard part of the PCI configuration space.
 */
lm_pci_config_space_t *lm_get_pci_config_space(lm_ctx_t * const lm_ctx);

lm_reg_info_t *lm_get_region_info(lm_ctx_t * const lm_ctx);

/*
 * TODO the rest of these functions don't need to be public, put them in a
 * private header file so libmuser.c can use them.
 * TODO replace the "muser" prefix
 */
int
muser_pci_hdr_access(lm_ctx_t * const lm_ctx, size_t * const count,
                     loff_t * const pos, const bool write,
                     unsigned char *const buf);

#define LM_DMA_REGIONS  0x10

typedef struct {
    uint32_t            irq_count[LM_DEV_NUM_IRQS];
    lm_reg_info_t	    reg_info[LM_DEV_NUM_REGS];

    lm_pci_hdr_id_t     id;
    lm_pci_hdr_cc_t     cc;
} lm_pci_info_t;

/**
 *  Callback function signature for log function
 *
 * @lm_log_fn_t: typedef for log function.
 */
typedef void (lm_log_fn_t) (void *pvt, const char *const msg);

/**
 * Callback function that gets called when a capability is accessed. The
 * will not be called when the ID and next fields are accessed, these are
 * hanlded by the library.
 *
 * pvt: private pointer
 * id: capability ID being accessed
 * buf: pointer to data being read or written
 * count: number of bytes being read or written
 * offset: offset within the capability
 * is_write: whether the capability is read or written
 */
typedef ssize_t (lm_cap_access_t) (void *pvt, const uint8_t id,
                                   char * const buf, size_t count,
                                   loff_t offset, const bool is_write);

typedef struct {
    uint8_t id;
    size_t size;
    lm_cap_access_t *fn;
} lm_cap_t;

#define LM_MAX_CAPS (PCI_CFG_SPACE_SIZE - PCI_STD_HEADER_SIZEOF) / PCI_CAP_SIZEOF

/**
 * Device information structure, used to create the lm_ctx.
 * To be filled and passed to lm_ctx_run()
 */
typedef struct {
    char            *uuid;
    void		    *pvt;
    /*
     * whether an extended PCI configuration space should be created
     */
    bool            extended;
    lm_log_fn_t		*log;
    lm_log_lvl_t	log_lvl;
    lm_pci_info_t	pci_info;

    /* device reset callback, optional */
    int (*reset)    (void *pvt);

    /*
     * PCI capabilities. The user needs to only define the ID and size of each
     * capability. The actual capability is not maintained by libmuser. When a
     * capability is accessed the appropriate callback function is called.
     */
    lm_cap_t        caps[LM_MAX_CAPS];
    int             nr_caps;
    
} lm_dev_info_t;

/**
 * Creates libmuser context.
 *
 * Arguments:
 * @dev_info: device information used to create the context.
 */
lm_ctx_t *lm_ctx_create(lm_dev_info_t * dev_info);

/**
 * Destroys libmuser context.
 *
 * Arguments:
 * @lm_ctx: libmuser context to destroy.
 */
void lm_ctx_destroy(lm_ctx_t * lm_ctx);

/**
 * Once the lm_ctx is configured lm_ctx_drive() drives it. This function waits
 * for commands comming from muser.ko and then processes it..
 *
 * Arguments:
 * @lm_ctx: libmuser context to drive.
 */

int lm_ctx_drive(lm_ctx_t * lm_ctx);


/**
 * Allocates memory that can be presented as device memory in the guest (e.g.
 * when serving a region map call).  This is the only reliable way to allocate
 * memory for this purpose
 *
 * Arguments:
 * @lm_ctx: libmuser context to create mapping from.
 */
void *lm_mmap(lm_ctx_t * lm_ctx, size_t length, off_t offset);

/**
 * Trigger interrupt.
 *
 * Arguments:
 * @lm_ctx: libmuser context to trigger interrupt.
 * @vector: vector to tirgger interrupt on.
 */
int lm_irq_trigger(lm_ctx_t * lm_ctx, uint32_t vector);

/* Helper functions */

int lm_ctx_run(lm_ctx_t * const ctx);

/**
 * Converts a guest physical address to a dma_scattergather_t element which can
 * be later passed on to lm_map_sg to memory map the GPA. It is the caller's
 * responsibility to unmap it by calling lm_unmap_sg.
 */
int lm_addr_to_sg(lm_ctx_t * const ctx, dma_addr_t dma_addr, uint32_t len,
                  dma_scattergather_t * sg, int max_sg);

int
lm_map_sg(lm_ctx_t * const ctx, int prot, const dma_scattergather_t * sg,
          struct iovec *iov, int cnt);

void
lm_unmap_sg(lm_ctx_t * const ctx, const dma_scattergather_t * sg,
            struct iovec *iov, int cnt);

/**
 * Returns the PCI region given the position in the PCI configuration space.
 * Sets @off relative to the region.
 */
int
lm_get_region(lm_ctx_t * const ctx, const loff_t pos,
              const size_t count, loff_t * const off);

/*
 * Advanced.
 */
uint8_t *lm_get_pci_non_std_config_space(lm_ctx_t * const lm_ctx);

#ifdef DEBUG
void
dump_buffer(lm_ctx_t const *const lm_ctx, char const *const prefix,
            unsigned char const *const buf, const uint32_t count);
#endif

#endif                          /* LIB_MUSER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
