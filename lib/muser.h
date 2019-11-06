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

/*
 * Influential enviroment variables:
 *
 * LM_TERSE_LOGGING: define to make libmuser log only erroneous PCI accesses.
 *                   (this should really be done with a more fine grained debug
 *                    level)
 */
#ifndef LM_TERSE_LOGGING
#define LM_TERSE_LOGGING 0
#endif

typedef uint64_t dma_addr_t;

typedef struct {
    int region;
    int length;
    uint64_t offset;
} dma_sg_t;

typedef struct lm_ctx lm_ctx_t;

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

/**
 * Prototype for region access callback. When a region is accessed, libmuser
 * calls the previously registered callback with the following arguments:
 *
 * @pvt: private data originally set in dev_info
 * @buf: buffer containing the data to be written or data to be read into
 * @count: number of bytes being read or written
 * @offset: byte offset within the region
 * @is_write: whether or not this is a write
 *
 * @returns the number of bytes read or written, or a negative integer on error
 */
typedef ssize_t (lm_region_access_t) (void *pvt, char *buf, size_t count,
                                      loff_t offset, bool is_write);

/**
 * Prototype for memory access callback. The program MUST first map device
 * memory in its own virtual address space using lm_mmap, do any additional
 * work required, and finally return that memory. When a region is memory
 * mapped, libmuser calls previously register callback with the following
 * arguments:
 *
 * @pvt: private data originally set in dev_info
 * @off: offset of memory area being memory mapped
 * @len: length of memory area being memory mapped
 *
 * @returns the memory address returned by lm_mmap, or MAP_FAILED on failure
 */
typedef unsigned long (lm_map_region_t) (void *pvt, unsigned long off,
                                         unsigned long len);

/**
 * Creates a mapping of a device region into the caller's virtual memory. It
 * must be called by lm_map_region_t.
 *
 * @lm_ctx: the libmuser context to create mapping from
 * @offset: offset of the region being mapped
 * @length: size of the region being mapped
 *
 * @returns a pointer to the requested memory or MAP_FAILED on error. Sets errno.
 */
void *lm_mmap(lm_ctx_t * lm_ctx, off_t offset, size_t length);

typedef struct  {

    /*
     * Region flags, see LM_REG_FLAG_XXX above.
     */
    uint32_t            flags;

    /*
     * Size of the region.
     */
    uint32_t            size;

    /*
     * Callback function that is called when the region is read or written.
     */
    lm_region_access_t  *fn;

    /*
     * Callback function that is called when the region is memory mapped.
     * Required if LM_REG_FLAG_MEM is set, otherwise ignored.
     */
    lm_map_region_t     *map;
    struct lm_sparse_mmap_areas *mmap_areas; /* sparse mmap areas */
} lm_reg_info_t;

enum {
    LM_DEV_INTX_IRQ_IDX,
    LM_DEV_MSI_IRQ_IDX,
    LM_DEV_MSIX_IRQ_IDX,
    LM_DEV_NUM_IRQS = 3
};

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

typedef struct {
    uint32_t            irq_count[LM_DEV_NUM_IRQS];

    /*
     * Per-region information. Only supported regions need to be defined,
     * unsupported regions should be left to 0.
     */
    lm_reg_info_t       reg_info[LM_DEV_NUM_REGS];

    /*
     * Device and vendor ID.
     */
    lm_pci_hdr_id_t     id;

    /*
     * Subsystem vendor and device ID.
     */
    lm_pci_hdr_ss_t     ss;

    /*
     * Class code.
     */
    lm_pci_hdr_cc_t     cc;
} lm_pci_info_t;

/*
 * Returns a pointer to the non-standard part of the PCI configuration space.
 */
lm_pci_config_space_t *lm_get_pci_config_space(lm_ctx_t *lm_ctx);

#define LM_DMA_REGIONS  0x10

typedef enum {
    LM_ERR,
    LM_INF,
    LM_DBG
} lm_log_lvl_t;

/**
 * Callback function signature for log function
 *
 * @lm_log_fn_t: typedef for log function.
 */
typedef void (lm_log_fn_t) (void *pvt, const char *msg);

/**
 * Callback function that gets called when a capability is accessed. The
 * callback is not called when the ID and next fields are accessed, these are
 * handled by the library.
 *
 * @pvt: private pointer
 * @id: capability ID being accessed
 * @buf: pointer to data being read or written
 * @count: number of bytes being read or written
 * @offset: offset within the capability
 * @is_write: whether the capability is read or written
 *
 * @returns the number of bytes read or written
 */
typedef ssize_t (lm_cap_access_t) (void *pvt, uint8_t id,
                                   char *buf, size_t count,
                                   loff_t offset, bool is_write);

typedef struct {

    /*
     * Capability ID, as defined by the PCI specification. Also defined as
     * PCI_CAP_ID_XXX in <linux/pci_regs.h>.
     */
    uint8_t id;

    /*
     * Size of the capability.
     */
    size_t size;

    /*
     * Function to call back when the capability gets read or written.
     */
    lm_cap_access_t *fn;
} lm_cap_t;

#define LM_MAX_CAPS (PCI_CFG_SPACE_SIZE - PCI_STD_HEADER_SIZEOF) / PCI_CAP_SIZEOF

/**
 * Device information structure, used to create the lm_ctx.
 * To be filled and passed to lm_ctx_create()
 */
typedef struct {
    char            *uuid;

    /*
     * Private data passed to various lm_XXX functions.
     */
    void            *pvt;

    /*
     * Whether an extended PCI configuration space should be created.
     */
    bool            extended;

    /*
     * Function to call for logging. Optional.
     */
    lm_log_fn_t     *log;

    /*
     * Log level. Messages above this level are not logged. Optional
     */
    lm_log_lvl_t    log_lvl;

    /*
     * PCI configuration.
     */
    lm_pci_info_t   pci_info;

    /*
     * Function that is called when the guest resets the device. Optional.
     */
    int (*reset)    (void *pvt);

    /*
     * PCI capabilities. The user needs to only define the ID and size of each
     * capability. The actual capability is not maintained by libmuser. When a
     * capability is accessed the appropriate callback function is called.
     */
    lm_cap_t        caps[LM_MAX_CAPS];

    /*
     * Number of capabilities in above array.
     */
    int             nr_caps;
} lm_dev_info_t;

/**
 * Creates libmuser context.
 *
 * @dev_info: device information used to create the context.
 *
 * @returns the lm_ctx to be used or NULL on error. Sets errno.
 */
lm_ctx_t *
lm_ctx_create(lm_dev_info_t *dev_info);

/**
 * Destroys libmuser context.
 *
 * @lm_ctx: the libmuser context to destroy
 */
void
lm_ctx_destroy(lm_ctx_t *lm_ctx);

/**
 * Once the lm_ctx is configured lm_ctx_drive() drives it. This function waits
 * for commands coming from muser.ko and then processes it.
 *
 * @lm_ctx: the libmuser context to drive
 *
 * @returns 0 on success, -errno on failure.
 */
int
lm_ctx_drive(lm_ctx_t *lm_ctx);

/**
 * Creates and runs an lm_ctx.
 *
 * @dev_info: device information used to create the context
 *
 * @returns 0 on success, -1 on failure. Sets errno.
 */
int
lm_ctx_run(lm_dev_info_t *dev_info);

/**
 * Triggers an interrupt.
 *
 * libmuser takes care of using the IRQ type (INTx, MSI/X), the caller only
 * needs to specify the sub-index.
 *
 * @lm_ctx: the libmuser context to trigger interrupt
 * @subindex: vector subindex to trigger interrupt on
 *
 * @returns 0 on success, or -1 on failure. Sets errno.
 */
int
lm_irq_trigger(lm_ctx_t *lm_ctx, uint32_t subindex);

/* Helper functions */

/**
 * Converts a guest physical address to a dma_sg_t element which can
 * be later passed on to lm_map_sg to memory map the GPA. It is the caller's
 * responsibility to unmap it by calling lm_unmap_sg.
 *
 */

/**
 * Takes a guest physical address and returns a list of scatter/gather entries
 * than can be individually mapped in the program's virtual memory.  A single
 * linear guest physical address span may need to be split into multiple
 * scatter/gather regions due to limitations of how memory can be mapped.
 *
 * @lm_ctx: the libmuser context
 * @dma_addr: the guest physical address
 * @len: size of memory to be mapped
 * @sg: array that receives the scatter/gather entries to be mapped
 * @max_sg: maximum number of elements in above array
 *
 * @returns the number of scatter/gather entries created on success, and on
 * failure:
 *  -1:         if the GPA address span is invalid, or
 *  (-x - 1):   if @max_sg is too small, where x is the number of scatter/gather
 *              entries necessary to complete this request.
 */
int
lm_addr_to_sg(lm_ctx_t *lm_ctx, dma_addr_t dma_addr, uint32_t len,
              dma_sg_t *sg, int max_sg);

/**
 * Maps a list scatter/gather entries from the guest's physical address space
 * to the program's virtual memory. It is the caller's responsibility to remove
 * the mappings by calling lm_unmap_sg.
 *
 * @lm_ctx: the libmuser context
 * @prot: protection flags, defined as PROT_XXX in <sys/mman.h>
 * @sg: array of scatter/gather entries returned by lm_addr_to_sg
 * @iov: array of iovec structures (defined in <sys/uio.h>) to receive each
 *       mapping
 * @cnt: number of scatter/gather entries to map
 *
 * @returns 0 on success, -1 on failure
 */
int
lm_map_sg(lm_ctx_t *lm_ctx, int prot, const dma_sg_t *sg,
          struct iovec *iov, int cnt);

/**
 * Unmaps a list scatter/gather entries (previously mapped by lm_map_sg) from
 * the program's virtual memory.
 *
 * @lm_ctx: the libmuser context
 * @sg: array of scatter/gather entries to unmap
 * @iov: array of iovec structures for each scatter/gather entry
 * @cnt: number of scatter/gather entries to unmap
 */
void
lm_unmap_sg(lm_ctx_t *lm_ctx, const dma_sg_t *sg,
            struct iovec *iov, int cnt);

/**
 * Returns the PCI region given the position and size of an address span in the
 * PCI configuration space.
 *
 * @pos: offset of the address span
 * @count: size of the address span
 * @off: output parameter that receives the relative offset within the region.
 *
 * Returns the PCI region (LM_DEV_XXX_REG_IDX), or -errno on error.
 */
int
lm_get_region(loff_t pos, size_t count, loff_t *off);

/*
 * Advanced stuff.
 */

/**
 * Returns the non-standard part of the PCI configuragion space.
 */
uint8_t *
lm_get_pci_non_std_config_space(lm_ctx_t *lm_ctx);

#endif /* LIB_MUSER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
