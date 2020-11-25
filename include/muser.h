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
#include "pci_caps/pm.h"
#include "pci_caps/px.h"
#include "pci_caps/msi.h"
#include "pci_caps/msix.h"
#include "vfio_user.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LIB_MUSER_VFIO_USER_VERS_MJ 0
#define LIB_MUSER_VFIO_USER_VERS_MN 1

typedef uint64_t dma_addr_t;

typedef struct {
    dma_addr_t dma_addr;
    int region;
    int length;
    uint64_t offset;
} dma_sg_t;

typedef struct lm_ctx lm_ctx_t;

struct lm_mmap_area {
    uint64_t start;
    uint64_t size;
};

struct lm_sparse_mmap_areas {
    int nr_mmap_areas;
    struct lm_mmap_area areas[];
};

/**
 * Prototype for memory access callback. The program MUST first map device
 * memory in its own virtual address space using lm_mmap, do any additional
 * work required, and finally return that memory. When a region is memory
 * mapped, libmuser calls previously register callback with the following
 * arguments:
 *
 * @pvt: private pointer
 * @off: offset of memory area being memory mapped
 * @len: length of memory area being memory mapped
 *
 * @returns the memory address returned by lm_mmap, or MAP_FAILED on failure
 */
typedef unsigned long (lm_map_region_cb_t) (void *pvt, unsigned long off,
                                         unsigned long len);

/**
 * Creates a mapping of a device region into the caller's virtual memory. It
 * must be called by lm_map_region_cb_t.
 *
 * @lm_ctx: the libmuser context to create mapping from
 * @offset: offset of the region being mapped
 * @length: size of the region being mapped
 *
 * @returns a pointer to the requested memory or MAP_FAILED on error. Sets errno.
 */
void *lm_mmap(lm_ctx_t * lm_ctx, off_t offset, size_t length);

/*
 * Returns a pointer to the standard part of the PCI configuration space.
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
 * @pvt: private pointer
 * @lm_log_fn_t: typedef for log function.
 * @msg: message
 */
typedef void (lm_log_fn_t) (void *pvt, lm_log_lvl_t lvl, const char *msg);

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

/* FIXME does it have to be packed as well? */
typedef union {
    struct msicap msi;
    struct msixcap msix;
    struct pmcap pm;
    struct pxcap px;
} lm_cap_t;

typedef enum {
    LM_TRANS_SOCK,
    LM_TRANS_MAX
} lm_trans_t;

#define LM_MAX_CAPS (PCI_CFG_SPACE_SIZE - PCI_STD_HEADER_SIZEOF) / PCI_CAP_SIZEOF

/*
 * FIXME the names of migration callback functions are probably far too long,
 * but for now it helps with the implementation.
 */
/**
 * Migration callback function.
 * @pvt: private pointer
 */
typedef int (lm_migration_callback_t)(void *pvt);

typedef enum {
    LM_MIGR_STATE_STOP,
    LM_MIGR_STATE_RUNNING,
    LM_MIGR_STATE_STOP_AND_COPY,
    LM_MIGR_STATE_PRE_COPY,
    LM_MIGR_STATE_RESUME
} lm_migr_state_t;

typedef struct {

    /* migration state transition callback */
    /* TODO rename to lm_migration_state_transition_callback */
    /* FIXME maybe we should create a single callback and pass the state? */
    int (*transition)(void *pvt, lm_migr_state_t state);

    /* Callbacks for saving device state */

    /*
     * Function that is called to retrieve pending migration data. If migration
     * data were previously made available (function prepare_data has been
     * called) then calling this function signifies that they have been read
     * (e.g. migration data can be discarded). If the function returns 0 then
     * migration has finished and this function won't be called again.
     */
    __u64 (*get_pending_bytes)(void *pvt);

    /*
     * Function that is called to instruct the device to prepare migration data.
     * The function must return only after migration data are available at the
     * specified offset.
     */
    int (*prepare_data)(void *pvt, __u64 *offset, __u64 *size);

    /*
     * Function that is called to read migration data. offset and size can
     * be any subrange on the offset and size previously returned by
     * prepare_data. The function must return the amount of data read. This
     * function can be called even if the migration data can be memory mapped.
     *
     * Does this mean that reading data_offset/data_size updates the values?
     */
    size_t (*read_data)(void *pvt, void *buf, __u64 count, __u64 offset);

    /* Callbacks for restoring device state */

    /*
     * Function that is called when client has written some previously stored
     * device state.
     */
    int (*data_written)(void *pvt, __u64 count, __u64 offset);

    /* Fuction that is called for writing previously stored device state. */
    size_t (*write_data)(void *pvt, void *buf, __u64 count, __u64 offset);

} lm_migration_callbacks_t;

typedef struct {
    size_t                      size;
    lm_migration_callbacks_t    callbacks;
    struct lm_sparse_mmap_areas *mmap_areas;
} lm_migration_t;

/*
 * Attaching to the transport is non-blocking. The library will not attempt
 * to attach during context creation time. The caller must then manually
 * call lm_ctx_try_attach(), which is non-blocking, as many times as
 * necessary.
 */
#define LM_FLAG_ATTACH_NB  (1 << 0)

/**
 * Creates libmuser context.
 * @trans: transport type
 * @path: path to socket file.
 * @flags: context flag
 * @log: log function
 * @log_lvl: logging level
 * @pvt: private data
 * @returns the lm_ctx to be used or NULL on error. Sets errno.
 */
lm_ctx_t *lm_create_ctx(lm_trans_t trans, const char *path,
                        int flags, lm_log_fn_t *log, lm_log_lvl_t log_lvl,
                        void *pvt);

//TODO: Check other PCI header registers suitable to be filled by device.
//      Or should we pass whole lm_pci_hdr_t to be filled by user.
/**
 * Setup PCI header data.
 * @lm_ctx: the libmuser context
 * @id: Device and vendor ID
 * @ss: Subsystem vendor and device ID
 * @cc: Class code
 * @extended: support extended PCI config space
 */
int lm_pci_setup_config_hdr(lm_ctx_t *lm_ctx, lm_pci_hdr_id_t id,
                            lm_pci_hdr_ss_t ss, lm_pci_hdr_cc_t cc,
                            bool extended);

//TODO: Support variable size capabilities.
/**
 * Setup PCI capabilities.
 * @lm_ctx: the libmuser context
 * @caps: array of (lm_cap_t *)
 * *nr_caps: number of elements in @caps
 */
int lm_pci_setup_caps(lm_ctx_t *lm_ctx, lm_cap_t **caps, int nr_caps);

// Region flags.
#define LM_REG_FLAG_READ    (1 << 0)
#define LM_REG_FLAG_WRITE   (1 << 1)
#define LM_REG_FLAG_MMAP    (1 << 2)    // TODO: how this relates to IO bar?
#define LM_REG_FLAG_RW      (LM_REG_FLAG_READ | LM_REG_FLAG_WRITE)
#define LM_REG_FLAG_MEM     (1 << 3)    // if unset, bar is IO

/**
 * Prototype for region access callback. When a region is accessed, libmuser
 * calls the previously registered callback with the following arguments:
 *
 * @pvt: private data originally passed by lm_create_ctx()
 * @buf: buffer containing the data to be written or data to be read into
 * @count: number of bytes being read or written
 * @offset: byte offset within the region
 * @is_write: whether or not this is a write
 *
 * @returns the number of bytes read or written, or a negative integer on error
 */
typedef ssize_t (lm_region_access_cb_t) (void *pvt, char *buf, size_t count,
                                         loff_t offset, bool is_write);

/* PCI regions */
enum {
    LM_PCI_DEV_BAR0_REGION_IDX,
    LM_PCI_DEV_BAR1_REGION_IDX,
    LM_PCI_DEV_BAR2_REGION_IDX,
    LM_PCI_DEV_BAR3_REGION_IDX,
    LM_PCI_DEV_BAR4_REGION_IDX,
    LM_PCI_DEV_BAR5_REGION_IDX,
    LM_PCI_DEV_ROM_REGION_IDX,
    LM_PCI_DEV_CFG_REGION_IDX,
    LM_PCI_DEV_VGA_REGION_IDX,
    LM_PCI_DEV_NUM_REGIONS,
};

/**
 * Set up a region.
 * @lm_ctx: the libmuser context
 * @region_idx: region index
 * @size: size of the region
 * @region_access: callback function to access region
 * @flags: region  flags
 * @mmap_areas: mmap areas info
 * @region_map: callback function to map region
 */
int lm_setup_region(lm_ctx_t *lm_ctx, int region_idx, size_t size,
                    lm_region_access_cb_t *region_access, int flags,
                    struct lm_sparse_mmap_areas *mmap_areas,
                    lm_map_region_cb_t *map);

/*
 * Callback function that is called when the guest resets the device.
 * @pvt: private pointer
 */
typedef int (lm_reset_cb_t) (void *pvt);

/*
 * Function that is called when the guest maps a DMA region. Optional.
 * @pvt: private pointer
 * @iova: iova address
 * @len: length
 */
typedef void (lm_map_dma_cb_t) (void *pvt, uint64_t iova, uint64_t len);

/*
 * Function that is called when the guest unmaps a DMA region. The device
 * must release all references to that region before the callback returns.
 * This is required if you want to be able to access guest memory.
 * @pvt: private pointer
 * @iova: iova address
 * @len: length
 */
typedef int (lm_unmap_dma_cb_t) (void *pvt, uint64_t iova, uint64_t len);

/**
 * Setup device reset callback.
 * @lm_ctx: the libmuser context
 * @reset: device reset callback (optional)
 */
int lm_setup_device_reset_cb(lm_ctx_t *lm_ctx, lm_reset_cb_t *reset);

/**
 * Setup device DMA map/unmap callbacks.
 * @lm_ctx: the libmuser context
 * @map_dma: DMA region map callback (optional)
 * @unmap_dma: DMA region unmap callback (optional)
 */

int lm_setup_device_dma_cb(lm_ctx_t *lm_ctx, lm_map_dma_cb_t *map_dma,
                           lm_unmap_dma_cb_t *unmap_dma);

enum lm_dev_irq_type {
    LM_DEV_INTX_IRQ,
    LM_DEV_MSI_IRQ,
    LM_DEV_MSIX_IRQ,
    LM_DEV_ERR_IRQ,
    LM_DEV_REQ_IRQ,
    LM_DEV_NUM_IRQS
};

/**
 * Setup device IRQ counts.
 * @lm_ctx: the libmuser context
 * @type: IRQ type (LM_DEV_INTX_IRQ ... LM_DEV_REQ_IRQ)
 * @count: number of irqs
 */
int lm_setup_device_nr_irqs(lm_ctx_t *lm_ctx, enum lm_dev_irq_type type,
                            uint32_t count);

//TODO: Re-visit once migration support is done.
/**
 * Enable support for device migration.
 * @lm_ctx: the libmuser context
 * @migration: information required to migrate device
 */
int lm_setup_device_migration(lm_ctx_t *lm_ctx, lm_migration_t *migration);

/**
 * Destroys libmuser context.
 *
 * @lm_ctx: the libmuser context to destroy
 */
void
lm_ctx_destroy(lm_ctx_t *lm_ctx);

/**
 * Once the lm_ctx is configured lm_ctx_drive() drives it. This function waits
 * for commands coming from the client, and processes them in a loop.
 *
 * @lm_ctx: the libmuser context to drive
 *
 * @returns 0 on success, -errno on failure.
 */
int
lm_ctx_drive(lm_ctx_t *lm_ctx);

/**
 * Polls, without blocking, an lm_ctx. This is an alternative to using
 * a thread and making a blocking call to lm_ctx_drive(). Instead, the
 * application can periodically poll the context directly from one of
 * its own threads.
 *
 * This is only allowed when LM_FLAG_ATTACH_NB is specified during creation.
 *
 * @lm_ctx: The libmuser context to poll
 *
 * @returns 0 on success, -errno on failure.
 */
int
lm_ctx_poll(lm_ctx_t *lm_ctx);

/**
 * Triggers an interrupt.
 *
 * libmuser takes care of using the correct IRQ type (IRQ index: INTx or MSI/X),
 * the caller only needs to specify the sub-index.
 *
 * @lm_ctx: the libmuser context to trigger interrupt
 * @subindex: vector subindex to trigger interrupt on
 *
 * @returns 0 on success, or -1 on failure. Sets errno.
 */
int
lm_irq_trigger(lm_ctx_t *lm_ctx, uint32_t subindex);

/**
 * Sends message to client to trigger an interrupt.
 *
 * libmuser takes care of using the IRQ type (INTx, MSI/X), the caller only
 * needs to specify the sub-index.
 * This api can be used to trigger interrupt by sending message to client.
 *
 * @lm_ctx: the libmuser context to trigger interrupt
 * @subindex: vector subindex to trigger interrupt on
 *
 * @returns 0 on success, or -1 on failure. Sets errno.
 */

int
lm_irq_message(lm_ctx_t *lm_ctx, uint32_t subindex);

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
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @lm_ctx: the libmuser context
 * @dma_addr: the guest physical address
 * @len: size of memory to be mapped
 * @sg: array that receives the scatter/gather entries to be mapped
 * @max_sg: maximum number of elements in above array
 * @prot: protection as define in <sys/mman.h>
 *
 * @returns the number of scatter/gather entries created on success, and on
 * failure:
 *  -1:         if the GPA address span is invalid, or
 *  (-x - 1):   if @max_sg is too small, where x is the number of scatter/gather
 *              entries necessary to complete this request.
 */
int
lm_addr_to_sg(lm_ctx_t *lm_ctx, dma_addr_t dma_addr, uint32_t len,
              dma_sg_t *sg, int max_sg, int prot);

/**
 * Maps a list scatter/gather entries from the guest's physical address space
 * to the program's virtual memory. It is the caller's responsibility to remove
 * the mappings by calling lm_unmap_sg.
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @lm_ctx: the libmuser context
 * @sg: array of scatter/gather entries returned by lm_addr_to_sg
 * @iov: array of iovec structures (defined in <sys/uio.h>) to receive each
 *       mapping
 * @cnt: number of scatter/gather entries to map
 *
 * @returns 0 on success, -1 on failure
 */
int
lm_map_sg(lm_ctx_t *lm_ctx, const dma_sg_t *sg,
          struct iovec *iov, int cnt);

/**
 * Unmaps a list scatter/gather entries (previously mapped by lm_map_sg) from
 * the program's virtual memory.
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @lm_ctx: the libmuser context
 * @sg: array of scatter/gather entries to unmap
 * @iov: array of iovec structures for each scatter/gather entry
 * @cnt: number of scatter/gather entries to unmap
 */
void
lm_unmap_sg(lm_ctx_t *lm_ctx, const dma_sg_t *sg,
            struct iovec *iov, int cnt);

//FIXME: Remove if we dont need this.
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

/**
 * Read from the dma region exposed by the client.
 *
 * @lm_ctx: the libmuser context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to read into
 */
int
lm_dma_read(lm_ctx_t *lm_ctx, dma_sg_t *sg, void *data);

/**
 * Write to the dma region exposed by the client.
 *
 * @lm_ctx: the libmuser context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to write
 */
int
lm_dma_write(lm_ctx_t *lm_ctx, dma_sg_t *sg, void *data);

/*
 * Advanced stuff.
 */

/**
 * Returns the non-standard part of the PCI configuration space.
 * @lm_ctx: the libmuser context
 */
uint8_t *
lm_get_pci_non_std_config_space(lm_ctx_t *lm_ctx);

/*
 * Attempts to attach to the transport. LM_FLAG_ATTACH_NB must be set when
 * creating the context. Returns 0 on success and -1 on error. If errno is set
 * to EAGAIN or EWOULDBLOCK then the transport is not ready to attach to and the
 * operation must be retried.
 * @lm_ctx: the libmuser context
 */
int
lm_ctx_try_attach(lm_ctx_t *lm_ctx);

/*
 * FIXME need to make sure that there can be at most one capability with a given
 * ID, otherwise this function will return the first one with this ID.
 * @lm_ctx: the libmuser context
 * @id: capability id
 */
uint8_t *
lm_ctx_get_cap(lm_ctx_t *lm_ctx, uint8_t id);

void
lm_log(lm_ctx_t *lm_ctx, lm_log_lvl_t lvl, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* LIB_MUSER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
