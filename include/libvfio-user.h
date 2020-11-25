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

/*
 * Defines the libvfio-user server-side API.  The protocol definitions can be
 * found in vfio-user.h.
 */

#ifndef LIB_VFIO_USER_H
#define LIB_VFIO_USER_H

#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>

#include "pci.h"
#include "pci_caps/pm.h"
#include "pci_caps/px.h"
#include "pci_caps/msi.h"
#include "pci_caps/msix.h"
#include "vfio-user.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LIB_VFIO_USER_MAJOR 0
#define LIB_VFIO_USER_MINOR 1

// FIXME: too common a name?
typedef uint64_t dma_addr_t;

typedef struct {
    dma_addr_t dma_addr;
    int region;
    int length;
    uint64_t offset;
} dma_sg_t;

typedef struct vu_ctx vu_ctx_t;

struct vu_mmap_area {
    uint64_t start;
    uint64_t size;
};

struct vu_sparse_mmap_areas {
    int nr_mmap_areas;
    struct vu_mmap_area areas[];
};

/**
 * Prototype for memory access callback. The program MUST first map device
 * memory in its own virtual address space using vu_mmap, do any additional work
 * required, and finally return that memory. When a region is memory mapped,
 * libvfio-user calls the previously registered callback with the following
 * arguments:
 *
 * @pvt: private pointer
 * @off: offset of memory area being memory mapped
 * @len: length of memory area being memory mapped
 *
 * @returns the memory address returned by vu_mmap, or MAP_FAILED on failure
 */
typedef unsigned long (vu_map_region_cb_t) (void *pvt, unsigned long off,
                                            unsigned long len);

/**
 * Creates a mapping of a device region into the caller's virtual memory. It
 * must be called by vu_map_region_cb_t.
 *
 * @vu_ctx: the context to create mapping from
 * @offset: offset of the region being mapped
 * @length: size of the region being mapped
 *
 * @returns a pointer to the requested memory or MAP_FAILED on error. Sets errno.
 */
void *
vu_mmap(vu_ctx_t * vu_ctx, off_t offset, size_t length);

/*
 * Returns a pointer to the standard part of the PCI configuration space.
 */
vu_pci_config_space_t *
vu_pci_get_config_space(vu_ctx_t *vu_ctx);

#define VU_DMA_REGIONS  0x10

typedef enum {
    VU_ERR,
    VU_INF,
    VU_DBG
} vu_log_lvl_t;

/**
 * Callback function signature for log function
 * @pvt: private pointer
 * @vu_log_fn_t: typedef for log function.
 * @msg: message
 */
typedef void (vu_log_fn_t) (void *pvt, vu_log_lvl_t lvl, const char *msg);

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
typedef ssize_t (vu_cap_access_t) (void *pvt, uint8_t id,
                                   char *buf, size_t count,
                                   loff_t offset, bool is_write);

/* FIXME does it have to be packed as well? */
typedef union {
    struct msicap msi;
    struct msixcap msix;
    struct pmcap pm;
    struct pxcap px;
} vu_cap_t;

typedef enum {
    VU_TRANS_SOCK,
    VU_TRANS_MAX
} vu_trans_t;

#define VU_MAX_CAPS (PCI_CFG_SPACE_SIZE - PCI_STD_HEADER_SIZEOF) / PCI_CAP_SIZEOF

/*
 * FIXME the names of migration callback functions are probably far too long,
 * but for now it helps with the implementation.
 */
/**
 * Migration callback function.
 * @pvt: private pointer
 */
typedef int (vu_migration_callback_t)(void *pvt);

typedef enum {
    VU_MIGR_STATE_STOP,
    VU_MIGR_STATE_RUNNING,
    VU_MIGR_STATE_STOP_AND_COPY,
    VU_MIGR_STATE_PRE_COPY,
    VU_MIGR_STATE_RESUME
} vu_migr_state_t;

typedef struct {

    /* migration state transition callback */
    /* TODO rename to vu_migration_state_transition_callback */
    /* FIXME maybe we should create a single callback and pass the state? */
    int (*transition)(void *pvt, vu_migr_state_t state);

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

} vu_migration_callbacks_t;

typedef struct {
    size_t                      size;
    vu_migration_callbacks_t    callbacks;
    struct vu_sparse_mmap_areas *mmap_areas;
} vu_migration_t;

/*
 * Attaching to the transport is non-blocking. The library will not attempt
 * to attach during context creation time. The caller must then manually
 * call vu_ctx_try_attach(), which is non-blocking, as many times as
 * necessary.
 */
#define LIBVFIO_USER_FLAG_ATTACH_NB  (1 << 0)

/**
 * Creates libvfio-user context.
 * @trans: transport type
 * @path: path to socket file.
 * @flags: context flag
 * @pvt: private data
 * @returns the vu_ctx to be used or NULL on error. Sets errno.
 */
vu_ctx_t *
vu_create_ctx(vu_trans_t trans, const char *path,
              int flags, void *pvt);

/**
 * Setup logging information.
 * @vu_ctx: the libvfio-user context
 * @log: logging function
 * @log_lvl: logging level
 */
int
vu_setup_log(vu_ctx_t *vu_ctx, vu_log_fn_t *log, vu_log_lvl_t log_lvl);

//TODO: Check other PCI header registers suitable to be filled by device.
//      Or should we pass whole vu_pci_hdr_t to be filled by user.
/**
 * Setup PCI header data.
 * @vu_ctx: the libvfio-user context
 * @id: Device and vendor ID
 * @ss: Subsystem vendor and device ID
 * @cc: Class code
 * @extended: support extended PCI config space
 */
int
vu_pci_setup_config_hdr(vu_ctx_t *vu_ctx, vu_pci_hdr_id_t id,
                        vu_pci_hdr_ss_t ss, vu_pci_hdr_cc_t cc,
                        bool extended);

//TODO: Support variable size capabilities.
/**
 * Setup PCI capabilities.
 * @vu_ctx: the libvfio-user context
 * @caps: array of (vu_cap_t *)
 * *nr_caps: number of elements in @caps
 */
int
vu_pci_setup_caps(vu_ctx_t *vu_ctx, vu_cap_t **caps, int nr_caps);

// Region flags.
#define VU_REG_FLAG_READ    (1 << 0)
#define VU_REG_FLAG_WRITE   (1 << 1)
#define VU_REG_FLAG_MMAP    (1 << 2)    // TODO: how this relates to IO bar?
#define VU_REG_FLAG_RW      (VU_REG_FLAG_READ | VU_REG_FLAG_WRITE)
#define VU_REG_FLAG_MEM     (1 << 3)    // if unset, bar is IO

/**
 * Prototype for region access callback. When a region is accessed, libvfio-user
 * calls the previously registered callback with the following arguments:
 *
 * @pvt: private data originally passed by vu_create_ctx()
 * @buf: buffer containing the data to be written or data to be read into
 * @count: number of bytes being read or written
 * @offset: byte offset within the region
 * @is_write: whether or not this is a write
 *
 * @returns the number of bytes read or written, or a negative integer on error
 */
typedef ssize_t (vu_region_access_cb_t) (void *pvt, char *buf, size_t count,
                                         loff_t offset, bool is_write);

/* PCI regions */
enum {
    VU_PCI_DEV_BAR0_REGION_IDX,
    VU_PCI_DEV_BAR1_REGION_IDX,
    VU_PCI_DEV_BAR2_REGION_IDX,
    VU_PCI_DEV_BAR3_REGION_IDX,
    VU_PCI_DEV_BAR4_REGION_IDX,
    VU_PCI_DEV_BAR5_REGION_IDX,
    VU_PCI_DEV_ROM_REGION_IDX,
    VU_PCI_DEV_CFG_REGION_IDX,
    VU_PCI_DEV_VGA_REGION_IDX,
    VU_PCI_DEV_NUM_REGIONS,
};

/**
 * Set up a region.
 * @vu_ctx: the libvfio-user context
 * @region_idx: region index
 * @size: size of the region
 * @region_access: callback function to access region
 * @flags: region  flags
 * @mmap_areas: mmap areas info
 * @region_map: callback function to map region
 */
int
vu_setup_region(vu_ctx_t *vu_ctx, int region_idx, size_t size,
                vu_region_access_cb_t *region_access, int flags,
                struct vu_sparse_mmap_areas *mmap_areas,
                vu_map_region_cb_t *map);

/*
 * Callback function that is called when the guest resets the device.
 * @pvt: private pointer
 */
typedef int (vu_reset_cb_t) (void *pvt);

/*
 * Function that is called when the guest maps a DMA region. Optional.
 * @pvt: private pointer
 * @iova: iova address
 * @len: length
 */
typedef void (vu_map_dma_cb_t) (void *pvt, uint64_t iova, uint64_t len);

/*
 * Function that is called when the guest unmaps a DMA region. The device
 * must release all references to that region before the callback returns.
 * This is required if you want to be able to access guest memory.
 * @pvt: private pointer
 * @iova: iova address
 * @len: length
 */
typedef int (vu_unmap_dma_cb_t) (void *pvt, uint64_t iova, uint64_t len);

/**
 * Setup device reset callback.
 * @vu_ctx: the libvfio-user context
 * @reset: device reset callback (optional)
 */
int
vu_setup_device_reset_cb(vu_ctx_t *vu_ctx, vu_reset_cb_t *reset);

/**
 * Setup device DMA map/unmap callbacks.
 * @vu_ctx: the libvfio-user context
 * @map_dma: DMA region map callback (optional)
 * @unmap_dma: DMA region unmap callback (optional)
 */

int
vu_setup_device_dma_cb(vu_ctx_t *vu_ctx, vu_map_dma_cb_t *map_dma,
                       vu_unmap_dma_cb_t *unmap_dma);

enum vu_dev_irq_type {
    VU_DEV_INTX_IRQ,
    VU_DEV_MSI_IRQ,
    VU_DEV_MSIX_IRQ,
    VU_DEV_ERR_IRQ,
    VU_DEV_REQ_IRQ,
    VU_DEV_NUM_IRQS
};

/**
 * Setup device IRQ counts.
 * @vu_ctx: the libvfio-user context
 * @type: IRQ type (VU_DEV_INTX_IRQ ... VU_DEV_REQ_IRQ)
 * @count: number of irqs
 */
int
vu_setup_device_nr_irqs(vu_ctx_t *vu_ctx, enum vu_dev_irq_type type,
                        uint32_t count);

//TODO: Re-visit once migration support is done.
/**
 * Enable support for device migration.
 * @vu_ctx: the libvfio-user context
 * @migration: information required to migrate device
 */
int
vu_setup_device_migration(vu_ctx_t *vu_ctx, vu_migration_t *migration);

/**
 * Destroys libvfio-user context.
 *
 * @vu_ctx: the libvfio-user context to destroy
 */
void
vu_ctx_destroy(vu_ctx_t *vu_ctx);

/**
 * Once the vu_ctx is configured vu_ctx_drive() drives it. This function waits
 * for commands coming from the client, and processes them in a loop.
 *
 * @vu_ctx: the libvfio-user context to drive
 *
 * @returns 0 on success, -errno on failure.
 */
int
vu_ctx_drive(vu_ctx_t *vu_ctx);

/**
 * Polls, without blocking, an vu_ctx. This is an alternative to using
 * a thread and making a blocking call to vu_ctx_drive(). Instead, the
 * application can periodically poll the context directly from one of
 * its own threads.
 *
 * This is only allowed when LIBVFIO_USER_FLAG_ATTACH_NB is specified during
 * creation.
 *
 * @vu_ctx: The libvfio-user context to poll
 *
 * @returns 0 on success, -errno on failure.
 */
int
vu_ctx_poll(vu_ctx_t *vu_ctx);

/**
 * Triggers an interrupt.
 *
 * libvfio-user takes care of using the correct IRQ type (IRQ index: INTx or
 * MSI/X), the caller only needs to specify the sub-index.
 *
 * @vu_ctx: the libvfio-user context to trigger interrupt
 * @subindex: vector subindex to trigger interrupt on
 *
 * @returns 0 on success, or -1 on failure. Sets errno.
 */
int
vu_irq_trigger(vu_ctx_t *vu_ctx, uint32_t subindex);

/**
 * Sends message to client to trigger an interrupt.
 *
 * libvfio-user takes care of using the IRQ type (INTx, MSI/X), the caller only
 * needs to specify the sub-index.
 * This api can be used to trigger interrupt by sending message to client.
 *
 * @vu_ctx: the libvfio-user context to trigger interrupt
 * @subindex: vector subindex to trigger interrupt on
 *
 * @returns 0 on success, or -1 on failure. Sets errno.
 */

int
vu_irq_message(vu_ctx_t *vu_ctx, uint32_t subindex);

/* Helper functions */

/**
 * Converts a guest physical address to a dma_sg_t element which can
 * be later passed on to vu_map_sg to memory map the GPA. It is the caller's
 * responsibility to unmap it by calling vu_unmap_sg.
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
 * @vu_ctx: the libvfio-user context
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
vu_addr_to_sg(vu_ctx_t *vu_ctx, dma_addr_t dma_addr, uint32_t len,
              dma_sg_t *sg, int max_sg, int prot);

/**
 * Maps a list scatter/gather entries from the guest's physical address space
 * to the program's virtual memory. It is the caller's responsibility to remove
 * the mappings by calling vu_unmap_sg.
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @vu_ctx: the libvfio-user context
 * @sg: array of scatter/gather entries returned by vu_addr_to_sg
 * @iov: array of iovec structures (defined in <sys/uio.h>) to receive each
 *       mapping
 * @cnt: number of scatter/gather entries to map
 *
 * @returns 0 on success, -1 on failure
 */
int
vu_map_sg(vu_ctx_t *vu_ctx, const dma_sg_t *sg,
          struct iovec *iov, int cnt);

/**
 * Unmaps a list scatter/gather entries (previously mapped by vu_map_sg) from
 * the program's virtual memory.
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @vu_ctx: the libvfio-user context
 * @sg: array of scatter/gather entries to unmap
 * @iov: array of iovec structures for each scatter/gather entry
 * @cnt: number of scatter/gather entries to unmap
 */
void
vu_unmap_sg(vu_ctx_t *vu_ctx, const dma_sg_t *sg,
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
 * Returns the PCI region (VU_PCI_DEV_XXX_REGION_IDX), or -errno on error.
 */
int
vu_get_region(loff_t pos, size_t count, loff_t *off);

/**
 * Read from the dma region exposed by the client.
 *
 * @vu_ctx: the libvfio-user context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to read into
 */
int
vu_dma_read(vu_ctx_t *vu_ctx, dma_sg_t *sg, void *data);

/**
 * Write to the dma region exposed by the client.
 *
 * @vu_ctx: the libvfio-user context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to write
 */
int
vu_dma_write(vu_ctx_t *vu_ctx, dma_sg_t *sg, void *data);

/*
 * Advanced stuff.
 */

/**
 * Returns the non-standard part of the PCI configuration space.
 * @vu_ctx: the libvfio-user context
 */
uint8_t *
vu_get_pci_non_std_config_space(vu_ctx_t *vu_ctx);

/*
 * Attempts to attach to the transport. LIBVFIO_USER_FLAG_ATTACH_NB must be set
 * when creating the context. Returns 0 on success and -1 on error. If errno is
 * set to EAGAIN or EWOULDBLOCK then the transport is not ready to attach to and
 * the operation must be retried.
 *
 * @vu_ctx: the libvfio-user context
 */
int
vu_ctx_try_attach(vu_ctx_t *vu_ctx);

/*
 * FIXME need to make sure that there can be at most one capability with a given
 * ID, otherwise this function will return the first one with this ID.
 * @vu_ctx: the libvfio-user context
 * @id: capability id
 */
uint8_t *
vu_ctx_get_cap(vu_ctx_t *vu_ctx, uint8_t id);

void
vu_log(vu_ctx_t *vu_ctx, vu_log_lvl_t lvl, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* LIB_VFIO_USER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
