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
#include <syslog.h>

#include "pci_defs.h"
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

#define VFU_DMA_REGIONS  0x10

// FIXME: too common a name?
typedef uint64_t dma_addr_t;

typedef struct {
    dma_addr_t dma_addr;
    int region; /* TODO replace region and length with struct iovec */
    int length;
    uint64_t offset;
    bool mappable;
} dma_sg_t;

typedef struct vfu_ctx vfu_ctx_t;

/*
 * Attaching to the transport is non-blocking.
 * The caller must then manually call vfu_attach_ctx(),
 * which is non-blocking, as many times as necessary.
 */
#define LIBVFIO_USER_FLAG_ATTACH_NB  (1 << 0)

typedef enum {
    VFU_TRANS_SOCK,
    VFU_TRANS_MAX
} vfu_trans_t;

typedef enum {
    VFU_DEV_TYPE_PCI
} vfu_dev_type_t;

/**
 * Creates libvfio-user context. By default one ERR and one REQ IRQs are
 * initialized, this can be overridden with vfu_setup_device_nr_irqs.
 *
 * @trans: transport type
 * @path: path to socket file.
 * @flags: context flags
 * @pvt: private data
 * @dev_type: device type
 *
 * @returns the vfu_ctx to be used or NULL on error. Sets errno.
 */
vfu_ctx_t *
vfu_create_ctx(vfu_trans_t trans, const char *path,
               int flags, void *pvt, vfu_dev_type_t dev_type);

/*
 * Finalizes the device making it ready for vfu_attach_ctx(). This function is
 * mandatory to be called before vfu_attach_ctx().
 * @vfu_ctx: the libvfio-user context
 *
 * @returns: 0 on success, -1 on error. Sets errno.
 */
int
vfu_realize_ctx(vfu_ctx_t *vfu_ctx);

/*
 * Attempts to attach to the transport. Attach is mandatory before
 * vfu_run_ctx() and is non blocking if context is created
 * with LIBVFIO_USER_FLAG_ATTACH_NB flag.
 * Returns client's file descriptor on success and -1 on error. If errno is
 * set to EAGAIN or EWOULDBLOCK then the transport is not ready to attach to and
 * the operation must be retried.
 *
 * @vfu_ctx: the libvfio-user context
 */
int
vfu_attach_ctx(vfu_ctx_t *vfu_ctx);

/**
 * Polls the vfu_ctx and processes the command recieved from client.
 * - Blocking vfu_ctx:
 *   Blocks until new request is received from client and continues processing
 *   the requests. Exits only in case of error or if the client disconnects.
 * - Non-blocking vfu_ctx(LIBVFIO_USER_FLAG_ATTACH_NB):
 *   Processes one request from client if it's available, otherwise it
 *   immediatelly returns and the caller is responsible for periodically
 *   calling again.
 *
 * @vfu_ctx: The libvfio-user context to poll
 *
 * @returns 0 on success, -errno on failure.
 */
int
vfu_run_ctx(vfu_ctx_t *vfu_ctx);

/**
 * Destroys libvfio-user context.
 *
 * @vfu_ctx: the libvfio-user context to destroy
 */
void
vfu_destroy_ctx(vfu_ctx_t *vfu_ctx);

/**
 * Return the private pointer given to vfu_create_ctx().
 */
void *
vfu_get_private(vfu_ctx_t *vfu_ctx);

/**
 * Callback function signature for log function
 * @vfu_ctx: the libvfio-user context
 * @level: log level as defined in syslog(3)
 * @vfu_log_fn_t: typedef for log function.
 * @msg: message
 */
typedef void (vfu_log_fn_t)(vfu_ctx_t *vfu_ctx, int level, const char *msg);

/**
 * Log to the logging function configured for this context.
 */
void
vfu_log(vfu_ctx_t *vfu_ctx, int level, const char *fmt, ...);

/**
 * Setup logging information.
 * @vfu_ctx: the libvfio-user context
 * @log: logging function
 * @level: logging level as defined in syslog(3)
 */
int
vfu_setup_log(vfu_ctx_t *vfu_ctx, vfu_log_fn_t *log, int level);

/**
 * Prototype for region access callback. When a region is accessed, libvfio-user
 * calls the previously registered callback with the following arguments:
 *
 * @vfu_ctx: the libvfio-user context
 * @buf: buffer containing the data to be written or data to be read into
 * @count: number of bytes being read or written
 * @offset: byte offset within the region
 * @is_write: whether or not this is a write
 *
 * @returns the number of bytes read or written, or a negative integer on error
 */
typedef ssize_t (vfu_region_access_cb_t)(vfu_ctx_t *vfu_ctx, char *buf,
                                         size_t count, loff_t offset,
                                         bool is_write);

#define VFU_REGION_FLAG_READ    (1 << 0)
#define VFU_REGION_FLAG_WRITE   (1 << 1)
#define VFU_REGION_FLAG_MMAP    (1 << 2)    // TODO: how this relates to IO bar?
#define VFU_REGION_FLAG_RW      (VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE)
#define VFU_REGION_FLAG_MEM     (1 << 3)    // if unset, bar is IO

/**
 * Set up a region.
 *
 * If this is the PCI configuration space, the @size argument is ignored. The
 * size of the region is determined by the PCI type (set when the libvfio-user
 * context is created). Accesses to the PCI configuration space header and the
 * PCI capabilities are handled internally; the user supplied callback is not
 * called.
 *
 * @vfu_ctx: the libvfio-user context
 * @region_idx: region index
 * @size: size of the region
 * @region_access: callback function to access region. If the region is memory
 *  mappable and the client accesses the region or part of sparse area, then
 *  the callback is not called.
 * @flags: region flags (VFU_REGION_FLAG_)
 * @mmap_areas: array of memory mappable areas. This array provides to the
 *  server greater control of which specific areas should be memory mapped by
 *  the client. Each element in the @mmap_areas array describes one such area.
 *  Ignored if @nr_mmap_areas is 0 or if the region is not memory mappable.
 * @nr_mmap_areas: number of sparse areas in @mmap_areas. Must be 0 if the
 *  region is not memory mappable.
 * @fd: file descriptor of the file backing the region if it's a mappable
 *  region. It is the server's responsibility to create a file suitable for
 *  memory mapping by the client. Ignored if the region is not memory mappable.
 *
 * A note on memory-mappable regions: the client can memory map any part of the
 * file descriptor, even if not supposed to do so according to @mmap_areas.
 * There is no way in Linux to avoid this.
 *
 * TODO maybe we should introduce per-sparse region file descriptors so that
 * the client cannot possibly memory map areas it's not supposed to. Even if
 * the client needs to have region under the same backing file, it is possible
 * to create linear device-mapper targets, one for each area, and provide file
 * descriptors of these DM targets. This is something we can document and
 * demonstrate in a sample.
 *
 * @returns 0 on success, -1 on error, Sets errno.
 */
int
vfu_setup_region(vfu_ctx_t *vfu_ctx, int region_idx, size_t size,
                 vfu_region_access_cb_t *region_access, int flags,
                 struct iovec *mmap_areas, uint32_t nr_mmap_areas,
                 int fd);

/*
 * Callback function that is called when the guest resets the device.
 */
typedef int (vfu_reset_cb_t)(vfu_ctx_t *vfu_ctx);

/**
 * Setup device reset callback.
 * @vfu_ctx: the libvfio-user context
 * @reset: device reset callback (optional)
 */
int
vfu_setup_device_reset_cb(vfu_ctx_t *vfu_ctx, vfu_reset_cb_t *reset);

/*
 * Function that is called when the guest maps a DMA region. Optional.
 *
 * @vfu_ctx: the libvfio-user context
 * @iova: iova address
 * @len: length
 */
typedef void (vfu_map_dma_cb_t)(vfu_ctx_t *vfu_ctx,
                                uint64_t iova, uint64_t len);

/*
 * Function that is called when the guest unmaps a DMA region. The device
 * must release all references to that region before the callback returns.
 * This is required if you want to be able to access guest memory.
 *
 * @vfu_ctx: the libvfio-user context
 * @iova: iova address
 * @len: length
 */
typedef int (vfu_unmap_dma_cb_t)(vfu_ctx_t *vfu_ctx,
                                 uint64_t iova, uint64_t len);

/**
 * Setup device DMA map/unmap callbacks. This will also enable bookkeeping of
 * DMA regions received from client, otherwise they will be just acknowledged.
 *
 * @vfu_ctx: the libvfio-user context
 * @map_dma: DMA region map callback (optional)
 * @unmap_dma: DMA region unmap callback (optional)
 */

int
vfu_setup_device_dma_cb(vfu_ctx_t *vfu_ctx, vfu_map_dma_cb_t *map_dma,
                        vfu_unmap_dma_cb_t *unmap_dma);

enum vfu_dev_irq_type {
    VFU_DEV_INTX_IRQ,
    VFU_DEV_MSI_IRQ,
    VFU_DEV_MSIX_IRQ,
    VFU_DEV_ERR_IRQ,
    VFU_DEV_REQ_IRQ,
    VFU_DEV_NUM_IRQS
};

/**
 * Setup device IRQ counts.
 * @vfu_ctx: the libvfio-user context
 * @type: IRQ type (VFU_DEV_INTX_IRQ ... VFU_DEV_REQ_IRQ)
 * @count: number of irqs
 */
int
vfu_setup_device_nr_irqs(vfu_ctx_t *vfu_ctx, enum vfu_dev_irq_type type,
                         uint32_t count);

/*
 * FIXME the names of migration callback functions are probably far too long,
 * but for now it helps with the implementation.
 */
/**
 * Migration callback function.
 * @vfu_ctx: the libvfio-user context
 */
typedef int (vfu_migration_callback_t)(vfu_ctx_t *vfu_ctx);

typedef enum {
    VFU_MIGR_STATE_STOP,
    VFU_MIGR_STATE_RUNNING,
    VFU_MIGR_STATE_STOP_AND_COPY,
    VFU_MIGR_STATE_PRE_COPY,
    VFU_MIGR_STATE_RESUME
} vfu_migr_state_t;

typedef struct {

    /* migration state transition callback */
    /* TODO rename to vfu_migration_state_transition_callback */
    /* FIXME maybe we should create a single callback and pass the state? */
    int (*transition)(vfu_ctx_t *vfu_ctx, vfu_migr_state_t state);

    /* Callbacks for saving device state */

    /*
     * Function that is called to retrieve pending migration data. If migration
     * data were previously made available (function prepare_data has been
     * called) then calling this function signifies that they have been read
     * (e.g. migration data can be discarded). If the function returns 0 then
     * migration has finished and this function won't be called again.
     */
    __u64 (*get_pending_bytes)(vfu_ctx_t *vfu_ctx);

    /*
     * Function that is called to instruct the device to prepare migration data.
     * The function must return only after migration data are available at the
     * specified offset.
     */
    int (*prepare_data)(vfu_ctx_t *vfu_ctx, __u64 *offset, __u64 *size);

    /*
     * Function that is called to read migration data. offset and size can
     * be any subrange on the offset and size previously returned by
     * prepare_data. The function must return the amount of data read. This
     * function can be called even if the migration data can be memory mapped.
     *
     * Does this mean that reading data_offset/data_size updates the values?
     */
    size_t (*read_data)(vfu_ctx_t *vfu_ctx, void *buf,
                        __u64 count, __u64 offset);

    /* Callbacks for restoring device state */

    /*
     * Function that is called when client has written some previously stored
     * device state.
     */
    int (*data_written)(vfu_ctx_t *vfu_ctx,
                        __u64 count, __u64 offset);

    /* Fuction that is called for writing previously stored device state. */
    size_t (*write_data)(vfu_ctx_t *vfu_ctx, void *buf,
                         __u64 count, __u64 offset);

} vfu_migration_callbacks_t;

typedef struct {
    size_t                      size;
    vfu_migration_callbacks_t   callbacks;
    struct iovec                *mmap_areas;
    uint32_t                    nr_mmap_areas;
} vfu_migration_t;

//TODO: Re-visit once migration support is done.
/**
 * Enable support for device migration.
 * @vfu_ctx: the libvfio-user context
 * @migration: information required to migrate device
 */
int
vfu_setup_device_migration(vfu_ctx_t *vfu_ctx, vfu_migration_t *migration);

/**
 * Triggers an interrupt.
 *
 * libvfio-user takes care of using the correct IRQ type (IRQ index: INTx or
 * MSI/X), the caller only needs to specify the sub-index.
 *
 * @vfu_ctx: the libvfio-user context to trigger interrupt
 * @subindex: vector subindex to trigger interrupt on
 *
 * @returns 0 on success, or -1 on failure. Sets errno.
 */
int
vfu_irq_trigger(vfu_ctx_t *vfu_ctx, uint32_t subindex);

/**
 * Sends message to client to trigger an interrupt.
 *
 * libvfio-user takes care of using the IRQ type (INTx, MSI/X), the caller only
 * needs to specify the sub-index.
 * This api can be used to trigger interrupt by sending message to client.
 *
 * @vfu_ctx: the libvfio-user context to trigger interrupt
 * @subindex: vector subindex to trigger interrupt on
 *
 * @returns 0 on success, or -1 on failure. Sets errno.
 */

int
vfu_irq_message(vfu_ctx_t *vfu_ctx, uint32_t subindex);

/**
 * Takes a guest physical address and returns a list of scatter/gather entries
 * than can be individually mapped in the program's virtual memory.  A single
 * linear guest physical address span may need to be split into multiple
 * scatter/gather regions due to limitations of how memory can be mapped.
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @vfu_ctx: the libvfio-user context
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
vfu_addr_to_sg(vfu_ctx_t *vfu_ctx, dma_addr_t dma_addr, uint32_t len,
               dma_sg_t *sg, int max_sg, int prot);

/**
 * Maps a list scatter/gather entries from the guest's physical address space
 * to the program's virtual memory. It is the caller's responsibility to remove
 * the mappings by calling vfu_unmap_sg.
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @vfu_ctx: the libvfio-user context
 * @sg: array of scatter/gather entries returned by vfu_addr_to_sg
 * @iov: array of iovec structures (defined in <sys/uio.h>) to receive each
 *       mapping
 * @cnt: number of scatter/gather entries to map
 *
 * @returns 0 on success, -1 on failure
 */
int
vfu_map_sg(vfu_ctx_t *vfu_ctx, const dma_sg_t *sg,
           struct iovec *iov, int cnt);

/**
 * Unmaps a list scatter/gather entries (previously mapped by vfu_map_sg) from
 * the program's virtual memory.
 * Field unmap_dma must have been provided at context creation time in order
 * to use this function.
 *
 * @vfu_ctx: the libvfio-user context
 * @sg: array of scatter/gather entries to unmap
 * @iov: array of iovec structures for each scatter/gather entry
 * @cnt: number of scatter/gather entries to unmap
 */
void
vfu_unmap_sg(vfu_ctx_t *vfu_ctx, const dma_sg_t *sg,
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
 * Returns the PCI region (VFU_PCI_DEV_XXX_REGION_IDX), or -errno on error.
 */
int
vfu_get_region(loff_t pos, size_t count, loff_t *off);

/**
 * Read from the dma region exposed by the client.
 *
 * @vfu_ctx: the libvfio-user context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to read into
 */
int
vfu_dma_read(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data);

/**
 * Write to the dma region exposed by the client.
 *
 * @vfu_ctx: the libvfio-user context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to write
 */
int
vfu_dma_write(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data);

/*
 * Supported PCI regions.
 *
 * FIXME: update with CFG behaviour etc.
 */
enum {
    VFU_PCI_DEV_BAR0_REGION_IDX,
    VFU_PCI_DEV_BAR1_REGION_IDX,
    VFU_PCI_DEV_BAR2_REGION_IDX,
    VFU_PCI_DEV_BAR3_REGION_IDX,
    VFU_PCI_DEV_BAR4_REGION_IDX,
    VFU_PCI_DEV_BAR5_REGION_IDX,
    VFU_PCI_DEV_ROM_REGION_IDX,
    VFU_PCI_DEV_CFG_REGION_IDX,
    VFU_PCI_DEV_VGA_REGION_IDX,
    VFU_PCI_DEV_NUM_REGIONS,
};

typedef enum {
    VFU_PCI_TYPE_CONVENTIONAL,
    VFU_PCI_TYPE_PCI_X_1,
    VFU_PCI_TYPE_PCI_X_2,
    VFU_PCI_TYPE_EXPRESS
} vfu_pci_type_t;

/**
 * Initialize the context for a PCI device. This function must be called only
 * once per libvfio-user context.
 *
 * This function initializes a buffer for the PCI config space, accessible via
 * vfu_pci_get_config_space().
 *
 * Returns 0 on success, or -1 on error, setting errno.
 *
 * @vfu_ctx: the libvfio-user context
 * @pci_type: PCI type (convention PCI, PCI-X mode 1, PCI-X mode2, PCI-Express)
 * @hdr_type: PCI header type. Only PCI_HEADER_TYPE_NORMAL is supported.
 * @revision: PCI/PCI-X/PCIe revision
 */
int
vfu_pci_init(vfu_ctx_t *vfu_ctx, vfu_pci_type_t pci_type,
             int hdr_type, int revision __attribute__((unused)));

/*
 * Set the Vendor ID, Device ID, Subsystem Vendor ID, and Subsystem ID fields of
 * the PCI config header (PCI3 6.2.1, 6.2.4).
 *
 * This must always be called for PCI devices, after vfu_pci_init().
 */
void
vfu_pci_set_id(vfu_ctx_t *vfu_ctx, uint16_t vid, uint16_t did,
               uint16_t ssvid, uint16_t ssid);

/*
 * Set the class code fields (base, sub-class, and programming interface) of the
 * PCI config header (PCI3 6.2.1).
 *
 * If this function is not called, the fields are initialized to zero.
 */
void
vfu_pci_set_class(vfu_ctx_t *vfu_ctx, uint8_t base, uint8_t sub, uint8_t pi);


/*
 * Returns a pointer to the PCI configuration space.
 *
 * PCI config space consists of an initial 64-byte vfu_pci_hdr_t, plus
 * additional space, containing capabilities and/or device-specific
 * configuration.  Standard config space is 256 bytes (PCI_CFG_SPACE_SIZE);
 * extended config space is 4096 bytes (PCI_CFG_SPACE_EXP_SIZE).
 */
vfu_pci_config_space_t *
vfu_pci_get_config_space(vfu_ctx_t *vfu_ctx);

/* FIXME does it have to be packed as well? */
typedef union {
    struct msicap   msi;
    struct msixcap  msix;
    struct pmcap    pm;
    struct pxcap    px;
    struct vsc      vsc;
} vfu_cap_t;

//TODO: Support variable size capabilities.

/**
 * Setup PCI capabilities.
 *
 * @vfu_ctx: the libvfio-user context
 * @caps: array of (vfu_cap_t *)
 * @nr_caps: number of elements in @caps
 */
int
vfu_pci_setup_caps(vfu_ctx_t *vfu_ctx, vfu_cap_t **caps, int nr_caps);

/* FIXME this function is broken as the can be multiples capabilities with the
 * same ID, e.g. the vendor-specific capability.
 * @vfu_ctx: the libvfio-user context
 * @id: capability id
 */
uint8_t *
vfu_ctx_get_cap(vfu_ctx_t *vfu_ctx, uint8_t id);

/**
 * Returns the memory offset where the specific region starts in device memory.
 *
 * @region: the region to translate
 *
 * @returns the absolute offset
 */
uint64_t
vfu_region_to_offset(uint32_t region);

#ifdef __cplusplus
}
#endif

#endif /* LIB_VFIO_USER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
