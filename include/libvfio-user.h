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

#include "pci_caps/dsn.h"
#include "pci_caps/msi.h"
#include "pci_caps/msix.h"
#include "pci_caps/pm.h"
#include "pci_caps/px.h"
#include "pci_defs.h"
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
#define VFU_REGION_FLAG_RW      (VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE)
#define VFU_REGION_FLAG_MEM     (1 << 2)    // if unset, bar is IO

/**
 * Set up a device region.
 *
 * A region is an area of device memory that can be accessed by the client,
 * either via VFIO_USER_REGION_READ/WRITE, or directly by mapping the region
 * into the client's address space if an fd is given.
 *
 * A mappable region can be split into mappable sub-areas according to the
 * @mmap_areas array. Note that the client can memory map any part of the
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
 * Areas that are accessed via such a mapping by definition do not invoke any
 * given callback.  However, the callback can still be invoked, even on a
 * mappable area, if the client chooses to call VFIO_USER_REGION_READ/WRITE.
 *
 * The following regions are special and are explained below:
 *  - VFU_PCI_DEV_CFG_REGION_IDX,
 *  - VFU_PCI_DEV_MIGR_REGION_IDX, and
 *  - VFU_GENERIC_DEV_MIGR_REG_IDX.
 *
 * Region VFU_PCI_DEV_CFG_REGION_IDX, corresponding to PCI config space, has
 * special handling:
 *
 *  - the @size argument is ignored: the region size is always the size defined
 *    by the relevant PCI specification
 *  - all accesses to the standard PCI header (i.e. the first 64 bytes of the
 *    region) are handled by the library
 *  - all accesses to known PCI capabilities (see vfu_pci_add_capability())
 *    are handled by the library
 *  - if no callback is provided, reads to other areas are a simple memcpy(),
 *    and writes are an error
 *  - otherwise, the callback is expected to handle the access
 *
 * Regions VFU_PCI_DEV_MIGR_REGION_IDX and VFU_GENERIC_DEV_MIGR_REG_IDX,
 * corresponding to the migration region, enable live migration support for
 * the device. The migration region must contain at the beginning the migration
 * registers (struct vfio_device_migration_info defined in <linux/vfio.h>) and
 * the remaining part of the region can be arbitrarily used by the device
 * implementation. The region provided must have at least
 * vfu_get_migr_register_area_size() bytes available at the start of the region
 * (this size is guaranteed to be page-aligned). If mmap_areas is given, it
 * must _not_ include this part of the region.
 *
 * libvfio-user offers two ways for the migration region to be used:
 *  1. natively: the device implementation must handle accesses to the
 *      migration registers and migration data via the region callbacks. The
 *      semantics of these registers are explained in <linux/vfio.h>.
 *  2. via the vfu_migration_t callbacks: the device implementation registers
 *      a set of callbacks by calling vfu_setup_device_migration. The region's
 *      read/write callbacks are never called.
 *
 * @vfu_ctx: the libvfio-user context
 * @region_idx: region index
 * @size: size of the region
 * @region_access: callback function to access region
 * @flags: region flags (VFU_REGION_FLAG_*)
 * @mmap_areas: array of memory mappable areas; if an fd is provided, but this
 * is NULL, then the entire region is mappable.
 * @nr_mmap_areas: number of sparse areas in @mmap_areas; must be provided if
 *  the @mmap_areas is non-NULL, or 0 otherwise.
 * @fd: file descriptor of the file backing the region if the region is
 *  mappable; it is the server's responsibility to create a file suitable for
 *  memory mapping by the client.
 *
 * @returns 0 on success, -1 on error, Sets errno.
 */
int
vfu_setup_region(vfu_ctx_t *vfu_ctx, int region_idx, size_t size,
                 vfu_region_access_cb_t *region_access, int flags,
                 struct iovec *mmap_areas, uint32_t nr_mmap_areas,
                 int fd);

/*
 * Returns the size of the area needed to hold the migration registers at the
 * beginning of the migration region; guaranteed to be page aligned.
 */
size_t
vfu_get_migr_register_area_size(void);

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
 * @prot: memory protection used to map region as defined in <sys/mman.h>
 */
typedef void (vfu_map_dma_cb_t)(vfu_ctx_t *vfu_ctx,
                                uint64_t iova, uint64_t len, uint32_t prot);

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


#define VFU_MIGR_CALLBACKS_VERS 1

/*
 * Callbacks during the pre-copy and stop-and-copy phases.
 *
 * The client executes the following steps to copy migration data:
 *
 * 1. get_pending_bytes: device must return amount of migration data
 * 2. prepare_data: device must prepare migration data
 * 3. read_data: device must provide migration data
 *
 * The client repeats the above steps until there is no more migration data to
 * return (the device must return 0 from get_pending_bytes to indicate that
 * there are no more migration data to be consumed in this iteration).
 */
typedef struct {

    /*
     * Set it to VFU_MIGR_CALLBACKS_VERS.
     */
    int version;

    /* migration state transition callback */
    /* TODO rename to vfu_migration_state_transition_callback */
    /* FIXME maybe we should create a single callback and pass the state? */
    int (*transition)(vfu_ctx_t *vfu_ctx, vfu_migr_state_t state);

    /* Callbacks for saving device state */

    /*
     * Function that is called to retrieve the amount of pending migration
     * data. If migration data were previously made available (function
     * prepare_data has been called) then calling this function signifies that
     * they have been read (e.g. migration data can be discarded). If the
     * function returns 0 then migration has finished and this function won't
     * be called again.
     */
    __u64 (*get_pending_bytes)(vfu_ctx_t *vfu_ctx);

    /*
     * Function that is called to instruct the device to prepare migration data
     * to be read when in pre-copy or stop-and-copy state, and to prepare for
     * receiving migration data when in resuming state.
     *
     * When in pre-copy and stop-and-copy state, the function must return only
     * after migration data are available at the specified offset.
     *
     * When in resuming state, @offset must be set to where migration data must
     * written. @size points to NULL.
     */
    int (*prepare_data)(vfu_ctx_t *vfu_ctx, __u64 *offset, __u64 *size);

    /*
     * Function that is called to read migration data. offset and size can be
     * any subrange on the offset and size previously returned by prepare_data.
     * The function must return the amount of data read or -errno on error.
     * This function can be called even if the migration data can be memory
     * mapped.
     *
     * Does this mean that reading data_offset/data_size updates the values?
     */
    ssize_t (*read_data)(vfu_ctx_t *vfu_ctx, void *buf,
                         __u64 count, __u64 offset);

    /* Callbacks for restoring device state */

    /*
     * Fuction that is called for writing previously stored device state. The
     * function must return the amount of data written or -errno on error.
     */
    ssize_t (*write_data)(vfu_ctx_t *vfu_ctx, void *buf, __u64 count,
                          __u64 offset);

    /*
     * Function that is called when client has written some previously stored
     * device state.
     */
    int (*data_written)(vfu_ctx_t *vfu_ctx, __u64 count);

} vfu_migration_callbacks_t;

/**
 * vfu_setup_device_migration provides an abstraction over the migration
 * protocol: the user specifies a set of callbacks which are called in response
 * to client accesses of the migration region; the migration region read/write
 * callbacks are not called after this function call. Offsets in callbacks are
 * relative to @data_offset.
 * 
 * @vfu_ctx: the libvfio-user context
 * @callbacks: migration callbacks
 * @data_offset: offset in the migration region where data begins.
 *
 * @returns 0 on success, -1 on error, sets errno.
 */
int
vfu_setup_device_migration_callbacks(vfu_ctx_t *vfu_ctx,
                                     const vfu_migration_callbacks_t *callbacks,
                                     uint64_t data_offset);

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
 * @prot: protection as defined in <sys/mman.h>
 *
 * @returns the number of scatter/gather entries created on success, and on
 * failure:
 *  -1:         if the GPA address span is invalid (errno=0) or
 *              protection violation (errno=EACCES)
 *  (-x - 1):   if @max_sg is too small, where x is the number of scatter/gather
 *              entries necessary to complete this request (errno=0).
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
 * @returns 0 on success, -1 on failure. Sets errno.
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

/**
 * Read from the dma region exposed by the client.
 *
 * @vfu_ctx: the libvfio-user context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to read into
 *
 * @returns 0 on success, -1 on failure. Sets errno.
 */
int
vfu_dma_read(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data);

/**
 * Write to the dma region exposed by the client.
 *
 * @vfu_ctx: the libvfio-user context
 * @sg: a DMA segment obtained from dma_addr_to_sg
 * @data: data buffer to write
 *
 * @returns 0 on success, -1 on failure. Sets errno.
 */
int
vfu_dma_write(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data);

/*
 * Supported PCI regions.
 *
 * Note: in VFIO, each region starts at a terabyte offset
 * (VFIO_PCI_INDEX_TO_OFFSET) and because Linux supports up to 128 TB of user
 * space virtual memory, there can be up to 128 device regions. PCI regions are
 * fixed and in retrospect this choice has proven to be problematic because
 * devices might contain potentially unused regions. New regions can now be
 * positioned anywhere by using the VFIO_REGION_INFO_CAP_TYPE capability.  In
 * vfio-user we don't have this problem because the region index is just an
 * identifier: the VMM memory maps a file descriptor that is passed to it and
 * the mapping offset is derived from the mmap_areas offset value, rather than a
 * static mapping from region index to offset. Thus, additional regions can
 * have static indexes in vfio-user.
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
    VFU_PCI_DEV_MIGR_REGION_IDX,
    VFU_PCI_DEV_NUM_REGIONS,
};

typedef enum {
    VFU_PCI_TYPE_CONVENTIONAL,
    VFU_PCI_TYPE_PCI_X_1,
    VFU_PCI_TYPE_PCI_X_2,
    VFU_PCI_TYPE_EXPRESS
} vfu_pci_type_t;

enum {
    VFU_GENERIC_DEV_MIGR_REGION_IDX,
    VFU_GENERIC_DEV_NUM_REGIONS
};

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

#define VFU_CAP_FLAG_EXTENDED (1 << 0)
#define VFU_CAP_FLAG_CALLBACK (1 << 1)
#define VFU_CAP_FLAG_READONLY (1 << 2)

/**
 * Add a PCI capability to PCI config space.
 *
 * Certain standard capabilities are handled entirely within the library:
 *
 * PCI_CAP_ID_EXP (pxcap)
 * PCI_CAP_ID_MSIX (msixcap)
 * PCI_CAP_ID_PM (pmcap)
 *
 * However, they must still be explicitly initialized and added here.
 *
 * The contents of @data are copied in. It must start with either a struct
 * cap_hdr or a struct ext_cap_hdr, with the ID field set; the 'next' field is
 * ignored.  For PCI_CAP_ID_VNDR or PCI_EXT_CAP_ID_VNDR, the embedded size field
 * must also be set; in general, any non-fixed-size capability must be
 * initialized such that the size can be derived at this point.
 *
 * If @pos is non-zero, the capability will be placed at the given offset within
 * configuration space. It must not overlap the PCI standard header, or any
 * existing capability. Note that if a capability is added "out of order" in
 * terms of the offset, there is no re-ordering of the capability list written
 * in configuration space.
 *
 * If @pos is zero, the capability will be placed at a suitable offset
 * automatically.
 *
 * The @flags field can be set as follows:
 *
 * VFU_CAP_FLAG_EXTENDED: this is an extended capability; supported if device is
 * of PCI type VFU_PCI_TYPE_{PCI_X_2,EXPRESS}.
 *
 * VFU_CAP_FLAG_CALLBACK: all accesses to the capability are delegated to the
 * callback for the region VFU_PCI_DEV_CFG_REGION_IDX. The callback should copy
 * data into and out of the capability as needed (this could be directly on the
 * config space area from vfu_pci_get_config_space()). It is not supported to
 * allow writes to the initial capability header (ID/next fields).
 *
 * VFU_CAP_FLAG_READONLY: this prevents clients from writing to the capability.
 * By default, clients are allowed to write to any part of the capability,
 * excluding the initial header.
 *
 * Returns the offset of the capability in config space, or -1 on error, with
 * errno set.
 *
 * @vfu_ctx: the libvfio-user context
 * @pos: specific offset for the capability, or 0.
 * @flags: VFU_CAP_FLAG_*
 * @data: capability data, including the header
 */
ssize_t
vfu_pci_add_capability(vfu_ctx_t *vfu_ctx, size_t pos, int flags, void *data);

/**
 * Find the offset within config space of a given capability (if there are
 * multiple possible matches, use vfu_pci_find_next_capability()).
 *
 * Returns 0 if no such capability was found, with errno set.
 *
 * @vfu_ctx: the libvfio-user context
 * @extended whether capability is an extended one or not
 * @id: capability id (PCI_CAP_ID_* or PCI_EXT_CAP_ID *)
 */
size_t
vfu_pci_find_capability(vfu_ctx_t *vfu_ctx, bool extended, int cap_id);

/**
 * Find the offset within config space of the given capability, starting from
 * @pos, which must be the valid offset of an existing capability. This can be
 * used to iterate through multiple capabilities with the same ID.
 *
 * Returns 0 if no more matching capabilities were found, with errno set.
 *
 * @vfu_ctx: the libvfio-user context
 * @extended whether capability is an extended one or not
 * @pos: offset within config space to start looking
 * @id: capability id (PCI_CAP_ID_*)
 */
size_t
vfu_pci_find_next_capability(vfu_ctx_t *vfu_ctx, bool extended,
                             size_t pos, int cap_id);

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
