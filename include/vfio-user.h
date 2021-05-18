/*
 * Copyright (c) 2020 Nutanix Inc. All rights reserved.
 *
 * Derived from Intel's vfio-user.h:
 * Copyright (c) 2020 Intel Corporation. All rights reserved.
 *
 * Authors: Changpeng Liu <changpeng.liu@intel.com>
 *          Thanos Makatos <thanos@nutanix.com>
 *          Swapnil Ingle <swapnil.ingle@nutanix.com>
 *          John Levon <john.levon@nutanix.com>
 *
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

#ifndef VFIO_USER_H
#define VFIO_USER_H

/*
 * Shared definitions for the vfio-user protocol.
 */

#include <inttypes.h>
#include <linux/vfio.h>
#include <linux/version.h>

#ifdef __cplusplus
extern "C" {
#endif

enum vfio_user_command {
    VFIO_USER_VERSION                   = 1,
    VFIO_USER_DMA_MAP                   = 2,
    VFIO_USER_DMA_UNMAP                 = 3,
    VFIO_USER_DEVICE_GET_INFO           = 4,
    VFIO_USER_DEVICE_GET_REGION_INFO    = 5,
    VFIO_USER_DEVICE_GET_IRQ_INFO       = 6,
    VFIO_USER_DEVICE_SET_IRQS           = 7,
    VFIO_USER_REGION_READ               = 8,
    VFIO_USER_REGION_WRITE              = 9,
    VFIO_USER_DMA_READ                  = 10,
    VFIO_USER_DMA_WRITE                 = 11,
    VFIO_USER_VM_INTERRUPT              = 12,
    VFIO_USER_DEVICE_RESET              = 13,
    VFIO_USER_DIRTY_PAGES               = 14,
    VFIO_USER_MAX,
};

enum vfio_user_message_type {
    VFIO_USER_MESSAGE_COMMAND   = 0,
    VFIO_USER_MESSAGE_REPLY     = 1,
};

#define VFIO_USER_FLAGS_NO_REPLY    (0x1)

struct vfio_user_header {
    uint16_t    msg_id;
    uint16_t    cmd;
    uint32_t    msg_size;
    struct {
        uint32_t    type     : 4;
#define VFIO_USER_F_TYPE_COMMAND    0
#define VFIO_USER_F_TYPE_REPLY      1
        uint32_t    no_reply : 1;
        uint32_t    error    : 1;
        uint32_t    resvd    : 26;
    } flags;
    uint32_t    error_no;
} __attribute__((packed));

struct vfio_user_version {
    uint16_t    major;
    uint16_t    minor;
    uint8_t     data[];
} __attribute__((packed));

/*
 * Similar to vfio_device_info, but without caps (yet).
 */
struct vfio_user_device_info {
    uint32_t    argsz;
    /* VFIO_DEVICE_FLAGS_* */
    uint32_t    flags;
    uint32_t    num_regions;
    uint32_t    num_irqs;
} __attribute__((packed));

struct vfio_user_dma_region {
    uint64_t    addr;
    uint64_t    size;
    uint64_t    offset;
    uint32_t    prot;
    uint32_t    flags;
#define VFIO_USER_F_DMA_REGION_MAPPABLE (1 << 0)
} __attribute__((packed));

struct vfio_user_region_access {
    uint64_t    offset;
    uint32_t    region;
    uint32_t    count;
    uint8_t     data[];
} __attribute__((packed));

struct vfio_user_dma_region_access {
    uint64_t    addr;
    uint64_t    count;
    uint8_t     data[];
} __attribute__((packed));

struct vfio_user_irq_info {
    uint32_t    subindex;
} __attribute__((packed));

/* based on struct vfio_bitmap */
struct vfio_user_bitmap {
    uint64_t pgsize;
    uint64_t size;
    char data[];
} __attribute__((packed));

/* based on struct vfio_iommu_type1_dirty_bitmap_get */
struct vfio_user_bitmap_range {
    uint64_t iova;
    uint64_t size;
    struct vfio_user_bitmap bitmap;
} __attribute__((packed));

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)

/* copied from <linux/vfio.h> */

#define VFIO_DEVICE_STATE_STOP      (0)
#define VFIO_DEVICE_STATE_RUNNING   (1 << 0)
#define VFIO_DEVICE_STATE_SAVING    (1 << 1)
#define VFIO_DEVICE_STATE_RESUMING  (1 << 2)
#define VFIO_DEVICE_STATE_MASK      (VFIO_DEVICE_STATE_RUNNING | \
				     VFIO_DEVICE_STATE_SAVING |  \
				     VFIO_DEVICE_STATE_RESUMING)

#define VFIO_DEVICE_STATE_VALID(state) \
	(state & VFIO_DEVICE_STATE_RESUMING ? \
	(state & VFIO_DEVICE_STATE_MASK) == VFIO_DEVICE_STATE_RESUMING : 1)

#define VFIO_DEVICE_STATE_IS_ERROR(state) \
	((state & VFIO_DEVICE_STATE_MASK) == (VFIO_DEVICE_STATE_SAVING | \
					      VFIO_DEVICE_STATE_RESUMING))

#define VFIO_DEVICE_STATE_SET_ERROR(state) \
	((state & ~VFIO_DEVICE_STATE_MASK) | VFIO_DEVICE_SATE_SAVING | \
					     VFIO_DEVICE_STATE_RESUMING)

/* RHEL kernels have some of it backported */
#ifndef VFIO_REGION_TYPE_MIGRATION /* not a RHEL kernel */
#define VFIO_REGION_TYPE_MIGRATION              (3)
#define VFIO_REGION_SUBTYPE_MIGRATION           (1)

struct vfio_device_migration_info {
	__u32 device_state;         /* VFIO device state */
	__u32 reserved;
	__u64 pending_bytes;
	__u64 data_offset;
	__u64 data_size;
};
#endif /* not a RHEL kernel */

struct vfio_iommu_type1_dirty_bitmap {
	__u32        argsz;
	__u32        flags;
#define VFIO_IOMMU_DIRTY_PAGES_FLAG_START	(1 << 0)
#define VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP	(1 << 1)
#define VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP	(1 << 2)
	__u8         data[];
};

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0) */

#ifdef __cplusplus
}
#endif

#endif /* VFIO_USER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
