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

#define VFIO_USER_DEFAULT_MAX_DATA_XFER_SIZE (1024 * 1024)

enum vfio_user_command {
    VFIO_USER_VERSION                   = 1,
    VFIO_USER_DMA_MAP                   = 2,
    VFIO_USER_DMA_UNMAP                 = 3,
    VFIO_USER_DEVICE_GET_INFO           = 4,
    VFIO_USER_DEVICE_GET_REGION_INFO    = 5,
    VFIO_USER_DEVICE_GET_REGION_IO_FDS  = 6,
    VFIO_USER_DEVICE_GET_IRQ_INFO       = 7,
    VFIO_USER_DEVICE_SET_IRQS           = 8,
    VFIO_USER_REGION_READ               = 9,
    VFIO_USER_REGION_WRITE              = 10,
    VFIO_USER_DMA_READ                  = 11,
    VFIO_USER_DMA_WRITE                 = 12,
    VFIO_USER_DEVICE_RESET              = 13,
    VFIO_USER_REGION_WRITE_MULTI        = 15,
    VFIO_USER_DEVICE_FEATURE            = 16,
    VFIO_USER_MIG_DATA_READ             = 17,
    VFIO_USER_MIG_DATA_WRITE            = 18,
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
    uint32_t    flags;
#define VFIO_USER_F_TYPE_MASK       (0xf)
#define VFIO_USER_F_TYPE_COMMAND    (0x0)
#define VFIO_USER_F_TYPE_REPLY      (0x1)
#define VFIO_USER_F_NO_REPLY        (0x10)
#define VFIO_USER_F_ERROR           (0x20)
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

/* based on struct vfio_bitmap */
struct vfio_user_bitmap {
    uint64_t pgsize;
    uint64_t size;
    char data[];
} __attribute__((packed));

/* based on struct vfio_iommu_type1_dma_map */
struct vfio_user_dma_map {
    uint32_t argsz;
#define VFIO_USER_F_DMA_REGION_READ     (1 << 0)
#define VFIO_USER_F_DMA_REGION_WRITE    (1 << 1)
    uint32_t flags;
    uint64_t offset;
    uint64_t addr;
    uint64_t size;
} __attribute__((packed));

/* based on struct vfio_iommu_type1_dma_unmap */
struct vfio_user_dma_unmap {
    uint32_t argsz;
#ifndef VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP
#define VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP (1 << 0)
#endif
#ifndef VFIO_DMA_UNMAP_FLAG_ALL
#define VFIO_DMA_UNMAP_FLAG_ALL (1 << 1)
#endif
    uint32_t flags;
    uint64_t addr;
    uint64_t size;
    struct vfio_user_bitmap bitmap[];
};

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

typedef struct vfio_user_region_io_fds_request {
    uint32_t argsz;
    uint32_t flags;
    uint32_t index;
    uint32_t count;
} __attribute__((packed)) vfio_user_region_io_fds_request_t;

#define VFIO_USER_IO_FD_TYPE_IOEVENTFD 0
#define VFIO_USER_IO_FD_TYPE_IOREGIONFD 1
#define VFIO_USER_IO_FD_TYPE_IOEVENTFD_SHADOW 2

typedef struct vfio_user_sub_region_ioeventfd {
    uint64_t gpa_offset;
    uint64_t size;
    uint32_t fd_index;
    uint32_t type;
    uint32_t flags;
    uint32_t shadow_mem_fd_index;
    uint64_t shadow_offset;
    uint64_t datamatch;
} __attribute__((packed)) vfio_user_sub_region_ioeventfd_t;

typedef struct vfio_user_sub_region_ioregionfd {
    uint64_t offset;
    uint64_t size;
    uint32_t fd_index;
    uint32_t type;
    uint32_t flags;
    uint32_t padding;
    uint64_t user_data;
} __attribute__((packed)) vfio_user_sub_region_ioregionfd_t;

typedef struct vfio_user_region_io_fds_reply {
    uint32_t argsz;
    uint32_t flags;
    uint32_t index;
    uint32_t count;
    union sub_region {
        struct vfio_user_sub_region_ioeventfd ioeventfd;
        struct vfio_user_sub_region_ioregionfd ioregionfd;
    } sub_regions[];
} __attribute__((packed)) vfio_user_region_io_fds_reply_t;

/* Analogous to struct vfio_device_feature_dma_logging_range */
struct vfio_user_device_feature_dma_logging_range {
    uint64_t iova;
    uint64_t length;
} __attribute__((packed));

/* Analogous to struct vfio_device_feature_dma_logging_control */
struct vfio_user_device_feature_dma_logging_control {
    uint64_t page_size;
    uint32_t num_ranges;
    uint32_t reserved;
    struct vfio_user_device_feature_dma_logging_range ranges[];
} __attribute__((packed));

/* Analogous to struct vfio_device_feature_dma_logging_report */
struct vfio_user_device_feature_dma_logging_report {
    uint64_t iova;
    uint64_t length;
    uint64_t page_size;
    uint8_t  bitmap[];
} __attribute__((packed));

#ifndef VFIO_DEVICE_FEATURE_DMA_LOGGING_START
#define VFIO_DEVICE_FEATURE_DMA_LOGGING_START  6
#define VFIO_DEVICE_FEATURE_DMA_LOGGING_STOP   7
#define VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT 8
#endif

/* Analogous to struct vfio_device_feature */
struct vfio_user_device_feature {
	uint32_t	argsz;
	uint32_t	flags;
#ifndef VFIO_DEVICE_FEATURE_MASK
#define VFIO_DEVICE_FEATURE_MASK	(0xffff)  /* 16-bit feature index */
#define VFIO_DEVICE_FEATURE_GET		(1 << 16) /* Get feature into data[] */
#define VFIO_DEVICE_FEATURE_SET		(1 << 17) /* Set feature from data[] */
#define VFIO_DEVICE_FEATURE_PROBE	(1 << 18) /* Probe feature support */
#endif
	uint8_t  	data[];
} __attribute__((packed));

/* Analogous to struct vfio_device_feature_migration */
struct vfio_user_device_feature_migration {
    uint64_t flags;
#ifndef VFIO_REGION_TYPE_MIGRATION_DEPRECATED
#define VFIO_MIGRATION_STOP_COPY    (1 << 0)
#define VFIO_MIGRATION_P2P          (1 << 1)
#endif
/*
 * PRE_COPY was added in a later kernel version, after
 * VFIO_REGION_TYPE_MIGRATION_DEPRECATED had been introduced.
 */
#ifndef VFIO_MIGRATION_PRE_COPY
#define VFIO_MIGRATION_PRE_COPY     (1 << 2)
#endif
} __attribute__((packed));
#ifndef VFIO_REGION_TYPE_MIGRATION_DEPRECATED
#define VFIO_DEVICE_FEATURE_MIGRATION 1
#endif
_Static_assert(sizeof(struct vfio_user_device_feature_migration) == 8,
               "bad vfio_user_device_feature_migration size");

/* Analogous to struct vfio_device_feature_mig_state */
struct vfio_user_device_feature_mig_state {
    uint32_t    device_state;
    uint32_t    data_fd;
} __attribute__((packed));
#ifndef VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE
#define VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE 2
#endif
_Static_assert(sizeof(struct vfio_user_device_feature_migration) == 8,
               "bad vfio_user_device_feature_mig_state size");

/* Analogous to enum vfio_device_mig_state */
enum vfio_user_device_mig_state {
    VFIO_USER_DEVICE_STATE_ERROR = 0,
    VFIO_USER_DEVICE_STATE_STOP = 1,
    VFIO_USER_DEVICE_STATE_RUNNING = 2,
    VFIO_USER_DEVICE_STATE_STOP_COPY = 3,
    VFIO_USER_DEVICE_STATE_RESUMING = 4,
    VFIO_USER_DEVICE_STATE_RUNNING_P2P = 5,
    VFIO_USER_DEVICE_STATE_PRE_COPY = 6,
    VFIO_USER_DEVICE_STATE_PRE_COPY_P2P = 7,
    VFIO_USER_DEVICE_NUM_STATES = 8,
};

struct vfio_user_mig_data {
    uint32_t    argsz;
    uint32_t    size;
    uint8_t     data[];
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif /* VFIO_USER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
