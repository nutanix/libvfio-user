// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2019, Nutanix Inc. All rights reserved.
 *
 * Author: Thanos Makatos <thanos@nutanix.com>
 *         Swapnil Ingle <swapnil.ingle@nutanix.com>
 *         Felipe Franciosi <felipe@nutanix.com>
 *
 */

#ifndef _UAPI_LINUX_MUSER_H
#define _UAPI_LINUX_MUSER_H

#ifndef __KERNEL__
#include <sys/types.h>
#include <stddef.h>
#include <errno.h>

/* FIXME copied from include/linux/stddef.h, is this OK license-wise? */
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))

#endif

#include <linux/ioctl.h>
#include <linux/vfio.h>

#define MUSER_DEVNODE "muser"

enum muser_cmd_type {
	MUSER_IOCTL = 1,
	MUSER_READ,
	MUSER_WRITE,
	MUSER_MMAP,
	MUSER_DMA_MMAP,
	MUSER_DMA_MUNMAP,
};

struct muser_cmd_rw {
	size_t count;
	loff_t pos;
};

struct muser_cmd_ioctl {
	int vfio_cmd;
	union {
		struct vfio_device_info dev_info;
		struct vfio_region_info reg_info;
		struct vfio_irq_info irq_info;
		struct vfio_irq_set irq_set;
		struct vfio_group_status group_status;
		int vfio_api_version;
		int vfio_extension;
		int container_fd;
		int device_fd;
		int iommu_type;
		struct vfio_iommu_type1_info iommu_type1_info;
		struct vfio_iommu_type1_dma_map dma_map;
		struct vfio_iommu_type1_dma_unmap dma_unmap;
	} data;
};

union muser_cmd_mmap {
	struct {
		unsigned long addr; /* iova for DMA_MAP, offset for MMAP */
		unsigned long len;
		unsigned long offset;
		unsigned long flags;
		struct file *file;
		int fd;
	} request;
	unsigned long response;
};

struct muser_cmd {
	enum muser_cmd_type type;
	union {
		struct muser_cmd_rw rw;
		struct muser_cmd_ioctl ioctl;
		union muser_cmd_mmap mmap;
	};
	int err;
};

/* ioctl cmds valid for /dev/muser/<uuid> */
#define MUSER_DEV_CMD_WAIT	_IOR('M', 1, struct muser_cmd)
#define MUSER_DEV_CMD_DONE	_IOW('M', 2, struct muser_cmd)

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

static inline ssize_t get_argsz(unsigned int cmd, struct muser_cmd *muser_cmd)
{
	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return muser_cmd->ioctl.data.dev_info.argsz;
	case VFIO_DEVICE_GET_REGION_INFO:
		return muser_cmd->ioctl.data.reg_info.argsz;
	case VFIO_DEVICE_GET_IRQ_INFO:
		return muser_cmd->ioctl.data.irq_info.argsz;
	case VFIO_DEVICE_SET_IRQS:
		return muser_cmd->ioctl.data.irq_set.argsz;
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

#endif /* _UAPI_LINUX_MUSER_H */
