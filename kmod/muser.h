// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2019, Nutanix Inc. All rights reserved.
 *
 * Author: Thanos Makatos <thanos@nutanix.com>
 *         Swapnil Ingle <swapnil.ingle@nutanix.com>
 *         Felipe Franciosi <felipe@nutanix.com>
 *
 */

#ifndef _LINUX_MUSER_H
#define _LINUX_MUSER_H

#ifndef __KERNEL__
#include <sys/types.h>
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
	char *buf;		/* only used for write */
};

struct muser_cmd_ioctl {
	int vfio_cmd;
	union {
		struct vfio_device_info dev_info;
		struct vfio_region_info reg_info;
		struct vfio_irq_info irq_info;
		struct vfio_irq_set irq_set;
	} data;
};

union muser_cmd_mmap {
	struct {
		unsigned long start;
		unsigned long end;
		unsigned long flags;
		unsigned long pgoff;
	} request;
	struct {
		unsigned long addr;
	} response;
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
#define MUSER_DEV_CMD_WAIT	_IOW('M', 1, struct muser_cmd)
#define MUSER_DEV_CMD_DONE	_IOW('M', 2, struct muser_cmd)

#endif /* _LINUX_MUSER_H */
