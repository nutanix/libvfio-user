/*
 * Userspace mediated device sample application
 *
 * Copyright (c) 2019, Nutanix Inc. All rights reserved.
 *     Author: Thanos Makatos <thanos@nutanix.com>
 *             Swapnil Ingle <swapnil.ingle@nutanix.com>
 *             Felipe Franciosi <felipe@nutanix.com>
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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <string.h>
#include <linux/vfio.h>
#include <limits.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#define VFIO_PATH           "/dev/vfio/"
#define VFIO_CTR_PATH       VFIO_PATH "vfio"
#define SYSFS_PCI_DEV_PATH  "/sys/bus/pci/devices/"
#define SYSFS_IOMMU_GROUP   "/iommu_group"

static int
pci_group_id(const char *bdf)
{
	char *dev_path;
	char group_path[PATH_MAX];
	int group_id;

	assert(bdf);

	asprintf(&dev_path, SYSFS_PCI_DEV_PATH "%s" SYSFS_IOMMU_GROUP, bdf);
	memset(group_path, 0, sizeof(group_path));
	readlink(dev_path, group_path, sizeof(group_path));
	free(dev_path);
	sscanf(basename(group_path), "%d", &group_id);
	return group_id;
}

static inline void*
test_map_dma(const int fd, const unsigned long size, const unsigned long iova)
{
	int err;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map),
		.size = size,
		.iova = iova,
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
	};

	/* Allocate some space and setup a DMA mapping */
	/* FIXME it *must* be MAP_SHARED */
	dma_map.vaddr = (unsigned long long)mmap(0, size, PROT_READ | PROT_WRITE,
			     MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (dma_map.vaddr == (unsigned long)MAP_FAILED) {
		perror("failed to map DMA");
		return NULL;
	}
	printf("%llx\n", dma_map.vaddr);
	strcpy((char*)dma_map.vaddr, "foo");

	fprintf(stderr, "attempting to MAP_DMA IOVA=%llx\n", dma_map.iova);
	
	err = ioctl(fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (err) {
		fprintf(stderr, "failed to MAP_DMA: %d (errno=%d)", err, errno);
		return NULL;
	}
	printf("[%s]\n", (char*)dma_map.vaddr);

	return (void*)dma_map.vaddr;
}

static inline void
test_unmap_dma(const int fd, const unsigned long size, const unsigned long iova)
{
	int err;
	struct vfio_iommu_type1_dma_unmap dma_unmap = {
		.argsz = sizeof dma_unmap,
		.size = size,
		.iova = iova,
		.flags = 0
	};

	err = ioctl(fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	if (err) {
		perror("UNMAP_DMA\n");
		return;
	}
	printf("unmapped IOVA=%llx\n", dma_unmap.iova);
}

int main(int argc, char * argv[])
{
	int err, vfio_ctr_fd, vfio_grp_fd, vfio_dev_fd;
	char *grp_path;
#ifdef DEBUG
	struct vfio_group_status grp_status;
#endif
	struct vfio_iommu_type1_info iommu_info;
	void *dma_map_addr = NULL;

	if (argc != 2) {
		printf("Usage: %s <device bdf in full>\n", argv[0]);
		printf("   ex: %s 0000:82:00.0\n", argv[0]);
		return EXIT_FAILURE;
	}

	vfio_ctr_fd = open(VFIO_CTR_PATH, O_RDWR);
	assert(vfio_ctr_fd >= 0);

#ifdef DEBUG
	err = ioctl(vfio_ctr_fd, VFIO_GET_API_VERSION);
	assert(err == VFIO_API_VERSION);
	err = ioctl(vfio_ctr_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU);
	assert(err == 1);
#endif

	// Open the VFIO entry for this device's IOMMU GROUP.
	err = asprintf(&grp_path, VFIO_PATH "%d", pci_group_id(argv[1]));
	assert(err > 0);
	vfio_grp_fd = open(grp_path, O_RDWR);
	assert(vfio_grp_fd >= 0);
	free(grp_path);

#ifdef DEBUG
	// Ensure group is viable.
	memset(&grp_status, 0, sizeof(grp_status));
	grp_status.argsz = sizeof(grp_status);
	err = ioctl(vfio_grp_fd, VFIO_GROUP_GET_STATUS, &grp_status);
	assert(!err);
	assert((grp_status.flags & VFIO_GROUP_FLAGS_VIABLE) == 1);
#endif

	// Add the group to the container.
	err = ioctl(vfio_grp_fd, VFIO_GROUP_SET_CONTAINER, &vfio_ctr_fd);
	assert(!err);

	// Enable IOMMU type 1 on container.
	err = ioctl(vfio_ctr_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU);
	assert(!err);

	// Fetch IOMMU information from VFIO.
	memset(&iommu_info, 0, sizeof(iommu_info));
	iommu_info.argsz = sizeof(iommu_info);
	err = ioctl(vfio_ctr_fd, VFIO_IOMMU_GET_INFO, &iommu_info);
	assert(!err);

	// Get a device fd from VFIO.
	vfio_dev_fd = ioctl(vfio_grp_fd, VFIO_GROUP_GET_DEVICE_FD, argv[1]);
	assert(vfio_dev_fd >= 0);

	void *p;
	p = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE,
			MAP_SHARED, vfio_dev_fd, 0);
	assert(p != MAP_FAILED);
	printf("%p\n", p);
	printf("%s\n", (char*)p);

	dma_map_addr = test_map_dma(vfio_ctr_fd, 4096, 0xdeadbeef000);
	if (!dma_map_addr)
		exit(EXIT_FAILURE);
	test_unmap_dma(vfio_ctr_fd, 4096, 0xdeadbeef000);

	return 0;
}
