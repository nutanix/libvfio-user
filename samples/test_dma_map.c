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
#include <err.h>
#include "../lib/muser_priv.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

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

static void*
test_map_dma(const int fd, void *vaddr, unsigned long size, unsigned long iova)
{
	int err;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map),
		.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
		.vaddr = (unsigned long long)vaddr,
		.iova = iova,
		.size = size,
	};
	fprintf(stderr, "attempting to MAP_DMA IOVA=%llx\n", dma_map.iova);

	err = ioctl(fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (err) {
		fprintf(stderr, "failed to MAP_DMA: %d (%s)\n", err,
		        strerror(errno));
		return NULL;
	}

	return (void*)dma_map.vaddr;
}

static void
test_unmap_dma(const int fd, unsigned long size, unsigned long long iova)
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

static int
get_container_fd(const char *path)
{
	int err, vfio_ctr_fd, vfio_grp_fd, vfio_dev_fd;
	char *grp_path;

	vfio_ctr_fd = open(VFIO_CTR_PATH, O_RDWR);
	assert(vfio_ctr_fd >= 0);

	// Open the VFIO entry for this device's IOMMU GROUP.
	err = asprintf(&grp_path, VFIO_PATH "%d", pci_group_id(path));
	assert(err > 0);
	vfio_grp_fd = open(grp_path, O_RDWR);
	assert(vfio_grp_fd >= 0);
	free(grp_path);

	// Add the group to the container.
	err = ioctl(vfio_grp_fd, VFIO_GROUP_SET_CONTAINER, &vfio_ctr_fd);
	assert(!err);

	// Enable IOMMU type 1 on container.
	err = ioctl(vfio_ctr_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU);
	assert(!err);

	// Get a device fd from VFIO.
	vfio_dev_fd = ioctl(vfio_grp_fd, VFIO_GROUP_GET_DEVICE_FD, path);
	assert(vfio_dev_fd >= 0);

	return vfio_ctr_fd;
}

int main(int argc, char * argv[])
{
	int vfio_ctr_fd;
	void *dma_map_addr;
	struct iovec dma_regions[] = {
		{.iov_base = (void*)0x0, .iov_len = 1 << 21},
		{.iov_base = (void*)(1 << 21), .iov_len = 1 << 21},
	};
	size_t i;
	bool huge = true;
	int fd;
	int flags = MAP_SHARED;
	void *vaddr;
	size_t size = 1 << 23; /* FIXME */
	int ret;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <MUSER device UUID>\n", argv[0]);
		return EXIT_FAILURE;
	}

	vfio_ctr_fd = get_container_fd(argv[1]);

	if (huge) {
		char template[] = "/dev/hugepages/XXXXXX";
		fd = mkstemp(template);
		assert(fd != -1);
	}

	ret = lseek(fd, size, SEEK_END);
	if (ret == -1) {
		err(EXIT_FAILURE, "failed to seek at %lu", size);
	}

	/*
	 * Allocate some space and setup a DMA mapping.
	 * It *must* be MAP_SHARED.
	 */
	vaddr = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0);
	if (vaddr == MAP_FAILED) {
		err(EXIT_FAILURE, "failed to mmap");
	}

	for (i = 0; i < ARRAY_SIZE(dma_regions); i++) {
		if ((unsigned long long)dma_regions[i].iov_base + dma_regions[i].iov_len > size
		    || (huge && (dma_regions[i].iov_len < (1 << 21)))) {
			err(EXIT_FAILURE, "bad IOVA %#lx-%#lx\n",
			    (unsigned long)dma_regions[i].iov_base,
			    (unsigned long)dma_regions[i].iov_base + dma_regions[i].iov_len);
		}
		dma_map_addr = test_map_dma(vfio_ctr_fd, vaddr,
		                            dma_regions[i].iov_len,
		                            (unsigned long)dma_regions[i].iov_base);
		if (!dma_map_addr)
			exit(EXIT_FAILURE);
	}

	printf("press enter to continue\n");
	getchar();

	for (i = 0; i < ARRAY_SIZE(dma_regions); i++) {
		test_unmap_dma(vfio_ctr_fd,
		               (unsigned long long)dma_regions[i].iov_len,
		               (unsigned long long)dma_regions[i].iov_base);
	}
	return 0;
}
