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

#define VFIO_PATH               "/dev/vfio/"
#define VFIO_CTR_PATH           VFIO_PATH "vfio"
#define SYSFS_MUSER_DEV_PATH    "/sys/class/muser/muser/"
#define SYSFS_IOMMU_GROUP       "/iommu_group"

static int
test_read(int vfio_dev_fd, off_t offset)
{
    size_t bytes;
    char buf[256];
    int i;

    memset(buf, 0, sizeof(buf));
    printf("* Reading %zd bytes\n", sizeof(buf));
    bytes = pread(vfio_dev_fd, buf, sizeof(buf), offset);
    assert(bytes == sizeof(buf));
    printf("** Read %zd bytes\n", bytes);

    for (i = 0; i < sizeof(buf); i++) {
        if (i % 16 == 0) {
            printf("%04X:", i);
        }
        printf(" %02hhX", buf[i]);
        if (i % 16 == 15) {
            printf("\n");
        }
    }
    if (i % 16 != 0) {
        printf("\n");
    }

    return 0;
}

static int
pci_group_id(const char *uuid)
{
    char *dev_path;
    char group_path[PATH_MAX];
    int group_id;

    assert(uuid != NULL);

    asprintf(&dev_path, SYSFS_MUSER_DEV_PATH "%s" SYSFS_IOMMU_GROUP, uuid);
    memset(group_path, 0, sizeof(group_path));
    readlink(dev_path, group_path, sizeof(group_path));
    free(dev_path);
    sscanf(basename(group_path), "%d", &group_id);
    return group_id;
}

void print_sparse_mmap_info(struct vfio_region_info *reg)
{
	struct vfio_region_info_cap_sparse_mmap *sparse;

	printf("argsz %u, cap_off %u\n", reg->argsz, reg->cap_offset);
	if (reg->cap_offset) {
		sparse = (struct vfio_region_info_cap_sparse_mmap *)
                  ((void *)reg + reg->cap_offset);
		printf("cap_hdr: id %u version %u\n", sparse->header.id,
               sparse->header.version);
		printf("sparse: nr_areas %u, off 0x%llx size 0x%llx\n", sparse->nr_areas,
               sparse->areas[0].offset, sparse->areas[0].size);
	}
}

int
main(int argc, char * argv[])
{
    int vfio_ctr_fd, vfio_grp_fd, vfio_dev_fd;
    char *grp_path;
    size_t size = 0;
    int i;
    int err;

    if (argc != 2) {
        printf("Usage: %s <muser_dev_uuid>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Create a new VFIO container.
    printf("* Creating new VFIO container...\n");
    vfio_ctr_fd = open(VFIO_CTR_PATH, O_RDWR);
    assert(vfio_ctr_fd >= 0);
    printf("** vfio_ctr_fd = %d\n", vfio_ctr_fd);

    // Ensure kernel VFIO is compatible.
    printf("* Fetching VFIO API version...\n");
    err = ioctl(vfio_ctr_fd, VFIO_GET_API_VERSION);
    assert(err == VFIO_API_VERSION);

    // Ensure VFIO supports TYPE1 IOMMU.
    printf("* Checking for IOMMU TYPE1 extension in VFIO...\n");
    err = ioctl(vfio_ctr_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU);
    assert(err == 1);

    // Open the VFIO entry for this device's IOMMU GROUP.
    err = asprintf(&grp_path, VFIO_PATH "%d", pci_group_id(argv[1]));
    assert(err > 0);
    printf("* Opening the VFIO group (%s)...\n", grp_path);
    vfio_grp_fd = open(grp_path, O_RDWR);
    assert(vfio_grp_fd >= 0);
    printf("** vfio_grp_fd = %d\n", vfio_grp_fd);
    free(grp_path);

    // Ensure group is viable.
    struct vfio_group_status grp_status;
    printf("* Ensuring all devices in this group are bound to VFIO...\n");
    memset(&grp_status, 0, sizeof(grp_status));
    grp_status.argsz = sizeof(grp_status);
    err = ioctl(vfio_grp_fd, VFIO_GROUP_GET_STATUS, &grp_status);
    assert(!err);
    assert((grp_status.flags & VFIO_GROUP_FLAGS_VIABLE) == 1);

    // Add the group to the container.
    printf("* Adding group to container...\n");
    err = ioctl(vfio_grp_fd, VFIO_GROUP_SET_CONTAINER, &vfio_ctr_fd);
    assert(!err);

    // Enable IOMMU type 1 on container.
    printf("* Setting IOMMU Type 1 on container...\n");
    err = ioctl(vfio_ctr_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU);
    assert(!err);

    // Fetch IOMMU information from VFIO.
    struct vfio_iommu_type1_info iommu_info;
    printf("* Fetching IOMMU information...\n");
    memset(&iommu_info, 0, sizeof(iommu_info));
    iommu_info.argsz = sizeof(iommu_info);
    err = ioctl(vfio_ctr_fd, VFIO_IOMMU_GET_INFO, &iommu_info);
    assert(!err);

    // Get a device fd from VFIO.
    printf("* Getting a device (%s) fd from group...\n", argv[1]);
    vfio_dev_fd = ioctl(vfio_grp_fd, VFIO_GROUP_GET_DEVICE_FD, argv[1]);
    assert(vfio_dev_fd >= 0);
    printf("** vfio_dev_fd = %d\n", vfio_dev_fd);

    // Fetch device information.
    printf("* Fetching device information...\n");
    struct vfio_device_info dev_info;
    memset(&dev_info, 0, sizeof(dev_info));
    dev_info.argsz = sizeof(dev_info);
    err = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_INFO, &dev_info);
    assert(err == 0);
    assert(dev_info.num_regions <= VFIO_PCI_NUM_REGIONS);

    // Fetch region information for this device.
    struct vfio_region_info *reg_info[VFIO_PCI_NUM_REGIONS] = {0};
    struct vfio_region_info *reg;
    printf("* Fetching information for %u regions\n", dev_info.num_regions);
    for (i = 0; i < (int)dev_info.num_regions; i++) {
	    size = sizeof(struct vfio_region_info);
	    reg = calloc(1, size);
        assert(reg != NULL);
        reg->argsz = size;
        reg->index = i;
retry:
        err = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_REGION_INFO, reg);
        if (err != 0) {
            // This region doesn't exist or isn't accessible.
            printf("** %d: Region info unavailable\n", i);
            memset(reg, 0, size);
        } else {
            printf("** %d: argsz=0x%X, flags=0x%X, index=0x%X, "
                          "size=0x%llX, offset=0x%llX\n",
                   i,
                   reg->argsz,
                   reg->flags,
                   reg->index,
                   reg->size,
                   reg->offset);
	        if (reg->argsz > size) {
		        size = reg->argsz;
		        reg = realloc(reg, reg->argsz);
		        goto retry;
	        }
	        print_sparse_mmap_info(reg);
        }
	    reg_info[i] = reg;
    }

    // Fetch irq information for this device.
    struct vfio_irq_info irq_info[VFIO_PCI_NUM_IRQS];
    printf("* Fetching information for %u irqs\n", dev_info.num_irqs);
    for (i = 0; i < (int)dev_info.num_irqs; i++) {
        memset(&irq_info[i], 0, sizeof(irq_info[i]));
        irq_info[i].argsz = sizeof(irq_info[i]);
        irq_info[i].index = i;
        err = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_IRQ_INFO, irq_info[i]);
        if (err != 0) {
            // This irq doesn't exist or isn't accessible.
            printf("** %d: Irq info unavailable\n", i);
            memset(&irq_info[i], 0, sizeof(irq_info[i]));
        } else {
            printf("** %d: argsz=0x%X, flags=0x%X, index=0x%X, count=%u\n",
                   i,
                   irq_info[i].argsz,
                   irq_info[i].flags,
                   irq_info[i].index,
                   irq_info[i].count);
        }
    }

    // Test.
    err = test_read(vfio_dev_fd, reg_info[VFIO_PCI_CONFIG_REGION_INDEX]->offset);
    assert(!err);
    for (i = 0; i < (int)dev_info.num_regions; i++) {
        free(reg_info[i]);
    }

    return 0;
}
