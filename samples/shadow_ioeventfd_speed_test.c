/*
 * Copyright (c) 2022, Nutanix Inc. All rights reserved.
 *     Author: Thanos Makatos <thanos@nutanix.com>
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
 * shadow_ioeventfd_speed_test.c: application that is run in the guest to
 * demonstrate the performance benefit of shadow ioeventfd. To be used with
 * shadow_ioeventfd_server.c on the host.
 */

#include <stdio.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/vfio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <sys/time.h>

int main(int argc, char *argv[])
{
	int container = open("/dev/vfio/vfio", O_RDWR);
	assert(container != -1);
	char path[PATH_MAX];
	sprintf(path, "/dev/vfio/%d", atoi(argv[1]));
	int group = open(path, O_RDWR);
	assert(group != 0);
	struct vfio_group_status status = { .argsz = sizeof(status) };
	int ret = ioctl(group, VFIO_GROUP_GET_STATUS, &status);
	assert(ret != -1);
	assert(status.flags & VFIO_GROUP_FLAGS_VIABLE);
	ret = ioctl(group, VFIO_GROUP_SET_CONTAINER, &container);
	assert(ret != -1);
	ret = ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
	assert(ret == 0);
	int device = ioctl(group, VFIO_GROUP_GET_DEVICE_FD, argv[2]);
	assert(device >= 0);
	struct vfio_region_info region_info = {
		.argsz = sizeof(region_info),
		.index = 0
	};
	ret = ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &region_info);
	assert(ret == 0);
	u_int32_t val = 0xdeadbeef;
	struct timeval t0, t1;
	const int count = 100000;
	gettimeofday(&t0, NULL);
	for (int i = 0; i < count; i++) {
		ret = pwrite(device, &val, sizeof val, region_info.offset);
		assert(ret == sizeof val);
	}
	gettimeofday(&t1, NULL);
	printf("shadow:\t%lu us\n",
	       (t1.tv_sec - t0.tv_sec) * 1000000 + t1.tv_usec - t0.tv_usec);
	gettimeofday(&t0, NULL);
	for (int i = 0; i < count; i++) {
		ret = pwrite(device, &val, sizeof val, region_info.offset + 8);
		assert(ret == sizeof val);
	}
	gettimeofday(&t1, NULL);
	printf("legacy:\t%lu us\n",
	       (t1.tv_sec - t0.tv_sec) * 1000000 + t1.tv_usec - t0.tv_usec);
	return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
