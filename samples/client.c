/*
 * Copyright (c) 2020 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
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

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

#include "../lib/muser.h"
#include "../lib/muser_priv.h"
#include "../lib/common.h"

static int
init_sock(const char *path)
{
    int ret, sock;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};

	/* TODO path should be defined elsewhere */
	ret = snprintf(addr.sun_path, sizeof addr.sun_path, path);

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("failed to open socket");
		return sock;
	}

	if ((ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr))) == -1) {
		perror("failed to connect server");
        return ret;
	}
	return sock;
}

static int
map_dma(int sock)
{
    struct vfio_user_header hdr = {.msg_id = 1, .cmd = VFIO_USER_DMA_MAP};
}

static int
set_version(int sock)
{
    int ret, mj, mn;
    uint16_t msg_id;

    ret = recv_version(sock, &mj, &mn, &msg_id, false);
    if (ret < 0) {
        fprintf(stderr, "failed to receive version from server: %s\n",
                strerror(-ret));
        return ret;
    }

    if (mj != LIB_MUSER_VFIO_USER_VERS_MJ || mn != LIB_MUSER_VFIO_USER_VERS_MN) {
        fprintf(stderr, "bad server version %d.%d\n", mj, mn);
        return -EINVAL;
    }

    ret = send_version(sock, mj, mn, msg_id, true); 
    if (ret < 0) {
        fprintf(stderr, "failed to send version to server: %s\n",
                strerror(-ret));
        return ret;
    }

    return 0;
}

int main(int argc, char *argv[])
{
	int ret, sock;

    char template[] = "XXXXXX";
    struct vfio_user_dma_region dma_regions[2];
    int dma_region_fds[ARRAY_SIZE(dma_regions)];
    struct vfio_user_header hdr;
    uint16_t msg_id;

    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/socket\n", argv[0]);
        return -1;
    }

    if ((sock = init_sock(argv[1])) < 0) {
        return sock;
    }

    /*
     * The server proposes version upon connection, we need to send back the
     * version the version we support.
     */
    if ((ret = set_version(sock)) < 0) {
        return ret;
    }

    /* Tell the server we have a memory DMA region it can access. */
    if ((dma_region_fds[0] = mkstemp(template)) == -1) {
        perror("failed to create DMA file");
        return -1;
    }
    if ((ret = ftruncate(dma_region_fds[0], 2 * sysconf(_SC_PAGESIZE))) == -1) {
        perror("failed to truncate file");
        return -1;
    }

    dma_regions[0].addr = 0xdeadbeef;
    dma_regions[0].size = sysconf(_SC_PAGESIZE);
    dma_regions[0].offset = 0;
    dma_regions[0].prot = PROT_READ | PROT_WRITE;
    dma_regions[0].flags = VFIO_USER_F_DMA_REGION_MAPPABLE;

    dma_regions[1].addr = 0xcafebabe;
    dma_regions[1].size = sysconf(_SC_PAGESIZE);
    dma_regions[1].offset = dma_regions[0].size;
    dma_regions[1].prot = PROT_READ | PROT_WRITE;
    dma_regions[1].flags = VFIO_USER_F_DMA_REGION_MAPPABLE;

    dma_region_fds[1] = dma_region_fds[0];

    msg_id = 1;
    ret = send_vfio_user_msg(sock, msg_id, false, VFIO_USER_DMA_MAP, dma_regions,
                             sizeof(dma_regions), dma_region_fds,
                             ARRAY_SIZE(dma_region_fds));

    if (ret < 0) {
        fprintf(stderr, "failed to send DMA regions: %s\n", strerror(-ret));
        return ret;
    }
    ret = recv_vfio_user_msg(sock, &hdr, true, &msg_id);
    if (ret < 0) {
        fprintf(stderr, "failed to receive response for mapping DMA regions: %s\n",
               strerror(-ret));
        return ret;
    }

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
