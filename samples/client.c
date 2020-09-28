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

#define _GNU_SOURCE
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
set_version(int sock, int client_max_fds, int *server_max_fds)
{
    int ret, mj, mn;
    uint16_t msg_id;
    char *client_caps = NULL;

    ret = recv_version(sock, &mj, &mn, &msg_id, false, server_max_fds);
    if (ret < 0) {
        fprintf(stderr, "failed to receive version from server: %s\n",
                strerror(-ret));
        goto out;
    }

    if (mj != LIB_MUSER_VFIO_USER_VERS_MJ || mn != LIB_MUSER_VFIO_USER_VERS_MN) {
        fprintf(stderr, "bad server version %d.%d\n", mj, mn);
        ret = -EINVAL;
        goto out;
    }

    ret = asprintf(&client_caps, "{max_fds: %d}", client_max_fds);
    if (ret == -1) {
        client_caps = NULL;
        ret = -ENOMEM; /* FIXME */
        goto out;
    }

    ret = send_version(sock, mj, mn, msg_id, true, client_caps);
    if (ret < 0) {
        fprintf(stderr, "failed to send version to server: %s\n",
                strerror(-ret));
        goto out;
    }
    ret = 0;

out:
    free(client_caps);
    return ret;
}

static int
get_device_info(int sock)
{
    struct vfio_user_header hdr;
    struct vfio_device_info dev_info =  {
        .argsz = sizeof(dev_info)
    };
    uint16_t msg_id;
    int ret;
    int size = sizeof dev_info;

    msg_id = 1;
    ret = send_vfio_user_msg(sock, msg_id, false, VFIO_USER_DEVICE_GET_INFO,
                             &dev_info, size, NULL,0);
    if (ret < 0) {
        fprintf(stderr, "%s: failed to send message: %s\n", __func__,
                strerror(-ret));
        return ret;
    }

    ret = recv_vfio_user_msg(sock, &hdr, true, &msg_id, &dev_info, &size);
    if (ret < 0) {
        fprintf(stderr, "%s: failed to receive header: %s\n", __func__,
                strerror(-ret));
        return ret;
    }

    fprintf(stdout, "devinfo: flags %#x, num_regions %d, num_irqs %d\n",
	    dev_info.flags, dev_info.num_regions, dev_info.num_irqs);
    return 0;
}

int main(int argc, char *argv[])
{
	int ret, sock;

    struct vfio_user_dma_region *dma_regions;
    int *dma_region_fds;
    struct vfio_user_header hdr;
    uint16_t msg_id = 1;
    int i;
    FILE *fp;
    int fd;
    const int client_max_fds = 32;
    int server_max_fds;
    int nr_dma_regions;

    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/socket\n", argv[0]);
        return -1;
    }

    if ((sock = init_sock(argv[1])) < 0) {
        return sock;
    }

    /*
     * XXX VFIO_USER_VERSION
     *
     * The server proposes version upon connection, we need to send back the
     * version the version we support.
     */
    if ((ret = set_version(sock, client_max_fds, &server_max_fds)) < 0) {
        return ret;
    }

    /* XXX VFIO_USER_DEVICE_GET_INFO */
    ret = get_device_info(sock);
    if (ret < 0) {
        return ret;
    }

    /*
     * XXX VFIO_USER_DMA_MAP
     *
     * Tell the server we have some DMA regions it can access. Each DMA regions
     * is accompanied by a file descriptor, so let's create more (2x) DMA
     * regions that can fit in a message that can be handled by the server.
     */
    nr_dma_regions = server_max_fds << 1;

    if ((fp = tmpfile()) == NULL) {
        perror("failed to create DMA file");
        return -1;
    }

    if ((ret = ftruncate(fileno(fp), nr_dma_regions * sysconf(_SC_PAGESIZE))) == -1) {
        perror("failed to truncate file");
        return -1;
    }

    dma_regions = alloca(sizeof *dma_regions * nr_dma_regions);
    dma_region_fds = alloca(sizeof *dma_region_fds * nr_dma_regions);

    for (i = 0; i < nr_dma_regions; i++) {
        dma_regions[i].addr = i * sysconf(_SC_PAGESIZE);
        dma_regions[i].size = sysconf(_SC_PAGESIZE);
        dma_regions[i].offset = dma_regions[i].addr;
        dma_regions[i].prot = PROT_READ | PROT_WRITE;
        dma_regions[i].flags = VFIO_USER_F_DMA_REGION_MAPPABLE;
        dma_region_fds[i] = fileno(fp);
    }

    for (i = 0; i < nr_dma_regions / server_max_fds; i++, msg_id++) {
        ret = send_vfio_user_msg(sock, msg_id, false, VFIO_USER_DMA_MAP,
                                 dma_regions + (i * server_max_fds),
                                 sizeof *dma_regions * server_max_fds,
                                 dma_region_fds + (i * server_max_fds),
                                 server_max_fds);
        if (ret < 0) {
            fprintf(stderr, "failed to map DMA regions: %s\n", strerror(-ret));
            return ret;
        }
        ret = recv_vfio_user_msg(sock, &hdr, true, &msg_id, NULL, NULL);
        if (ret < 0) {
            fprintf(stderr,
                    "failed to receive response for mapping DMA regions: %s\n",
                    strerror(-ret));
            return ret;
        }
    }

    /*
     * XXX VFIO_USER_DMA_UNMAP
     *
     * unmap the first group of the DMA regions
     */
    ret = send_vfio_user_msg(sock, msg_id, false, VFIO_USER_DMA_UNMAP,
                             dma_regions, sizeof *dma_regions * server_max_fds,
                             NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to unmap DMA regions: %s\n", strerror(-ret));
        return ret;
    }
    ret = recv_vfio_user_msg(sock, &hdr, true, &msg_id, NULL, NULL);
    if (ret < 0) {
        fprintf(stderr,
                "failed to receive response for unmapping DMA regions: %s\n",
                strerror(-ret));
        return ret;
    }

    msg_id++;

    /* XXX VFIO_USER_DEVICE_GET_IRQ_INFO */
    for (i = 0; i < LM_DEV_NUM_IRQS; i++) {
        struct vfio_irq_info irq_info = {.argsz = sizeof irq_info, .index = i};
        int size;
        ret = send_vfio_user_msg(sock, msg_id, false,
                             VFIO_USER_DEVICE_GET_IRQ_INFO,
                             &irq_info, sizeof irq_info, NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "failed to request %s info: %s\n", irq_to_str[i],
                    strerror(-ret));
            return ret;
        }
        size = sizeof irq_info;
        ret = recv_vfio_user_msg(sock, &hdr, true, &msg_id, &irq_info, &size);
        if (ret < 0) {
            fprintf(stderr, "failed to receive %s info: %s\n", irq_to_str[i],
                    strerror(-ret));
            return ret;
        }
        if (irq_info.count > 0) {
            printf("IRQ %s: count=%d flags=%#x\n",
                   irq_to_str[i], irq_info.count, irq_info.flags);
        }
    }

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
