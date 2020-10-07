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
#include <sys/eventfd.h>
#include <time.h>
#include <err.h>

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
send_device_reset(int sock)
{
    int ret, msg_id = 1;

    return send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DEVICE_RESET,
                                  NULL, 0, NULL, 0, NULL, NULL, 0);
}

static int
get_device_region_info(int sock, struct vfio_device_info *client_dev_info)
{
    struct vfio_region_info region_info;
    struct vfio_region_info_cap_sparse_mmap *sparse;
    struct vfio_user_header hdr;
    uint16_t msg_id = 0;
    size_t cap_sz;
    int regsz = sizeof(region_info);
    int i, ret;

    msg_id = 1;
    for (i = 0; i < client_dev_info->num_regions; i++) {
        memset(&region_info, 0, sizeof(region_info));
        region_info.argsz = sizeof(region_info);
        region_info.index = i;
        msg_id++;
        ret = send_recv_vfio_user_msg(sock, msg_id,
                                      VFIO_USER_DEVICE_GET_REGION_INFO,
                                      &region_info, regsz, NULL, 0, NULL,
                                      &region_info, regsz);
        if (ret < 0) {
            fprintf(stderr, "failed to get device region info: %s\n",
                    strerror(-ret));
            return ret;
        }

	    cap_sz = region_info.argsz - sizeof(struct vfio_region_info);
        fprintf(stdout, "%s: region_info[%d] offset %#lx flags %#x size %llu "
                "cap_sz %d\n", __func__, i, region_info.offset,
                region_info.flags, region_info.size, cap_sz);
	    if (cap_sz) {
            int j;

            sparse = calloc(cap_sz, 1);
            if (sparse == NULL) {
                return -ENOMEM;
            }

            ret = recv(sock, sparse, cap_sz, 0);
            if (ret < 0) {
                ret = -errno;
		        fprintf(stderr, "%s: failed to receive sparse cap info: %s\n",
                        __func__, strerror(-ret));
                free(sparse);
                return ret;
            }
            fprintf(stdout, "%s: Sparse cap nr_mmap_areas %d\n", __func__,
                    sparse->nr_areas);
            for (j = 0; j < sparse->nr_areas; j++) {
                fprintf(stdout, "%s: area %d offset %#lx size %llu\n", __func__,
                        j, sparse->areas[j].offset, sparse->areas[j].size);
            }
            free(sparse);
	    }
    }
}

static int get_device_info(int sock, struct vfio_device_info *dev_info)
{
    struct vfio_user_header hdr;
    int dev_info_sz = sizeof(*dev_info);
    uint16_t msg_id;
    int ret;

    dev_info->argsz = dev_info_sz;
    msg_id = 1;
    ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DEVICE_GET_INFO,
                                  dev_info, dev_info_sz, NULL, 0, NULL,
                                  dev_info, dev_info_sz);
    if (ret < 0) {
        fprintf(stderr, "failed to get device info: %s\n", strerror(-ret));
        return ret;
    }

    printf("devinfo: flags %#x, num_regions %d, num_irqs %d\n",
           dev_info->flags, dev_info->num_regions, dev_info->num_irqs);
    return 0;
}

static int
configure_irqs(int sock)
{
    int i, size;
    int ret;
    struct vfio_irq_set irq_set;
    struct vfio_user_irq_info irq_info;
    struct vfio_user_header hdr;
    uint16_t msg_id = 1;
    int irq_fd;
    uint64_t val;

    for (i = 0; i < LM_DEV_NUM_IRQS; i++) {
        struct vfio_irq_info irq_info = {.argsz = sizeof irq_info, .index = i};
        int size;
        ret = send_recv_vfio_user_msg(sock, msg_id,
                                      VFIO_USER_DEVICE_GET_IRQ_INFO,
                                      &irq_info, sizeof irq_info, NULL, 0, NULL,
                                      &irq_info, sizeof irq_info);
        if (ret < 0) {
            fprintf(stderr, "failed to get  %s info: %s\n", irq_to_str[i],
                    strerror(-ret));
            return ret;
        }
        if (irq_info.count > 0) {
            printf("IRQ %s: count=%d flags=%#x\n",
                   irq_to_str[i], irq_info.count, irq_info.flags);
        }
    }

    msg_id++;

    irq_set.argsz = sizeof irq_set;
    irq_set.flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set.index = 0;
    irq_set.start = 0;
    irq_set.count = 1;
    irq_fd = eventfd(0, 0);
    if (irq_fd == -1) {
        perror("failed to create eventfd");
        return -1;
    }
    ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DEVICE_SET_IRQS,
                                  &irq_set, sizeof irq_set, &irq_fd, 1, NULL,
                                  NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to send configure IRQs message: %s\n",
                strerror(-ret));
        return ret;
    }

    printf("client waiting for server to trigger INTx\n");
    printf("(send SIGUSR1 to the server trigger INTx)\n");

    ret = read(irq_fd, &val, sizeof val);
    if (ret == -1) {
        ret = -errno;
        perror("server failed to trigger IRQ");
        return ret;
    }

    printf("INTx triggered!\n");

    msg_id++;
    size = sizeof(irq_info);
    ret = recv_vfio_user_msg(sock, &hdr, false, &msg_id, &irq_info, &size);
    if (ret < 0) {
        fprintf(stderr, "failed to recieve IRQ message: %s\n", strerror(-ret));
        return ret;
    }
    if (irq_info.subindex >= irq_set.count) {
        fprintf(stderr, "bad IRQ %d, max=%d\n", irq_info.subindex,
                irq_set.count);
        return -ENOENT;
    }

    ret = send_vfio_user_msg(sock, msg_id, true, VFIO_USER_VM_INTERRUPT,
                             NULL, 0, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to send reply for VFIO_USER_VM_INTERRUPT: "
                "%s\n", strerror(-ret));
        return ret;
    }
    printf("INTx messaged triggered!\n");

    return 0;
}

static int
access_bar0(int sock)
{
    struct {
        struct vfio_user_region_access region_access;
        time_t t;
    } __attribute__((packed)) data = {
        .region_access = {
            .region = LM_DEV_BAR0_REG_IDX,
            .count = sizeof(data.t)
        },
        .t = time(NULL)
    };
    uint16_t msg_id = 1;
    int ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_REGION_WRITE,
                                      &data, sizeof data, NULL, 0, NULL, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to write to BAR0: %s\n", strerror(-ret));
        return ret;
    }

    printf("wrote to BAR0: %ld\n", data.t);

    sleep(2);

    msg_id++;

    ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_REGION_READ,
                                  &data.region_access, sizeof data.region_access,
                                  NULL, 0, NULL, &data.t, sizeof data.t);
    if (ret < 0) {
        fprintf(stderr, "failed to read from BAR0: %s\n", strerror(-ret));
        return ret;
    }

    printf("read from BAR0: %ld\n", data.t);

    return 0;
}

static int handle_dma_write(int sock, struct vfio_user_dma_region *dma_regions,
                            int nr_dma_regions, int *dma_region_fds)
{
    struct vfio_user_dma_region_access dma_access;
    struct vfio_user_header hdr;
    int ret, size = sizeof(dma_access), i;
    uint16_t msg_id;
    void *data;

    msg_id = 1;
    ret = recv_vfio_user_msg(sock, &hdr, false, &msg_id, &dma_access, &size);
    if (ret < 0) {
        fprintf(stderr, "failed to recieve DMA read: %m\n");
        return ret;
    }

    data = calloc(dma_access.count, 1);
    if (data == NULL) {
        return -ENOMEM;
    }

    ret = recv(sock, data, dma_access.count, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to recieve DMA read data: %m\n");
        goto out;
    }

    for (i = 0; i < nr_dma_regions; i++) {
        if (dma_regions[i].addr == dma_access.addr) {
            ret = pwrite(dma_region_fds[i], data, dma_access.count,
                         dma_regions[i].offset);
            if (ret < 0) {
                fprintf(stderr, "failed to write data at %#lu: %m\n",
                        dma_regions[i].offset);
                goto out;
            }
            break;
	    }
    }

    dma_access.count = 0;
    ret = send_vfio_user_msg(sock, msg_id, true, VFIO_USER_DMA_WRITE,
                             &dma_access, sizeof(dma_access), NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to send reply of DMA write: %m\n");
    }

out:
    free(data);
    return ret;
}

static int handle_dma_read(int sock, struct vfio_user_dma_region *dma_regions,
                            int nr_dma_regions, int *dma_region_fds)
{
    struct vfio_user_dma_region_access dma_access, *response;
    struct vfio_user_header hdr;
    int ret, size = sizeof(dma_access), i, response_sz;
    uint16_t msg_id;
    void *data;

    msg_id = 1;
    ret = recv_vfio_user_msg(sock, &hdr, false, &msg_id, &dma_access, &size);
    if (ret < 0) {
        fprintf(stderr, "failed to recieve DMA read: %m\n");
        return ret;
    }

    response_sz = sizeof(dma_access) + dma_access.count;
    response = calloc(response_sz, 1);
    if (response == NULL) {
        return -ENOMEM;
    }
    response->count = dma_access.count;
    data = (char *)response->data;

    for (i = 0; i < nr_dma_regions; i++) {
        if (dma_regions[i].addr == dma_access.addr) {
            ret = pread(dma_region_fds[i], data, dma_access.count,
                         dma_regions[i].offset);
            if (ret < 0) {
                fprintf(stderr, "failed to write data at %#lu: %m\n",
                        dma_regions[i].offset);
                goto out;
            }
            break;
	    }
    }

    ret = send_vfio_user_msg(sock, msg_id, true, VFIO_USER_DMA_READ,
                             response, response_sz, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to send reply of DMA write: %m\n");
    }

out:
    free(response);
    return ret;
}

static int handle_dma_io(int sock, struct vfio_user_dma_region *dma_regions,
                     int nr_dma_regions, int *dma_region_fds)
{
    int ret;

    ret = handle_dma_write(sock, dma_regions, nr_dma_regions, dma_region_fds);
    if (ret < 0) {
        fprintf(stderr, "failed to handle DMA write data: %m\n");
        return ret;
    }

    ret = handle_dma_read(sock, dma_regions, nr_dma_regions, dma_region_fds);
    if (ret < 0) {
        fprintf(stderr, "failed to handle DMA read data: %m\n");
        return ret;
    }

    return 0;
}

int main(int argc, char *argv[])
{
	int ret, sock;
    struct vfio_user_dma_region *dma_regions;
    struct vfio_device_info client_dev_info = {0};
    int *dma_region_fds;
    uint16_t msg_id = 1;
    int i;
    FILE *fp;
    int fd;
    const int client_max_fds = 32;
    int server_max_fds;
    int nr_dma_regions;

    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/socket\n", argv[0]);
        exit(EXIT_FAILURE);
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
    ret = get_device_info(sock, &client_dev_info);
    if (ret < 0) {
        return ret;
    }

    /* XXX VFIO_USER_DEVICE_GET_REGION_INFO */
    ret = get_device_region_info(sock, &client_dev_info);
    if (ret < 0) {
        return ret;
    }

    /* XXX VFIO_USER_DEVICE_RESET */
    ret = send_device_reset(sock);
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
        err(EXIT_FAILURE, "failed to create DMA file");
    }

    if ((ret = ftruncate(fileno(fp), nr_dma_regions * sysconf(_SC_PAGESIZE))) == -1) {
        err(EXIT_FAILURE,"failed to truncate file");
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
        ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DMA_MAP,
                                 dma_regions + (i * server_max_fds),
                                 sizeof *dma_regions * server_max_fds,
                                 dma_region_fds + (i * server_max_fds),
                                 server_max_fds, NULL, NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "failed to map DMA regions: %s\n", strerror(-ret));
            return ret;
        }
    }

    /*
     * XXX VFIO_USER_DEVICE_GET_IRQ_INFO and VFIO_IRQ_SET_ACTION_TRIGGER
     * Query interrupts, configure an eventfd to be associated with INTx, and
     * finally wait for the server to fire the interrupt.
     */
    ret = configure_irqs(sock);
    if (ret < 0) {
        fprintf(stderr, "failed to configure IRQs: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    ret = handle_dma_io(sock, dma_regions, nr_dma_regions, dma_region_fds);
    if (ret < 0) {
        fprintf(stderr, "DMA IO failed: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    /*
     * XXX VFIO_USER_REGION_READ and VFIO_USER_REGION_WRITE
     *
     * BAR0 in the server does not support memory mapping so it must be accessed
     * via explicit messages.
     */
    ret = access_bar0(sock);
    if (ret < 0) {
        fprintf(stderr, "failed to access BAR0: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    /*
     * FIXME now that region read/write works, change the server implementation
     * to trigger an interrupt after N seconds, where N is the value written to
     * BAR0 by the client.
     */

    /* BAR1 can be memory mapped and read directly */
    /* TODO implement the following: write a value in BAR1, a server timer will increase it every second (SIGALARM) */

    /*
     * XXX VFIO_USER_DMA_UNMAP
     *
     * unmap the first group of the DMA regions
     */
    ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DMA_UNMAP,
                                  dma_regions,
                                  sizeof *dma_regions * server_max_fds,
                                  NULL, 0, NULL, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to unmap DMA regions: %s\n", strerror(-ret));
        return ret;
    }

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
