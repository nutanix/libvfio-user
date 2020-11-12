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
#include <assert.h>
//#include <sys/uio.h>

#include "../lib/muser.h"
#include "../lib/muser_priv.h"
#include "../lib/common.h"

static int
init_sock(const char *path)
{
    int ret, sock;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};

	/* TODO path should be defined elsewhere */
	ret = snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);

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
set_version(int sock, int client_max_fds, int *server_max_fds, size_t *pgsize)
{
    int ret, mj, mn;
    uint16_t msg_id;
    char *client_caps = NULL;

    assert(server_max_fds != NULL);
    assert(pgsize != NULL);

    ret = recv_version(sock, &mj, &mn, &msg_id, false, server_max_fds, pgsize);
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

    ret = asprintf(&client_caps, "{max_fds: %d, migration: {pgsize: %lu}}",
                   client_max_fds, sysconf(_SC_PAGESIZE));
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
    int msg_id = 1;

    return send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DEVICE_RESET,
                                  NULL, 0, NULL, 0, NULL, NULL, 0);
}

static int
get_region_vfio_caps(int sock, size_t cap_sz)
{
    struct vfio_info_cap_header *header, *_header;
    struct vfio_region_info_cap_type *type;
    struct vfio_region_info_cap_sparse_mmap *sparse;
    unsigned int i;
    ssize_t ret;

    header = _header = calloc(cap_sz, 1);
    if (header == NULL) {
        return -ENOMEM;
    }

    ret = recv(sock, header, cap_sz, 0);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to receive VFIO cap info");
    }
    assert((size_t)ret == cap_sz);

    while (true) {
        switch (header->id) {
            case VFIO_REGION_INFO_CAP_SPARSE_MMAP:
                sparse = (struct vfio_region_info_cap_sparse_mmap*)header;
                fprintf(stdout, "%s: Sparse cap nr_mmap_areas %d\n", __func__,
                        sparse->nr_areas);
                for (i = 0; i < sparse->nr_areas; i++) {
                    fprintf(stdout, "%s: area %d offset %#llx size %llu\n", __func__,
                            i, sparse->areas[i].offset, sparse->areas[i].size);
                }
                break;
            case VFIO_REGION_INFO_CAP_TYPE:
                type = (struct vfio_region_info_cap_type*)header;
                if (type->type != VFIO_REGION_TYPE_MIGRATION ||
                    type->subtype != VFIO_REGION_SUBTYPE_MIGRATION) {
                    fprintf(stderr, "bad region type %d/%d\n", type->type,
                            type->subtype);
                    exit(EXIT_FAILURE);
                }
                printf("migration region\n");
                break;
            default:
                fprintf(stderr, "bad VFIO cap ID %#x\n", header->id);
                exit(EXIT_FAILURE);
        }
        if (header->next == 0) {
            break;
        }
        header = (struct vfio_info_cap_header*)((char*)header + header->next - sizeof(struct vfio_region_info));
    }
    free(_header);

    return 0;
}

static int
get_device_region_info(int sock, struct vfio_device_info *client_dev_info)
{
    struct vfio_region_info region_info;
    uint16_t msg_id = 0;
    size_t cap_sz;
    int ret;
    unsigned int i;

    msg_id = 1;
    for (i = 0; i < client_dev_info->num_regions; i++) {
        memset(&region_info, 0, sizeof(region_info));
        region_info.argsz = sizeof(region_info);
        region_info.index = i;
        msg_id++;
        ret = send_recv_vfio_user_msg(sock, msg_id,
                                      VFIO_USER_DEVICE_GET_REGION_INFO,
                                      &region_info, sizeof region_info,
                                      NULL, 0, NULL,
                                      &region_info, sizeof(region_info));
        if (ret < 0) {
            fprintf(stderr, "failed to get device region info: %s\n",
                    strerror(-ret));
            return ret;
        }

	    cap_sz = region_info.argsz - sizeof(struct vfio_region_info);
        fprintf(stdout, "%s: region_info[%d] offset %#llx flags %#x size %llu "
                "cap_sz %lu\n", __func__, i, region_info.offset,
                region_info.flags, region_info.size, cap_sz);
	    if (cap_sz) {
            ret = get_region_vfio_caps(sock, cap_sz);
            if (ret != 0) {
                return ret;
            }
	    }
    }
    return 0;
}

static int get_device_info(int sock, struct vfio_device_info *dev_info)
{
    uint16_t msg_id;
    int ret;

    dev_info->argsz = sizeof(*dev_info);
    msg_id = 1;
    ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DEVICE_GET_INFO,
                                  dev_info, sizeof(*dev_info), NULL, 0, NULL,
                                  dev_info, sizeof(*dev_info));
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
    int i, ret;
    size_t size;
    struct vfio_irq_set irq_set;
    struct vfio_user_irq_info vfio_user_irq_info;
    struct vfio_user_header hdr;
    uint16_t msg_id = 1;
    int irq_fd;
    uint64_t val;

    for (i = 0; i < LM_DEV_NUM_IRQS; i++) { /* TODO move body of loop into function */
        struct vfio_irq_info vfio_irq_info = {
            .argsz = sizeof vfio_irq_info,
            .index = i
        };
        ret = send_recv_vfio_user_msg(sock, msg_id,
                                      VFIO_USER_DEVICE_GET_IRQ_INFO,
                                      &vfio_irq_info, sizeof vfio_irq_info,
                                      NULL, 0, NULL,
                                      &vfio_irq_info, sizeof vfio_irq_info);
        if (ret < 0) {
            fprintf(stderr, "failed to get  %s info: %s\n", irq_to_str[i],
                    strerror(-ret));
            return ret;
        }
        if (vfio_irq_info.count > 0) {
            printf("IRQ %s: count=%d flags=%#x\n",
                   irq_to_str[i], vfio_irq_info.count, vfio_irq_info.flags);
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

    size = sizeof(vfio_user_irq_info);
    ret = recv_vfio_user_msg(sock, &hdr, false, &msg_id, &vfio_user_irq_info,
                             &size);
    if (ret < 0) {
        fprintf(stderr, "failed to receive IRQ message: %s\n", strerror(-ret));
        return ret;
    }
    if (vfio_user_irq_info.subindex >= irq_set.count) {
        fprintf(stderr, "bad IRQ %d, max=%d\n", vfio_user_irq_info.subindex,
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
access_region(int sock, int region, bool is_write, uint64_t offset,
            void *data, size_t data_len)
{
    struct vfio_user_region_access send_region_access = {
        .offset = offset,
        .region = region,
        .count = data_len
    };
    struct iovec send_iovecs[3] = {
        [1] = {
            .iov_base = &send_region_access,
            .iov_len = sizeof send_region_access
        },
        [2] = {
            .iov_base = data,
            .iov_len = data_len
        }
    };
    struct {
        struct vfio_user_region_access region_access;
        char data[data_len];
    } __attribute__((packed)) recv_data;
    int op, ret;
    size_t nr_send_iovecs, recv_data_len;

    if (is_write) {
        op = VFIO_USER_REGION_WRITE;
        nr_send_iovecs = 3;
        recv_data_len = sizeof(recv_data.region_access);
    } else {
        op = VFIO_USER_REGION_READ;
        nr_send_iovecs = 2;
        recv_data_len = sizeof(recv_data);
    }

    ret = _send_recv_vfio_user_msg(sock, 0, op,
                                   send_iovecs, nr_send_iovecs,
                                   NULL, 0, NULL,
                                   &recv_data, recv_data_len);
    if (ret != 0) {
        fprintf(stderr, "failed to %s region %d %#lx-%#lx: %s\n",
                is_write ? "write to" : "read from", region, offset,
                offset + data_len - 1, strerror(-ret));
        return ret;
    }
    if (recv_data.region_access.count != data_len) {
        fprintf(stderr, "bad %s data count, expected=%lu, actual=%d\n",
                is_write ? "write" : "read", data_len,
                recv_data.region_access.count);
        return -EINVAL;
    }

    /*
     * TODO we could avoid the memcpy if _sed_recv_vfio_user_msg received the
     * response into an iovec, but it's some work to implement it.
     */
    if (!is_write) {
        memcpy(data, recv_data.data, data_len);
    }
    return 0;
}

static int
access_bar0(int sock)
{
    time_t t = time(NULL);
    const int sleep_time = 1;
    int ret = access_region(sock, LM_DEV_BAR0_REG_IDX, true, 0, &t, sizeof t);

    if (ret < 0) {
        fprintf(stderr, "failed to write to BAR0: %s\n", strerror(-ret));
        return ret;
    }

    printf("wrote to BAR0: %ld\n", t);

    sleep(sleep_time);

    ret = access_region(sock, LM_DEV_BAR0_REG_IDX, false, 0, &t, sizeof t);
    if (ret < 0) {
        fprintf(stderr, "failed to read from BAR0: %s\n", strerror(-ret));
        return ret;
    }

    printf("read from BAR0: %ld\n", t);

    assert(t >= sleep_time);

    return 0;
}

static int handle_dma_write(int sock, struct vfio_user_dma_region *dma_regions,
                            int nr_dma_regions, int *dma_region_fds)
{
    struct vfio_user_dma_region_access dma_access;
    struct vfio_user_header hdr;
    int ret, i;
    size_t size = sizeof(dma_access);
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
                fprintf(stderr, "failed to write data at %lu: %m\n",
                        dma_regions[i].offset);
                goto out;
            }
            break;
	    }
    }

    dma_access.count = 0;
    ret = send_vfio_user_msg(sock, msg_id, true, VFIO_USER_DMA_WRITE,
                             &dma_access, sizeof dma_access, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to send reply of DMA write: %s\n",
                strerror(-ret));
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
    int ret, i, response_sz;
    size_t size = sizeof(dma_access);
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
                fprintf(stderr, "failed to write data at %lu: %m\n",
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

static int
get_dirty_bitmaps(int sock, struct vfio_user_dma_region *dma_regions,
                  int nr_dma_regions)
{
    struct vfio_iommu_type1_dirty_bitmap dirty_bitmap = {0};
    struct vfio_iommu_type1_dirty_bitmap_get bitmaps[2];
    int ret;
    size_t i;
    struct iovec iovecs[4] = {
        [1] = {
            .iov_base = &dirty_bitmap,
            .iov_len = sizeof dirty_bitmap
        }
    };
    struct vfio_user_header hdr = {0};
    char data[ARRAY_SIZE(bitmaps)];

    assert(dma_regions != NULL);
    assert(nr_dma_regions >= (int)ARRAY_SIZE(bitmaps));

    for (i = 0; i < ARRAY_SIZE(bitmaps); i++) {
        bitmaps[i].iova = dma_regions[i].addr;
        bitmaps[i].size = dma_regions[i].size;
        bitmaps[i].bitmap.size = 1; /* FIXME calculate based on page and IOVA size, don't hardcode */
        bitmaps[i].bitmap.pgsize = sysconf(_SC_PAGESIZE);
        iovecs[(i + 2)].iov_base = &bitmaps[i]; /* FIXME the +2 is because iovecs[0] is the vfio_user_header and iovecs[1] is vfio_iommu_type1_dirty_bitmap */
        iovecs[(i + 2)].iov_len = sizeof(struct vfio_iommu_type1_dirty_bitmap_get);
    }

    /*
     * FIXME there should be at least two IOVAs. Send single message for two
     * IOVAs and ensure only one bit is set in first IOVA.
     */
    dirty_bitmap.flags = VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP;
    ret = _send_recv_vfio_user_msg(sock, 0, VFIO_USER_DIRTY_PAGES,
                                  iovecs, ARRAY_SIZE(iovecs),
                                  NULL, 0,
                                  &hdr, data, ARRAY_SIZE(data));
    if (ret != 0) {
        fprintf(stderr, "failed to start dirty page logging: %s\n",
                strerror(-ret));
        return ret;
    }

    for (i = 0; i < ARRAY_SIZE(bitmaps); i++) {
        printf("%#llx-%#llx\t%hhu\n", bitmaps[i].iova,
               bitmaps[i].iova + bitmaps[i].size - 1, data[i]);
    }
    return 0;
}

enum migration {
    NO_MIGRATION,
    MIGRATION_SOURCE,
    MIGRATION_DESTINATION,
};

static void
usage(char *path) {
    fprintf(stderr, "Usage: %s [-h] [-m src|dst] /path/to/socket\n",
            basename(path));
}

static int
migrate_from(int sock)
{
    __u32 device_state = VFIO_DEVICE_STATE_SAVING;
    __u64 pending_bytes, data_offset, data_size;
    void *data;

    /* XXX set device state to stop-and-copy */
    int ret = access_region(sock, LM_DEV_MIGRATION_REG_IDX, true,
                            offsetof(struct vfio_device_migration_info, device_state),
                            &device_state, sizeof(device_state));
    if (ret < 0) {
        fprintf(stderr, "failed to write to device state: %s\n",
                strerror(-ret));
        return ret;
    }

    /* XXX read pending_bytes */
    ret = access_region(sock, LM_DEV_MIGRATION_REG_IDX, false,
                        offsetof(struct vfio_device_migration_info, pending_bytes),
                        &pending_bytes, sizeof pending_bytes);
    if (ret < 0) {
        fprintf(stderr, "failed to read pending_bytes: %s\n", strerror(-ret));
        return ret;
    }

    while (pending_bytes > 0) {

        /* XXX read data_offset and data_size */
        ret = access_region(sock, LM_DEV_MIGRATION_REG_IDX, false,
                            offsetof(struct vfio_device_migration_info, data_offset),
                            &data_offset, sizeof data_offset);
        if (ret < 0) {
            fprintf(stderr, "failed to read data_offset: %s\n", strerror(-ret));
            return ret;
        }

        ret = access_region(sock, LM_DEV_MIGRATION_REG_IDX, false,
                            offsetof(struct vfio_device_migration_info, data_size),
                            &data_size, sizeof data_size);
        if (ret < 0) {
            fprintf(stderr, "failed to read data_size: %s\n", strerror(-ret));
            return ret;
        }

        /* XXX read migration data */
        data = malloc(data_size);
        if (data == NULL) {
            return -errno;
        }
        ret = access_region(sock, LM_DEV_MIGRATION_REG_IDX, false, data_offset,
                            data, data_size);
        if (ret < 0) {
            fprintf(stderr, "failed to read migration data: %s\n",
                    strerror(-ret));
        }

        /* FIXME send migration data to the destination client process */
        printf("XXX migration: %#llx bytes worth of data\n", data_size);

        /*
         * XXX read pending_bytes again to indicate to the sever that the
         * migration data have been consumed.
         */
        ret = access_region(sock, LM_DEV_MIGRATION_REG_IDX, false,
                            offsetof(struct vfio_device_migration_info, pending_bytes),
                            &pending_bytes, sizeof pending_bytes);
        if (ret < 0) {
            fprintf(stderr, "failed to read pending_bytes: %s\n", strerror(-ret));
            return ret;
        }
    }

    /* XXX read device state, migration must have finished now */
    device_state = VFIO_DEVICE_STATE_STOP;
    ret = access_region(sock, LM_DEV_MIGRATION_REG_IDX, true,
                        offsetof(struct vfio_device_migration_info, device_state),
                        &device_state, sizeof(device_state));
    if (ret < 0) {
        fprintf(stderr, "failed to write to device state: %s\n",
                strerror(-ret));
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
    const int client_max_fds = 32;
    int server_max_fds;
    size_t pgsize;
    int nr_dma_regions;
    struct vfio_iommu_type1_dirty_bitmap dirty_bitmap = {0};
    int opt;
    enum migration migration = NO_MIGRATION;

    while ((opt = getopt(argc, argv, "hm:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'm':
                if (strcmp(optarg, "src") == 0) {
                    migration = MIGRATION_SOURCE;
                } else if (strcmp(optarg, "dst") == 0) {
                    migration = MIGRATION_DESTINATION;
                } else {
                    fprintf(stderr, "invalid migration argument %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((sock = init_sock(argv[optind])) < 0) {
        return sock;
    }

    /*
     * XXX VFIO_USER_VERSION
     *
     * The server proposes version upon connection, we need to send back the
     * version the version we support.
     */
    if ((ret = set_version(sock, client_max_fds, &server_max_fds, &pgsize)) < 0) {
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
     * Tell the server we have some DMA regions it can access. Each DMA region
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
                                      sizeof(*dma_regions) * server_max_fds,
                                      dma_region_fds + (i * server_max_fds),
                                      server_max_fds, NULL, NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "failed to map DMA regions: %s\n", strerror(-ret));
            return ret;
        }
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


    dirty_bitmap.flags = VFIO_IOMMU_DIRTY_PAGES_FLAG_START;
    ret = send_recv_vfio_user_msg(sock, 0, VFIO_USER_DIRTY_PAGES,
                                  &dirty_bitmap, sizeof dirty_bitmap,
                                  NULL, 0, NULL, NULL, 0);
    if (ret != 0) {
        fprintf(stderr, "failed to start dirty page logging: %s\n",
                strerror(-ret));
        exit(EXIT_FAILURE);
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

    ret = get_dirty_bitmaps(sock, dma_regions, nr_dma_regions);
    if (ret < 0) {
        fprintf(stderr, "failed to receive dirty bitmaps: %s\n",
                strerror(-ret));
        exit(EXIT_FAILURE);
    }

    dirty_bitmap.flags = VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP;
    ret = send_recv_vfio_user_msg(sock, 0, VFIO_USER_DIRTY_PAGES,
                                  &dirty_bitmap, sizeof dirty_bitmap,
                                  NULL, 0, NULL, NULL, 0);
    if (ret != 0) {
        fprintf(stderr, "failed to stop dirty page logging: %s\n",
                strerror(-ret));
        exit(EXIT_FAILURE);
    }

    /*
     * FIXME now that region read/write works, change the server implementation
     * to trigger an interrupt after N seconds, where N is the value written to
     * BAR0 by the client.
     */

    /* BAR1 can be memory mapped and read directly */

    /*
     * TODO implement the following: write a value in BAR1, a server timer will
     * increase it every second (SIGALARM)
     */

    /*
     * XXX VFIO_USER_DMA_UNMAP
     *
     * unmap the first group of the DMA regions
     */
    ret = send_recv_vfio_user_msg(sock, msg_id, VFIO_USER_DMA_UNMAP,
                                  dma_regions, sizeof *dma_regions * server_max_fds,
                                  NULL, 0, NULL, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "failed to unmap DMA regions: %s\n", strerror(-ret));
        return ret;
    }

    if (migration == MIGRATION_SOURCE) {
       ret = migrate_from(sock);
    }

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
