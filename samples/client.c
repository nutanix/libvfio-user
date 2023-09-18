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
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/param.h>
#include <time.h>
#include <err.h>
#include <assert.h>
#include <sys/stat.h>
#include <libgen.h>
#include <pthread.h>
#include <linux/limits.h>

#include "common.h"
#include "libvfio-user.h"
#include "rte_hash_crc.h"
#include "tran_sock.h"

#define CLIENT_MAX_FDS (32)

/* This is low, so we get testing of vfu_sgl_read/write() chunking. */
#define CLIENT_MAX_DATA_XFER_SIZE (1024)


static char const *irq_to_str[] = {
    [VFU_DEV_INTX_IRQ] = "INTx",
    [VFU_DEV_MSI_IRQ] = "MSI",
    [VFU_DEV_MSIX_IRQ] = "MSI-X",
    [VFU_DEV_ERR_IRQ] = "ERR",
    [VFU_DEV_REQ_IRQ] = "REQ"
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct client_dma_region {
/*
 * Our DMA regions are one page in size so we only need one bit to mark them as
 * dirty.
 */
#define CLIENT_DIRTY_PAGE_TRACKING_ENABLED (1 << 0)
#define CLIENT_DIRTY_DMA_REGION (1 << 1)
    uint32_t flags;
    struct vfio_user_dma_map map;
    int fd;
};

void
vfu_log(UNUSED vfu_ctx_t *vfu_ctx, UNUSED int level,
        const char *fmt, ...)
{
    va_list ap;

    printf("client: ");

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static int
init_sock(const char *path)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    int sock;

    /* TODO path should be defined elsewhere */
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        err(EXIT_FAILURE, "failed to open socket %s", path);
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        err(EXIT_FAILURE, "failed to connect server");
    }
    return sock;
}

static void
send_version(int sock)
{
    struct vfio_user_version cversion;
    struct iovec iovecs[3] = { { 0 } };
    char client_caps[1024];
    int msg_id = 0xbada55;
    int slen;
    int ret;

    slen = snprintf(client_caps, sizeof(client_caps),
        "{"
            "\"capabilities\":{"
                "\"max_msg_fds\":%u,"
                "\"max_data_xfer_size\":%u"
            "}"
         "}", CLIENT_MAX_FDS, CLIENT_MAX_DATA_XFER_SIZE);

    cversion.major = LIB_VFIO_USER_MAJOR;
    cversion.minor = LIB_VFIO_USER_MINOR;

    /* [0] is for the header. */
    iovecs[1].iov_base = &cversion;
    iovecs[1].iov_len = sizeof(cversion);
    iovecs[2].iov_base = client_caps;
    /* Include the NUL. */
    iovecs[2].iov_len = slen + 1;

    ret = tran_sock_send_iovec(sock, msg_id, false, VFIO_USER_VERSION,
                               iovecs, ARRAY_SIZE(iovecs), NULL, 0, 0);

    if (ret < 0) {
        err(EXIT_FAILURE, "failed to send client version message");
    }
}

static void
recv_version(int sock, int *server_max_fds, size_t *server_max_data_xfer_size,
             size_t *pgsize)
{
    struct vfio_user_version *sversion = NULL;
    struct vfio_user_header hdr;
    size_t vlen;
    int ret;

    ret = tran_sock_recv_alloc(sock, &hdr, true, NULL,
                               (void **)&sversion, &vlen);

    if (ret < 0) {
        err(EXIT_FAILURE, "failed to receive version");
    }

    if (hdr.cmd != VFIO_USER_VERSION) {
        errx(EXIT_FAILURE, "msg%hx: invalid cmd %hu (expected %u)",
               hdr.msg_id, hdr.cmd, VFIO_USER_VERSION);
    }

    if (vlen < sizeof(*sversion)) {
        errx(EXIT_FAILURE, "VFIO_USER_VERSION: invalid size %zu", vlen);
    }

    if (sversion->major != LIB_VFIO_USER_MAJOR) {
        errx(EXIT_FAILURE, "unsupported server major %hu (must be %u)",
               sversion->major, LIB_VFIO_USER_MAJOR);
    }

    /*
     * The server is supposed to tell us the minimum agreed version.
     */
    if (sversion->minor > LIB_VFIO_USER_MINOR) {
        errx(EXIT_FAILURE, "unsupported server minor %hu (must be <= %u)",
               sversion->minor, LIB_VFIO_USER_MINOR);
    }

    *server_max_fds = 1;
    *server_max_data_xfer_size = VFIO_USER_DEFAULT_MAX_DATA_XFER_SIZE;
    *pgsize = sysconf(_SC_PAGESIZE);

    if (vlen > sizeof(*sversion)) {
        const char *json_str = (const char *)sversion->data;
        size_t len = vlen - sizeof(*sversion);

        if (json_str[len - 1] != '\0') {
            errx(EXIT_FAILURE, "ignoring invalid JSON from server");
        }

        ret = tran_parse_version_json(json_str, server_max_fds,
                                      server_max_data_xfer_size, pgsize, NULL);

        if (ret < 0) {
            err(EXIT_FAILURE, "failed to parse server JSON \"%s\"", json_str);
        }
    }

    free(sversion);
}

static void
negotiate(int sock, int *server_max_fds, size_t *server_max_data_xfer_size,
          size_t *pgsize)
{
    send_version(sock);
    recv_version(sock, server_max_fds, server_max_data_xfer_size, pgsize);
}

static void
send_device_reset(int sock)
{
    int ret = tran_sock_msg(sock, 1, VFIO_USER_DEVICE_RESET,
                            NULL, 0, NULL, NULL, 0);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to reset device");
    }
}

static void
get_region_vfio_caps(struct vfio_info_cap_header *header,
                     struct vfio_region_info_cap_sparse_mmap **sparse)
{
    unsigned int i;

    while (true) {
        switch (header->id) {
            case VFIO_REGION_INFO_CAP_SPARSE_MMAP:
                *sparse = (struct vfio_region_info_cap_sparse_mmap *)header;
                printf("client: %s: Sparse cap nr_mmap_areas %d\n", __func__,
                       (*sparse)->nr_areas);
                for (i = 0; i < (*sparse)->nr_areas; i++) {
                    printf("client: %s: area %d offset %#llx size %llu\n",
                           __func__, i,
			               (ull_t)(*sparse)->areas[i].offset,
                           (ull_t)(*sparse)->areas[i].size);
                }
                break;
            default:
                errx(EXIT_FAILURE, "bad VFIO cap ID %#x", header->id);
        }
        if (header->next == 0) {
            break;
        }
        header = (struct vfio_info_cap_header*)((char*)header + header->next - sizeof(struct vfio_region_info));
    }
}

static void
do_get_device_region_info(int sock, struct vfio_region_info *region_info,
                          int *fds, size_t *nr_fds)
{
    int ret = tran_sock_msg_fds(sock, 0xabcd, VFIO_USER_DEVICE_GET_REGION_INFO,
                                region_info, region_info->argsz, NULL,
                                region_info, region_info->argsz, fds, nr_fds);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to get device region info");
    }
}

static void
mmap_sparse_areas(int fd, struct vfio_region_info *region_info,
                  struct vfio_region_info_cap_sparse_mmap *sparse)
{
    size_t i;

    for (i = 0; i < sparse->nr_areas; i++) {

        ssize_t ret;
        void *addr;
        char pathname[PATH_MAX];
        char buf[PATH_MAX] = "";

        ret = snprintf(pathname, sizeof(pathname), "/proc/self/fd/%d", fd);
        assert(ret != -1 && (size_t)ret < sizeof(pathname));
        ret = readlink(pathname, buf, sizeof(buf) - 1);
        if (ret == -1) {
            err(EXIT_FAILURE, "failed to resolve file descriptor %d", fd);
        }
        addr = mmap(NULL, sparse->areas[i].size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, region_info->offset +
                    sparse->areas[i].offset);
        if (addr == MAP_FAILED) {
            err(EXIT_FAILURE,
                "failed to mmap sparse region %zu in %s (%#llx-%#llx)",
                i, buf, (ull_t)sparse->areas[i].offset,
                (ull_t)sparse->areas[i].offset + sparse->areas[i].size - 1);
        }

        ret = munmap(addr, sparse->areas[i].size);
        assert(ret == 0);
    }
}

static void
get_device_region_info(int sock, uint32_t index)
{
    struct vfio_region_info *region_info;
    size_t cap_sz;
    size_t size = sizeof(struct vfio_region_info);
    int fds[CLIENT_MAX_FDS] = { 0 };
    size_t nr_fds = ARRAY_SIZE(fds);


    region_info = malloc(size);
    if (region_info == NULL) {
        err(EXIT_FAILURE, "%m\n");
    }

    memset(region_info, 0, size);
    region_info->argsz = size;
    region_info->index = index;

    do_get_device_region_info(sock, region_info, NULL, 0);
    if (region_info->argsz > size) {
        size = region_info->argsz;
        region_info = malloc(size);
        if (region_info == NULL) {
            err(EXIT_FAILURE, "%m\n");
        }
        memset(region_info, 0, size);
        region_info->argsz = size;
        region_info->index = index;
        do_get_device_region_info(sock, region_info, fds, &nr_fds);
        assert(region_info->argsz == size);
    } else {
        nr_fds = 0;
    }

    cap_sz = region_info->argsz - sizeof(struct vfio_region_info);
    printf("client: %s: region_info[%d] offset %#llx flags %#x "
           "size %llu cap_sz %zu #FDs %zu\n", __func__, index,
           (ull_t)region_info->offset, region_info->flags,
           (ull_t)region_info->size, cap_sz,
           nr_fds);
    if (cap_sz) {
        struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
        get_region_vfio_caps((struct vfio_info_cap_header*)(region_info + 1),
                             &sparse);

        if (sparse != NULL) {
            assert(index == VFU_PCI_DEV_BAR1_REGION_IDX && nr_fds == 1);
            mmap_sparse_areas(fds[0], region_info, sparse);
        } else {
            assert(index != VFU_PCI_DEV_BAR1_REGION_IDX);
        }
    }
    free(region_info);
}

static void
get_device_regions_info(int sock, struct vfio_user_device_info *client_dev_info)
{
    unsigned int i;

    for (i = 0; i < client_dev_info->num_regions; i++) {
        get_device_region_info(sock, i);
    }
}

static void
get_device_info(int sock, struct vfio_user_device_info *dev_info)
{
    uint16_t msg_id = 0xb10c;
    int ret;

    dev_info->argsz = sizeof(*dev_info);

    ret = tran_sock_msg(sock, msg_id,
                        VFIO_USER_DEVICE_GET_INFO,
                        dev_info, sizeof(*dev_info),
                        NULL,
                        dev_info, sizeof(*dev_info));

    if (ret < 0) {
        err(EXIT_FAILURE, "failed to get device info");
    }

    if (dev_info->num_regions != 9) {
        errx(EXIT_FAILURE, "bad number of device regions %d",
             dev_info->num_regions);
    }

    printf("client: devinfo: flags %#x, num_regions %d, num_irqs %d\n",
           dev_info->flags, dev_info->num_regions, dev_info->num_irqs);
}

static int
configure_irqs(int sock)
{
    struct iovec iovecs[2] = { { 0, } };
    struct vfio_irq_set irq_set;
    uint16_t msg_id = 0x1bad;
    int irq_fd;
    int i, ret;

    for (i = 0; i < VFU_DEV_NUM_IRQS; i++) { /* TODO move body of loop into function */
        struct vfio_irq_info vfio_irq_info = {
            .argsz = sizeof(vfio_irq_info),
            .index = i
        };
        ret = tran_sock_msg(sock, msg_id,
                            VFIO_USER_DEVICE_GET_IRQ_INFO,
                            &vfio_irq_info, sizeof(vfio_irq_info),
                            NULL,
                            &vfio_irq_info, sizeof(vfio_irq_info));
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to get %s info", irq_to_str[i]);
        }
        if (vfio_irq_info.count > 0) {
            printf("client: IRQ %s: count=%d flags=%#x\n",
                   irq_to_str[i], vfio_irq_info.count, vfio_irq_info.flags);
        }
    }

    msg_id++;

    irq_set.argsz = sizeof(irq_set);
    irq_set.flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set.index = 0;
    irq_set.start = 0;
    irq_set.count = 1;
    irq_fd = eventfd(0, 0);
    if (irq_fd == -1) {
        err(EXIT_FAILURE, "failed to create eventfd");
    }

    /* [0] is for the header. */
    iovecs[1].iov_base = &irq_set;
    iovecs[1].iov_len = sizeof(irq_set);

    ret = tran_sock_msg_iovec(sock, msg_id, VFIO_USER_DEVICE_SET_IRQS,
                              iovecs, ARRAY_SIZE(iovecs),
                              &irq_fd, 1,
                              NULL, NULL, 0, NULL, 0);

    if (ret < 0) {
        err(EXIT_FAILURE, "failed to send configure IRQs message");
    }

    return irq_fd;
}

static int
access_region(int sock, int region, bool is_write, uint64_t offset,
            void *data, size_t data_len)
{
    static int msg_id = 0xf00f;
    struct vfio_user_region_access send_region_access = {
        .offset = offset,
        .region = region,
        .count = data_len
    };
    struct iovec send_iovecs[3] = {
        [1] = {
            .iov_base = &send_region_access,
            .iov_len = sizeof(send_region_access)
        },
        [2] = {
            .iov_base = data,
            .iov_len = data_len
        }
    };
    struct vfio_user_region_access *recv_data;
    size_t nr_send_iovecs, recv_data_len;
    int op, ret;

    if (is_write) {
        op = VFIO_USER_REGION_WRITE;
        nr_send_iovecs = 3;
        recv_data_len = sizeof(*recv_data);
    } else {
        op = VFIO_USER_REGION_READ;
        nr_send_iovecs = 2;
        recv_data_len = sizeof(*recv_data) + data_len;
    }

    recv_data = calloc(1, recv_data_len);

    if (recv_data == NULL) {
        err(EXIT_FAILURE, "failed to alloc recv_data");
    }

    pthread_mutex_lock(&mutex);
    ret = tran_sock_msg_iovec(sock, msg_id--, op,
                              send_iovecs, nr_send_iovecs,
                              NULL, 0, NULL,
                              recv_data, recv_data_len, NULL, 0);
    pthread_mutex_unlock(&mutex);
    if (ret != 0) {
        warn("failed to %s region %d %#llx-%#llx",
             is_write ? "write to" : "read from", region,
             (ull_t)offset,
             (ull_t)(offset + data_len - 1));
        free(recv_data);
        return ret;
    }
    if (recv_data->count != data_len) {
        warnx("bad %s data count, expected=%zu, actual=%d",
             is_write ? "write" : "read", data_len,
             recv_data->count);
        free(recv_data);
        errno = EINVAL;
        return -1;
    }

    /*
     * TODO we could avoid the memcpy if tran_sock_msg_iovec() received the
     * response into an iovec, but it's some work to implement it.
     */
    if (!is_write) {
        memcpy(data, ((char *)recv_data) + sizeof(*recv_data), data_len);
    }
    free(recv_data);
    return 0;
}

static int
set_migration_state(int sock, uint32_t state)
{
    static int msg_id = 0xfab1;
    struct vfio_user_device_feature req = {
        .argsz = sizeof(struct vfio_user_device_feature)
                 + sizeof(struct vfio_user_device_feature_mig_state),
        .flags = VFIO_DEVICE_FEATURE_SET | VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE
    };
    struct vfio_user_device_feature_mig_state change_state = {
        .device_state = state,
        .data_fd = -1
    };
    struct iovec send_iovecs[3] = {
        [1] = {
            .iov_base = &req,
            .iov_len = sizeof(req)
        },
        [2] = {
            .iov_base = &change_state,
            .iov_len = sizeof(change_state)
        }
    };
    void *response = alloca(sizeof(req) + sizeof(change_state));

    if (response == NULL) {
        return -1;
    }
    
    pthread_mutex_lock(&mutex);
    int ret = tran_sock_msg_iovec(sock, msg_id--, VFIO_USER_DEVICE_FEATURE,
                                  send_iovecs, 3, NULL, 0, NULL,
                                  response, sizeof(req) + sizeof(change_state),
                                  NULL, 0);
    pthread_mutex_unlock(&mutex);

    if (ret < 0) {
        err(EXIT_FAILURE, "failed to set state: %d", ret);
    }

    if (memcmp(&req, response, sizeof(req)) != 0) {
        err(EXIT_FAILURE, "invalid response to set_migration_state (header)");
    }

    if (memcmp(&change_state, response + sizeof(req),
               sizeof(change_state)) != 0) {
        err(EXIT_FAILURE, "invalid response to set_migration_state (payload)");
    }

    return ret;
}

static ssize_t
read_migr_data(int sock, void *buf, size_t len)
{
    static int msg_id = 0x6904;
    struct vfio_user_mig_data req = {
        .argsz = sizeof(struct vfio_user_mig_data) + len,
        .size = len
    };
    struct iovec send_iovecs[2] = {
        [1] = {
            .iov_base = &req,
            .iov_len = sizeof(req)
        }
    };
    struct vfio_user_mig_data *res = calloc(1, sizeof(req) + len);

    assert(res != NULL);

    pthread_mutex_lock(&mutex);
    ssize_t ret = tran_sock_msg_iovec(sock, msg_id--, VFIO_USER_MIG_DATA_READ,
                                      send_iovecs, 2, NULL, 0, NULL,
                                      res, sizeof(req) + len, NULL, 0);
    pthread_mutex_unlock(&mutex);

    if (ret < 0) {
        err(EXIT_FAILURE, "failed to read migration data: %ld", ret);
    }

    memcpy(buf, res->data, res->size);

    ssize_t size = res->size;

    free(res);

    return size;
}

static ssize_t
write_migr_data(int sock, void *buf, size_t len)
{
    static int msg_id = 0x2023;
    struct vfio_user_mig_data req = {
        .argsz = sizeof(struct vfio_user_mig_data) + len,
        .size = len
    };
    struct iovec send_iovecs[3] = {
        [1] = {
            .iov_base = &req,
            .iov_len = sizeof(req)
        },
        [2] = {
            .iov_base = buf,
            .iov_len = len
        }
    };

    pthread_mutex_lock(&mutex);
    ssize_t ret = tran_sock_msg_iovec(sock, msg_id--, VFIO_USER_MIG_DATA_WRITE,
                                      send_iovecs, 3, NULL, 0, NULL,
                                      &req, sizeof(req), NULL, 0);
    pthread_mutex_unlock(&mutex);

    return ret;
}

static void
access_bar0(int sock, time_t *t)
{
    int ret;

    assert(t != NULL);

    ret = access_region(sock, VFU_PCI_DEV_BAR0_REGION_IDX, true, 0, t, sizeof(*t));
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to write to BAR0");
    }

    printf("client: wrote to BAR0: %ld\n", *t);

    ret = access_region(sock, VFU_PCI_DEV_BAR0_REGION_IDX, false, 0, t, sizeof(*t));
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to read from BAR0");
    }

    printf("client: read from BAR0: %ld\n", *t);
}

static void
wait_for_irq(int irq_fd)
{
    uint64_t val;

    if (read(irq_fd, &val, sizeof(val)) == -1) {
        err(EXIT_FAILURE, "failed to read from irqfd");
    }
    printf("client: INTx triggered!\n");
}

static void
handle_dma_write(int sock, struct client_dma_region *dma_regions,
                 int nr_dma_regions)
{
    struct vfio_user_dma_region_access dma_access;
    struct vfio_user_header hdr;
    int ret, i;
    size_t size = sizeof(dma_access);
    uint16_t msg_id = 0xcafe;
    void *data;

    ret = tran_sock_recv(sock, &hdr, false, &msg_id, &dma_access, &size);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to receive DMA read");
    }

    data = calloc(dma_access.count, 1);
    if (data == NULL) {
        err(EXIT_FAILURE, NULL);
    }

    if (recv(sock, data, dma_access.count, 0) == -1) {
        err(EXIT_FAILURE, "failed to receive DMA read data");
    }

    for (i = 0; i < nr_dma_regions; i++) {
        off_t offset;
        ssize_t c;

        if (dma_access.addr < dma_regions[i].map.addr ||
            dma_access.addr >= dma_regions[i].map.addr + dma_regions[i].map.size) {
            continue;
        }

        offset = dma_regions[i].map.offset + dma_access.addr;

        c = pwrite(dma_regions[i].fd, data, dma_access.count, offset);

        if (c != (ssize_t)dma_access.count) {
            err(EXIT_FAILURE, "failed to write to fd=%d at [%#llx-%#llx)",
                    dma_regions[i].fd, (ull_t)offset,
                    (ull_t)(offset + dma_access.count));
        }

        /*
         * DMA regions in this example are one page in size so we use one bit
         * to mark the newly-dirtied page as dirty.
         */
        if (dma_regions[i].flags & CLIENT_DIRTY_PAGE_TRACKING_ENABLED) {
            assert(dma_regions[i].map.size == PAGE_SIZE);
            dma_regions[i].flags |= CLIENT_DIRTY_DMA_REGION;
        }

        break;
    }

    assert(i != nr_dma_regions);

    ret = tran_sock_send(sock, msg_id, true, VFIO_USER_DMA_WRITE,
                         &dma_access, sizeof(dma_access));
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to send reply of DMA write");
    }
    free(data);
}

static void
handle_dma_read(int sock, struct client_dma_region *dma_regions,
                int nr_dma_regions)
{
    struct vfio_user_dma_region_access dma_access, *response;
    struct vfio_user_header hdr;
    int ret, i, response_sz;
    size_t size = sizeof(dma_access);
    uint16_t msg_id = 0xcafe;
    void *data;

    ret = tran_sock_recv(sock, &hdr, false, &msg_id, &dma_access, &size);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to receive DMA read");
    }

    response_sz = sizeof(dma_access) + dma_access.count;
    response = calloc(response_sz, 1);
    if (response == NULL) {
        err(EXIT_FAILURE, NULL);
    }
    response->addr = dma_access.addr;
    response->count = dma_access.count;
    data = (char *)response->data;

    for (i = 0; i < nr_dma_regions; i++) {
        off_t offset;
        ssize_t c;

        if (dma_access.addr < dma_regions[i].map.addr ||
            dma_access.addr >= dma_regions[i].map.addr + dma_regions[i].map.size) {
            continue;
        }

        offset = dma_regions[i].map.offset + dma_access.addr;

        c = pread(dma_regions[i].fd, data, dma_access.count, offset);

        if (c != (ssize_t)dma_access.count) {
            err(EXIT_FAILURE, "failed to read from fd=%d at [%#llx-%#llx)",
                    dma_regions[i].fd, (ull_t)offset,
                    (ull_t)offset + dma_access.count);
        }
        break;
    }

    assert(i != nr_dma_regions);

    ret = tran_sock_send(sock, msg_id, true, VFIO_USER_DMA_READ,
                         response, response_sz);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to send reply of DMA read");
    }
    free(response);
}

static void
handle_dma_io(int sock, struct client_dma_region *dma_regions,
              int nr_dma_regions)
{
    size_t i;

    for (i = 0; i < 4096 / CLIENT_MAX_DATA_XFER_SIZE; i++) {
        handle_dma_write(sock, dma_regions, nr_dma_regions);
    }
    for (i = 0; i < 4096 / CLIENT_MAX_DATA_XFER_SIZE; i++) {
        handle_dma_read(sock, dma_regions, nr_dma_regions);
    }
}

static void
get_dirty_bitmap(int sock, struct client_dma_region *dma_region,
                 bool expect_dirty)
{
    struct vfio_user_device_feature *res;
    struct vfio_user_device_feature_dma_logging_report *report;
    char *bitmap;
    int ret;

    uint64_t bitmap_size = get_bitmap_size(dma_region->map.size,
                                           sysconf(_SC_PAGESIZE));

    size_t size = sizeof(*res) + sizeof(*report) + bitmap_size;

    void *data = calloc(1, size);
    assert(data != NULL);

    res = data;
    res->flags = VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT
               | VFIO_DEVICE_FEATURE_GET;
    res->argsz = size;

    report = (struct vfio_user_device_feature_dma_logging_report *)(res + 1);
    report->iova = dma_region->map.addr;
    report->length = dma_region->map.size;
    report->page_size = sysconf(_SC_PAGESIZE);

    bitmap = data + sizeof(*res) + sizeof(*report);

    ret = tran_sock_msg(sock, 0x99, VFIO_USER_DEVICE_FEATURE,
                        data, sizeof(*res) + sizeof(*report),
                        NULL, data, size);
    if (ret != 0) {
        err(EXIT_FAILURE, "failed to get dirty page bitmap");
    }

    char dirtied_by_server = bitmap[0];
    char dirtied_by_client = (dma_region->flags & CLIENT_DIRTY_DMA_REGION) != 0;
    char dirtied = dirtied_by_server | dirtied_by_client;

    if (expect_dirty) {
        assert(dirtied);
    }

    printf("client: %s: %#llx-%#llx\t%#x\n", __func__,
           (ull_t)report->iova,
           (ull_t)(report->iova + report->length - 1), dirtied);

    free(data);
}

static void
usage(char *argv0)
{
    fprintf(stderr, "Usage: %s [-h] [-m src|dst] /path/to/socket\n",
            basename(argv0));
}

/*
 * Normally each time the source client (QEMU) would read migration data from
 * the device it would send them to the destination client. However, since in
 * our sample both the source and the destination client are the same process,
 * we simply accumulate the migration data of each iteration and apply it to
 * the destination server at the end.
 *
 * Performs as many migration loops as @nr_iters or until the device has no
 * more migration data (pending_bytes is zero), which ever comes first. The
 * result of each migration iteration is stored in @migr_iter.  @migr_iter must
 * be at least @nr_iters.
 *
 * @returns the number of iterations performed
 */
static size_t
do_migrate(int sock, size_t nr_iters, size_t max_iter_size,
           struct iovec *migr_iter)
{
    ssize_t ret;
    size_t i = 0;

    for (i = 0; i < nr_iters; i++) {

        migr_iter[i].iov_len = max_iter_size;
        migr_iter[i].iov_base = malloc(migr_iter[i].iov_len);

        if (migr_iter[i].iov_base == NULL) {
            err(EXIT_FAILURE, "failed to allocate migration buffer");
        }

        /* XXX read migration data */
        ret = read_migr_data(sock, migr_iter[i].iov_base, migr_iter[i].iov_len);
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to read migration data");
        }

        migr_iter[i].iov_len = ret;

        // We know we've finished transferring data when we read 0 bytes.
        if (ret == 0) {
            break;
        }
    }
    return i;
}

struct fake_guest_data {
    int sock;
    size_t bar1_size;
    bool done;
    uint32_t *crcp;
};

static void *
fake_guest(void *arg)
{
    struct fake_guest_data *fake_guest_data = arg;
    int ret;
    char buf[fake_guest_data->bar1_size];
    FILE *fp = fopen("/dev/urandom", "r");

    if (fp == NULL) {
        err(EXIT_FAILURE, "failed to open /dev/urandom");
    }

    do {
        ret = fread(buf, fake_guest_data->bar1_size, 1, fp);
        if (ret != 1) {
            errx(EXIT_FAILURE, "short read %d", ret);
        }
        ret = access_region(fake_guest_data->sock, 1, true, 0, buf,
                            fake_guest_data->bar1_size);
        if (ret != 0) {
            err(EXIT_FAILURE, "fake guest failed to write garbage to BAR1");
        }
    } while (!fake_guest_data->done);

    *fake_guest_data->crcp = rte_hash_crc(buf, fake_guest_data->bar1_size, 0);

    return NULL;
}

static size_t
migrate_from(int sock, size_t *nr_iters, struct iovec **migr_iters,
             uint32_t *crcp, size_t bar1_size, size_t max_iter_size)
{
    size_t expected_data;
    uint32_t device_state;
    size_t iters;
    int ret;
    pthread_t thread;
    struct fake_guest_data fake_guest_data = {
        .sock = sock,
        .bar1_size = bar1_size,
        .done = false,
        .crcp = crcp
    };

    ret = pthread_create(&thread, NULL, fake_guest, &fake_guest_data);
    if (ret != 0) {
        errno = ret;
        err(EXIT_FAILURE, "failed to create pthread");
    }

    expected_data = bar1_size;
    *nr_iters = (expected_data + max_iter_size - 1) / max_iter_size;
    assert(*nr_iters == 12);
    *migr_iters = malloc(sizeof(struct iovec) * *nr_iters);
    if (*migr_iters == NULL) {
        err(EXIT_FAILURE, NULL);
    }

    /*
     * XXX set device state to pre-copy. This is technically optional but any
     * VMM that cares about performance needs this.
     */
    device_state = VFIO_USER_DEVICE_STATE_PRE_COPY;
    ret = set_migration_state(sock, device_state);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to write to device state");
    }

    iters = do_migrate(sock, *nr_iters, max_iter_size, *migr_iters);
    assert(iters == *nr_iters);

    printf("client: stopping fake guest thread\n");
    fake_guest_data.done = true;
    __sync_synchronize();
    ret = pthread_join(thread, NULL);
    if (ret != 0) {
        errno = ret;
        err(EXIT_FAILURE, "failed to join fake guest pthread");
    }

    printf("client: setting device state to stop-and-copy\n");

    device_state = VFIO_USER_DEVICE_STATE_STOP_COPY;
    ret = set_migration_state(sock, device_state);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to write to device state");
    }

    expected_data = bar1_size + sizeof(time_t);
    *nr_iters = (expected_data + max_iter_size - 1) / max_iter_size;
    assert(*nr_iters == 13);
    free(*migr_iters);
    *migr_iters = malloc(sizeof(struct iovec) * *nr_iters);
    if (*migr_iters == NULL) {
        err(EXIT_FAILURE, NULL);
    }

    iters = do_migrate(sock, *nr_iters, max_iter_size, *migr_iters);
    assert(iters == *nr_iters);

    /* XXX read device state, migration must have finished now */
    device_state = VFIO_USER_DEVICE_STATE_STOP;
    ret = set_migration_state(sock, device_state);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to write to device state");
    }

    return iters;
}

static int
migrate_to(char *old_sock_path, int *server_max_fds,
           size_t *server_max_data_xfer_size, size_t *pgsize, size_t nr_iters,
           struct iovec *migr_iters, char *path_to_server,
           uint32_t src_crc, size_t bar1_size)
{
    ssize_t ret;
    int sock;
    char *sock_path;
    struct stat sb;
    uint32_t device_state = VFIO_USER_DEVICE_STATE_RESUMING;
    size_t i;
    uint32_t dst_crc;
    char buf[bar1_size];

    assert(old_sock_path != NULL);

    printf("client: starting destination server\n");

    ret = asprintf(&sock_path, "%s_migrated", old_sock_path);
    if (ret == -1) {
        err(EXIT_FAILURE, "failed to asprintf");
    }

    ret = fork();
    if (ret == -1) {
        err(EXIT_FAILURE, "failed to fork");
    }
    if (ret > 0) { /* child (destination server) */
        char *_argv[] = {
            path_to_server,
            (char *)"-v",
            sock_path,
            NULL
        };
        ret = execvp(_argv[0] , _argv);
        if (ret != 0) {
            err(EXIT_FAILURE, "failed to start destination server (%s)",
                              path_to_server);
        }
    }

    /* parent (client) */

    /* wait for the server to come up */
    while (stat(sock_path, &sb) == -1) {
        if (errno != ENOENT) {
            err(EXIT_FAILURE, "failed to stat %s", sock_path);
        }
    }
   if ((sb.st_mode & S_IFMT) != S_IFSOCK) {
       errx(EXIT_FAILURE, "%s: not a socket", sock_path);
   }

    /* connect to the destination server */
    sock = init_sock(sock_path);
    free(sock_path);

    negotiate(sock, server_max_fds, server_max_data_xfer_size, pgsize);

    device_state = VFIO_USER_DEVICE_STATE_RESUMING;
    ret = set_migration_state(sock, device_state);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to set device state to resuming");
    }

    for (i = 0; i < nr_iters; i++) {
        /* XXX write migration data */
        ret = write_migr_data(sock, migr_iters[i].iov_base,
                              migr_iters[i].iov_len);
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to write device migration data");
        }
    }

    /* XXX set device state to stop to finish the transfer */
    device_state = VFIO_USER_DEVICE_STATE_STOP;
    ret = set_migration_state(sock, device_state);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to set device state to stop");
    }

    /* validate contents of BAR1 */

    if (access_region(sock, 1, false, 0, buf, bar1_size) != 0) {
        err(EXIT_FAILURE, "failed to read BAR1");
    }

    dst_crc = rte_hash_crc(buf, bar1_size, 0);

    if (dst_crc != src_crc) {
        fprintf(stderr, "client: CRC mismatch: %u != %u\n", src_crc, dst_crc);
        abort();
    }

    /* XXX set device state to running */
    device_state = VFIO_USER_DEVICE_STATE_RUNNING;
    ret = set_migration_state(sock, device_state);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to set device state to running");
    }

    return sock;
}

static void
map_dma_regions(int sock, struct client_dma_region *dma_regions,
                int nr_dma_regions)
{
    int i, ret;

    for (i = 0; i < nr_dma_regions; i++) {
        struct iovec iovecs[2] = {
            /* [0] is for the header. */
            [1] = {
                .iov_base = &dma_regions[i].map,
                .iov_len = sizeof(struct vfio_user_dma_map)
            }
        };
        ret = tran_sock_msg_iovec(sock, 0x1234 + i, VFIO_USER_DMA_MAP,
                                  iovecs, ARRAY_SIZE(iovecs),
                                  &dma_regions[i].fd, 1,
                                  NULL, NULL, 0, NULL, 0);
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to map DMA regions");
        }
    }
}

int main(int argc, char *argv[])
{
    char template[] = "/tmp/libvfio-user.XXXXXX";
    int ret, sock, irq_fd;
    struct client_dma_region *dma_regions;
    struct vfio_user_device_info client_dev_info = {0};
    int i;
    int tmpfd;
    int server_max_fds;
    size_t server_max_data_xfer_size;
    size_t pgsize;
    int nr_dma_regions;
    int opt;
    time_t t;
    char *path_to_server = NULL;
    vfu_pci_hdr_t config_space;
    struct iovec *migr_iters;
    size_t nr_iters;
    uint32_t crc;
    size_t bar1_size = 0x3000; /* FIXME get this value from region info */

    struct vfio_user_device_feature *dirty_pages_feature;
    struct vfio_user_device_feature_dma_logging_control *dirty_pages_control;
    size_t dirty_pages_size = sizeof(*dirty_pages_feature) +
                               sizeof(*dirty_pages_control);
    void *dirty_pages = malloc(dirty_pages_size);
    dirty_pages_feature = dirty_pages;
    dirty_pages_control = (void *)(dirty_pages_feature + 1);

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    sock = init_sock(argv[optind]);

    /*
     * VFIO_USER_VERSION
     *
     * Do initial negotiation with the server, and discover parameters.
     */
    negotiate(sock, &server_max_fds, &server_max_data_xfer_size, &pgsize);

    /* try to access a bogus region, we should get an error */
    ret = access_region(sock, 0xdeadbeef, false, 0, &ret, sizeof(ret));
    if (ret != -1 || errno != EINVAL) {
        errx(EXIT_FAILURE,
             "expected EINVAL accessing bogus region, got %d instead", errno);
    }

    /* XXX VFIO_USER_DEVICE_GET_INFO */
    get_device_info(sock, &client_dev_info);

    /* VFIO_USER_DEVICE_GET_REGION_INFO */
    get_device_regions_info(sock, &client_dev_info);

    ret = access_region(sock, VFU_PCI_DEV_CFG_REGION_IDX, false, 0, &config_space,
                        sizeof(config_space));
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to read PCI configuration space");
    }

    assert(config_space.id.vid == 0xdead);
    assert(config_space.id.did == 0xbeef);
    assert(config_space.ss.vid == 0xcafe);
    assert(config_space.ss.sid == 0xbabe);

    /* XXX VFIO_USER_DEVICE_RESET */
    send_device_reset(sock);

    /*
     * XXX VFIO_USER_DMA_MAP
     *
     * Tell the server we have some DMA regions it can access.
     */
    nr_dma_regions = server_max_fds << 1;

    umask(0022);

    if ((tmpfd = mkstemp(template)) == -1) {
        err(EXIT_FAILURE, "failed to create backing file");
    }

    if ((ret = ftruncate(tmpfd, nr_dma_regions * sysconf(_SC_PAGESIZE))) == -1) {
        err(EXIT_FAILURE, "failed to truncate file");
    }

    unlink(template);

    dma_regions = calloc(nr_dma_regions, sizeof(*dma_regions));
    if (dma_regions == NULL) {
        err(EXIT_FAILURE, "%m\n");
    }

    for (i = 0; i < nr_dma_regions; i++) {
        dma_regions[i].map.argsz = sizeof(struct vfio_user_dma_map);
        dma_regions[i].map.addr = i * sysconf(_SC_PAGESIZE);
        dma_regions[i].map.size = sysconf(_SC_PAGESIZE);
        dma_regions[i].map.offset = dma_regions[i].map.addr;
        dma_regions[i].map.flags = VFIO_USER_F_DMA_REGION_READ |
                                   VFIO_USER_F_DMA_REGION_WRITE;
        dma_regions[i].fd = tmpfd;
    }

    map_dma_regions(sock, dma_regions, nr_dma_regions);

    /*
     * XXX VFIO_USER_DEVICE_GET_IRQ_INFO and VFIO_IRQ_SET_ACTION_TRIGGER
     * Query interrupts and configure an eventfd to be associated with INTx.
     */
    irq_fd = configure_irqs(sock);

    /* start dirty pages logging */
    dirty_pages_feature->argsz = sizeof(*dirty_pages_feature) +
                                 sizeof(*dirty_pages_control);
    dirty_pages_feature->flags = VFIO_DEVICE_FEATURE_DMA_LOGGING_START |
                                 VFIO_DEVICE_FEATURE_SET;
    dirty_pages_control->num_ranges = 0;
    dirty_pages_control->page_size = sysconf(_SC_PAGESIZE);

    ret = tran_sock_msg(sock, 0, VFIO_USER_DEVICE_FEATURE, dirty_pages,
                        dirty_pages_size, NULL, dirty_pages, dirty_pages_size);
    if (ret != 0) {
        err(EXIT_FAILURE, "failed to start dirty page logging");
    }

    /*
     * Start client-side dirty page tracking (which happens in
     * `handle_dma_write` when writes are successful).
     */
    for (i = 0; i < nr_dma_regions; i++) {
        dma_regions[i].flags |= CLIENT_DIRTY_PAGE_TRACKING_ENABLED;
    }

    /*
     * XXX VFIO_USER_REGION_READ and VFIO_USER_REGION_WRITE
     *
     * BAR0 in the server does not support memory mapping so it must be accessed
     * via explicit messages.
     */
    t = time(NULL) + 1;
    access_bar0(sock, &t);

    wait_for_irq(irq_fd);

    /* FIXME check that above took at least 1s */

    handle_dma_io(sock, dma_regions, nr_dma_regions);

    for (i = 0; i < nr_dma_regions; i++) {
        /*
         * We expect regions 0 and 1 to be dirtied: 0 through messages (so
         * marked by the client) and 1 directly (so marked by the server). See
         * the bottom of the main function of server.c.
         */
        get_dirty_bitmap(sock, &dma_regions[i], i < 2);
    }

    /* stop logging dirty pages */
    dirty_pages_feature->argsz = sizeof(*dirty_pages_feature) +
                                 sizeof(*dirty_pages_control);
    dirty_pages_feature->flags = VFIO_DEVICE_FEATURE_DMA_LOGGING_STOP |
                                 VFIO_DEVICE_FEATURE_SET;
    dirty_pages_control->num_ranges = 0;
    dirty_pages_control->page_size = sysconf(_SC_PAGESIZE);

    ret = tran_sock_msg(sock, 0, VFIO_USER_DEVICE_FEATURE, dirty_pages,
                        dirty_pages_size, NULL, dirty_pages, dirty_pages_size);
    if (ret != 0) {
        err(EXIT_FAILURE, "failed to stop dirty page logging");
    }

    /* Stop client-side dirty page tracking */
    for (i = 0; i < nr_dma_regions; i++) {
        dma_regions[i].flags &= ~CLIENT_DIRTY_PAGE_TRACKING_ENABLED;
    }

    /* BAR1 can be memory mapped and read directly */

    /*
     * XXX VFIO_USER_DMA_UNMAP
     *
     * unmap the first group of the DMA regions
     */
    for (i = 0; i < server_max_fds; i++) {
        struct vfio_user_dma_unmap r = {
            .argsz = sizeof(r),
            .addr = dma_regions[i].map.addr,
            .size = dma_regions[i].map.size
        };
        ret = tran_sock_msg(sock, 7, VFIO_USER_DMA_UNMAP, &r, sizeof(r),
                            NULL, &r, sizeof(r));
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to unmap DMA region");
        }
    }

    /*
     * Schedule an interrupt in 10 seconds from now in the old server and then
     * immediatelly migrate the device. The new server should deliver the
     * interrupt. Hopefully 10 seconds should be enough for migration to finish.
     * TODO make this value a command line option.
     */
    t = time(NULL) + 10;
    ret = access_region(sock, VFU_PCI_DEV_BAR0_REGION_IDX, true, 0, &t, sizeof(t));
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to write to BAR0");
    }

    nr_iters = migrate_from(sock, &nr_iters, &migr_iters, &crc, bar1_size,
        MIN(server_max_data_xfer_size, CLIENT_MAX_DATA_XFER_SIZE));

    /*
     * Normally the client would now send the device state to the destination
     * client and then exit. We don't demonstrate how this works as this is a
     * client implementation detail. Instead, the client starts the destination
     * server and then applies the migration data.
     */
    if (asprintf(&path_to_server, "%s/server", dirname(argv[0])) == -1) {
        err(EXIT_FAILURE, "failed to asprintf");
    }

    sock = migrate_to(argv[optind], &server_max_fds, &server_max_data_xfer_size,
                      &pgsize, nr_iters, migr_iters, path_to_server,
                      crc, bar1_size);
    free(path_to_server);
    for (i = 0; i < (int)nr_iters; i++) {
        free(migr_iters[i].iov_base);
    }
    free(migr_iters);

    /*
     * Now we must reconfigure the destination server.
     */

    /*
     * XXX reconfigure DMA regions, note that the first half of the has been
     * unmapped.
     */
    map_dma_regions(sock, dma_regions + server_max_fds,
                    nr_dma_regions - server_max_fds);

    /*
     * XXX reconfigure IRQs.
     * FIXME is this something the client needs to do? I would expect so since
     * it's the client that creates and provides the FD. Do we need to save some
     * state in the migration data?
     */
    irq_fd = configure_irqs(sock);

    wait_for_irq(irq_fd);

    handle_dma_io(sock, dma_regions + server_max_fds,
                  nr_dma_regions - server_max_fds);

    struct vfio_user_dma_unmap r = {
        .argsz = sizeof(r),
        .addr = 0,
        .size = 0,
        .flags = VFIO_DMA_UNMAP_FLAG_ALL
    };
    ret = tran_sock_msg(sock, 8, VFIO_USER_DMA_UNMAP, &r, sizeof(r),
                        NULL, &r, sizeof(r));
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to unmap all DMA regions");
    }

    free(dma_regions);
    free(dirty_pages);

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
