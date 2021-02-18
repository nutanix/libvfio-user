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
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <time.h>
#include <err.h>
#include <assert.h>
#include <sys/stat.h>
#include <libgen.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <linux/limits.h>

#include "common.h"
#include "libvfio-user.h"
#include "tran_sock.h"

#define CLIENT_MAX_FDS (32)

static char *irq_to_str[] = {
    [VFU_DEV_INTX_IRQ] = "INTx",
    [VFU_DEV_MSI_IRQ] = "MSI",
    [VFU_DEV_MSIX_IRQ] = "MSI-X",
    [VFU_DEV_ERR_IRQ] = "ERR",
    [VFU_DEV_REQ_IRQ] = "REQ"
};

void
vfu_log(UNUSED vfu_ctx_t *vfu_ctx, UNUSED int level,
        const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static int
init_sock(const char *path)
{
    int ret, sock;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};

	/* TODO path should be defined elsewhere */
	ret = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		err(EXIT_FAILURE, "failed to open socket %s", path);
	}

	if ((ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr))) == -1) {
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
                "\"max_fds\":%u,"
                "\"migration\":{"
                    "\"pgsize\":%zu"
                "}"
            "}"
         "}", CLIENT_MAX_FDS, sysconf(_SC_PAGESIZE));

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
recv_version(int sock, int *server_max_fds, size_t *pgsize)
{
    struct vfio_user_version *sversion = NULL;
    struct vfio_user_header hdr;
    size_t vlen;
    int ret;

    ret = tran_sock_recv_alloc(sock, &hdr, true, NULL,
                               (void **)&sversion, &vlen);

    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to receive version: %s", strerror(-ret));
    }

// FIXME: are we out of spec? reply cmd's are zero
#if 0
    if (hdr.cmd != VFIO_USER_VERSION) {
        errx(EXIT_FAILURE, "msg%hx: invalid cmd %hu (expected %hu)",
               msg_id, hdr.cmd, VFIO_USER_VERSION);
    }
#endif

    if (vlen < sizeof(*sversion)) {
        errx(EXIT_FAILURE, "VFIO_USER_VERSION: invalid size %lu", vlen);
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
    *pgsize = sysconf(_SC_PAGESIZE);

    if (vlen > sizeof(*sversion)) {
        const char *json_str = (const char *)sversion->data;
        size_t len = vlen - sizeof(*sversion);

        if (json_str[len - 1] != '\0') {
            errx(EXIT_FAILURE, "ignoring invalid JSON from server");
        }

        ret = tran_parse_version_json(json_str, server_max_fds, pgsize);

        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to parse server JSON \"%s\"", json_str);
        }
    }

    free(sversion);
}

static void
negotiate(int sock, int *server_max_fds, size_t *pgsize)
{
    send_version(sock);
    recv_version(sock, server_max_fds, pgsize);
}

static void
send_device_reset(int sock)
{
    int ret = tran_sock_msg(sock, 1, VFIO_USER_DEVICE_RESET,
                            NULL, 0, NULL, NULL, 0);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to reset device: %s\n", strerror(-ret));
    }
}

/* returns whether a VFIO migration capability is found */
static bool
get_region_vfio_caps(struct vfio_info_cap_header *header,
                     struct vfio_region_info_cap_sparse_mmap **sparse)
{
    struct vfio_region_info_cap_type *type;
    unsigned int i;
    bool migr = false;

    while (true) {
        switch (header->id) {
            case VFIO_REGION_INFO_CAP_SPARSE_MMAP:
                *sparse = (struct vfio_region_info_cap_sparse_mmap *)header;
                printf("%s: Sparse cap nr_mmap_areas %d\n", __func__,
                       (*sparse)->nr_areas);
                for (i = 0; i < (*sparse)->nr_areas; i++) {
                    printf("%s: area %d offset %#llx size %llu\n", __func__,
                           i, (*sparse)->areas[i].offset,
                           (*sparse)->areas[i].size);
                }
                break;
            case VFIO_REGION_INFO_CAP_TYPE:
                type = (struct vfio_region_info_cap_type*)header;
                if (type->type != VFIO_REGION_TYPE_MIGRATION ||
                    type->subtype != VFIO_REGION_SUBTYPE_MIGRATION) {
                    errx(EXIT_FAILURE, "bad region type %d/%d", type->type,
                         type->subtype);
                }
                migr = true;
                printf("migration region\n");
                break;
            default:
                errx(EXIT_FAILURE, "bad VFIO cap ID %#x", header->id);
        }
        if (header->next == 0) {
            break;
        }
        header = (struct vfio_info_cap_header*)((char*)header + header->next - sizeof(struct vfio_region_info));
    }
    return migr;
}

static void
do_get_device_region_info(int sock, struct vfio_region_info *region_info,
                          int *fds, size_t *nr_fds)
{
    int ret = tran_sock_msg_fds(sock, 0xabcd, VFIO_USER_DEVICE_GET_REGION_INFO,
                                region_info, region_info->argsz, NULL,
                                region_info, region_info->argsz, fds, nr_fds);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to get device region info: %s",
             strerror(-ret));
    }
}

static void
mmap_sparse_areas(int *fds, struct vfio_region_info_cap_sparse_mmap *sparse)
{
    size_t i;

    for (i = 0; i < sparse->nr_areas; i++) {

        ssize_t ret;
        void *addr;
        char pathname[BUFSIZ];
        char buf[PATH_MAX];

        ret = snprintf(pathname, sizeof(pathname), "/proc/self/fd/%d", fds[i]);
        assert(ret != -1 && (size_t)ret < sizeof(pathname));
        ret = readlink(pathname, buf, sizeof(buf) - 1);
        if (ret == -1) {
            err(EXIT_FAILURE, "failed to resolve file descriptor %d", fds[i]);
        }
        buf[ret + 1] = '\0';
        addr = mmap(NULL, sparse->areas[i].size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fds[i], sparse->areas[i].offset);
        if (addr == MAP_FAILED) {
            err(EXIT_FAILURE,
                "failed to mmap sparse region #%lu in %s (%#llx-%#llx)",
                i, buf, sparse->areas[i].offset,
                sparse->areas[i].offset + sparse->areas[i].size - 1);
        }
    }
}

static bool
get_device_region_info(int sock, uint32_t index)
{
    struct vfio_region_info *region_info;
    size_t cap_sz;
    size_t size = sizeof(struct vfio_region_info);
    int fds[CLIENT_MAX_FDS] = { 0 };
    size_t nr_fds = ARRAY_SIZE(fds);


    region_info = alloca(size);
    memset(region_info, 0, size);
    region_info->argsz = size;
    region_info->index = index;

    do_get_device_region_info(sock, region_info, NULL, 0);
    if (region_info->argsz > size) {
        size = region_info->argsz;
        region_info = alloca(size);
        memset(region_info, 0, size);
        region_info->argsz = size;
        region_info->index = index;
        do_get_device_region_info(sock, region_info, fds, &nr_fds);
        assert(region_info->argsz == size);
    } else {
        nr_fds = 0;
    }

    cap_sz = region_info->argsz - sizeof(struct vfio_region_info);
    printf("%s: region_info[%d] offset %#llx flags %#x size %llu "
           "cap_sz %lu #FDs %lu\n", __func__, index, region_info->offset,
           region_info->flags, region_info->size, cap_sz, nr_fds);
    if (cap_sz) {
        struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
        if (get_region_vfio_caps((struct vfio_info_cap_header*)(region_info + 1),
                                 &sparse)) {
            if (sparse != NULL) {
                assert((index == VFU_PCI_DEV_BAR1_REGION_IDX && nr_fds == 2) ||
                       (index == VFU_PCI_DEV_MIGR_REGION_IDX && nr_fds == 1));
                assert(nr_fds == sparse->nr_areas);
                mmap_sparse_areas(fds, sparse);
            }
            return true;
        }
    }
    return false;
}

/*
 * Returns the index of the migration region if found, -1 otherwise.
 */
static int
get_device_regions_info(int sock, struct vfio_device_info *client_dev_info)
{
    int migr_reg_index = -1;
    unsigned int i;

    for (i = 0; i < client_dev_info->num_regions; i++) {
        if (get_device_region_info(sock, i)) {
            assert(migr_reg_index == -1);
            migr_reg_index = i;
        }
    }
    return migr_reg_index;
}

static void
get_device_info(int sock, struct vfio_device_info *dev_info)
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
        errx(EXIT_FAILURE, "failed to get device info: %s", strerror(-ret));
    }

    if (dev_info->num_regions != 10) {
        errx(EXIT_FAILURE, "bad number of device regions %d",
             dev_info->num_regions);
    }

    printf("devinfo: flags %#x, num_regions %d, num_irqs %d\n",
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
            errx(EXIT_FAILURE, "failed to get  %s info: %s", irq_to_str[i],
                 strerror(-ret));
        }
        if (vfio_irq_info.count > 0) {
            printf("IRQ %s: count=%d flags=%#x\n",
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
        errx(EXIT_FAILURE, "failed to send configure IRQs message: %s",
             strerror(-ret));
    }

    return irq_fd;
}

static int
access_region(int sock, int region, bool is_write, uint64_t offset,
            void *data, size_t data_len)
{
    static int msg_id = -1;
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
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
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
        warnx("failed to %s region %d %#lx-%#lx: %s",
             is_write ? "write to" : "read from", region, offset,
             offset + data_len - 1, strerror(-ret));
        free(recv_data);
        return ret;
    }
    if (recv_data->count != data_len) {
        warnx("bad %s data count, expected=%lu, actual=%d",
             is_write ? "write" : "read", data_len,
             recv_data->count);
        free(recv_data);
        return -EINVAL;
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

static void
wait_for_irqs(int sock, int irq_fd)
{
    int ret;
    uint64_t val;
    size_t size;
    struct vfio_user_irq_info vfio_user_irq_info;
    struct vfio_user_header hdr;
    uint16_t msg_id = 0xbabe;

    if (read(irq_fd, &val, sizeof(val)) == -1) {
        err(EXIT_FAILURE, "failed to read from irqfd");
    }
    printf("INTx triggered!\n");

    size = sizeof(vfio_user_irq_info);
    ret = tran_sock_recv(sock, &hdr, false, &msg_id,
                         &vfio_user_irq_info, &size);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to receive IRQ message: %s",
             strerror(-ret));
    }

    if (hdr.cmd != VFIO_USER_VM_INTERRUPT) {
        errx(EXIT_FAILURE, "unexpected cmd %d\n", hdr.cmd);
    }

    if (vfio_user_irq_info.subindex >= 1) {
        errx(EXIT_FAILURE, "bad IRQ %d, max=1\n", vfio_user_irq_info.subindex);
    }

    // Is a NULL iovec like this OK?
    ret = tran_sock_send(sock, msg_id, true, hdr.cmd, NULL, 0);
    if (ret < 0) {
        errx(EXIT_FAILURE,
             "failed to send reply for VFIO_USER_VM_INTERRUPT: %s",
             strerror(-ret));
    }
}

static void
access_bar0(int sock, int irq_fd, time_t *t)
{
    int ret;

    assert(t != NULL);

    ret = access_region(sock, VFU_PCI_DEV_BAR0_REGION_IDX, true, 0, t, sizeof(*t));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to write to BAR0: %s", strerror(-ret));
    }

    printf("wrote to BAR0: %ld\n", *t);

    ret = access_region(sock, VFU_PCI_DEV_BAR0_REGION_IDX, false, 0, t, sizeof(*t));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to read from BAR0: %s", strerror(-ret));
    }

    printf("read from BAR0: %ld\n", *t);

    wait_for_irqs(sock, irq_fd);
}

static void
handle_dma_write(int sock, struct vfio_user_dma_region *dma_regions,
                 int nr_dma_regions, int *dma_region_fds)
{
    struct vfio_user_dma_region_access dma_access;
    struct vfio_user_header hdr;
    int ret, i;
    size_t size = sizeof(dma_access);
    uint16_t msg_id = 0xcafe;
    void *data;

    ret = tran_sock_recv(sock, &hdr, false, &msg_id, &dma_access, &size);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to receive DMA read: %s", strerror(-ret));
    }

    data = calloc(dma_access.count, 1);
    if (data == NULL) {
        err(EXIT_FAILURE, NULL);
    }

    if (recv(sock, data, dma_access.count, 0) == -1) {
        err(EXIT_FAILURE, "failed to recieve DMA read data");
    }

    for (i = 0; i < nr_dma_regions; i++) {
        if (dma_regions[i].addr == dma_access.addr) {
            ret = pwrite(dma_region_fds[i], data, dma_access.count,
                         dma_regions[i].offset);
            if (ret < 0) {
                err(EXIT_FAILURE,
                    "failed to write data to fd=%d at %#lx-%#lx",
                        dma_region_fds[i],
                        dma_regions[i].offset,
                        dma_regions[i].offset + dma_access.count - 1);
            }
            break;
	    }
    }

    dma_access.count = 0;
    ret = tran_sock_send(sock, msg_id, true, VFIO_USER_DMA_WRITE,
                         &dma_access, sizeof(dma_access));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to send reply of DMA write: %s",
             strerror(-ret));
    }
    free(data);
}

static void
handle_dma_read(int sock, struct vfio_user_dma_region *dma_regions,
                int nr_dma_regions, int *dma_region_fds)
{
    struct vfio_user_dma_region_access dma_access, *response;
    struct vfio_user_header hdr;
    int ret, i, response_sz;
    size_t size = sizeof(dma_access);
    uint16_t msg_id = 0xcafe;
    void *data;

    ret = tran_sock_recv(sock, &hdr, false, &msg_id, &dma_access, &size);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to recieve DMA read");
    }

    response_sz = sizeof(dma_access) + dma_access.count;
    response = calloc(response_sz, 1);
    if (response == NULL) {
        err(EXIT_FAILURE, NULL);
    }
    response->count = dma_access.count;
    data = (char *)response->data;

    for (i = 0; i < nr_dma_regions; i++) {
        if (dma_regions[i].addr == dma_access.addr) {
            if (pread(dma_region_fds[i], data, dma_access.count, dma_regions[i].offset) == -1) {
                err(EXIT_FAILURE, "failed to write data at %#lx-%#lx",
                    dma_regions[i].offset,
                    dma_regions[i].offset + dma_access.count);
            }
            break;
	    }
    }

    ret = tran_sock_send(sock, msg_id, true, VFIO_USER_DMA_READ,
                         response, response_sz);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to send reply of DMA write: %s",
             strerror(-ret));
    }
    free(response);
}

static void
handle_dma_io(int sock, struct vfio_user_dma_region *dma_regions,
              int nr_dma_regions, int *dma_region_fds)
{
    handle_dma_write(sock, dma_regions, nr_dma_regions, dma_region_fds);
    handle_dma_read(sock, dma_regions, nr_dma_regions, dma_region_fds);
}

static void
get_dirty_bitmaps(int sock, struct vfio_user_dma_region *dma_regions,
                  UNUSED int nr_dma_regions)
{
    struct vfio_iommu_type1_dirty_bitmap dirty_bitmap = { 0 };
    struct vfio_iommu_type1_dirty_bitmap_get bitmaps[2] = { { 0 }, };
    int ret;
    size_t i;
    struct iovec iovecs[4] = {
        [1] = {
            .iov_base = &dirty_bitmap,
            .iov_len = sizeof(dirty_bitmap)
        }
    };
    struct vfio_user_header hdr = {0};
    char data[ARRAY_SIZE(bitmaps)];

    assert(dma_regions != NULL);
    //FIXME: Is below assert correct?
    //assert(nr_dma_regions >= (int)ARRAY_SIZE(bitmaps));

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
    dirty_bitmap.argsz = sizeof(dirty_bitmap) + ARRAY_SIZE(bitmaps) * sizeof(struct vfio_iommu_type1_dirty_bitmap_get);
    dirty_bitmap.flags = VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP;
    ret = tran_sock_msg_iovec(sock, 0, VFIO_USER_DIRTY_PAGES,
                              iovecs, ARRAY_SIZE(iovecs),
                              NULL, 0,
                              &hdr, data, ARRAY_SIZE(data), NULL, 0);
    if (ret != 0) {
        errx(EXIT_FAILURE, "failed to start dirty page logging: %s",
             strerror(-ret));
    }

    for (i = 0; i < ARRAY_SIZE(bitmaps); i++) {
        printf("%#llx-%#llx\t%hhu\n", bitmaps[i].iova,
               bitmaps[i].iova + bitmaps[i].size - 1, data[i]);
    }
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
do_migrate(int sock, int migr_reg_index, size_t nr_iters,
           struct iovec *migr_iter)
{
    int ret;
    __u64 pending_bytes, data_offset, data_size;
    size_t i = 0;

    assert(nr_iters > 0);

    /* XXX read pending_bytes */
    ret = access_region(sock, migr_reg_index, false,
                        offsetof(struct vfio_device_migration_info, pending_bytes),
                        &pending_bytes, sizeof(pending_bytes));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to read pending_bytes: %s",
             strerror(-ret));
    }

    for (i = 0; i < nr_iters && pending_bytes > 0; i++) {

        /* XXX read data_offset and data_size */
        ret = access_region(sock, migr_reg_index, false,
                            offsetof(struct vfio_device_migration_info, data_offset),
                            &data_offset, sizeof(data_offset));
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to read data_offset: %s",
                 strerror(-ret));
        }

        ret = access_region(sock, migr_reg_index, false,
                            offsetof(struct vfio_device_migration_info, data_size),
                            &data_size, sizeof(data_size));
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to read data_size: %s",
                 strerror(-ret));
        }

        migr_iter[i].iov_len = data_size;
        migr_iter[i].iov_base = malloc(data_size);
        if (migr_iter[i].iov_base == NULL) {
            err(EXIT_FAILURE, "failed to allocate migration buffer");
        }

        /* XXX read migration data */
        ret = access_region(sock, migr_reg_index, false, data_offset,
                            (char*)migr_iter[i].iov_base, data_size);
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to read migration data: %s",
                 strerror(-ret));
        }

        /* FIXME send migration data to the destination client process */

        /*
         * XXX read pending_bytes again to indicate to the server that the
         * migration data have been consumed.
         */
        ret = access_region(sock, migr_reg_index, false,
                            offsetof(struct vfio_device_migration_info, pending_bytes),
                            &pending_bytes, sizeof(pending_bytes));
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to read pending_bytes: %s",
                 strerror(-ret));
        }
    }
    return i;
}

struct fake_guest_data {
    int sock;
    size_t bar1_size;
    bool done;
    unsigned char *md5sum;
};

static void *
fake_guest(void *arg)
{
    struct fake_guest_data *fake_guest_data = arg;
    int ret;
    char buf[fake_guest_data->bar1_size];
	MD5_CTX md5_ctx;
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
        MD5_Init(&md5_ctx);
        MD5_Update(&md5_ctx, buf, fake_guest_data->bar1_size);
        __sync_synchronize();
    } while (!fake_guest_data->done);

    MD5_Final(fake_guest_data->md5sum, &md5_ctx);

    return NULL;
}

static size_t
migrate_from(int sock, int migr_reg_index, size_t *nr_iters,
             struct iovec **migr_iters, unsigned char *md5sum, size_t bar1_size)
{
    __u32 device_state;
    int ret;
    size_t _nr_iters;
    pthread_t thread;
    struct fake_guest_data fake_guest_data = {
        .sock = sock,
        .bar1_size = bar1_size,
        .done = false,
        .md5sum = md5sum
    };

    ret = pthread_create(&thread, NULL, fake_guest, &fake_guest_data);
    if (ret != 0) {
        errno = ret;
        err(EXIT_FAILURE, "failed to create pthread");
    }

    *nr_iters = 2;
    *migr_iters = malloc(sizeof(struct iovec) * *nr_iters);
    if (*migr_iters == NULL) {
        err(EXIT_FAILURE, NULL);
    }

    /*
     * XXX set device state to pre-copy. This is technically optional but any
     * VMM that cares about performance needs this.
     */
    device_state = VFIO_DEVICE_STATE_SAVING | VFIO_DEVICE_STATE_RUNNING;
    ret = access_region(sock, migr_reg_index, true,
                        offsetof(struct vfio_device_migration_info, device_state),
                        &device_state, sizeof(device_state));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to write to device state: %s",
             strerror(-ret));
    }

    _nr_iters = do_migrate(sock, migr_reg_index, 1, *migr_iters);
    assert(_nr_iters == 1);
    printf("stopping fake guest thread\n");
    fake_guest_data.done = true;
    __sync_synchronize();
    ret = pthread_join(thread, NULL);
    if (ret != 0) {
        errno = ret;
        err(EXIT_FAILURE, "failed to join fake guest pthread");
    }

    printf("setting device state to stop-and-copy\n");

    device_state = VFIO_DEVICE_STATE_SAVING;
    ret = access_region(sock, migr_reg_index, true,
                        offsetof(struct vfio_device_migration_info, device_state),
                        &device_state, sizeof(device_state));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to write to device state: %s",
             strerror(-ret));
    }

    _nr_iters += do_migrate(sock, migr_reg_index, 1, (*migr_iters) + _nr_iters);
    if (_nr_iters != 2) {
        errx(EXIT_FAILURE,
             "expected 2 iterations instead of %ld while in stop-and-copy state\n",
             _nr_iters);
    }

    /* XXX read device state, migration must have finished now */
    device_state = VFIO_DEVICE_STATE_STOP;
    ret = access_region(sock, migr_reg_index, true,
                              offsetof(struct vfio_device_migration_info, device_state),
                              &device_state, sizeof(device_state));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to write to device state: %s",
             strerror(-ret));
    }

    return _nr_iters;
}

static int
migrate_to(char *old_sock_path, int *server_max_fds,
           size_t *pgsize, size_t nr_iters, struct iovec *migr_iters,
           char *path_to_server, int migr_reg_index, unsigned char *src_md5sum,
           size_t bar1_size)
{
    int ret, sock;
    char *sock_path;
    struct stat sb;
    __u32 device_state = VFIO_DEVICE_STATE_RESUMING;
    __u64 data_offset, data_len;
    size_t i;
	MD5_CTX md5_ctx;
    char buf[bar1_size];
    unsigned char dst_md5sum[MD5_DIGEST_LENGTH];

    assert(old_sock_path != NULL);

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
            "-v",
            sock_path,
            NULL
        };
        ret = execvp(_argv[0] , _argv);
        if (ret != 0) {
            err(EXIT_FAILURE, "failed to start destination sever (%s)",
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

    negotiate(sock, server_max_fds, pgsize);

    /* XXX set device state to resuming */
    ret = access_region(sock, migr_reg_index, true,
                        offsetof(struct vfio_device_migration_info, device_state),
                        &device_state, sizeof(device_state));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to set device state to resuming: %s",
             strerror(-ret));
    }

    for (i = 0; i < nr_iters; i++) {

        /* XXX read data offset */
        ret = access_region(sock, migr_reg_index, false,
                            offsetof(struct vfio_device_migration_info, data_offset),
                            &data_offset, sizeof(data_offset));
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to read migration data offset: %s",
                 strerror(-ret));
        }

        /* XXX write migration data */

        /*
         * TODO write half of migration data via regular write and other half via
         * memopy map.
         */
        printf("writing migration device data %#llx-%#llx\n", data_offset,
               data_offset + migr_iters[i].iov_len - 1);
        ret = access_region(sock, migr_reg_index, true,
                            data_offset, migr_iters[i].iov_base,
                            migr_iters[i].iov_len);
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to write device migration data: %s",
                 strerror(-ret));
        }

        /* XXX write data_size */
        data_len = migr_iters[i].iov_len;
        ret = access_region(sock, migr_reg_index, true,
                            offsetof(struct vfio_device_migration_info, data_size),
                            &data_len, sizeof(data_len));
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to write migration data size: %s",
                 strerror(-ret));
        }
    }

    /* XXX set device state to running */
    device_state = VFIO_DEVICE_STATE_RUNNING;
    ret = access_region(sock, migr_reg_index, true,
                            offsetof(struct vfio_device_migration_info, device_state),
                            &device_state, sizeof(device_state));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to set device state to running: %s",
             strerror(-ret));
    }

    /* validate contents of BAR1 */
    MD5_Init(&md5_ctx);

    if (access_region(sock, 1, false, 0, buf, bar1_size) != 0) {
        err(EXIT_FAILURE, "failed to read BAR1");
    }
    MD5_Update(&md5_ctx, buf, bar1_size);
    MD5_Final(dst_md5sum, &md5_ctx);

    if (strncmp((char*)src_md5sum, (char*)dst_md5sum, MD5_DIGEST_LENGTH) != 0) {
        int i;
        fprintf(stderr, "md5sum mismatch: ");
        for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
            fprintf(stderr, "%02x", src_md5sum[i]);
        }
        fprintf(stderr, " != ");
        for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
            fprintf(stderr, "%02x", dst_md5sum[i]);
        }
        fprintf(stderr, "\n");
        abort();
    }

    return sock;
}

static void
map_dma_regions(int sock, int max_fds, struct vfio_user_dma_region *dma_regions,
                int *dma_region_fds, int nr_dma_regions)
{
    int i, ret;

    for (i = 0; i < nr_dma_regions / max_fds; i++) {
        struct iovec iovecs[2] = { { 0, } };

        /* [0] is for the header. */
        iovecs[1].iov_base = dma_regions + (i * max_fds);
        iovecs[1].iov_len = sizeof(*dma_regions) * max_fds;

        ret = tran_sock_msg_iovec(sock, 0x1234 + i, VFIO_USER_DMA_MAP,
                                  iovecs, ARRAY_SIZE(iovecs),
                                  dma_region_fds + (i * max_fds), max_fds,
                                  NULL, NULL, 0, NULL, 0);
        if (ret < 0) {
            errx(EXIT_FAILURE, "failed to map DMA regions: %s", strerror(-ret));
        }
    }
}

int main(int argc, char *argv[])
{
	int ret, sock, irq_fd;
    struct vfio_user_dma_region *dma_regions;
    struct vfio_device_info client_dev_info = {0};
    int *dma_region_fds;
    int i;
    FILE *fp;
    int server_max_fds;
    size_t pgsize;
    int nr_dma_regions;
    struct vfio_iommu_type1_dirty_bitmap dirty_bitmap = {0};
    int opt;
    time_t t;
    char *path_to_server = NULL;
    vfu_pci_hdr_t config_space;
    int migr_reg_index;
    struct iovec *migr_iters;
    size_t nr_iters;
    unsigned char md5sum[MD5_DIGEST_LENGTH];
    size_t bar1_size = 0x3000; /* FIXME get this value from region info */

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
     * Do intial negotiation with the server, and discover parameters.
     */
    negotiate(sock, &server_max_fds, &pgsize);

    /* try to access a bogus region, we should get an error */
    ret = access_region(sock, 0xdeadbeef, false, 0, &ret, sizeof(ret));
    if (ret != -EINVAL) {
        errx(EXIT_FAILURE,
             "expected -EINVAL accessing bogus region, got %d instead",
             ret);
    }

    /* XXX VFIO_USER_DEVICE_GET_INFO */
    get_device_info(sock, &client_dev_info);

    /* XXX VFIO_USER_DEVICE_GET_REGION_INFO */
    migr_reg_index = get_device_regions_info(sock, &client_dev_info);
    if (migr_reg_index == -1) {
        errx(EXIT_FAILURE, "could not find migration region");
    }

    ret = access_region(sock, VFU_PCI_DEV_CFG_REGION_IDX, false, 0, &config_space,
                        sizeof(config_space));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to read PCI configuration space: %s\n",
             strerror(-ret));
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
     * Tell the server we have some DMA regions it can access. Each DMA region
     * is accompanied by a file descriptor, so let's create more (2x) DMA
     * regions that can fit in a message that can be handled by the server.
     */
    nr_dma_regions = server_max_fds << 1;

    if ((fp = tmpfile()) == NULL) {
        err(EXIT_FAILURE, "failed to create DMA file");
    }

    if ((ret = ftruncate(fileno(fp), nr_dma_regions * sysconf(_SC_PAGESIZE))) == -1) {
        err(EXIT_FAILURE, "failed to truncate file");
    }

    dma_regions = alloca(sizeof(*dma_regions) * nr_dma_regions);
    dma_region_fds = alloca(sizeof(*dma_region_fds) * nr_dma_regions);

    for (i = 0; i < nr_dma_regions; i++) {
        dma_regions[i].addr = i * sysconf(_SC_PAGESIZE);
        dma_regions[i].size = sysconf(_SC_PAGESIZE);
        dma_regions[i].offset = dma_regions[i].addr;
        dma_regions[i].prot = PROT_READ | PROT_WRITE;
        dma_regions[i].flags = VFIO_USER_F_DMA_REGION_MAPPABLE;
        dma_region_fds[i] = fileno(fp);
    }

    map_dma_regions(sock, server_max_fds, dma_regions, dma_region_fds,
                    nr_dma_regions);

    /*
     * XXX VFIO_USER_DEVICE_GET_IRQ_INFO and VFIO_IRQ_SET_ACTION_TRIGGER
     * Query interrupts and configure an eventfd to be associated with INTx.
     */
    irq_fd = configure_irqs(sock);

    dirty_bitmap.argsz = sizeof(dirty_bitmap);
    dirty_bitmap.flags = VFIO_IOMMU_DIRTY_PAGES_FLAG_START;
    ret = tran_sock_msg(sock, 0, VFIO_USER_DIRTY_PAGES,
                        &dirty_bitmap, sizeof(dirty_bitmap),
                        NULL, NULL, 0);
    if (ret != 0) {
        errx(EXIT_FAILURE, "failed to start dirty page logging: %s",
             strerror(-ret));
    }

    /*
     * XXX VFIO_USER_REGION_READ and VFIO_USER_REGION_WRITE
     *
     * BAR0 in the server does not support memory mapping so it must be accessed
     * via explicit messages.
     */
    t = time(NULL) + 1;
    access_bar0(sock, irq_fd, &t);

    /* FIXME check that above took at least 1s */

    handle_dma_io(sock, dma_regions, nr_dma_regions, dma_region_fds);

    get_dirty_bitmaps(sock, dma_regions, nr_dma_regions);

    dirty_bitmap.argsz = sizeof(dirty_bitmap);
    dirty_bitmap.flags = VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP;
    ret = tran_sock_msg(sock, 0, VFIO_USER_DIRTY_PAGES,
                        &dirty_bitmap, sizeof(dirty_bitmap),
                        NULL, NULL, 0);
    if (ret != 0) {
        errx(EXIT_FAILURE, "failed to stop dirty page logging: %s",
             strerror(-ret));
    }

    /* BAR1 can be memory mapped and read directly */

    /*
     * XXX VFIO_USER_DMA_UNMAP
     *
     * unmap the first group of the DMA regions
     */
    ret = tran_sock_msg(sock, 7, VFIO_USER_DMA_UNMAP,
                        dma_regions, sizeof(*dma_regions) * server_max_fds,
                        NULL, NULL, 0);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to unmap DMA regions: %s", strerror(-ret));
    }

    /*
     * Schedule an interrupt in 3 seconds from now in the old server and then
     * immediatelly migrate the device. The new server should deliver the
     * interrupt. Hopefully 3 seconds should be enough for migration to finish.
     * TODO make this value a command line option.
     */
    t = time(NULL) + 3;
    ret = access_region(sock, VFU_PCI_DEV_BAR0_REGION_IDX, true, 0, &t, sizeof(t));
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to write to BAR0: %s", strerror(-ret));
    }

    nr_iters = migrate_from(sock, migr_reg_index, &nr_iters, &migr_iters,
                            md5sum, bar1_size);

    /*
     * Normally the client would now send the device state to the destination
     * client and then exit. We don't demonstrate how this works as this is a
     * client implementation detail. Instead, the client starts the destination
     * server and then applies the migration data.
     */
    if (asprintf(&path_to_server, "%s/server", dirname(argv[0])) == -1) {
        err(EXIT_FAILURE, "failed to asprintf");
    }

    sock = migrate_to(argv[optind], &server_max_fds, &pgsize,
                      nr_iters, migr_iters, path_to_server, migr_reg_index,
                      md5sum, bar1_size);
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
    map_dma_regions(sock, server_max_fds, dma_regions + server_max_fds,
                    dma_region_fds + server_max_fds,
                    nr_dma_regions - server_max_fds);

    /*
     * XXX reconfigure IRQs.
     * FIXME is this something the client needs to do? I would expect so since
     * it's the client that creates and provides the FD. Do we need to save some
     * state in the migration data?
     */
    ret = configure_irqs(sock);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to configure IRQs on destination server: %s",
             strerror(-ret));
    }
    irq_fd = ret;

    wait_for_irqs(sock, irq_fd);

    handle_dma_io(sock, dma_regions + server_max_fds,
                  nr_dma_regions - server_max_fds,
                  dma_region_fds + server_max_fds);
    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
