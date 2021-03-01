/*
 * Copyright (c) 2019 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
 *          Swapnil Ingle <swapnil.ingle@nutanix.com>
 *          Felipe Franciosi <felipe@nutanix.com>
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <linux/vfio.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "dma.h"
#include "irq.h"
#include "libvfio-user.h"
#include "migration.h"
#include "pci.h"
#include "private.h"
#include "tran_sock.h"

void
vfu_log(vfu_ctx_t *vfu_ctx, int level, const char *fmt, ...)
{
    va_list ap;
    char buf[BUFSIZ];
    int _errno = errno;

    assert(vfu_ctx != NULL);

    if (vfu_ctx->log == NULL || level > vfu_ctx->log_level || fmt == NULL) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    vfu_ctx->log(vfu_ctx, level, buf);
    errno = _errno;
}

static size_t
get_vfio_caps_size(bool is_migr_reg, vfu_reg_info_t *reg)
{
    size_t type_size = 0;
    size_t sparse_size = 0;

    if (is_migr_reg) {
        type_size = sizeof(struct vfio_region_info_cap_type);
    }

    if (reg->nr_mmap_areas != 0) {
        sparse_size = sizeof(struct vfio_region_info_cap_sparse_mmap)
                      + (reg->nr_mmap_areas * sizeof(struct vfio_region_sparse_mmap_area));
    }

    return type_size + sparse_size;
}

/*
 * Populate the sparse mmap capability information to vfio-client.
 * Sparse mmap information stays after struct vfio_region_info and cap_offest
 * points accordingly.
 */
static int
dev_get_caps(vfu_ctx_t *vfu_ctx, vfu_reg_info_t *vfu_reg, bool is_migr_reg,
             struct vfio_region_info *vfio_reg, int **fds, size_t *nr_fds)
{
    struct vfio_info_cap_header *header;
    struct vfio_region_info_cap_type *type = NULL;
    struct vfio_region_info_cap_sparse_mmap *sparse = NULL;

    assert(vfu_ctx != NULL);
    assert(vfio_reg != NULL);
    assert(fds != NULL);
    assert(nr_fds != NULL);

    header = (struct vfio_info_cap_header*)(vfio_reg + 1);

    if (is_migr_reg) {
        type = (struct vfio_region_info_cap_type*)header;
        type->header.id = VFIO_REGION_INFO_CAP_TYPE;
        type->header.version = 1;
        type->header.next = 0;
        type->type = VFIO_REGION_TYPE_MIGRATION;
        type->subtype = VFIO_REGION_SUBTYPE_MIGRATION;
        vfio_reg->cap_offset = sizeof(struct vfio_region_info);
    }

    if (vfu_reg->mmap_areas != NULL) {
        int i, nr_mmap_areas = vfu_reg->nr_mmap_areas;
        if (type != NULL) {
            type->header.next = vfio_reg->cap_offset + sizeof(struct vfio_region_info_cap_type);
            sparse = (struct vfio_region_info_cap_sparse_mmap*)(type + 1);
        } else {
            vfio_reg->cap_offset = sizeof(struct vfio_region_info);
            sparse = (struct vfio_region_info_cap_sparse_mmap*)header;
        }

        /*
         * FIXME need to figure out how to break message into smaller messages
         * so that we don't exceed client_max_fds
         */
        assert(nr_mmap_areas <= vfu_ctx->client_max_fds);

        *fds = malloc(nr_mmap_areas * sizeof(int));
        if (*fds == NULL) {
            return -ENOMEM;
        }
        sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
        sparse->header.version = 1;
        sparse->header.next = 0;
        sparse->nr_areas = *nr_fds = nr_mmap_areas;

        for (i = 0; i < nr_mmap_areas; i++) {
            struct iovec *iov = &vfu_reg->mmap_areas[i];

            vfu_log(vfu_ctx, LOG_DEBUG, "%s: area %d [%#llx-%#llx)", __func__,
                    i, iov->iov_base, iov->iov_base + iov->iov_len);

            (*fds)[i] = vfu_reg->fd;
            sparse->areas[i].offset = (uintptr_t)iov->iov_base;
            sparse->areas[i].size = iov->iov_len;
        }
    }
    return 0;
}

inline void
dump_buffer(const char *prefix UNUSED, const char *buf UNUSED,
            uint32_t count UNUSED)
{
#ifdef VFU_VERBOSE_LOGGING
    int i;
    const size_t bytes_per_line = 0x8;

    if (strcmp(prefix, "")) {
        fprintf(stderr, "%s\n", prefix);
    }
    for (i = 0; i < (int)count; i++) {
        if (i % bytes_per_line != 0) {
            fprintf(stderr, " ");
        }
        /* TODO valgrind emits a warning if count is 1 */
        fprintf(stderr,"0x%02x", *(buf + i));
        if ((i + 1) % bytes_per_line == 0) {
            fprintf(stderr, "\n");
        }
    }
    if (i % bytes_per_line != 0) {
        fprintf(stderr, "\n");
    }
#endif
}

static bool
is_migr_reg(vfu_ctx_t *vfu_ctx, int index)
{
    return &vfu_ctx->reg_info[index] == vfu_ctx->migr_reg;
}

static ssize_t
region_access(vfu_ctx_t *vfu_ctx, size_t region_index, char *buf,
              size_t count, uint64_t offset, bool is_write)
{
    ssize_t ret;

    assert(vfu_ctx != NULL);
    assert(buf != NULL);

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %zu %#lx-%#lx", is_write ? "W" : "R",
            region_index, offset, offset + count);

    if (is_write) {
        dump_buffer("buffer write", buf, count);
    }

    if (region_index == VFU_PCI_DEV_CFG_REGION_IDX) {
        ret = pci_config_space_access(vfu_ctx, buf, count, offset, is_write);
    } else if (is_migr_reg(vfu_ctx, region_index) && vfu_ctx->migration != NULL) {
        ret = migration_region_access(vfu_ctx, buf, count, offset, is_write);
    } else {
        vfu_region_access_cb_t *cb = vfu_ctx->reg_info[region_index].cb;

        if (cb == NULL) {
            vfu_log(vfu_ctx, LOG_ERR, "no callback for region %d",
                    region_index);
            return -EINVAL;
        }

        ret = cb(vfu_ctx, buf, count, offset, is_write);
    }

    if (!is_write && (size_t)ret == count) {
        dump_buffer("buffer read", buf, count);
    }

    return ret;
}

static bool
is_valid_region_access(vfu_ctx_t *vfu_ctx, size_t size, uint16_t cmd,
                       struct vfio_user_region_access *ra)
{
    size_t index;

    assert(vfu_ctx != NULL);
    assert(ra != NULL);

    if (size < sizeof(*ra)) {
        vfu_log(vfu_ctx, LOG_ERR, "message size too small (%d)", size);
        return false;
    }

    if (cmd == VFIO_USER_REGION_WRITE && size - sizeof(*ra) != ra->count) {
        vfu_log(vfu_ctx, LOG_ERR, "region write count too small: "
                "expected %lu, got %u", size - sizeof(*ra), ra->count);
        return false;
    }

    index = ra->region;

    if (index >= vfu_ctx->nr_regions) {
        vfu_log(vfu_ctx, LOG_ERR, "bad region index %u", index);
        return false;
    }

    // FIXME: need to audit later for wraparound
    if (ra->offset + ra->count > vfu_ctx->reg_info[index].size) {
        vfu_log(vfu_ctx, LOG_ERR, "out of bounds region access %#lx-%#lx "
                "(size %#lx)", ra->offset, ra->offset + ra->count,
                vfu_ctx->reg_info[index].size);

        return false;
    }

    if (device_is_stopped_and_copying(vfu_ctx->migration) &&
        !is_migr_reg(vfu_ctx, index)) {
        vfu_log(vfu_ctx, LOG_ERR,
                "cannot access region %u while device in stop-and-copy state",
                index);
        return false;
    }

    return true;
}

static int
handle_region_access(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_user_region_access *in_ra = msg->in_data;
    struct vfio_user_region_access *out_ra;
    ssize_t ret;
    char *buf;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    if (!is_valid_region_access(vfu_ctx, msg->in_size, msg->hdr.cmd, in_ra)) {
        return -EINVAL;
    }

    if (in_ra->count == 0) {
        return 0;
    }

    msg->out_size = sizeof(*in_ra);
    if (msg->hdr.cmd == VFIO_USER_REGION_READ) {
        msg->out_size += in_ra->count;
    }

    msg->out_data = calloc(1, msg->out_size);
    if (msg->out_data == NULL) {
        return -ENOMEM;
    }

    out_ra = msg->out_data;

    // FIXME: fill in the rest of out_ra?

    if (msg->hdr.cmd == VFIO_USER_REGION_READ) {
        buf = (char *)(&out_ra->data);
    } else {
        buf = (char *)(&in_ra->data);
    }

    ret = region_access(vfu_ctx, in_ra->region, buf, in_ra->count,
                        in_ra->offset, msg->hdr.cmd == VFIO_USER_REGION_WRITE);

    if (ret != in_ra->count) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to %s %#x-%#lx: %s",
                msg->hdr.cmd == VFIO_USER_REGION_WRITE ? "write" : "read",
                in_ra->count, in_ra->offset + in_ra->count - 1, strerror(-ret));
        /* FIXME we should return whatever has been accessed, not an error */
        if (ret >= 0) {
            ret = -EINVAL;
        }
        return ret;
    }

    out_ra->count = ret;

    return 0;
}

int
handle_device_get_info(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_device_info *in_info;
    struct vfio_device_info *out_info;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    in_info = msg->in_data;

    if (msg->in_size < sizeof(*in_info) || in_info->argsz < sizeof(*in_info)) {
        return -EINVAL;
    }

    msg->out_size = sizeof (*out_info);
    msg->out_data = calloc(1, sizeof(*out_info));

    if (msg->out_data == NULL) {
        return -errno;
    }

    out_info = msg->out_data;
    out_info->argsz = sizeof(*in_info);
    out_info->flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
    out_info->num_regions = vfu_ctx->nr_regions;
    out_info->num_irqs = VFU_DEV_NUM_IRQS;

    vfu_log(vfu_ctx, LOG_DEBUG, "devinfo flags %#x, num_regions %d, "
            "num_irqs %d", out_info->flags, out_info->num_regions,
            out_info->num_irqs);

    return 0;
}

#define VFU_REGION_SHIFT 40

static inline uint64_t
region_to_offset(uint32_t region)
{
    return (uint64_t)region << VFU_REGION_SHIFT;
}

static int
handle_device_get_region_info(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_region_info *in_info;
    struct vfio_region_info *out_info;
    vfu_reg_info_t *vfu_reg;
    size_t caps_size;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    in_info = msg->in_data;

    // FIXME: we don't cap client-provided in_info->argsz

    if (msg->in_size < sizeof(*in_info) || in_info->argsz < sizeof(*in_info)) {
        return -EINVAL;
    }

    if (in_info->index >= vfu_ctx->nr_regions) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad region index %d in get region info",
                index);
        return -EINVAL;
    }

    msg->out_size = in_info->argsz;
    msg->out_data = calloc(1, msg->out_size);

    if (msg->out_data == NULL) {
        return -errno;
    }

    out_info = msg->out_data;

    vfu_reg = &vfu_ctx->reg_info[in_info->index];

    caps_size = get_vfio_caps_size(is_migr_reg(vfu_ctx, in_info->index),
                                   vfu_reg);
    /* This might be more than the buffer we actually return. */
    out_info->argsz = sizeof(*out_info) + caps_size;
    out_info->index = in_info->index;
    out_info->offset = region_to_offset(out_info->index);
    out_info->size = vfu_reg->size;

    out_info->flags = 0;

    if (vfu_reg->flags & VFU_REGION_FLAG_READ) {
        out_info->flags |= VFIO_REGION_INFO_FLAG_READ;
    }
    if (vfu_reg->flags & VFU_REGION_FLAG_WRITE) {
        out_info->flags |= VFIO_REGION_INFO_FLAG_WRITE;
    }

    if (vfu_reg->fd != -1) {
        out_info->flags |= VFIO_REGION_INFO_FLAG_MMAP;
    }

    if (caps_size > 0) {
        out_info->flags |= VFIO_REGION_INFO_FLAG_CAPS;
        /* Only actually provide the caps if they fit. */
        if (in_info->argsz >= out_info->argsz) {
            dev_get_caps(vfu_ctx, vfu_reg, is_migr_reg(vfu_ctx, in_info->index),
                         out_info, &msg->out_fds, &msg->nr_out_fds);
        }
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "region_info[%d] offset %#llx flags %#x "
            "size %llu " "argsz %u", out_info->index, out_info->offset,
            out_info->flags, out_info->size, out_info->argsz);

    return 0;
}

int
consume_fd(int *fds, size_t nr_fds, size_t index)
{
   int fd;

   if (index >= nr_fds) {
       return -EINVAL;
   }

   fd = fds[index];
   fds[index] = -1;
   return fd;
}

int
handle_dma_map_or_unmap(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_user_dma_region *dma_regions = msg->in_data;
    bool is_map = (msg->hdr.cmd == VFIO_USER_DMA_MAP);
    size_t nr_dma_regions;
    size_t fdi;
    size_t i;
    int ret;

    assert(vfu_ctx != NULL);

    if (msg->in_size % sizeof(struct vfio_user_dma_region) != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "bad size of DMA regions %d", msg->in_size);
        return -EINVAL;
    }

    if (vfu_ctx->dma == NULL) {
        return 0;
    }

    nr_dma_regions = msg->in_size / sizeof(struct vfio_user_dma_region);
    if (nr_dma_regions == 0) {
        return 0;
    }

    for (i = 0, fdi = 0; i < nr_dma_regions; i++) {
        if (is_map) {
            int fd = -1;
            if (dma_regions[i].flags == VFIO_USER_F_DMA_REGION_MAPPABLE) {
                fd = consume_fd(msg->in_fds, msg->nr_in_fds, fdi++);
                if (fd < 0) {
                    ret = fd;
                    break;
                }
            }

            ret = dma_controller_add_region(vfu_ctx->dma,
                                            dma_regions[i].addr,
                                            dma_regions[i].size,
                                            fd,
                                            dma_regions[i].offset,
                                            dma_regions[i].prot);
            if (ret < 0) {
                if (fd != -1) {
                    close(fd);
                }
                vfu_log(vfu_ctx, LOG_INFO,
                        "failed to add DMA region %#lx-%#lx offset=%#lx fd=%d: %s",
                        dma_regions[i].addr,
                        dma_regions[i].addr + dma_regions[i].size - 1,
                        dma_regions[i].offset, fd,
                        strerror(-ret));
                break;
            }
            if (vfu_ctx->map_dma != NULL) {
                vfu_ctx->map_dma(vfu_ctx, dma_regions[i].addr,
                                 dma_regions[i].size, dma_regions[i].prot);
            }
            ret = 0;
            vfu_log(vfu_ctx, LOG_DEBUG,
                    "added DMA region %#lx-%#lx offset=%#lx fd=%d prot=%#x",
                    dma_regions[i].addr,
                    dma_regions[i].addr + dma_regions[i].size - 1,
                    dma_regions[i].offset, fd, dma_regions[i].prot);
        } else {
            ret = dma_controller_remove_region(vfu_ctx->dma,
                                               dma_regions[i].addr,
                                               dma_regions[i].size,
                                               vfu_ctx->unmap_dma, vfu_ctx);
            if (ret < 0) {
                vfu_log(vfu_ctx, LOG_INFO,
                        "failed to remove DMA region %#lx-%#lx: %s",
                        dma_regions[i].addr,
                        dma_regions[i].addr + dma_regions[i].size - 1,
                        strerror(-ret));
                break;
            }
            vfu_log(vfu_ctx, LOG_DEBUG,
                    "removed DMA region %#lx-%#lx",
                    dma_regions[i].addr,
                    dma_regions[i].addr + dma_regions[i].size - 1);
        }
    }
    return ret;
}

static int
handle_device_reset(vfu_ctx_t *vfu_ctx)
{
    vfu_log(vfu_ctx, LOG_DEBUG, "Device reset called by client");
    if (vfu_ctx->reset != NULL) {
        return vfu_ctx->reset(vfu_ctx);
    }
    return 0;
}

static int
handle_dirty_pages_get(vfu_ctx_t *vfu_ctx,
                       struct iovec **iovecs, size_t *nr_iovecs,
                       struct vfio_iommu_type1_dirty_bitmap_get *ranges,
                       uint32_t size)
{
    int ret = -EINVAL;
    size_t i;

    assert(vfu_ctx != NULL);
    assert(iovecs != NULL);
    assert(nr_iovecs != NULL);
    assert(ranges != NULL);

    if (size % sizeof(struct vfio_iommu_type1_dirty_bitmap_get) != 0) {
        return -EINVAL;
    }
    *nr_iovecs = size / sizeof(struct vfio_iommu_type1_dirty_bitmap_get);
    *iovecs = malloc(*nr_iovecs * sizeof(struct iovec));
    if (*iovecs == NULL) {
        return -ENOMEM;
    }

    for (i = 0; i < *nr_iovecs; i++) {
        struct vfio_iommu_type1_dirty_bitmap_get *r = &ranges[i];
        ret = dma_controller_dirty_page_get(vfu_ctx->dma, r->iova, r->size,
                                            r->bitmap.pgsize, r->bitmap.size,
                                            (char**)&((*iovecs)[i].iov_base));
        if (ret != 0) {
            goto out;
        }
        (*iovecs)[i].iov_len = r->bitmap.size;
    }

out:
    if (ret != 0) {
        if (*iovecs != NULL) {
            free(*iovecs);
            *iovecs = NULL;
        }
    }
    return ret;
}

int
handle_dirty_pages(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_iommu_type1_dirty_bitmap *dirty_bitmap = msg->in_data;
    int ret;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    if (msg->in_size < sizeof(*dirty_bitmap) ||
        msg->in_size != dirty_bitmap->argsz) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid header size %u", msg->in_size);
        return -EINVAL;
    }

    switch (dirty_bitmap->flags) {
    case VFIO_IOMMU_DIRTY_PAGES_FLAG_START:
        ret = dma_controller_dirty_page_logging_start(vfu_ctx->dma,
                  migration_get_pgsize(vfu_ctx->migration));
        break;

    case VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP:
        ret = dma_controller_dirty_page_logging_stop(vfu_ctx->dma);
        break;

    case VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP: {
        struct vfio_iommu_type1_dirty_bitmap_get *get;
        get = (void *)(dirty_bitmap + 1);

        ret = handle_dirty_pages_get(vfu_ctx, &msg->out_iovecs,
                                     &msg->nr_out_iovecs, get,
                                     msg->in_size - sizeof(*dirty_bitmap));
        break;
    }

    default:
        vfu_log(vfu_ctx, LOG_ERR, "bad flags %#x", dirty_bitmap->flags);
        ret = -EINVAL;
        break;
    }

    return ret;
}
UNIT_TEST_SYMBOL(handle_dirty_pages);
#define handle_dirty_pages __wrap_handle_dirty_pages

static vfu_msg_t *
alloc_msg(struct vfio_user_header *hdr, int *fds, size_t nr_fds)
{
    vfu_msg_t *msg;
    size_t i;

    msg = calloc(1, sizeof(*msg));

    if (msg == NULL) {
        return NULL;
    }

    msg->hdr = *hdr;
    msg->nr_in_fds = nr_fds;

    if (nr_fds > 0) {
        msg->in_fds = calloc(msg->nr_in_fds, sizeof(int));

        if (msg->in_fds == NULL) {
            free(msg);
            return NULL;
        }

        for (i = 0; i < msg->nr_in_fds; i++) {
            msg->in_fds[i] = fds[i];
        }
    }

    return msg;
}

/*
 * Read the header of the next request to be processed, if any.
 * Note that we avoid any malloc() before we see data, as this is used for
 * polling by SPDK.
 *
 * Returns 0 if we read a header, or -errno if an error occurred.
 */
int
get_request_header(vfu_ctx_t *vfu_ctx, vfu_msg_t **msgp)
{
    int fds[VFIO_USER_CLIENT_MAX_FDS_LIMIT] = { 0 };
    struct vfio_user_header hdr = { 0, };
    size_t nr_fds = VFIO_USER_CLIENT_MAX_FDS_LIMIT;
    size_t i;
    int ret;

    ret = vfu_ctx->tran->get_request_header(vfu_ctx, &hdr, fds, &nr_fds);

    if (ret < 0) {
        if (ret != -EINTR && ret != -EAGAIN && ret != -EWOULDBLOCK) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to get request header: %s",
                    strerror(-ret));
        }

        goto out;
    }

    if (unlikely(ret == 0)) {
        if (errno == 0) {
            ret = -ENOTCONN;
            vfu_log(vfu_ctx, LOG_INFO, "vfio-user client closed connection");
        } else {
            ret = -errno;
            vfu_log(vfu_ctx, LOG_ERR, "end of file: %m");
        }

        goto out;
    }

    if (ret != sizeof(hdr)) {
        vfu_log(vfu_ctx, LOG_ERR, "short header read %ld", ret);
        ret = -EINVAL;
        goto out;
    }

    *msgp = alloc_msg(&hdr, fds, nr_fds);

    if (*msgp == NULL) {
        ret = -errno;
        goto out;
    }

    return 0;

out:
    if (ret != 0) {
        for (i = 0; i < nr_fds; i++) {
            close(fds[i]);
        }
    }

    return ret;
}
UNIT_TEST_SYMBOL(get_request_header);
#define get_request_header __wrap_get_request_header

/*
 * Returns 0 if the header is valid, -errno otherwise.
 */
static int
validate_header(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    if (msg->hdr.flags.type != VFIO_USER_F_TYPE_COMMAND) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: not a command req", msg->hdr.msg_id);
        return -EINVAL;
    }

    if (msg->hdr.msg_size < sizeof(msg->hdr)) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: bad size %d in header",
                msg->hdr.msg_id, msg->hdr.msg_size);
        return -EINVAL;
    }

    if (msg->hdr.msg_size > SERVER_MAX_MSG_SIZE) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: size of %u is too large",
                msg->hdr.msg_id, msg->hdr.msg_size);
        return -EINVAL;
    }

    return 0;
}

bool
cmd_allowed_when_stopped_and_copying(uint16_t cmd)
{
    return cmd == VFIO_USER_REGION_READ ||
           cmd == VFIO_USER_REGION_WRITE ||
           cmd == VFIO_USER_DIRTY_PAGES;
}
UNIT_TEST_SYMBOL(cmd_allowed_when_stopped_and_copying);
#define cmd_allowed_when_stopped_and_copying __wrap_cmd_allowed_when_stopped_and_copying

bool
should_exec_command(vfu_ctx_t *vfu_ctx, uint16_t cmd)
{
    if (device_is_stopped_and_copying(vfu_ctx->migration)) {
        if (!cmd_allowed_when_stopped_and_copying(cmd)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "bad command %d while device in stop-and-copy state", cmd);
            return false;
        }
    } else if (device_is_stopped(vfu_ctx->migration) &&
               cmd != VFIO_USER_DIRTY_PAGES) {
        vfu_log(vfu_ctx, LOG_ERR,
               "bad command %d while device in stopped state", cmd);
        return false;
    }
    return true;
}
UNIT_TEST_SYMBOL(should_exec_command);
#define should_exec_command __wrap_should_exec_command

int
exec_command(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    int ret = 0;

    switch (msg->hdr.cmd) {
    case VFIO_USER_DMA_MAP:
    case VFIO_USER_DMA_UNMAP:
        ret = handle_dma_map_or_unmap(vfu_ctx, msg);
        break;

    case VFIO_USER_DEVICE_GET_INFO:
        ret = handle_device_get_info(vfu_ctx, msg);
        break;

    case VFIO_USER_DEVICE_GET_REGION_INFO:
        ret = handle_device_get_region_info(vfu_ctx, msg);
        break;

    case VFIO_USER_DEVICE_GET_IRQ_INFO:
        ret = handle_device_get_irq_info(vfu_ctx, msg);
        break;

    case VFIO_USER_DEVICE_SET_IRQS:
        ret = handle_device_set_irqs(vfu_ctx, msg);
        break;

    case VFIO_USER_REGION_READ:
    case VFIO_USER_REGION_WRITE:
        ret = handle_region_access(vfu_ctx, msg);
        break;

    case VFIO_USER_DEVICE_RESET:
        ret = handle_device_reset(vfu_ctx);
        break;

    case VFIO_USER_DIRTY_PAGES:
        // FIXME: don't allow migration calls if migration == NULL
        if (vfu_ctx->dma != NULL) {
            ret = handle_dirty_pages(vfu_ctx, msg);
        } else {
            ret = 0;
        }
        break;

    default:
        vfu_log(vfu_ctx, LOG_ERR, "bad command %d", msg->hdr.cmd);
        ret = -EINVAL;
        break;
    }

    return ret;
}
UNIT_TEST_SYMBOL(exec_command);
#define exec_command __wrap_exec_command


static void
free_msg(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    size_t i;

    if (msg == NULL) {
        return;
    }

    free(msg->in_data);

    // FIXME: only complain if we processed command
    for (i = 0; i < msg->nr_in_fds; i++) {
        if (msg->in_fds[i] != -1) {
            vfu_log(vfu_ctx, LOG_DEBUG,
                    "closing unexpected fd %d (index %zu) from cmd %u",
                    msg->in_fds[i], i, msg->hdr.cmd);
            close(msg->in_fds[i]);
        }
    }

    free(msg->in_fds);

    for (i = 0; i < msg->nr_out_fds; i++) {
        assert(msg->out_fds[i] != -1);
        close(msg->out_fds[i]);
    }

    free(msg->out_fds);

    assert(msg->out_data == NULL || msg->out_iovecs == NULL);

    free(msg->out_data);

    /*
     * Each iov_base refers to data we don't want to free, but we *do* want to
     * free the allocated array of iovecs if there is one.
     */
    free(msg->out_iovecs);

    free(msg);
}

/*
 * Handle requests over the vfio-user socket. This can return immediately if we
 * are non-blocking, and there is no request from the client ready to read from
 * the socket. Otherwise, we synchronously process the request in place, and
 * possibly reply.
 */
int
process_request(vfu_ctx_t *vfu_ctx)
{
    vfu_msg_t *msg = NULL;
    int ret;

    assert(vfu_ctx != NULL);

    ret = get_request_header(vfu_ctx, &msg);

    if (ret < 0) {
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            ret = 0;
        }
        goto out;
    }

    ret = validate_header(vfu_ctx, msg);
    if (ret < 0) {
        goto out;
    }

    msg->in_size = msg->hdr.msg_size - sizeof(msg->hdr);

    if (msg->in_size > 0) {
        ret = vfu_ctx->tran->recv_body(vfu_ctx, msg);

        if (ret < 0) {
            goto out;
        }
    }

    if (!should_exec_command(vfu_ctx, msg->hdr.cmd)) {
        ret = -EINVAL;
        goto out;
    }

    ret = exec_command(vfu_ctx, msg);

    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: cmd %d failed: %s", msg->hdr.msg_id,
                msg->hdr.cmd, strerror(-ret));
    }

    if (msg->hdr.flags.no_reply) {
        /*
         * A failed client request is not a failure of process_request() itself.
         */
        ret = 0;
    } else {
        ret = vfu_ctx->tran->reply(vfu_ctx, msg, -ret);
        if (unlikely(ret < 0)) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to reply: %s", strerror(-ret));
        }
    }

out:
    free_msg(vfu_ctx, msg);
    return ret;
}
UNIT_TEST_SYMBOL(process_request);
#define process_request __wrap_process_request

int
vfu_realize_ctx(vfu_ctx_t *vfu_ctx)
{
    vfu_reg_info_t *cfg_reg;
    const vfu_reg_info_t zero_reg = { 0 };
    uint32_t max_ivs = 0, i;
    size_t size;

    if (vfu_ctx->realized) {
        return 0;
    }

    cfg_reg = &vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX];

    // Set a default config region if none provided.
    /* TODO should it be enough to check that the size of region is 0? */
    if (memcmp(cfg_reg, &zero_reg, sizeof(*cfg_reg)) == 0) {
        cfg_reg->flags = VFU_REGION_FLAG_RW;
        cfg_reg->size = PCI_CFG_SPACE_SIZE;
    }

    // This may have been allocated by vfu_setup_pci_config_hdr().
    if (vfu_ctx->pci.config_space == NULL) {
        vfu_ctx->pci.config_space = calloc(1, cfg_reg->size);
        if (vfu_ctx->pci.config_space == NULL) {
            return ERROR_INT(ENOMEM);
        }
    }

    // Set type for region registers.
    for (i = 0; i < PCI_BARS_NR; i++) {
        if (!(vfu_ctx->reg_info[i].flags & VFU_REGION_FLAG_MEM)) {
            vfu_ctx->pci.config_space->hdr.bars[i].io.region_type |= 0x1;
        }
    }

    if (vfu_ctx->irqs == NULL) {
        /*
         * FIXME need to check that the number of MSI and MSI-X IRQs are valid
         * (1, 2, 4, 8, 16 or 32 for MSI and up to 2048 for MSI-X).
         */

        // Work out highest count of irq vectors.
        for (i = 0; i < VFU_DEV_NUM_IRQS; i++) {
            if (max_ivs < vfu_ctx->irq_count[i]) {
                max_ivs = vfu_ctx->irq_count[i];
            }
        }

        // FIXME: assert(max_ivs > 0)?
        size = sizeof(int) * max_ivs;
        vfu_ctx->irqs = calloc(1, sizeof(vfu_irqs_t) + size);
        if (vfu_ctx->irqs == NULL) {
            // vfu_ctx->pci.config_space should be free'ed by vfu_destroy_ctx().
            return ERROR_INT(ENOMEM);
        }

        // Set context irq information.
        for (i = 0; i < max_ivs; i++) {
            vfu_ctx->irqs->efds[i] = -1;
        }
        vfu_ctx->irqs->err_efd = -1;
        vfu_ctx->irqs->req_efd = -1;
        vfu_ctx->irqs->max_ivs = max_ivs;

        // Reflect on the config space whether INTX is available.
        if (vfu_ctx->irq_count[VFU_DEV_INTX_IRQ] != 0) {
            vfu_ctx->pci.config_space->hdr.intr.ipin = 1; // INTA#
        }
    }

    if (vfu_ctx->pci.nr_caps != 0) {
        vfu_ctx->pci.config_space->hdr.sts.cl = 0x1;
    }

    vfu_ctx->realized = true;

    return 0;
}

int
vfu_run_ctx(vfu_ctx_t *vfu_ctx)
{
    int err;
    bool blocking;

    assert(vfu_ctx != NULL);

    if (!vfu_ctx->realized) {
        return ERROR_INT(EINVAL);
    }

    blocking = !(vfu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB);
    do {
        err = process_request(vfu_ctx);
    } while (err == 0 && blocking);

    return err == 0 ? 0 : ERROR_INT(-err);
}

static void
free_sparse_mmap_areas(vfu_ctx_t *vfu_ctx)
{
    int i;

    assert(vfu_ctx != NULL);

    for (i = 0; i < (int)vfu_ctx->nr_regions; i++) {
        free(vfu_ctx->reg_info[i].mmap_areas);
    }
}

void
vfu_destroy_ctx(vfu_ctx_t *vfu_ctx)
{

    if (vfu_ctx == NULL) {
        return;
    }

    free(vfu_ctx->uuid);
    free(vfu_ctx->pci.config_space);
    if (vfu_ctx->tran->detach != NULL) {
        vfu_ctx->tran->detach(vfu_ctx);
    }

    if (vfu_ctx->tran->fini != NULL) {
        vfu_ctx->tran->fini(vfu_ctx);
    }

    if (vfu_ctx->dma != NULL) {
        dma_controller_destroy(vfu_ctx->dma);
    }
    free_sparse_mmap_areas(vfu_ctx);
    free(vfu_ctx->reg_info);
    free(vfu_ctx->migration);
    free(vfu_ctx->irqs);
    free(vfu_ctx);
    // FIXME: Maybe close any open irq efds? Unmap stuff?
}

void *
vfu_get_private(vfu_ctx_t *vfu_ctx)
{
    assert(vfu_ctx != NULL);

    return vfu_ctx->pvt;
}

vfu_ctx_t *
vfu_create_ctx(vfu_trans_t trans, const char *path, int flags, void *pvt,
               vfu_dev_type_t dev_type)
{
    vfu_ctx_t *vfu_ctx = NULL;
    int err = 0;
    size_t i;

    //FIXME: Validate arguments.

    if (trans != VFU_TRANS_SOCK) {
        return ERROR_PTR(ENOTSUP);
    }

    if (dev_type != VFU_DEV_TYPE_PCI) {
        return ERROR_PTR(EINVAL);
    }

    vfu_ctx = calloc(1, sizeof(vfu_ctx_t));
    if (vfu_ctx == NULL) {
        return ERROR_PTR(ENOMEM);
    }

    vfu_ctx->dev_type = dev_type;
    vfu_ctx->tran = &tran_sock_ops;
    vfu_ctx->tran_data = NULL;
    vfu_ctx->pvt = pvt;
    vfu_ctx->flags = flags;
    vfu_ctx->log_level = LOG_ERR;

    vfu_ctx->uuid = strdup(path);
    if (vfu_ctx->uuid == NULL) {
        err = -errno;
        goto err_out;
    }

    /*
     * FIXME: Now we always allocate for migration region. Check if its better
     * to seperate migration region from standard regions in vfu_ctx.reg_info
     * and move it into vfu_ctx.migration.
     */
    vfu_ctx->nr_regions = VFU_PCI_DEV_NUM_REGIONS;
    vfu_ctx->reg_info = calloc(vfu_ctx->nr_regions, sizeof(*vfu_ctx->reg_info));
    if (vfu_ctx->reg_info == NULL) {
        err = -ENOMEM;
        goto err_out;
    }

    if (vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_ERR_IRQ, 1) == -1) {
        err = -errno;
        goto err_out;
    }
    if (vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_REQ_IRQ, 1) == -1) {
        err = -errno;
        goto err_out;
    }

    if (vfu_ctx->tran->init != NULL) {
        err = vfu_ctx->tran->init(vfu_ctx);
        if (err < 0) {
            goto err_out;
        }
    }

    for (i = 0; i< vfu_ctx->nr_regions; i++) {
        vfu_ctx->reg_info[i].fd = -1;
    }

    return vfu_ctx;

err_out:
    vfu_destroy_ctx(vfu_ctx);

    return ERROR_PTR(-err);
}

int
vfu_attach_ctx(vfu_ctx_t *vfu_ctx)
{

    assert(vfu_ctx != NULL);

    return vfu_ctx->tran->attach(vfu_ctx);
}

int
vfu_get_poll_fd(vfu_ctx_t *vfu_ctx)
{

    assert(vfu_ctx != NULL);

    return vfu_ctx->tran->get_poll_fd(vfu_ctx);
}

int
vfu_setup_log(vfu_ctx_t *vfu_ctx, vfu_log_fn_t *log, int log_level)
{

    if (log_level != LOG_ERR && log_level != LOG_INFO && log_level != LOG_DEBUG) {
        return ERROR_INT(EINVAL);
    }

    vfu_ctx->log = log;
    vfu_ctx->log_level = log_level;

    return 0;
}

static int
copyin_mmap_areas(vfu_reg_info_t *reg_info,
                  struct iovec *mmap_areas, uint32_t nr_mmap_areas)
{
    size_t size = nr_mmap_areas * sizeof(*mmap_areas);

    if (mmap_areas == NULL || nr_mmap_areas ==  0) {
        return 0;
    }

    reg_info->mmap_areas = malloc(size);

    if (reg_info->mmap_areas == NULL) {
        return -ENOMEM;
    }

    memcpy(reg_info->mmap_areas, mmap_areas, size);
    reg_info->nr_mmap_areas = nr_mmap_areas;

    return 0;
}

static bool
ranges_intersect(size_t off1, size_t size1, size_t off2, size_t size2)
{
    /*
     * For two ranges to intersect, the start of each range must be before the
     * end of the other range.
     * TODO already defined in lib/pci_caps.c, maybe introduce a file for misc
     * utility functions?
     */
    return (off1 < (off2 + size2) && off2 < (off1 + size1));
}

static bool
maps_over_migr_regs(struct iovec *iov)
{
    return ranges_intersect(0, vfu_get_migr_register_area_size(),
                            (size_t)iov->iov_base, iov->iov_len);
}

static bool
validate_sparse_mmaps_for_migr_reg(vfu_reg_info_t *reg)
{
    int i;

    for (i = 0; i < reg->nr_mmap_areas; i++) {
        if (maps_over_migr_regs(&reg->mmap_areas[i])) {
            return false;
        }
    }
    return true;
}

int
vfu_setup_region(vfu_ctx_t *vfu_ctx, int region_idx, size_t size,
                 vfu_region_access_cb_t *cb, int flags,
                 struct iovec *mmap_areas, uint32_t nr_mmap_areas, int fd)
{
    struct iovec whole_region = { .iov_base = 0, .iov_len = size };
    vfu_reg_info_t *reg;
    size_t i;
    int ret = 0;

    assert(vfu_ctx != NULL);

    if ((mmap_areas == NULL) != (nr_mmap_areas == 0) ||
        (mmap_areas != NULL && fd == -1)) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid mappable region arguments");
        return ERROR_INT(EINVAL);
    }

    if (region_idx < VFU_PCI_DEV_BAR0_REGION_IDX ||
        region_idx >= VFU_PCI_DEV_NUM_REGIONS) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid region index %d", region_idx);
        return ERROR_INT(EINVAL);
    }

    /*
     * PCI config space is never mappable or of type mem.
     */
    if (region_idx == VFU_PCI_DEV_CFG_REGION_IDX &&
        flags != VFU_REGION_FLAG_RW) {
        return ERROR_INT(EINVAL);
    }

    if (region_idx == VFU_PCI_DEV_MIGR_REGION_IDX &&
        size < vfu_get_migr_register_area_size()) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid migration region size %d", size);
        return ERROR_INT(EINVAL);
    }

    for (i = 0; i < nr_mmap_areas; i++) {
        struct iovec *iov = &mmap_areas[i];
        if ((size_t)iov->iov_base + iov->iov_len > size) {
            return ERROR_INT(EINVAL);
        }
    }

    reg = &vfu_ctx->reg_info[region_idx];

    reg->flags = flags;
    reg->size = size;
    reg->cb = cb;
    reg->fd = fd;

    if (mmap_areas == NULL && reg->fd != -1) {
        mmap_areas = &whole_region;
        nr_mmap_areas = 1;
    }

    if (nr_mmap_areas > 0) {
        ret = copyin_mmap_areas(reg, mmap_areas, nr_mmap_areas);
        if (ret < 0) {
            goto out;
        }
    }

    if (region_idx == VFU_PCI_DEV_MIGR_REGION_IDX) {
        if (!validate_sparse_mmaps_for_migr_reg(reg)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "migration registers cannot be memory mapped");
            ret = -EINVAL;
            goto out;
        }

        /*
         * FIXME keeping for now until we're sure we're OK with fixing the
         * migration region index.
         */
        vfu_ctx->migr_reg = reg;
    }
out:
    if (ret < 0) {
        free(reg->mmap_areas);
        memset(reg, 0, sizeof(*reg));
        return ERROR_INT(-ret);
    }
    return 0;
}

int
vfu_setup_device_reset_cb(vfu_ctx_t *vfu_ctx, vfu_reset_cb_t *reset)
{

    assert(vfu_ctx != NULL);
    vfu_ctx->reset = reset;

    return 0;
}

int
vfu_setup_device_dma_cb(vfu_ctx_t *vfu_ctx, vfu_map_dma_cb_t *map_dma,
                        vfu_unmap_dma_cb_t *unmap_dma)
{

    assert(vfu_ctx != NULL);

    // Create the internal DMA controller.
    vfu_ctx->dma = dma_controller_create(vfu_ctx, VFU_DMA_REGIONS);
    if (vfu_ctx->dma == NULL) {
        return ERROR_INT(ENOMEM);
    }

    vfu_ctx->map_dma = map_dma;
    vfu_ctx->unmap_dma = unmap_dma;

    return 0;
}

int
vfu_setup_device_nr_irqs(vfu_ctx_t *vfu_ctx, enum vfu_dev_irq_type type,
                         uint32_t count)
{

    assert(vfu_ctx != NULL);

    if (type >= VFU_DEV_NUM_IRQS) {
        vfu_log(vfu_ctx, LOG_ERR, "Invalid IRQ type index %u", type);
        return ERROR_INT(EINVAL);
    }

    vfu_ctx->irq_count[type] = count;

    return 0;
}

int
vfu_setup_device_migration_callbacks(vfu_ctx_t *vfu_ctx,
                                     const vfu_migration_callbacks_t *callbacks,
                                     uint64_t data_offset)
{
    int ret = 0;

    assert(vfu_ctx != NULL);
    assert(callbacks != NULL);

    if (vfu_ctx->migr_reg == NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "no device migration region");
        return ERROR_INT(EINVAL);
    }

    if (callbacks->version != VFU_MIGR_CALLBACKS_VERS) {
        vfu_log(vfu_ctx, LOG_ERR, "unsupported migration callbacks version %d",
                callbacks->version);
        return ERROR_INT(EINVAL);
    }

    vfu_ctx->migration = init_migration(callbacks, data_offset, &ret);
    if (vfu_ctx->migration == NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to initialize device migration");
        return ERROR_INT(ret);
    }

    return 0;
}

inline vfu_reg_info_t *
vfu_get_region_info(vfu_ctx_t *vfu_ctx)
{
    assert(vfu_ctx != NULL);
    return vfu_ctx->reg_info;
}

inline int
vfu_addr_to_sg(vfu_ctx_t *vfu_ctx, dma_addr_t dma_addr,
               uint32_t len, dma_sg_t *sg, int max_sg, int prot)
{
    assert(vfu_ctx != NULL);

    if (unlikely(vfu_ctx->unmap_dma == NULL)) {
        return ERROR_INT(EINVAL);
    }

    return dma_addr_to_sg(vfu_ctx->dma, dma_addr, len, sg, max_sg, prot);
}

inline int
vfu_map_sg(vfu_ctx_t *vfu_ctx, const dma_sg_t *sg,
	       struct iovec *iov, int cnt)
{
    int ret;

    if (unlikely(vfu_ctx->unmap_dma == NULL)) {
        return ERROR_INT(EINVAL);
    }

    ret = dma_map_sg(vfu_ctx->dma, sg, iov, cnt);
    if (ret < 0) {
        return ERROR_INT(-ret);
    }

    return 0;
}

inline void
vfu_unmap_sg(vfu_ctx_t *vfu_ctx, const dma_sg_t *sg, struct iovec *iov, int cnt)
{
    if (unlikely(vfu_ctx->unmap_dma == NULL)) {
        return;
    }
    return dma_unmap_sg(vfu_ctx->dma, sg, iov, cnt);
}

int
vfu_dma_read(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data)
{
    struct vfio_user_dma_region_access *dma_recv;
    struct vfio_user_dma_region_access dma_send;
    int recv_size;
    int msg_id = 1, ret;

    assert(vfu_ctx != NULL);
    assert(sg != NULL);

    recv_size = sizeof(*dma_recv) + sg->length;

    dma_recv = calloc(recv_size, 1);
    if (dma_recv == NULL) {
        return ERROR_INT(ENOMEM);
    }

    dma_send.addr = sg->dma_addr;
    dma_send.count = sg->length;
    ret = vfu_ctx->tran->send_msg(vfu_ctx, msg_id, VFIO_USER_DMA_READ,
                                  &dma_send, sizeof(dma_send), NULL,
                                  dma_recv, recv_size);
    memcpy(data, dma_recv->data, sg->length); /* FIXME no need for memcpy */
    free(dma_recv);

    return ret < 0 ? ERROR_INT(-ret) : 0;
}

int
vfu_dma_write(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data)
{
    struct vfio_user_dma_region_access *dma_send, dma_recv;
    int send_size = sizeof(*dma_send) + sg->length;
    int msg_id = 1, ret;

    assert(vfu_ctx != NULL);
    assert(sg != NULL);

    dma_send = calloc(send_size, 1);
    if (dma_send == NULL) {
        return ERROR_INT(ENOMEM);
    }
    dma_send->addr = sg->dma_addr;
    dma_send->count = sg->length;
    memcpy(dma_send->data, data, sg->length); /* FIXME no need to copy! */
    ret = vfu_ctx->tran->send_msg(vfu_ctx, msg_id, VFIO_USER_DMA_WRITE,
                                  dma_send, send_size, NULL,
                                  &dma_recv, sizeof(dma_recv));
    free(dma_send);

    return ret < 0 ? ERROR_INT(-ret) : 0;
}

uint64_t
vfu_region_to_offset(uint32_t region)
{
    return region_to_offset(region);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
