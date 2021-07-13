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

static void vfu_reset_ctx(vfu_ctx_t *vfu_ctx, const char *reason);

EXPORT void
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
 * Sparse mmap information stays after struct vfio_region_info and cap_offset
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
        type = (struct vfio_region_info_cap_type *)header;
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
            return ERROR_INT(ENOMEM);
        }
        sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
        sparse->header.version = 1;
        sparse->header.next = 0;
        sparse->nr_areas = *nr_fds = nr_mmap_areas;

        for (i = 0; i < nr_mmap_areas; i++) {
            struct iovec *iov = &vfu_reg->mmap_areas[i];

            vfu_log(vfu_ctx, LOG_DEBUG, "%s: area %d [%p, %p)", __func__,
                    i, iov->iov_base, iov_end(iov));

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
        if (ret == -1) {
            return ret;
        }
    } else if (region_index == VFU_PCI_DEV_MIGR_REGION_IDX) {
        if (vfu_ctx->migration == NULL) {
            return ERROR_INT(EINVAL);
        }

        ret = migration_region_access(vfu_ctx, buf, count, offset, is_write);
    } else {
        vfu_region_access_cb_t *cb = vfu_ctx->reg_info[region_index].cb;

        if (cb == NULL) {
            vfu_log(vfu_ctx, LOG_ERR, "no callback for region %zu",
                    region_index);
            return ERROR_INT(EINVAL);
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
        vfu_log(vfu_ctx, LOG_ERR, "message size too small (%zu)", size);
        return false;
    }

    if (ra->count > SERVER_MAX_DATA_XFER_SIZE) {
        vfu_log(vfu_ctx, LOG_ERR, "region access count too large (%u)",
                ra->count);
        return false;
    }

    if (cmd == VFIO_USER_REGION_WRITE && size - sizeof(*ra) != ra->count) {
        vfu_log(vfu_ctx, LOG_ERR, "region write count too small: "
                "expected %lu, got %u", size - sizeof(*ra), ra->count);
        return false;
    }

    index = ra->region;

    if (index >= vfu_ctx->nr_regions) {
        vfu_log(vfu_ctx, LOG_ERR, "bad region index %zu", index);
        return false;
    }

    // FIXME: need to audit later for wraparound
    if (ra->offset + ra->count > vfu_ctx->reg_info[index].size) {
        vfu_log(vfu_ctx, LOG_ERR, "out of bounds region access %#lx-%#lx "
                "(size %u)", ra->offset, ra->offset + ra->count,
                vfu_ctx->reg_info[index].size);

        return false;
    }

    if (device_is_stopped_and_copying(vfu_ctx->migration) &&
        index != VFU_PCI_DEV_MIGR_REGION_IDX) {
        vfu_log(vfu_ctx, LOG_ERR,
                "cannot access region %zu while device in stop-and-copy state",
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
        return ERROR_INT(EINVAL);
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
        return -1;
    }

    out_ra = msg->out_data;
    out_ra->region = in_ra->region;
    out_ra->offset = in_ra->offset;
    out_ra->count = in_ra->count;

    if (msg->hdr.cmd == VFIO_USER_REGION_READ) {
        buf = (char *)(&out_ra->data);
    } else {
        buf = (char *)(&in_ra->data);
    }

    ret = region_access(vfu_ctx, in_ra->region, buf, in_ra->count,
                        in_ra->offset, msg->hdr.cmd == VFIO_USER_REGION_WRITE);

    if (ret != in_ra->count) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to %s %#lx-%#lx: %m",
                msg->hdr.cmd == VFIO_USER_REGION_WRITE ? "write" : "read",
                in_ra->offset, in_ra->offset + in_ra->count - 1);
        /* FIXME we should return whatever has been accessed, not an error */
        if (ret >= 0) {
            ret = ERROR_INT(EINVAL);
        }
        return ret;
    }

    out_ra->count = ret;

    return 0;
}

static int
handle_device_get_info(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_user_device_info *in_info;
    struct vfio_user_device_info *out_info;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    in_info = msg->in_data;

    if (msg->in_size < sizeof(*in_info) || in_info->argsz < sizeof(*out_info)) {
        return ERROR_INT(EINVAL);
    }

    msg->out_size = sizeof (*out_info);
    msg->out_data = calloc(1, sizeof(*out_info));

    if (msg->out_data == NULL) {
        return -1;
    }

    out_info = msg->out_data;
    out_info->argsz = sizeof(*out_info);
    out_info->flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
    out_info->num_regions = vfu_ctx->nr_regions;
    out_info->num_irqs = VFU_DEV_NUM_IRQS;

    vfu_log(vfu_ctx, LOG_DEBUG, "devinfo flags %#x, num_regions %d, "
            "num_irqs %d", out_info->flags, out_info->num_regions,
            out_info->num_irqs);

    return 0;
}

int
handle_device_get_region_info(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_region_info *in_info;
    struct vfio_region_info *out_info;
    vfu_reg_info_t *vfu_reg;
    size_t caps_size = 0;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    in_info = msg->in_data;

    if (msg->in_size < sizeof(*in_info) || in_info->argsz < sizeof(*out_info)) {
        return ERROR_INT(EINVAL);
    }

    if (in_info->index >= vfu_ctx->nr_regions) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad region index %d in get region info",
                in_info->index);
        return ERROR_INT(EINVAL);
    }

    vfu_reg = &vfu_ctx->reg_info[in_info->index];

    if (vfu_reg->size > 0) {
        caps_size = get_vfio_caps_size(in_info->index == VFU_PCI_DEV_MIGR_REGION_IDX,
                                       vfu_reg);
    }

    msg->out_size = MIN(sizeof(*out_info) + caps_size, in_info->argsz);
    msg->out_data = calloc(1, msg->out_size);

    if (msg->out_data == NULL) {
        return -1;
    }

    out_info = msg->out_data;

    /* This might be more than the buffer we actually return. */
    out_info->argsz = sizeof(*out_info) + caps_size;
    out_info->index = in_info->index;
    out_info->offset = vfu_reg->offset;
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
            dev_get_caps(vfu_ctx, vfu_reg,
                         in_info->index == VFU_PCI_DEV_MIGR_REGION_IDX,
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
       return ERROR_INT(EINVAL);
   }

   fd = fds[index];
   fds[index] = -1;
   return fd;
}

int
handle_dma_map(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg,
               struct vfio_user_dma_map *dma_map)
{
    char rstr[1024];
    int fd = -1;
    int ret;
    uint32_t prot = 0;
    bool exist = false;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);
    assert(dma_map != NULL);

    if (msg->in_size < sizeof(*dma_map) || dma_map->argsz < sizeof(*dma_map)) {
        vfu_log(vfu_ctx, LOG_ERR, "bad DMA map region size=%zu argsz=%u",
                msg->in_size, dma_map->argsz);
        return ERROR_INT(EINVAL);
    }

    snprintf(rstr, sizeof(rstr), "[%#lx, %#lx) offset=%#lx flags=%#x",
             dma_map->addr, dma_map->addr + dma_map->size, dma_map->offset,
             dma_map->flags);

    vfu_log(vfu_ctx, LOG_DEBUG, "adding DMA region %s", rstr);

    if (dma_map->flags & VFIO_USER_F_DMA_REGION_READ) {
        prot |= PROT_READ;
        dma_map->flags &= ~VFIO_USER_F_DMA_REGION_READ;
    }

    if (dma_map->flags & VFIO_USER_F_DMA_REGION_WRITE) {
        prot |= PROT_WRITE;
        dma_map->flags &= ~VFIO_USER_F_DMA_REGION_WRITE;
    }

    if (dma_map->flags != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "bad flags=%#x", dma_map->flags);
        return ERROR_INT(EINVAL);
    }

    if (msg->nr_in_fds > 0) {
        fd = consume_fd(msg->in_fds, msg->nr_in_fds, 0);
        if (fd < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to add DMA region %s: %m", rstr);
            return -1;
        }
    }

    ret = dma_controller_add_region(vfu_ctx->dma, (void *)dma_map->addr,
                                    dma_map->size, fd, dma_map->offset,
                                    prot, &exist);
    if (ret < 0) {
        ret = errno;
        vfu_log(vfu_ctx, LOG_ERR, "failed to add DMA region %s: %m", rstr);
        if (fd != -1) {
            close(fd);
        }
        return ERROR_INT(ret);
    }

    if (vfu_ctx->dma_register != NULL && !exist) {
        vfu_ctx->dma_register(vfu_ctx, &vfu_ctx->dma->regions[ret].info);
    }
    return 0;
}

int
handle_dma_unmap(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg,
                 struct vfio_user_dma_unmap *dma_unmap)
{
    int ret;
    char rstr[1024];

    assert(vfu_ctx != NULL);
    assert(msg != NULL);
    assert(dma_unmap != NULL);

    if (msg->in_size < sizeof(*dma_unmap) || dma_unmap->argsz < sizeof(*dma_unmap)) {
        vfu_log(vfu_ctx, LOG_ERR, "bad DMA unmap region size=%zu argsz=%u",
                msg->in_size, dma_unmap->argsz);
        return ERROR_INT(EINVAL);
    }

    snprintf(rstr, sizeof(rstr), "[%#lx, %#lx) flags=%#x",
             dma_unmap->addr, dma_unmap->addr + dma_unmap->size, dma_unmap->flags);

    vfu_log(vfu_ctx, LOG_DEBUG, "removing DMA region %s", rstr);

    msg->out_size = sizeof(*dma_unmap);

    if (dma_unmap->flags == VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP) {
        if (msg->in_size < sizeof(*dma_unmap) + sizeof(*dma_unmap->bitmap)
            || dma_unmap->argsz < sizeof(*dma_unmap) + sizeof(*dma_unmap->bitmap) + dma_unmap->bitmap->size) {
            vfu_log(vfu_ctx, LOG_ERR, "bad message size=%#lx argsz=%#x",
                    msg->in_size, dma_unmap->argsz);

            /*
             * Ideally we should set argsz in the reply and fail the request
             * with a struct vfio_user_dma_unmap payload, however this isn't
             * currently supported. Instead, we simply fail the request,
             * that's what VFIO does anyway.
             */
            return ERROR_INT(EINVAL);
        }
        /*
         * TODO this could be a separate function, but the implementation is
         * temporary anyway since we're moving dirty page tracking out of
         * the DMA controller.
         */
        msg->out_size += sizeof(*dma_unmap->bitmap) + dma_unmap->bitmap->size;
    } else if (dma_unmap->flags != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "bad flags=%#x", dma_unmap->flags);
        return ERROR_INT(ENOTSUP);
    }



    msg->out_data = malloc(msg->out_size);
    if (msg->out_data == NULL) {
        return ERROR_INT(ENOMEM);
    }
    memcpy(msg->out_data, dma_unmap, sizeof(*dma_unmap));

    if (dma_unmap->flags & VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP) {
        memcpy(msg->out_data + sizeof(*dma_unmap), dma_unmap->bitmap, sizeof(*dma_unmap->bitmap));
        ret = dma_controller_dirty_page_get(vfu_ctx->dma,
                                            (vfu_dma_addr_t)dma_unmap->addr,
                                            dma_unmap->size,
                                            dma_unmap->bitmap->pgsize,
                                            dma_unmap->bitmap->size,
                                            msg->out_data + sizeof(*dma_unmap) + sizeof(*dma_unmap->bitmap));
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to get dirty page bitmap: %m");
            return -1;
        }
    }

    ret = dma_controller_remove_region(vfu_ctx->dma,
                                       (void *)dma_unmap->addr,
                                       dma_unmap->size,
                                       vfu_ctx->dma_unregister,
                                       vfu_ctx);
    if (ret < 0) {
        ret = errno;
        vfu_log(vfu_ctx, LOG_WARNING,
                "failed to remove DMA region %s: %m", rstr);
        return ERROR_INT(ret);
    }
    return ret;
}

static int
do_device_reset(vfu_ctx_t *vfu_ctx, vfu_reset_type_t reason)
{
    int ret;

    if (vfu_ctx->reset != NULL) {
        ret = vfu_ctx->reset(vfu_ctx, reason);
        if (ret < 0) {
            return ret;
        }
    }
    if (vfu_ctx->migration != NULL) {
        return handle_device_state(vfu_ctx, vfu_ctx->migration,
                                   VFIO_DEVICE_STATE_RUNNING, false);
    }
    return 0;
}

int
handle_device_reset(vfu_ctx_t *vfu_ctx, vfu_reset_type_t reason)
{
    return do_device_reset(vfu_ctx, reason);
}

static int
handle_dirty_pages_get(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_user_dirty_pages *dirty_pages_in;
    struct vfio_user_dirty_pages *dirty_pages_out;
    struct vfio_user_bitmap_range *range_in;
    struct vfio_user_bitmap_range *range_out;
    size_t argsz;
    int ret;


    dirty_pages_in = msg->in_data;

    if (msg->in_size < sizeof(*dirty_pages_in) + sizeof(*range_in)
        || dirty_pages_in->argsz < sizeof(*dirty_pages_out)) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid message size=%zu argsz=%u",
                msg->in_size, dirty_pages_in->argsz);
        return ERROR_INT(EINVAL);
    }

    range_in = msg->in_data + sizeof(*dirty_pages_in);

    /* NB: this is bound by MAX_DMA_SIZE. */
    argsz = sizeof(*dirty_pages_out) + sizeof(*range_out) +
            range_in->bitmap.size;
    msg->out_size = MIN(dirty_pages_in->argsz, argsz);
    msg->out_data = malloc(msg->out_size);
    if (msg->out_data == NULL) {
        return -1;
    }
    dirty_pages_out = msg->out_data;
    memcpy(dirty_pages_out, dirty_pages_in, sizeof(*dirty_pages_out));
    dirty_pages_out->argsz = argsz;

    /*
     * If the reply doesn't fit, reply with just the dirty pages header, giving
     * the needed argsz. Typically this shouldn't happen, as the client knows
     * the needed reply size and has already provided the correct bitmap size.
     */
    if (dirty_pages_in->argsz >= argsz) {
        void *bitmap_out = msg->out_data + sizeof(*dirty_pages_out)
                           + sizeof(*range_out);
        range_out = msg->out_data + sizeof(*dirty_pages_out);
        memcpy(range_out, range_in, sizeof(*range_out));
        ret = dma_controller_dirty_page_get(vfu_ctx->dma,
                                            (vfu_dma_addr_t)range_in->iova,
                                            range_in->size,
                                            range_in->bitmap.pgsize,
                                            range_in->bitmap.size, bitmap_out);
        if (ret != 0) {
            ret = errno;
            vfu_log(vfu_ctx, LOG_WARNING,
                    "failed to get dirty bitmap from DMA controller: %m");
            free(msg->out_data);
            msg->out_data = NULL;
            msg->out_size = 0;
            return ERROR_INT(ret);
        }
    }
    return 0;
}

static int
handle_dirty_pages(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    struct vfio_user_dirty_pages *dirty_pages = msg->in_data;
    int ret;

    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    if (msg->in_size < sizeof(*dirty_pages) ||
        dirty_pages->argsz < sizeof(*dirty_pages)) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid message size %zu", msg->in_size);
        return ERROR_INT(EINVAL);
    }

    if (vfu_ctx->migration == NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "migration not configured");
        return ERROR_INT(ENOTSUP);
    }

    switch (dirty_pages->flags) {
    case VFIO_IOMMU_DIRTY_PAGES_FLAG_START:
        ret = dma_controller_dirty_page_logging_start(vfu_ctx->dma,
                  migration_get_pgsize(vfu_ctx->migration));
        break;

    case VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP:
        dma_controller_dirty_page_logging_stop(vfu_ctx->dma);
        ret = 0;
        break;

    case VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP:
        ret = handle_dirty_pages_get(vfu_ctx, msg);
        break;

    default:
        vfu_log(vfu_ctx, LOG_ERR, "bad flags %#x", dirty_pages->flags);
        ret = ERROR_INT(EINVAL);
        break;
    }

    return ret;
}

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

static void
free_msg(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    int saved_errno = errno;
    size_t i;

    if (msg == NULL) {
        return;
    }

    free(msg->in_data);

    for (i = 0; i < msg->nr_in_fds; i++) {
        if (msg->in_fds[i] != -1) {
            if (msg->processed_cmd) {
                vfu_log(vfu_ctx, LOG_DEBUG,
                        "closing unexpected fd %d (index %zu) from cmd %u",
                        msg->in_fds[i], i, msg->hdr.cmd);
            }
            close(msg->in_fds[i]);
        }
    }

    free(msg->in_fds);
    free(msg->out_fds);

    assert(msg->out_data == NULL || msg->out_iovecs == NULL);

    free(msg->out_data);

    /*
     * Each iov_base refers to data we don't want to free, but we *do* want to
     * free the allocated array of iovecs if there is one.
     */
    free(msg->out_iovecs);

    free(msg);

    errno = saved_errno;
}

/*
 * Note that we avoid any malloc() before we see data, as this is used for
 * polling by SPDK.
 */
static int
get_request_header(vfu_ctx_t *vfu_ctx, vfu_msg_t **msgp)
{
    int fds[VFIO_USER_CLIENT_MAX_MSG_FDS_LIMIT] = { 0 };
    struct vfio_user_header hdr = { 0, };
    size_t nr_fds = VFIO_USER_CLIENT_MAX_MSG_FDS_LIMIT;
    size_t i;
    int ret;

    ret = vfu_ctx->tran->get_request_header(vfu_ctx, &hdr, fds, &nr_fds);

    if (unlikely(ret < 0)) {
        switch (errno) {
        case EAGAIN:
            return -1;

        case ENOMSG:
            vfu_reset_ctx(vfu_ctx, "closed");
            return ERROR_INT(ENOTCONN);

        case ECONNRESET:
            vfu_reset_ctx(vfu_ctx, "reset");
            return ERROR_INT(ENOTCONN);

        default:
            vfu_log(vfu_ctx, LOG_ERR, "failed to receive request: %m");
            return -1;
        }
    }

    *msgp = alloc_msg(&hdr, fds, nr_fds);

    if (*msgp == NULL) {
        ret = -1;
        goto out;
    }

    return 0;

out:
    if (ret != 0) {
        int saved_errno = errno;
        for (i = 0; i < nr_fds; i++) {
            close(fds[i]);
        }
        errno = saved_errno;
    }

    return ret;
}

static bool
is_valid_header(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    if (msg->hdr.flags.type != VFIO_USER_F_TYPE_COMMAND) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: not a command req",
                msg->hdr.msg_id);
        return false;
    }

    if (msg->hdr.msg_size < sizeof(msg->hdr)) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: bad size %u in header",
                msg->hdr.msg_id, msg->hdr.msg_size);
        return false;
    } else if (msg->hdr.msg_size == sizeof(msg->hdr) &&
               msg->hdr.cmd != VFIO_USER_DEVICE_RESET) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: no payload for cmd%u",
                msg->hdr.msg_id, msg->hdr.cmd);
        return false;
    } else if (msg->hdr.msg_size > SERVER_MAX_MSG_SIZE) {
        /*
         * We know we can reject this: all normal requests shouldn't need this
         * amount of space, including VFIO_USER_REGION_WRITE, which should be
         * bound by max_data_xfer_size.
         */
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: size of %u is too large",
                msg->hdr.msg_id, msg->hdr.msg_size);
        return false;
    }

    return true;
}

bool
MOCK_DEFINE(cmd_allowed_when_stopped_and_copying)(uint16_t cmd)
{
    return cmd == VFIO_USER_REGION_READ ||
           cmd == VFIO_USER_REGION_WRITE ||
           cmd == VFIO_USER_DIRTY_PAGES;
}

bool
MOCK_DEFINE(should_exec_command)(vfu_ctx_t *vfu_ctx, uint16_t cmd)
{
    if (device_is_stopped_and_copying(vfu_ctx->migration)) {
        if (!cmd_allowed_when_stopped_and_copying(cmd)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "bad command %d while device in stop-and-copy state", cmd);
            return false;
        }
    } else if (device_is_stopped(vfu_ctx->migration)) {
        if (!cmd_allowed_when_stopped_and_copying(cmd)) {
            vfu_log(vfu_ctx, LOG_ERR,
                   "bad command %d while device in stopped state", cmd);
            return false;
        }
    }
    return true;
}

int
exec_command(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    int ret = 0;

    msg->processed_cmd = true;

    switch (msg->hdr.cmd) {
    case VFIO_USER_DMA_MAP:
        if (vfu_ctx->dma != NULL) {
            ret = handle_dma_map(vfu_ctx, msg, msg->in_data);
        }
        break;

    case VFIO_USER_DMA_UNMAP:
        if (vfu_ctx->dma != NULL) {
            ret = handle_dma_unmap(vfu_ctx, msg, msg->in_data);
        }
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
        vfu_log(vfu_ctx, LOG_INFO, "device reset by client");
        ret = handle_device_reset(vfu_ctx, VFU_RESET_DEVICE);
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
        msg->processed_cmd = false;
        vfu_log(vfu_ctx, LOG_ERR, "bad command %d", msg->hdr.cmd);
        ret = ERROR_INT(EINVAL);
        break;
    }

    return ret;
}

/*
 * Handle requests over the vfio-user socket. This can return immediately if we
 * are non-blocking, and there is no request from the client ready to read from
 * the socket. Otherwise, we synchronously process the request in place, and
 * possibly reply.
 */
static int
process_request(vfu_ctx_t *vfu_ctx)
{
    vfu_msg_t *msg = NULL;
    int ret;

    assert(vfu_ctx != NULL);

    ret = get_request_header(vfu_ctx, &msg);

    if (ret < 0) {
        return ret;
    }

    if (!is_valid_header(vfu_ctx, msg)) {
        ret = ERROR_INT(EINVAL);
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
        ret = ERROR_INT(EINVAL);
        goto out;
    }

    ret = exec_command(vfu_ctx, msg);

    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "msg%#hx: cmd %d failed: %m", msg->hdr.msg_id,
                msg->hdr.cmd);
    }

out:
    if (msg->hdr.flags.no_reply) {
        /*
         * A failed client request is not a failure of process_request() itself.
         */
        ret = 0;
    } else {
        ret = vfu_ctx->tran->reply(vfu_ctx, msg, ret == 0 ? 0 : errno);

        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to reply: %m");

            if (errno == ECONNRESET) {
                vfu_reset_ctx(vfu_ctx, "reset");
                errno = ENOTCONN;
            } else if (errno == ENOMSG) {
                vfu_reset_ctx(vfu_ctx, "closed");
                errno = ENOTCONN;
            }
        }
    }

    free_msg(vfu_ctx, msg);
    return ret;
}

EXPORT int
vfu_realize_ctx(vfu_ctx_t *vfu_ctx)
{
    vfu_reg_info_t *cfg_reg;
    uint32_t max_ivs = 0, i;
    size_t size;

    if (vfu_ctx->realized) {
        return 0;
    }

    cfg_reg = &vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX];

    // Set a default config region if none provided.
    if (cfg_reg->size == 0) {
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
            return -1;
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

EXPORT int
vfu_run_ctx(vfu_ctx_t *vfu_ctx)
{
    int reqs_processed = 0;
    bool blocking;
    int err;

    assert(vfu_ctx != NULL);

    if (!vfu_ctx->realized) {
        return ERROR_INT(EINVAL);
    }

    blocking = !(vfu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB);

    do {
        err = process_request(vfu_ctx);

        if (err == 0) {
            reqs_processed++;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                err = 0;
            }
        }
    } while (err == 0 && blocking);

    return err == 0 ? reqs_processed : err;
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

static void
vfu_reset_ctx(vfu_ctx_t *vfu_ctx, const char *reason)
{
    vfu_log(vfu_ctx, LOG_INFO, "%s: %s", __func__,  reason);

    if (vfu_ctx->dma != NULL) {
        dma_controller_remove_all_regions(vfu_ctx->dma, vfu_ctx->dma_unregister,
                                          vfu_ctx);
    }

    do_device_reset(vfu_ctx, VFU_RESET_LOST_CONN);

    if (vfu_ctx->irqs != NULL) {
        irqs_reset(vfu_ctx);
    }

    if (vfu_ctx->tran->detach != NULL) {
        vfu_ctx->tran->detach(vfu_ctx);
    }
}

EXPORT void
vfu_destroy_ctx(vfu_ctx_t *vfu_ctx)
{

    if (vfu_ctx == NULL) {
        return;
    }

    vfu_reset_ctx(vfu_ctx, "destroyed");

    free(vfu_ctx->uuid);
    free(vfu_ctx->pci.config_space);

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
}

EXPORT void *
vfu_get_private(vfu_ctx_t *vfu_ctx)
{
    assert(vfu_ctx != NULL);

    return vfu_ctx->pvt;
}

EXPORT vfu_ctx_t *
vfu_create_ctx(vfu_trans_t trans, const char *path, int flags, void *pvt,
               vfu_dev_type_t dev_type)
{
    vfu_ctx_t *vfu_ctx = NULL;
    int err = 0;
    size_t i;

    if ((flags & ~(LIBVFIO_USER_FLAG_ATTACH_NB)) != 0) {
        return ERROR_PTR(EINVAL);
    }

    if (trans != VFU_TRANS_SOCK) {
        return ERROR_PTR(ENOTSUP);
    }

    if (dev_type != VFU_DEV_TYPE_PCI) {
        return ERROR_PTR(ENOTSUP);
    }

    vfu_ctx = calloc(1, sizeof(vfu_ctx_t));
    if (vfu_ctx == NULL) {
        return NULL;
    }

    vfu_ctx->dev_type = dev_type;
    vfu_ctx->tran = &tran_sock_ops;
    vfu_ctx->tran_data = NULL;
    vfu_ctx->pvt = pvt;
    vfu_ctx->flags = flags;
    vfu_ctx->log_level = LOG_ERR;

    vfu_ctx->uuid = strdup(path);
    if (vfu_ctx->uuid == NULL) {
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
        goto err_out;
    }

    for (i = 0; i < vfu_ctx->nr_regions; i++) {
        vfu_ctx->reg_info[i].fd = -1;
    }

    if (vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_ERR_IRQ, 1) == -1) {
        goto err_out;
    }
    if (vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_REQ_IRQ, 1) == -1) {
        goto err_out;
    }

    if (vfu_ctx->tran->init != NULL) {
        err = vfu_ctx->tran->init(vfu_ctx);
        if (err < 0) {
            goto err_out;
        }
    }

    return vfu_ctx;

err_out:
    err = errno;

    vfu_destroy_ctx(vfu_ctx);

    return ERROR_PTR(err);
}

EXPORT int
vfu_attach_ctx(vfu_ctx_t *vfu_ctx)
{

    assert(vfu_ctx != NULL);

    return vfu_ctx->tran->attach(vfu_ctx);
}

EXPORT int
vfu_get_poll_fd(vfu_ctx_t *vfu_ctx)
{

    assert(vfu_ctx != NULL);

    return vfu_ctx->tran->get_poll_fd(vfu_ctx);
}

EXPORT int
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
        return -1;
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

EXPORT int
vfu_setup_region(vfu_ctx_t *vfu_ctx, int region_idx, size_t size,
                 vfu_region_access_cb_t *cb, int flags,
                 struct iovec *mmap_areas, uint32_t nr_mmap_areas,
                 int fd, uint64_t offset)
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
        vfu_log(vfu_ctx, LOG_ERR, "invalid migration region size %zu", size);
        return ERROR_INT(EINVAL);
    }

    for (i = 0; i < nr_mmap_areas; i++) {
        struct iovec *iov = &mmap_areas[i];
        if ((size_t)iov_end(iov) > size) {
            return ERROR_INT(EINVAL);
        }
    }

    reg = &vfu_ctx->reg_info[region_idx];

    reg->flags = flags;
    reg->size = size;
    reg->cb = cb;
    reg->fd = fd;
    reg->offset = offset;

    if (mmap_areas == NULL && reg->fd != -1) {
        mmap_areas = &whole_region;
        nr_mmap_areas = 1;
    }

    if (nr_mmap_areas > 0) {
        ret = copyin_mmap_areas(reg, mmap_areas, nr_mmap_areas);
        if (ret < 0) {
            goto err;
        }
    }

    if (region_idx == VFU_PCI_DEV_MIGR_REGION_IDX) {
        if (!validate_sparse_mmaps_for_migr_reg(reg)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "migration registers cannot be memory mapped");
            errno = EINVAL;
            goto err;
        }
    }

    return 0;

err:
    ret = errno;
    free(reg->mmap_areas);
    memset(reg, 0, sizeof(*reg));
    return ERROR_INT(ret);
}

EXPORT int
vfu_setup_device_reset_cb(vfu_ctx_t *vfu_ctx, vfu_reset_cb_t *reset)
{
    assert(vfu_ctx != NULL);
    vfu_ctx->reset = reset;
    return 0;
}

EXPORT int
vfu_setup_device_dma(vfu_ctx_t *vfu_ctx, vfu_dma_register_cb_t *dma_register,
                     vfu_dma_unregister_cb_t *dma_unregister)
{

    assert(vfu_ctx != NULL);

    // Create the internal DMA controller.
    vfu_ctx->dma = dma_controller_create(vfu_ctx, MAX_DMA_REGIONS,
                                         MAX_DMA_SIZE);
    if (vfu_ctx->dma == NULL) {
        return ERROR_INT(errno);
    }

    vfu_ctx->dma_register = dma_register;
    vfu_ctx->dma_unregister = dma_unregister;

    return 0;
}

EXPORT int
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

EXPORT int
vfu_setup_device_migration_callbacks(vfu_ctx_t *vfu_ctx,
                                     const vfu_migration_callbacks_t *callbacks,
                                     uint64_t data_offset)
{
    int ret = 0;

    assert(vfu_ctx != NULL);
    assert(callbacks != NULL);

    if (vfu_ctx->reg_info[VFU_PCI_DEV_MIGR_REGION_IDX].size == 0) {
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

EXPORT int
vfu_addr_to_sg(vfu_ctx_t *vfu_ctx, vfu_dma_addr_t dma_addr,
               size_t len, dma_sg_t *sg, int max_sg, int prot)
{
    assert(vfu_ctx != NULL);

    if (unlikely(vfu_ctx->dma == NULL)) {
        return ERROR_INT(EINVAL);
    }

    return dma_addr_to_sg(vfu_ctx->dma, dma_addr, len, sg, max_sg, prot);
}

EXPORT int
vfu_map_sg(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, struct iovec *iov, int cnt,
           int flags)
{
    int ret;

    if (unlikely(vfu_ctx->dma_unregister == NULL) || flags != 0) {
        return ERROR_INT(EINVAL);
    }

    ret = dma_map_sg(vfu_ctx->dma, sg, iov, cnt);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

EXPORT void
vfu_unmap_sg(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, struct iovec *iov, int cnt)
{
    if (unlikely(vfu_ctx->dma_unregister == NULL)) {
        return;
    }
    return dma_unmap_sg(vfu_ctx->dma, sg, iov, cnt);
}

static int
vfu_dma_transfer(vfu_ctx_t *vfu_ctx, enum vfio_user_command cmd,
                 dma_sg_t *sg, void *data)
{
    struct vfio_user_dma_region_access *dma_reply;
    struct vfio_user_dma_region_access *dma_req;
    struct vfio_user_dma_region_access dma;
    static int msg_id = 1;
    size_t remaining;
    size_t count;
    size_t rlen;
    void *rbuf;

    assert(vfu_ctx != NULL);
    assert(sg != NULL);

    if (cmd == VFIO_USER_DMA_WRITE && !sg->writeable) {
        return ERROR_INT(EPERM);
    }

    rlen = sizeof(struct vfio_user_dma_region_access) +
           MIN(sg->length, vfu_ctx->client_max_data_xfer_size);

    rbuf = calloc(1, rlen);

    if (rbuf == NULL) {
        return -1;
    }

    remaining = sg->length;
    count = 0;

    if (cmd == VFIO_USER_DMA_READ) {
        dma_req = &dma;
        dma_reply = rbuf;
    } else {
        dma_req = rbuf;
        dma_reply = &dma;
    }

    while (remaining > 0) {
        int ret;

        dma_req->addr = (uint64_t)sg->dma_addr + count;
        dma_req->count = MIN(remaining, vfu_ctx->client_max_data_xfer_size);

        if (cmd == VFIO_USER_DMA_WRITE) {
            memcpy(rbuf + sizeof(*dma_req), data + count, dma_req->count);

            ret = vfu_ctx->tran->send_msg(vfu_ctx, msg_id++, VFIO_USER_DMA_WRITE,
                                          rbuf, rlen, NULL,
                                          dma_reply, sizeof(*dma_reply));
        } else {
            ret = vfu_ctx->tran->send_msg(vfu_ctx, msg_id++, VFIO_USER_DMA_READ,
                                          dma_req, sizeof(*dma_req), NULL,
                                          rbuf, rlen);
        }

        if (ret < 0) {
            ret = errno;
            if (ret == ENOMSG) {
                vfu_reset_ctx(vfu_ctx, "closed");
                ret = ENOTCONN;
            } else if (errno == ECONNRESET) {
                vfu_reset_ctx(vfu_ctx, "reset");
                ret = ENOTCONN;
            }
            free(rbuf);
            return ERROR_INT(ret);
        }

        if (dma_reply->addr != dma_req->addr ||
            dma_reply->count != dma_req->count) {
            vfu_log(vfu_ctx, LOG_ERR, "bad reply to DMA transfer: "
                    "request:%#lx,%lu reply:%#lx,%lu",
                    dma_req->addr, dma_req->count,
                    dma_reply->addr, dma_reply->count);
            free(rbuf);
            return ERROR_INT(EINVAL);
        }

        if (cmd == VFIO_USER_DMA_READ) {
            memcpy(data + count, rbuf + sizeof(*dma_reply), dma_req->count);
        }

        count += dma_req->count;
        remaining -= dma_req->count;
    }

    free(rbuf);
    return 0;
}

EXPORT int
vfu_dma_read(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data)
{
    return vfu_dma_transfer(vfu_ctx, VFIO_USER_DMA_READ, sg, data);
}

EXPORT int
vfu_dma_write(vfu_ctx_t *vfu_ctx, dma_sg_t *sg, void *data)
{
    return vfu_dma_transfer(vfu_ctx, VFIO_USER_DMA_WRITE, sg, data);
}

EXPORT bool
vfu_sg_is_mappable(vfu_ctx_t *vfu_ctx, dma_sg_t *sg)
{
    return dma_sg_is_mappable(vfu_ctx->dma, sg);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
