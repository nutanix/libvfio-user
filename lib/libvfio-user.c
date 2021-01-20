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
    vsnprintf(buf, sizeof buf, fmt, ap);
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
    } else if (is_migr_reg(vfu_ctx, region_index)) {
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

    if (size < sizeof (*ra)) {
        vfu_log(vfu_ctx, LOG_ERR, "message size too small (%d)", size);
        return false;
    }

    if (cmd == VFIO_USER_REGION_WRITE && size - sizeof (*ra) != ra->count) {
        vfu_log(vfu_ctx, LOG_ERR, "region write count too small: "
                "expected %lu, got %u", size - sizeof (*ra), ra->count);
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
handle_region_access(vfu_ctx_t *vfu_ctx, uint32_t size, uint16_t cmd,
                     void **data, size_t *len,
                     struct vfio_user_region_access *ra)
{
    ssize_t ret;
    char *buf;

    assert(vfu_ctx != NULL);
    assert(data != NULL);
    assert(ra != NULL);

    if (!is_valid_region_access(vfu_ctx, size, cmd, ra)) {
        return -EINVAL;
    }

    if (ra->count == 0) {
        return 0;
    }

    *len = sizeof (*ra);
    if (cmd == VFIO_USER_REGION_READ) {
        *len += ra->count;
    }
    *data = calloc(1, *len);
    if (*data == NULL) {
        return -ENOMEM;
    }
    if (cmd == VFIO_USER_REGION_READ) {
        buf = (char *)(((struct vfio_user_region_access*)(*data)) + 1);
    } else {
        buf = (char *)(ra + 1);
    }

    ret = region_access(vfu_ctx, ra->region, buf, ra->count, ra->offset,
                        cmd == VFIO_USER_REGION_WRITE);

    if (ret != ra->count) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to %s %#x-%#lx: %d",
                cmd == VFIO_USER_REGION_WRITE ? "write" : "read",
                ra->count, ra->offset + ra->count - 1, ret);
        /* FIXME we should return whatever has been accessed, not an error */
        if (ret >= 0) {
            ret = -EINVAL;
        }
        return ret;
    }

    ra = *data;
    ra->count = ret;

    return 0;
}

#define VFU_REGION_SHIFT 40

static inline uint64_t
region_to_offset(uint32_t region)
{
    return (uint64_t)region << VFU_REGION_SHIFT;
}

long
dev_get_reginfo(vfu_ctx_t *vfu_ctx, uint32_t index, uint32_t argsz,
                struct vfio_region_info **vfio_reg, int **fds, size_t *nr_fds)
{
    vfu_reg_info_t *vfu_reg;
    size_t caps_size;

    assert(vfu_ctx != NULL);
    assert(vfio_reg != NULL);

    vfu_reg = &vfu_ctx->reg_info[index];

    if (index >= vfu_ctx->nr_regions) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad region index %d in get region info",
                index);
        return -EINVAL;
    }

    if (argsz < sizeof(struct vfio_region_info)) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad argsz %d", argsz);
        return -EINVAL;
    }

    /*
     * TODO We assume that the client expects to receive argsz bytes.
     */
    *vfio_reg = calloc(1, argsz);
    if (!*vfio_reg) {
        return -ENOMEM;
    }
    caps_size = get_vfio_caps_size(is_migr_reg(vfu_ctx, index), vfu_reg);
    (*vfio_reg)->argsz = caps_size + sizeof(struct vfio_region_info);
    (*vfio_reg)->index = index;
    (*vfio_reg)->offset = region_to_offset((*vfio_reg)->index);
    (*vfio_reg)->size = vfu_reg->size;

    (*vfio_reg)->flags = 0;

    if (vfu_reg->flags & VFU_REGION_FLAG_READ) {
        (*vfio_reg)->flags |= VFIO_REGION_INFO_FLAG_READ;
    }
    if (vfu_reg->flags & VFU_REGION_FLAG_WRITE) {
        (*vfio_reg)->flags |= VFIO_REGION_INFO_FLAG_WRITE;
    }

    if (vfu_reg->fd != -1) {
        (*vfio_reg)->flags |= VFIO_REGION_INFO_FLAG_MMAP;
    }

    *nr_fds = 0;
    if (caps_size > 0) {
        if (vfu_reg->mmap_areas != NULL) {
            (*vfio_reg)->flags |= VFIO_REGION_INFO_FLAG_CAPS;
        }
        if (argsz >= (*vfio_reg)->argsz) {
            dev_get_caps(vfu_ctx, vfu_reg, is_migr_reg(vfu_ctx, index),
                         *vfio_reg, fds, nr_fds);
        }
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "region_info[%d] offset %#llx flags %#x size %llu "
            "argsz %u",
            (*vfio_reg)->index, (*vfio_reg)->offset, (*vfio_reg)->flags,
            (*vfio_reg)->size, (*vfio_reg)->argsz);

    return 0;
}

/* TODO merge with dev_get_reginfo */
static int
handle_device_get_region_info(vfu_ctx_t *vfu_ctx, uint32_t size,
                              struct vfio_region_info *reg_info_in,
                              struct vfio_region_info **reg_info_out,
                              int **fds, size_t *nr_fds)
{
    if (size < sizeof(*reg_info_in)) {
        return -EINVAL;
    }

    return dev_get_reginfo(vfu_ctx, reg_info_in->index, reg_info_in->argsz,
                           reg_info_out, fds, nr_fds);
}

int
handle_device_get_info(vfu_ctx_t *vfu_ctx, uint32_t size,
                       struct vfio_device_info *dev_info)
{
    assert(vfu_ctx != NULL);
    assert(dev_info != NULL);

    if (size < sizeof *dev_info) {
        return -EINVAL;
    }

    dev_info->argsz = sizeof *dev_info;
    dev_info->flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
    dev_info->num_regions = vfu_ctx->nr_regions;
    dev_info->num_irqs = VFU_DEV_NUM_IRQS;

    vfu_log(vfu_ctx, LOG_DEBUG, "sent devinfo flags %#x, num_regions %d, num_irqs"
            " %d", dev_info->flags, dev_info->num_regions, dev_info->num_irqs);

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

/*
 * Handles a DMA map/unmap request.
 *
 * @vfu_ctx: LM context
 * @size: size, in bytes, of the memory pointed to be @dma_regions
 * @map: whether this is a DMA map operation
 * @fds: array of file descriptors.
 * @nr_fds: size of above array.
 * @dma_regions: memory that contains the DMA regions to be mapped/unmapped
 *
 * @returns 0 on success, -errno on failure.
 */
int
handle_dma_map_or_unmap(vfu_ctx_t *vfu_ctx, uint32_t size, bool map,
                        int *fds, size_t nr_fds,
                        struct vfio_user_dma_region *dma_regions)
{
    int nr_dma_regions;
    int ret, i;
    size_t fdi;

    assert(vfu_ctx != NULL);
    assert(fds != NULL);

    if (vfu_ctx->dma == NULL) {
        return 0;
    }

    if (size % sizeof(struct vfio_user_dma_region) != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "bad size of DMA regions %d", size);
        return -EINVAL;
    }

    nr_dma_regions = (int)(size / sizeof(struct vfio_user_dma_region));
    if (nr_dma_regions == 0) {
        return 0;
    }

    for (i = 0, fdi = 0; i < nr_dma_regions; i++) {
        if (map) {
            int fd = -1;
            if (dma_regions[i].flags == VFIO_USER_F_DMA_REGION_MAPPABLE) {
                fd = consume_fd(fds, nr_fds, fdi++);
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
        if (ret < 0) {
            return ret;
        }
        if (vfu_ctx->map_dma != NULL) {
            vfu_ctx->map_dma(vfu_ctx, dma_regions[i].addr, dma_regions[i].size);
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
    *nr_iovecs = 1 + size / sizeof(struct vfio_iommu_type1_dirty_bitmap_get);
    *iovecs = malloc(*nr_iovecs * sizeof(struct iovec));
    if (*iovecs == NULL) {
        return -ENOMEM;
    }

    for (i = 1; i < *nr_iovecs; i++) {
        struct vfio_iommu_type1_dirty_bitmap_get *r = &ranges[(i - 1)]; /* FIXME ugly indexing */
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

static int
handle_dirty_pages(vfu_ctx_t *vfu_ctx, uint32_t size,
                   struct iovec **iovecs, size_t *nr_iovecs,
                   struct vfio_iommu_type1_dirty_bitmap *dirty_bitmap)
{
    int ret;

    assert(vfu_ctx != NULL);
    assert(iovecs != NULL);
    assert(nr_iovecs != NULL);
    assert(dirty_bitmap != NULL);

    if (size < sizeof *dirty_bitmap || size != dirty_bitmap->argsz) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid header size %u", size);
        return -EINVAL;
    }

    if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_START) {
        ret = dma_controller_dirty_page_logging_start(vfu_ctx->dma,
                                                      migration_get_pgsize(vfu_ctx->migration));
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP) {
        ret = dma_controller_dirty_page_logging_stop(vfu_ctx->dma);
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP) {
        ret = handle_dirty_pages_get(vfu_ctx, iovecs, nr_iovecs,
                                     (struct vfio_iommu_type1_dirty_bitmap_get*)(dirty_bitmap + 1),
                                     size - sizeof *dirty_bitmap);
    } else {
        vfu_log(vfu_ctx, LOG_ERR, "bad flags %#x", dirty_bitmap->flags);
        ret = -EINVAL;
    }

    return ret;
}

/*
 * FIXME return value is messed up, sometimes we return -1 and set errno while
 * other times we return -errno. Fix.
 */

/*
 * Returns 0 if the header is valid, -errno otherwise.
 */
static int
validate_header(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr, size_t size)
{
    assert(hdr != NULL);

    if (size < sizeof hdr) {
        vfu_log(vfu_ctx, LOG_ERR, "short header read %ld", size);
        return -EINVAL;
    }

    if (hdr->flags.type != VFIO_USER_F_TYPE_COMMAND) {
        vfu_log(vfu_ctx, LOG_ERR, "header not a request");
        return -EINVAL;
    }

    if (hdr->msg_size < sizeof hdr) {
        vfu_log(vfu_ctx, LOG_ERR, "bad size in header %d", hdr->msg_size);
        return -EINVAL;
    }

    return 0;
}

/*
 * Populates @hdr to contain the header for the next command to be processed.
 * Stores any passed FDs into @fds and the number in @nr_fds.
 *
 * Returns 0 if there is no command to process, -errno if an error occured, or
 * the number of bytes read.
 */
int
get_next_command(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr, int *fds,
                 size_t *nr_fds)
{
    int ret;

    /* FIXME get request shouldn't set errno, it should return it as -errno */
    ret = vfu_ctx->trans->get_request(vfu_ctx, hdr, fds, nr_fds);
    if (unlikely(ret < 0)) {
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            return 0;
        }
        if (ret != -EINTR) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to receive request: %s",
                   strerror(-ret));
        }
        return ret;
    }
    if (unlikely(ret == 0)) {
        if (errno == EINTR) {
            return -EINTR;
        }
        if (errno == 0) {
            vfu_log(vfu_ctx, LOG_INFO, "vfio-user client closed connection");
        } else {
            vfu_log(vfu_ctx, LOG_ERR, "end of file: %m");
        }
        return -ENOTCONN;
    }
    return ret;
}
UNIT_TEST_SYMBOL(get_next_command);
#define get_next_command __wrap_get_next_command

int
exec_command(vfu_ctx_t *vfu_ctx, struct vfio_user_header *hdr, size_t size,
             int *fds, size_t nr_fds, int **fds_out, size_t *nr_fds_out,
             struct iovec *_iovecs, struct iovec **iovecs, size_t *nr_iovecs,
             bool *free_iovec_data)
{
    int ret;
    struct vfio_irq_info *irq_info;
    struct vfio_device_info *dev_info;
    struct vfio_region_info *dev_region_info_in, *dev_region_info_out = NULL;
    void *cmd_data = NULL;

    assert(vfu_ctx != NULL);
    assert(hdr != NULL);
    assert(fds != NULL);
    assert(_iovecs != NULL);
    assert(iovecs != NULL);
    assert(free_iovec_data != NULL);

    ret = validate_header(vfu_ctx, hdr, size);
    if (ret < 0) {
        return ret;
    }

    /*
     * TODO from now on if an error occurs we still need to reply. Move this
     * code into a separate function so that we don't have to use goto.
     */

    hdr->msg_size -= sizeof(struct vfio_user_header);
    if (hdr->msg_size > 0) {
        cmd_data = malloc(hdr->msg_size);
        if (cmd_data == NULL) {
            ret = -ENOMEM;
            goto reply;
        }
        // FIXME: should be transport op
        ret = recv(vfu_ctx->conn_fd, cmd_data, hdr->msg_size, 0);
        if (ret < 0) {
            ret = -errno;
            goto reply;
        }
        if (ret != (int)hdr->msg_size) {
            vfu_log(vfu_ctx, LOG_ERR, "short read, expected=%d, actual=%d",
                    hdr->msg_size, ret);
            ret = -EINVAL;
            goto reply;
        }
    }

    if (device_is_stopped_and_copying(vfu_ctx->migration)
        && !(hdr->cmd == VFIO_USER_REGION_READ || hdr->cmd == VFIO_USER_REGION_WRITE)) {
        vfu_log(vfu_ctx, LOG_ERR,
               "bad command %d while device in stop-and-copy state", hdr->cmd);
        ret = -EINVAL;
        goto reply;
    }

    switch (hdr->cmd) {
        case VFIO_USER_DMA_MAP:
        case VFIO_USER_DMA_UNMAP:
            ret = handle_dma_map_or_unmap(vfu_ctx, hdr->msg_size,
                                          hdr->cmd == VFIO_USER_DMA_MAP,
                                          fds, nr_fds, cmd_data);
            break;
        case VFIO_USER_DEVICE_GET_INFO:
            dev_info = calloc(1, sizeof *dev_info);
            if (dev_info == NULL) {
                ret = -ENOMEM;
                goto reply;
            }
            ret = handle_device_get_info(vfu_ctx, hdr->msg_size, dev_info);
            if (ret >= 0) {
                _iovecs[1].iov_base = dev_info;
                _iovecs[1].iov_len = dev_info->argsz;
                *iovecs = _iovecs;
                *nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_REGION_INFO:
            dev_region_info_in = cmd_data;
            ret = handle_device_get_region_info(vfu_ctx, hdr->msg_size,
                                                dev_region_info_in,
                                                &dev_region_info_out, fds_out,
                                                nr_fds_out);
            if (ret == 0) {
                _iovecs[1].iov_base = dev_region_info_out;
                _iovecs[1].iov_len = dev_region_info_in->argsz;
                *iovecs = _iovecs;
                *nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_IRQ_INFO:
            irq_info = calloc(1, sizeof *irq_info);
            if (irq_info == NULL) {
                ret = -ENOMEM;
                goto reply;
            }
            ret = handle_device_get_irq_info(vfu_ctx, hdr->msg_size, cmd_data,
                                             irq_info);
            if (ret == 0) {
                _iovecs[1].iov_base = irq_info;
                _iovecs[1].iov_len = sizeof *irq_info;
                *iovecs = _iovecs;
                *nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_SET_IRQS:
            ret = handle_device_set_irqs(vfu_ctx, hdr->msg_size, fds, nr_fds,
                                         cmd_data);
            break;
        case VFIO_USER_REGION_READ:
        case VFIO_USER_REGION_WRITE:
            ret = handle_region_access(vfu_ctx, hdr->msg_size, hdr->cmd,
                                       &(_iovecs[1].iov_base),
                                       &(_iovecs[1].iov_len),
                                       cmd_data);
            if (ret == 0) {
                *iovecs = _iovecs;
                *nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_RESET:
            ret = handle_device_reset(vfu_ctx);
            break;
        case VFIO_USER_DIRTY_PAGES:
            // FIXME: don't allow migration calls if migration == NULL
            ret = handle_dirty_pages(vfu_ctx, hdr->msg_size, iovecs, nr_iovecs,
                                     cmd_data);
            if (ret >= 0) {
                *free_iovec_data = false;
            }
            break;
        default:
            vfu_log(vfu_ctx, LOG_ERR, "bad command %d", hdr->cmd);
            ret = -EINVAL;
            goto reply;
    }
reply:
    free(cmd_data);
    return ret;
}
UNIT_TEST_SYMBOL(exec_command);
#define exec_command __wrap_exec_command

int
process_request(vfu_ctx_t *vfu_ctx)
{
    struct vfio_user_header hdr = { 0, };
    int ret;
    int *fds = NULL, *fds_out = NULL;
    size_t nr_fds, i;
    size_t nr_fds_out = 0;
    struct iovec _iovecs[2] = { { 0, } };
    struct iovec *iovecs = NULL;
    size_t nr_iovecs = 0;
    bool free_iovec_data = true;

    assert(vfu_ctx != NULL);

    if (device_is_stopped(vfu_ctx->migration)) {
        return -ESHUTDOWN;
    }

    /*
     * FIXME if migration device state is VFIO_DEVICE_STATE_STOP then only
     * migration-related operations should execute. However, some operations
     * are harmless (e.g. get region info). At the minimum we should fail
     * accesses to device regions other than the migration region. I'd expect
     * DMA unmap and get dirty pages to be required even in the stop-and-copy
     * state.
     */

    nr_fds = vfu_ctx->client_max_fds;
    fds = alloca(nr_fds * sizeof(int));

    ret = get_next_command(vfu_ctx, &hdr, fds, &nr_fds);
    if (ret <= 0) {
        return ret;
    }

    ret = exec_command(vfu_ctx, &hdr, ret, fds, nr_fds, &fds_out, &nr_fds_out,
                       _iovecs, &iovecs, &nr_iovecs, &free_iovec_data);

    for (i = 0; i < nr_fds; i++) {
        if (fds[i] != -1) {
            vfu_log(vfu_ctx, LOG_DEBUG,
                    "closing unexpected fd %d (index %zu) from cmd %u",
                    fds[i], i, hdr.cmd);
            close(fds[i]);
        }
    }

    /*
     * TODO: In case of error during command handling set errno respectively
     * in the reply message.
     */

    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to handle command %d: %s", hdr.cmd,
                strerror(-ret));
    } else {
        ret = 0;
    }

    if (!(hdr.flags.no_reply)) {
        // FIXME: SPEC: should the reply include the command? I'd say yes?
        ret = vfu_send_iovec(vfu_ctx->conn_fd, hdr.msg_id, true,
                             0, iovecs, nr_iovecs, fds_out, nr_fds_out, -ret);
        if (unlikely(ret < 0)) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to complete command: %s",
                    strerror(-ret));
        }
    } else {
        /*
         * A failed client request is not a failure of process_request() itself.
         */
        ret = 0;
    }

    if (iovecs != NULL) {
        if (free_iovec_data) {
            size_t i;
            for (i = 1; i < nr_iovecs; i++) {
                free(iovecs[i].iov_base);
            }
        }
        if (iovecs != _iovecs) {
            free(iovecs);
        }
    }

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
            return ERROR(ENOMEM);
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

        //FIXME: assert(max_ivs > 0)?
        size = sizeof(int) * max_ivs;
        vfu_ctx->irqs = calloc(1, sizeof(vfu_irqs_t) + size);
        if (vfu_ctx->irqs == NULL) {
            // vfu_ctx->pci.config_space should be free'ed by vfu_destroy_ctx().
            return ERROR(ENOMEM);
        }

        // Set context irq information.
        for (i = 0; i < max_ivs; i++) {
            vfu_ctx->irqs->efds[i] = -1;
        }
        vfu_ctx->irqs->err_efd = -1;
        vfu_ctx->irqs->req_efd = -1;
        vfu_ctx->irqs->type = IRQ_NONE;
        vfu_ctx->irqs->max_ivs = max_ivs;

        // Reflect on the config space whether INTX is available.
        if (vfu_ctx->irq_count[VFU_DEV_INTX_IRQ] != 0) {
            vfu_ctx->pci.config_space->hdr.intr.ipin = 1; // INTA#
        }
    }

    // FIXME: verify we don't need this for ext caps
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
        return ERROR(EINVAL);
    }

    blocking = !(vfu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB);
    do {
        err = process_request(vfu_ctx);
    } while (err >= 0 && blocking);

    return err >= 0 ? 0 : err;
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
    if (vfu_ctx->trans->detach != NULL) {
        vfu_ctx->trans->detach(vfu_ctx);
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

int
vfu_attach_ctx(vfu_ctx_t *vfu_ctx)
{

    assert(vfu_ctx != NULL);

    return vfu_ctx->trans->attach(vfu_ctx);
}

vfu_ctx_t *
vfu_create_ctx(vfu_trans_t trans, const char *path, int flags, void *pvt,
               vfu_dev_type_t dev_type)
{
    vfu_ctx_t *vfu_ctx = NULL;
    int err = 0;

    if (trans != VFU_TRANS_SOCK) {
        errno = ENOTSUP;
        return NULL;
    }

    if (dev_type != VFU_DEV_TYPE_PCI) {
        errno = EINVAL;
        return NULL;
    }

    vfu_ctx = calloc(1, sizeof(vfu_ctx_t));
    if (vfu_ctx == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    vfu_ctx->dev_type = dev_type;
    vfu_ctx->trans = &sock_transport_ops;

    //FIXME: Validate arguments.
    // Set other context data.
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
    vfu_ctx->nr_regions = VFU_PCI_DEV_NUM_REGIONS + 1;
    vfu_ctx->reg_info = calloc(vfu_ctx->nr_regions, sizeof *vfu_ctx->reg_info);
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

    if (vfu_ctx->trans->init != NULL) {
        err = vfu_ctx->trans->init(vfu_ctx);
        if (err < 0) {
            goto err_out;
        }
        vfu_ctx->fd = err;
    }

    return vfu_ctx;

err_out:
    vfu_destroy_ctx(vfu_ctx);
    errno = -err;

    return NULL;
}

int
vfu_setup_log(vfu_ctx_t *vfu_ctx, vfu_log_fn_t *log, int log_level)
{

    if (log_level != LOG_ERR && log_level != LOG_INFO && log_level != LOG_DEBUG) {
        return ERROR(EINVAL);
    }

    vfu_ctx->log = log;
    vfu_ctx->log_level = log_level;

    return 0;
}

static int
copyin_mmap_areas(vfu_reg_info_t *reg_info,
                  struct iovec *mmap_areas, uint32_t nr_mmap_areas)
{
    size_t size = nr_mmap_areas * sizeof (*mmap_areas);

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

int
vfu_setup_region(vfu_ctx_t *vfu_ctx, int region_idx, size_t size,
                 vfu_region_access_cb_t *cb, int flags,
                 struct iovec *mmap_areas, uint32_t nr_mmap_areas, int fd)
{
    struct iovec whole_region = { .iov_base = 0, .iov_len = size };
    vfu_reg_info_t *reg;
    size_t i;
    int ret;

    assert(vfu_ctx != NULL);

    if ((mmap_areas == NULL) != (nr_mmap_areas == 0) ||
        (mmap_areas != NULL && fd == -1)) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid mappable region arguments");
        return ERROR(EINVAL);
    }

    if (region_idx < VFU_PCI_DEV_BAR0_REGION_IDX ||
        region_idx > VFU_PCI_DEV_VGA_REGION_IDX) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid region index %d", region_idx);
        return ERROR(EINVAL);
    }

    /*
     * PCI config space is never mappable or of type mem.
     */
    if (region_idx == VFU_PCI_DEV_CFG_REGION_IDX &&
        flags != VFU_REGION_FLAG_RW) {
        return ERROR(EINVAL);
    }

    for (i = 0; i < nr_mmap_areas; i++) {
        struct iovec *iov = &mmap_areas[i];
        if ((size_t)iov->iov_base + iov->iov_len > size) {
            return ERROR(EINVAL);
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
            memset(reg, 0, sizeof (*reg));
            return ERROR(-ret);
        }
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
        return ERROR(ENOMEM);
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

    if (type < VFU_DEV_INTX_IRQ || type > VFU_DEV_REQ_IRQ) {
        vfu_log(vfu_ctx, LOG_ERR, "Invalid IRQ index %d, should be between "
               "(%d to %d)", type, VFU_DEV_INTX_IRQ,
               VFU_DEV_REQ_IRQ);
        return ERROR(EINVAL);
    }

    vfu_ctx->irq_count[type] = count;

    return 0;
}

int
vfu_setup_device_migration(vfu_ctx_t *vfu_ctx, vfu_migration_t *migration)
{
    vfu_reg_info_t *migr_reg;
    int ret = 0;

    assert(vfu_ctx != NULL);

    //FIXME: Validate args.

    if (vfu_ctx->migr_reg != NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "device migration is already setup");
        return ERROR(EEXIST);
    }

    /* FIXME hacky, find a more robust way to allocate a region index */
    migr_reg = &vfu_ctx->reg_info[(vfu_ctx->nr_regions - 1)];

    /* FIXME: Are there sparse areas need to be setup flags accordingly */
    ret = copyin_mmap_areas(migr_reg, migration->mmap_areas,
                            migration->nr_mmap_areas);
    if (ret < 0) {
        return ERROR(-ret);
    }

    migr_reg->flags = VFU_REGION_FLAG_RW;
    migr_reg->size = sizeof(struct vfio_device_migration_info) + migration->size;

    vfu_ctx->migration = init_migration(migration, &ret);
    if (vfu_ctx->migration == NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to initialize device migration");
        free(migr_reg->mmap_areas);
        return ERROR(ret);
    }
    vfu_ctx->migr_reg = migr_reg;

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
        errno = EINVAL;
        return -1;
    }
    return dma_addr_to_sg(vfu_ctx->dma, dma_addr, len, sg, max_sg, prot);
}

inline int
vfu_map_sg(vfu_ctx_t *vfu_ctx, const dma_sg_t *sg,
	       struct iovec *iov, int cnt)
{
    if (unlikely(vfu_ctx->unmap_dma == NULL)) {
        errno = EINVAL;
        return -1;
    }
    return dma_map_sg(vfu_ctx->dma, sg, iov, cnt);
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
        return -ENOMEM;
    }

    dma_send.addr = sg->dma_addr;
    dma_send.count = sg->length;
    ret = vfu_msg(vfu_ctx->conn_fd, msg_id, VFIO_USER_DMA_READ,
                  &dma_send, sizeof dma_send, NULL,
                  dma_recv, recv_size);
    memcpy(data, dma_recv->data, sg->length); /* FIXME no need for memcpy */
    free(dma_recv);

    return ret;
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
        return -ENOMEM;
    }
    dma_send->addr = sg->dma_addr;
    dma_send->count = sg->length;
    memcpy(dma_send->data, data, sg->length); /* FIXME no need to copy! */
    ret = vfu_msg(vfu_ctx->conn_fd, msg_id, VFIO_USER_DMA_WRITE,
                  dma_send, send_size, NULL,
                  &dma_recv, sizeof(dma_recv));
    free(dma_send);

    return ret;
}

uint64_t
vfu_region_to_offset(uint32_t region)
{
    return region_to_offset(region);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
