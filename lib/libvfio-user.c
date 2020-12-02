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

#include "cap.h"
#include "dma.h"
#include "libvfio-user.h"
#include "private.h"
#include "tran_sock.h"
#include "migration.h"
#include "irq.h"

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
    vfu_ctx->log(vfu_ctx->pvt, level, buf);
    errno = _errno;
}

static inline int
ERROR(int err)
{
    errno = err;
    return -1;
}

static size_t
get_vfio_caps_size(bool is_migr_reg, struct vfu_sparse_mmap_areas *m)
{
    size_t type_size = 0;
    size_t sparse_size = 0;

    if (is_migr_reg) {
        type_size = sizeof(struct vfio_region_info_cap_type);
    }

    if (m != NULL) {
        sparse_size = sizeof(struct vfio_region_info_cap_sparse_mmap)
                      + (m->nr_mmap_areas * sizeof(struct vfio_region_sparse_mmap_area));
    }

    return type_size + sparse_size;
}

/*
 * Populate the sparse mmap capability information to vfio-client.
 * Sparse mmap information stays after struct vfio_region_info and cap_offest
 * points accordingly.
 */
static void
dev_get_caps(vfu_ctx_t *vfu_ctx, vfu_reg_info_t *vfu_reg, bool is_migr_reg,
             struct vfio_region_info *vfio_reg)
{
    struct vfio_info_cap_header *header;
    struct vfio_region_info_cap_type *type = NULL;
    struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
    struct vfu_sparse_mmap_areas *mmap_areas;

    assert(vfu_ctx != NULL);
    assert(vfio_reg != NULL);

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
        int i, nr_mmap_areas = vfu_reg->mmap_areas->nr_mmap_areas;
        if (type != NULL) {
            type->header.next = vfio_reg->cap_offset + sizeof(struct vfio_region_info_cap_type);
            sparse = (struct vfio_region_info_cap_sparse_mmap*)(type + 1);
        } else {
            vfio_reg->cap_offset = sizeof(struct vfio_region_info);
            sparse = (struct vfio_region_info_cap_sparse_mmap*)header;
        }
        sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
        sparse->header.version = 1;
        sparse->header.next = 0;
        sparse->nr_areas = nr_mmap_areas;

        mmap_areas = vfu_reg->mmap_areas;
        for (i = 0; i < nr_mmap_areas; i++) {
            sparse->areas[i].offset = (__u64)mmap_areas->areas[i].iov_base;
            sparse->areas[i].size = mmap_areas->areas[i].iov_len;
            vfu_log(vfu_ctx, LOG_DEBUG, "%s: area %d %#llx-%#llx", __func__,
                    i, sparse->areas[i].offset,
                    sparse->areas[i].offset + sparse->areas[i].size);
        }
    }

    /*
     * FIXME VFIO_REGION_INFO_FLAG_MMAP is valid if the region is
     * memory-mappable in general, not only if it supports sparse mmap.
     */
    vfio_reg->flags |= VFIO_REGION_INFO_FLAG_MMAP | VFIO_REGION_INFO_FLAG_CAPS;
}

#define VFU_REGION_SHIFT 40
#define VFU_REGION_MASK  ((1ULL << VFU_REGION_SHIFT) - 1)

uint64_t
region_to_offset(uint32_t region)
{
    return (uint64_t)region << VFU_REGION_SHIFT;
}

uint32_t
offset_to_region(uint64_t offset)
{
    return (offset >> VFU_REGION_SHIFT) & VFU_REGION_MASK;
}

#ifdef VFU_VERBOSE_LOGGING
void
dump_buffer(const char *prefix, const char *buf, uint32_t count)
{
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
}
#else
#define dump_buffer(prefix, buf, count)
#endif

static bool
is_migr_reg(vfu_ctx_t *vfu_ctx, int index)
{
    return &vfu_ctx->reg_info[index] == vfu_ctx->migr_reg;
}

static long
dev_get_reginfo(vfu_ctx_t *vfu_ctx, uint32_t index,
                struct vfio_region_info **vfio_reg)
{
    vfu_reg_info_t *vfu_reg;
    size_t caps_size;
    uint32_t argsz;

    assert(vfu_ctx != NULL);
    assert(vfio_reg != NULL);

    vfu_reg = &vfu_ctx->reg_info[index];

    if (index >= vfu_ctx->nr_regions) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad region index %d", index);
        return -EINVAL;
    }

    caps_size = get_vfio_caps_size(is_migr_reg(vfu_ctx, index),
                                   vfu_reg->mmap_areas);
    argsz = caps_size + sizeof(struct vfio_region_info);
    *vfio_reg = calloc(1, argsz);
    if (!*vfio_reg) {
        return -ENOMEM;
    }
    /* FIXME document in the protocol that vfio_req->argsz is ignored */
    (*vfio_reg)->argsz = argsz;
    (*vfio_reg)->flags = vfu_reg->flags;
    (*vfio_reg)->index = index;
    (*vfio_reg)->offset = region_to_offset((*vfio_reg)->index);
    (*vfio_reg)->size = vfu_reg->size;

    if (caps_size > 0) {
        dev_get_caps(vfu_ctx, vfu_reg, is_migr_reg(vfu_ctx, index), *vfio_reg);
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "region_info[%d] offset %#llx flags %#x size %llu "
            "argsz %u",
            (*vfio_reg)->index, (*vfio_reg)->offset, (*vfio_reg)->flags,
            (*vfio_reg)->size, (*vfio_reg)->argsz);

    return 0;
}

int
vfu_get_region(loff_t pos, size_t count, loff_t *off)
{
    int r;

    assert(off != NULL);

    r = offset_to_region(pos);
    if ((int)offset_to_region(pos + count) != r) {
        return -ENOENT;
    }
    *off = pos - region_to_offset(r);

    return r;
}

static uint32_t
region_size(vfu_ctx_t *vfu_ctx, int region)
{
        assert(region >= VFU_PCI_DEV_BAR0_REGION_IDX && region <= VFU_PCI_DEV_VGA_REGION_IDX);
        return vfu_ctx->reg_info[region].size;
}

static uint32_t
pci_config_space_size(vfu_ctx_t *vfu_ctx)
{
    return region_size(vfu_ctx, VFU_PCI_DEV_CFG_REGION_IDX);
}

static ssize_t
handle_pci_config_space_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                               loff_t pos, bool is_write)
{
    int ret;

    count = MIN(pci_config_space_size(vfu_ctx), count);
    if (is_write) {
        ret = cap_maybe_access(vfu_ctx, vfu_ctx->pci.caps, buf, count, pos);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "bad access to capabilities %#lx-%#lx\n",
                    pos, pos + count);
            return ret;
        }
    } else {
        memcpy(buf, vfu_ctx->pci.config_space->raw + pos, count);
    }
    return count;
}

static ssize_t
do_access(vfu_ctx_t *vfu_ctx, char *buf, uint8_t count, uint64_t pos, bool is_write)
{
    int idx;
    loff_t offset;

    assert(vfu_ctx != NULL);
    assert(buf != NULL);
    assert(count == 1 || count == 2 || count == 4 || count == 8);

    idx = vfu_get_region(pos, count, &offset);
    if (idx < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "invalid region %d", idx);
        return idx;
    }

    if (idx < 0 || idx >= (int)vfu_ctx->nr_regions) {
        vfu_log(vfu_ctx, LOG_ERR, "bad region %d", idx);
        return -EINVAL;
    }

    if (idx == VFU_PCI_DEV_CFG_REGION_IDX) {
        return handle_pci_config_space_access(vfu_ctx, buf, count, offset,
                                              is_write);
    }

    if (is_migr_reg(vfu_ctx, idx)) {
        if (offset + count > vfu_ctx->reg_info[idx].size) {
            vfu_log(vfu_ctx, LOG_ERR, "read %#lx-%#lx past end of migration region (%#x)",
                    offset, offset + count - 1,
                    vfu_ctx->reg_info[idx].size);
            return -EINVAL;
        }
        return handle_migration_region_access(vfu_ctx, vfu_ctx->pvt,
                                              vfu_ctx->migration,
                                              buf, count, offset, is_write);
    }

    /*
     * Checking whether a callback exists might sound expensive however this
     * code is not performance critical. This works well when we don't expect a
     * region to be used, so the user of the library can simply leave the
     * callback NULL in vfu_create_ctx.
     */
    if (vfu_ctx->reg_info[idx].fn != NULL) {
        return vfu_ctx->reg_info[idx].fn(vfu_ctx->pvt, buf, count, offset,
                                         is_write);
    }

    vfu_log(vfu_ctx, LOG_ERR, "no callback for region %d", idx);

    return -EINVAL;
}

/*
 * Returns the number of bytes processed on success or a negative number on
 * error.
 *
 * TODO function naming, general cleanup of access path
 * FIXME we must be able to return values up to uint32_t bit, or negative on
 * error. Better to make return value an int and return the number of bytes
 * processed via an argument.
 */
static ssize_t
_vfu_access(vfu_ctx_t *vfu_ctx, char *buf, uint32_t count, uint64_t *ppos,
          bool is_write)
{
    uint32_t done = 0;
    int ret;

    assert(vfu_ctx != NULL);
    /* buf and ppos can be NULL if count is 0 */

    while (count) {
        size_t size;
        /*
         * Limit accesses to qword and enforce alignment. Figure out whether
         * the PCI spec requires this
         * FIXME while this makes sense for registers, we might be able to relax
         * this requirement and make some transfers more efficient. Maybe make
         * this a per-region option that can be set by the user?
         */
        if (count >= 8 && !(*ppos % 8)) {
           size = 8;
        } else if (count >= 4 && !(*ppos % 4)) {
            size = 4;
        } else if (count >= 2 && !(*ppos % 2)) {
            size = 2;
        } else {
            size = 1;
        }
        ret = do_access(vfu_ctx, buf, size, *ppos, is_write);
        if (ret <= 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to %s %#lx-%#lx: %s",
                    is_write ? "write to" : "read from", *ppos, *ppos + size - 1,
                    strerror(-ret));
            /*
             * TODO if ret < 0 then it might contain a legitimate error code, why replace it with EFAULT?
             */
            return -EFAULT;
        }
        if (ret != (int)size) {
            vfu_log(vfu_ctx, LOG_DEBUG, "bad read %d != %ld", ret, size);
        }
        count -= size;
        done += size;
        *ppos += size;
        buf += size;
    }
    return done;
}

static inline int
vfu_access(vfu_ctx_t *vfu_ctx, bool is_write, char *rwbuf, uint32_t count,
             uint64_t *pos)
{
    uint32_t processed = 0, _count;
    int ret;

    assert(vfu_ctx != NULL);
    assert(rwbuf != NULL);
    assert(pos != NULL);

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %#lx-%#lx", is_write ? "W" : "R", *pos,
            *pos + count - 1);

#ifdef VFU_VERBOSE_LOGGING
    if (is_write) {
        dump_buffer("buffer write", rwbuf, count);
    }
#endif

    _count = count;
    ret = vfu_pci_hdr_access(vfu_ctx, &_count, pos, is_write, rwbuf);
    if (ret != 0) {
        /* FIXME shouldn't we fail here? */
        vfu_log(vfu_ctx, LOG_ERR, "failed to access PCI header: %s",
                strerror(-ret));
#ifdef VFU_VERBOSE_LOGGING
        dump_buffer("buffer write", rwbuf, _count);
#endif
    }

    /*
     * count is how much has been processed by vfu_pci_hdr_access,
     * _count is how much there's left to be processed by vfu_access
     */
    processed = count - _count;
    ret = _vfu_access(vfu_ctx, rwbuf + processed, _count, pos, is_write);
    if (ret >= 0) {
        ret += processed;
#ifdef VFU_VERBOSE_LOGGING
        if (!is_write && err == ret) {
            dump_buffer("buffer read", rwbuf, ret);
        }
#endif
    }

    return ret;
}

/* TODO merge with dev_get_reginfo */
static int
handle_device_get_region_info(vfu_ctx_t *vfu_ctx, uint32_t size,
                              struct vfio_region_info *reg_info_in,
                              struct vfio_region_info **reg_info_out)
{
    if (size != sizeof(*reg_info_in) || size != reg_info_in->argsz) {
        return -EINVAL;
    }

    return dev_get_reginfo(vfu_ctx, reg_info_in->index, reg_info_out);
}

static int
handle_device_get_info(vfu_ctx_t *vfu_ctx, uint32_t size,
                       struct vfio_device_info *dev_info)
{
    assert(vfu_ctx != NULL);
    assert(dev_info != NULL);

    if (size != sizeof *dev_info) {
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
                                            dma_regions[i].offset);
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
            vfu_log(vfu_ctx, LOG_DEBUG,
                    "added DMA region %#lx-%#lx offset=%#lx fd=%d",
                    dma_regions[i].addr,
                    dma_regions[i].addr + dma_regions[i].size - 1,
                    dma_regions[i].offset, fd);
        } else {
            ret = dma_controller_remove_region(vfu_ctx->dma,
                                               dma_regions[i].addr,
                                               dma_regions[i].size,
                                               vfu_ctx->unmap_dma, vfu_ctx->pvt);
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
            vfu_ctx->map_dma(vfu_ctx->pvt, dma_regions[i].addr,
                             dma_regions[i].size);
        }
    }
    return ret;
}

static int
handle_device_reset(vfu_ctx_t *vfu_ctx)
{
    vfu_log(vfu_ctx, LOG_DEBUG, "Device reset called by client");
    if (vfu_ctx->reset != NULL) {
        return vfu_ctx->reset(vfu_ctx->pvt);
    }
    return 0;
}

static int
validate_region_access(vfu_ctx_t *vfu_ctx, uint32_t size, uint16_t cmd,
                       struct vfio_user_region_access *region_access)
{
    assert(region_access != NULL);

    if (size < sizeof *region_access) {
        vfu_log(vfu_ctx, LOG_ERR, "message size too small (%d)", size);
        return -EINVAL;
    }

    if (region_access->region > vfu_ctx->nr_regions ||  region_access->count <= 0) {
        vfu_log(vfu_ctx, LOG_ERR, "bad region %d and/or count %d",
                region_access->region, region_access->count);
        return -EINVAL;
    }

    if (device_is_stopped_and_copying(vfu_ctx->migration) &&
        !is_migr_reg(vfu_ctx, region_access->region)) {
        vfu_log(vfu_ctx, LOG_ERR,
                "cannot access region %d while device in stop-and-copy state",
                region_access->region);
        return -EINVAL;
    }

    if (cmd == VFIO_USER_REGION_WRITE &&
        size - sizeof *region_access != region_access->count)
    {
        vfu_log(vfu_ctx, LOG_ERR, "bad region access, expected %lu, actual %d",
                size - sizeof *region_access, region_access->count);
        return -EINVAL;
    }

    return 0;
}

static int
handle_region_access(vfu_ctx_t *vfu_ctx, uint32_t size, uint16_t cmd,
                     void **data, size_t *len,
                     struct vfio_user_region_access *region_access)
{
    uint64_t count, offset;
    int ret;
    char *buf;

    assert(vfu_ctx != NULL);
    assert(data != NULL);
    assert(region_access != NULL);

    ret = validate_region_access(vfu_ctx, size, cmd, region_access);
    if (ret < 0) {
        return ret;
    }

    *len = sizeof *region_access;
    if (cmd == VFIO_USER_REGION_READ) {
        *len += region_access->count;
    }
    *data = malloc(*len);
    if (*data == NULL) {
        return -ENOMEM;
    }
    if (cmd == VFIO_USER_REGION_READ) {
        buf = (char*)(((struct vfio_user_region_access*)(*data)) + 1);
    } else {
        buf = (char*)(region_access + 1);
    }

    count = region_access->count;
    offset = region_to_offset(region_access->region) + region_access->offset;

    ret = vfu_access(vfu_ctx, cmd == VFIO_USER_REGION_WRITE, buf, count, &offset);
    if (ret != (int)region_access->count) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to %s %#x-%#lx: %d",
                cmd == VFIO_USER_REGION_WRITE ? "write" : "read",
                region_access->count,
                region_access->offset + region_access->count - 1, ret);
        /* FIXME we should return whatever has been accessed, not an error */
        if (ret >= 0) {
            ret = -EINVAL;
        }
        return ret;
    }

    region_access = *data;
    region_access->count = ret;

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
             int *fds, size_t nr_fds,
             struct iovec *_iovecs, struct iovec **iovecs, size_t *nr_iovecs,
             bool *free_iovec_data)
{
    int ret;
    struct vfio_irq_info irq_info;
    struct vfio_device_info dev_info;
    struct vfio_region_info *dev_reg_info = NULL;
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
            ret = handle_device_get_info(vfu_ctx, hdr->msg_size, &dev_info);
            if (ret >= 0) {
                _iovecs[1].iov_base = &dev_info;
                _iovecs[1].iov_len = dev_info.argsz;
                *iovecs = _iovecs;
                *nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_REGION_INFO:
            ret = handle_device_get_region_info(vfu_ctx, hdr->msg_size, cmd_data,
                                                &dev_reg_info);
            if (ret == 0) {
                _iovecs[1].iov_base = dev_reg_info;
                _iovecs[1].iov_len = dev_reg_info->argsz;
                *iovecs = _iovecs;
                *nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_IRQ_INFO:
            ret = handle_device_get_irq_info(vfu_ctx, hdr->msg_size, cmd_data,
                                             &irq_info);
            if (ret == 0) {
                _iovecs[1].iov_base = &irq_info;
                _iovecs[1].iov_len = sizeof irq_info;
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
            *iovecs = _iovecs;
            ret = handle_region_access(vfu_ctx, hdr->msg_size, hdr->cmd,
                                       &(*iovecs)[1].iov_base,
                                       &(*iovecs)[1].iov_len,
                                       cmd_data);
            *nr_iovecs = 2;
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
    int *fds = NULL;
    size_t nr_fds, i;
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

    ret = exec_command(vfu_ctx, &hdr, ret, fds, nr_fds, _iovecs, &iovecs,
                       &nr_iovecs, &free_iovec_data);

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
                             0, iovecs, nr_iovecs, NULL, 0, -ret);
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

    if (iovecs != NULL && iovecs != _iovecs) {
        if (free_iovec_data) {
            size_t i;
            for (i = 0; i < nr_iovecs; i++) {
                free(iovecs[i].iov_base);
            }
        }
        free(iovecs);
    }

    return ret;
}

static int
prepare_ctx(vfu_ctx_t *vfu_ctx)
{
    vfu_reg_info_t *cfg_reg;
    const vfu_reg_info_t zero_reg = { 0 };
    int err;
    uint32_t max_ivs = 0, i;
    size_t size;

    if (vfu_ctx->ready != 0) {
        return 0;
    }

    /*
     * With LIBVFIO_USER_FLAG_ATTACH_NB caller is always expected to call
     * vfu_ctx_try_attach().
     */
    if ((vfu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB) == 0) {
        vfu_ctx->conn_fd = vfu_ctx->trans->attach(vfu_ctx);
        if (vfu_ctx->conn_fd < 0) {
            err = vfu_ctx->conn_fd;
            if (err != EINTR) {
                vfu_log(vfu_ctx, LOG_ERR, "failed to attach: %s",
                       strerror(-err));
            }
            return err;
        }
    }

    cfg_reg = &vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX];

    // Set a default config region if none provided.
    /* TODO should it be enough to check that the size of region is 0? */
    if (memcmp(cfg_reg, &zero_reg, sizeof(*cfg_reg)) == 0) {
        cfg_reg->flags = VFU_REGION_FLAG_RW;
        cfg_reg->size = PCI_CFG_SPACE_SIZE;
    }

    // This maybe allocated by vfu_setup_pci_config_hdr().
    if (vfu_ctx->pci.config_space == NULL) {
        vfu_ctx->pci.config_space = calloc(1, cfg_reg->size);
        if (vfu_ctx->pci.config_space == NULL) {
            return -ENOMEM;
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
            return  -ENOMEM;
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

    if (vfu_ctx->pci.caps != NULL) {
        vfu_ctx->pci.config_space->hdr.sts.cl = 0x1;
        vfu_ctx->pci.config_space->hdr.cap = PCI_STD_HEADER_SIZEOF;
    }
    vfu_ctx->ready = 1;

    return 0;
}

int
vfu_ctx_drive(vfu_ctx_t *vfu_ctx)
{
    int err;

    if (vfu_ctx == NULL) {
        return ERROR(EINVAL);
    }

    err = prepare_ctx(vfu_ctx);
    if (err < 0) {
        return ERROR(-err);
    }

    do {
        err = process_request(vfu_ctx);
    } while (err >= 0);

    return err;
}

int
vfu_ctx_poll(vfu_ctx_t *vfu_ctx)
{
    int err;

    if (unlikely((vfu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB) == 0)) {
        return -ENOTSUP;
    }

    assert(vfu_ctx->ready == 1);
    err = process_request(vfu_ctx);

    return err >= 0 ? 0 : err;
}

/* FIXME this is not enough anymore ? */
void *
vfu_mmap(vfu_ctx_t *vfu_ctx, off_t offset, size_t length)
{
    if ((vfu_ctx == NULL) || (length == 0) || !PAGE_ALIGNED(offset)) {
        if (vfu_ctx != NULL) {
            vfu_log(vfu_ctx, LOG_DEBUG, "bad device mmap region %#lx-%#lx\n",
                   offset, offset + length);
        }
        errno = EINVAL;
        return MAP_FAILED;
    }

    return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED,
                vfu_ctx->fd, offset);
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
    free(vfu_ctx->pci.caps);
    free(vfu_ctx->migration);
    free(vfu_ctx->irqs);
    free(vfu_ctx);
    // FIXME: Maybe close any open irq efds? Unmap stuff?
}

int
vfu_ctx_try_attach(vfu_ctx_t *vfu_ctx)
{
    int err;

    assert(vfu_ctx != NULL);

    if ((vfu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB) == 0) {
        return ERROR(EINVAL);
    }

    err = prepare_ctx(vfu_ctx);
    if (err < 0) {
        return ERROR(-err);
    }

    return vfu_ctx->trans->attach(vfu_ctx);
}

bool
is_valid_pci_type(vfu_pci_type_t t)
{
    return t >= VFU_PCI_TYPE_CONVENTIONAL && t <= VFU_PCI_TYPE_EXPRESS;
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
        err = errno;
        goto out;
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
        goto out;
    }

    if (vfu_ctx->trans->init != NULL) {
        err = vfu_ctx->trans->init(vfu_ctx);
        if (err < 0) {
            goto out;
        }
        vfu_ctx->fd = err;
    }
    err = 0;

out:
    if (err != 0) {
        if (vfu_ctx != NULL) {
            vfu_destroy_ctx(vfu_ctx);
            vfu_ctx = NULL;
        }
        errno = -err;
    }

    return vfu_ctx;
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

int
vfu_pci_setup_config_hdr(vfu_ctx_t *vfu_ctx, vfu_pci_hdr_id_t id,
                         vfu_pci_hdr_ss_t ss, vfu_pci_hdr_cc_t cc,
                         vfu_pci_type_t pci_type,
                         int revision __attribute__((unused)))
{
    vfu_pci_config_space_t *config_space;
    size_t size;

    assert(vfu_ctx != NULL);

    /*
     * TODO there no real reason why we shouldn't allow this, we should just
     * clean up and redo it.
     */
    if (vfu_ctx->pci.config_space != NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "PCI configuration space header already setup");
        return ERROR(EEXIST);
    }

    switch (vfu_ctx->pci.type) {
    case VFU_PCI_TYPE_CONVENTIONAL:
    case VFU_PCI_TYPE_PCI_X_1:
        size = PCI_CFG_SPACE_SIZE;
        break;
    case VFU_PCI_TYPE_PCI_X_2:
    case VFU_PCI_TYPE_EXPRESS:
        size = PCI_CFG_SPACE_EXP_SIZE;
        break;
    default:
        vfu_log(vfu_ctx, LOG_ERR, "invalid PCI type %d", pci_type);
        return ERROR(EINVAL);
    }

    // Allocate a buffer for the config space.
    config_space = calloc(1, size);
    if (config_space == NULL) {
        return ERROR(ENOMEM);
    }

    config_space->hdr.id = id;
    config_space->hdr.ss = ss;
    config_space->hdr.cc = cc;
    vfu_ctx->pci.config_space = config_space;
    vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX].size = size;

    return 0;
}

int
vfu_pci_setup_caps(vfu_ctx_t *vfu_ctx, vfu_cap_t **caps, int nr_caps)
{
    int ret;

    assert(vfu_ctx != NULL);

    if (vfu_ctx->pci.caps != NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "capabilities are already setup");
        return ERROR(EEXIST);
    }

    if (caps == NULL || nr_caps == 0) {
        vfu_log(vfu_ctx, LOG_ERR, "Invalid args passed");
        return ERROR(EINVAL);
    }

    vfu_ctx->pci.caps = caps_create(vfu_ctx, caps, nr_caps, &ret);
    if (vfu_ctx->pci.caps == NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to create PCI capabilities: %s",
               strerror(ret));
        return ERROR(ret);
    }

    return 0;
}

static int
copy_sparse_mmap_areas(vfu_reg_info_t *reg_info,
                       struct iovec *mmap_areas, uint32_t nr_mmap_areas)
{
    struct vfu_sparse_mmap_areas *smmap_areas;
    size_t areas_sz;

    if (mmap_areas == NULL || nr_mmap_areas ==  0) {
        return 0;
    }

    areas_sz  = nr_mmap_areas * sizeof(struct iovec);

    smmap_areas = calloc(1, sizeof(struct vfu_sparse_mmap_areas) + areas_sz);
    if (smmap_areas == NULL) {
        return -ENOMEM;
    }

    smmap_areas->nr_mmap_areas = nr_mmap_areas;
    memcpy(smmap_areas->areas, mmap_areas, areas_sz);
    reg_info->mmap_areas  = smmap_areas;

    return 0;
}

int
vfu_setup_region(vfu_ctx_t *vfu_ctx, int region_idx, size_t size,
                 vfu_region_access_cb_t *region_access, int flags,
                 struct iovec *mmap_areas, uint32_t nr_mmap_areas,
                 vfu_map_region_cb_t *map)
{
    int ret;

    assert(vfu_ctx != NULL);

    switch(region_idx) {
    case VFU_PCI_DEV_BAR0_REGION_IDX ... VFU_PCI_DEV_VGA_REGION_IDX:
        // Validate the config region provided.
        if (region_idx == VFU_PCI_DEV_CFG_REGION_IDX &&
            flags != VFU_REGION_FLAG_RW) {
            return ERROR(EINVAL);
        }

        vfu_ctx->reg_info[region_idx].flags = flags;
        vfu_ctx->reg_info[region_idx].size = size;
        vfu_ctx->reg_info[region_idx].fn = region_access;

        if (map != NULL) {
            vfu_ctx->reg_info[region_idx].map = map;
        }
        if (mmap_areas) {
            ret = copy_sparse_mmap_areas(&vfu_ctx->reg_info[region_idx],
                                         mmap_areas, nr_mmap_areas);
            if (ret < 0) {
                return ERROR(-ret);
            }
        }
        break;
    default:
        vfu_log(vfu_ctx, LOG_ERR, "Invalid region index %d", region_idx);
        return ERROR(EINVAL);
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

    vfu_ctx->map_dma = map_dma;
    vfu_ctx->unmap_dma = unmap_dma;

    // Create the internal DMA controller.
    if (vfu_ctx->unmap_dma != NULL) {
        vfu_ctx->dma = dma_controller_create(vfu_ctx, VFU_DMA_REGIONS);
        if (vfu_ctx->dma == NULL) {
            return ERROR(ENOMEM);
        }
    }

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
    ret = copy_sparse_mmap_areas(migr_reg, migration->mmap_areas,
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

/*
 * Returns a pointer to the standard part of the PCI configuration space.
 */
inline vfu_pci_config_space_t *
vfu_pci_get_config_space(vfu_ctx_t *vfu_ctx)
{
    assert(vfu_ctx != NULL);
    return vfu_ctx->pci.config_space;
}

/*
 * Returns a pointer to the non-standard part of the PCI configuration space.
 */
inline uint8_t *
vfu_get_pci_non_std_config_space(vfu_ctx_t *vfu_ctx)
{
    assert(vfu_ctx != NULL);
    return (uint8_t *)&vfu_ctx->pci.config_space->non_std;
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

uint8_t *
vfu_ctx_get_cap(vfu_ctx_t *vfu_ctx, uint8_t id)
{
    assert(vfu_ctx != NULL);

    return cap_find_by_id(vfu_ctx, id);
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

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
