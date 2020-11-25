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
vu_log(vu_ctx_t *vu_ctx, vu_log_lvl_t lvl, const char *fmt, ...)
{
    va_list ap;
    char buf[BUFSIZ];
    int _errno = errno;

    assert(vu_ctx != NULL);

    if (vu_ctx->log == NULL || lvl > vu_ctx->log_lvl || fmt == NULL) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    vu_ctx->log(vu_ctx->pvt, lvl, buf);
    errno = _errno;
}

static inline int ERROR(int err)
{
    errno = err;
    return -1;
}

static size_t
get_vfio_caps_size(bool is_migr_reg, struct vu_sparse_mmap_areas *m)
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
dev_get_caps(vu_ctx_t *vu_ctx, vu_reg_info_t *vu_reg, bool is_migr_reg,
             struct vfio_region_info *vfio_reg)
{
    struct vfio_info_cap_header *header;
    struct vfio_region_info_cap_type *type = NULL;
    struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
    struct vu_sparse_mmap_areas *mmap_areas;

    assert(vu_ctx != NULL);
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

    if (vu_reg->mmap_areas != NULL) {
        int i, nr_mmap_areas = vu_reg->mmap_areas->nr_mmap_areas;
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

        mmap_areas = vu_reg->mmap_areas;
        for (i = 0; i < nr_mmap_areas; i++) {
            sparse->areas[i].offset = mmap_areas->areas[i].start;
            sparse->areas[i].size = mmap_areas->areas[i].size;
            vu_log(vu_ctx, VU_DBG, "%s: area %d %#llx-%#llx", __func__,
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

#define VU_REGION_SHIFT 40
#define VU_REGION_MASK  ((1ULL << VU_REGION_SHIFT) - 1)

uint64_t
region_to_offset(uint32_t region)
{
    return (uint64_t)region << VU_REGION_SHIFT;
}

uint32_t
offset_to_region(uint64_t offset)
{
    return (offset >> VU_REGION_SHIFT) & VU_REGION_MASK;
}

#ifdef VU_VERBOSE_LOGGING
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
is_migr_reg(vu_ctx_t *vu_ctx, int index)
{
    return &vu_ctx->reg_info[index] == vu_ctx->migr_reg;
}

static long
dev_get_reginfo(vu_ctx_t *vu_ctx, uint32_t index,
                struct vfio_region_info **vfio_reg)
{
    vu_reg_info_t *vu_reg;
    size_t caps_size;
    uint32_t argsz;

    assert(vu_ctx != NULL);
    assert(vfio_reg != NULL);

    vu_reg = &vu_ctx->reg_info[index];

    if (index >= vu_ctx->nr_regions) {
        vu_log(vu_ctx, VU_DBG, "bad region index %d", index);
        return -EINVAL;
    }

    caps_size = get_vfio_caps_size(is_migr_reg(vu_ctx, index), vu_reg->mmap_areas);
    argsz = caps_size + sizeof(struct vfio_region_info);
    *vfio_reg = calloc(1, argsz);
    if (!*vfio_reg) {
        return -ENOMEM;
    }
    /* FIXME document in the protocol that vfio_req->argsz is ignored */
    (*vfio_reg)->argsz = argsz;
    (*vfio_reg)->flags = vu_reg->flags;
    (*vfio_reg)->index = index;
    (*vfio_reg)->offset = region_to_offset((*vfio_reg)->index);
    (*vfio_reg)->size = vu_reg->size;

    if (caps_size > 0) {
        dev_get_caps(vu_ctx, vu_reg, is_migr_reg(vu_ctx, index), *vfio_reg);
    }

    vu_log(vu_ctx, VU_DBG, "region_info[%d] offset %#llx flags %#x size %llu "
           "argsz %u",
           (*vfio_reg)->index, (*vfio_reg)->offset, (*vfio_reg)->flags,
           (*vfio_reg)->size, (*vfio_reg)->argsz);

    return 0;
}

int
vu_get_region(loff_t pos, size_t count, loff_t *off)
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
region_size(vu_ctx_t *vu_ctx, int region)
{
        assert(region >= VU_PCI_DEV_BAR0_REGION_IDX && region <= VU_PCI_DEV_VGA_REGION_IDX);
        return vu_ctx->reg_info[region].size;
}

static uint32_t
pci_config_space_size(vu_ctx_t *vu_ctx)
{
    return region_size(vu_ctx, VU_PCI_DEV_CFG_REGION_IDX);
}

static ssize_t
handle_pci_config_space_access(vu_ctx_t *vu_ctx, char *buf, size_t count,
                               loff_t pos, bool is_write)
{
    int ret;

    count = MIN(pci_config_space_size(vu_ctx), count);
    if (is_write) {
        ret = cap_maybe_access(vu_ctx, vu_ctx->caps, buf, count, pos);
        if (ret < 0) {
            vu_log(vu_ctx, VU_ERR, "bad access to capabilities %#lx-%#lx\n",
                   pos, pos + count);
            return ret;
        }
    } else {
        memcpy(buf, vu_ctx->pci_config_space->raw + pos, count);
    }
    return count;
}

static ssize_t
do_access(vu_ctx_t *vu_ctx, char *buf, uint8_t count, uint64_t pos, bool is_write)
{
    int idx;
    loff_t offset;

    assert(vu_ctx != NULL);
    assert(buf != NULL);
    assert(count == 1 || count == 2 || count == 4 || count == 8);

    idx = vu_get_region(pos, count, &offset);
    if (idx < 0) {
        vu_log(vu_ctx, VU_ERR, "invalid region %d", idx);
        return idx;
    }

    if (idx < 0 || idx >= (int)vu_ctx->nr_regions) {
        vu_log(vu_ctx, VU_ERR, "bad region %d", idx);
        return -EINVAL;
    }

    if (idx == VU_PCI_DEV_CFG_REGION_IDX) {
        return handle_pci_config_space_access(vu_ctx, buf, count, offset,
                                              is_write);
    }

    if (is_migr_reg(vu_ctx, idx)) {
        if (offset + count > vu_ctx->reg_info[idx].size) {
            vu_log(vu_ctx, VU_ERR, "read %#lx-%#lx past end of migration region (%#x)",
                   offset, offset + count - 1,
                   vu_ctx->reg_info[idx].size);
            return -EINVAL;
        }
        return handle_migration_region_access(vu_ctx, vu_ctx->pvt,
                                              vu_ctx->migration,
                                              buf, count, offset, is_write);
    }

    /*
     * Checking whether a callback exists might sound expensive however this
     * code is not performance critical. This works well when we don't expect a
     * region to be used, so the user of the library can simply leave the
     * callback NULL in vu_create_ctx.
     */
    if (vu_ctx->reg_info[idx].fn != NULL) {
        return vu_ctx->reg_info[idx].fn(vu_ctx->pvt, buf, count, offset,
                                        is_write);
    }

    vu_log(vu_ctx, VU_ERR, "no callback for region %d", idx);

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
_vu_access(vu_ctx_t *vu_ctx, char *buf, uint32_t count, uint64_t *ppos,
          bool is_write)
{
    uint32_t done = 0;
    int ret;

    assert(vu_ctx != NULL);
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
        ret = do_access(vu_ctx, buf, size, *ppos, is_write);
        if (ret <= 0) {
            vu_log(vu_ctx, VU_ERR, "failed to %s %#lx-%#lx: %s",
                   is_write ? "write to" : "read from", *ppos, *ppos + size - 1,
                   strerror(-ret));
            /*
             * TODO if ret < 0 then it might contain a legitimate error code, why replace it with EFAULT?
             */
            return -EFAULT;
        }
        if (ret != (int)size) {
            vu_log(vu_ctx, VU_DBG, "bad read %d != %ld", ret, size);
        }
        count -= size;
        done += size;
        *ppos += size;
        buf += size;
    }
    return done;
}

static inline int
vu_access(vu_ctx_t *vu_ctx, bool is_write, char *rwbuf, uint32_t count,
             uint64_t *pos)
{
    uint32_t processed = 0, _count;
    int ret;

    assert(vu_ctx != NULL);
    assert(rwbuf != NULL);
    assert(pos != NULL);

    vu_log(vu_ctx, VU_DBG, "%s %#lx-%#lx", is_write ? "W" : "R", *pos,
           *pos + count - 1);

#ifdef VU_VERBOSE_LOGGING
    if (is_write) {
        dump_buffer("buffer write", rwbuf, count);
    }
#endif

    _count = count;
    ret = vu_pci_hdr_access(vu_ctx, &_count, pos, is_write, rwbuf);
    if (ret != 0) {
        /* FIXME shouldn't we fail here? */
        vu_log(vu_ctx, VU_ERR, "failed to access PCI header: %s",
               strerror(-ret));
#ifdef VU_VERBOSE_LOGGING
        dump_buffer("buffer write", rwbuf, _count);
#endif
    }

    /*
     * count is how much has been processed by vu_pci_hdr_access,
     * _count is how much there's left to be processed by vu_access
     */
    processed = count - _count;
    ret = _vu_access(vu_ctx, rwbuf + processed, _count, pos, is_write);
    if (ret >= 0) {
        ret += processed;
#ifdef VU_VERBOSE_LOGGING
        if (!is_write && err == ret) {
            dump_buffer("buffer read", rwbuf, ret);
        }
#endif
    }

    return ret;
}

/* TODO merge with dev_get_reginfo */
static int
handle_device_get_region_info(vu_ctx_t *vu_ctx, uint32_t size,
                              struct vfio_region_info *reg_info_in,
                              struct vfio_region_info **reg_info_out)
{
    if (size != sizeof(*reg_info_in) || size != reg_info_in->argsz) {
        return -EINVAL;
    }

    return dev_get_reginfo(vu_ctx, reg_info_in->index, reg_info_out);
}

static int
handle_device_get_info(vu_ctx_t *vu_ctx, uint32_t size,
                       struct vfio_device_info *dev_info)
{
    assert(vu_ctx != NULL);
    assert(dev_info != NULL);

    if (size != sizeof *dev_info) {
        return -EINVAL;
    }

    dev_info->argsz = sizeof *dev_info;
    dev_info->flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
    dev_info->num_regions = vu_ctx->nr_regions;
    dev_info->num_irqs = VU_DEV_NUM_IRQS;

    vu_log(vu_ctx, VU_DBG, "sent devinfo flags %#x, num_regions %d, num_irqs"
           " %d", dev_info->flags, dev_info->num_regions, dev_info->num_irqs);

    return 0;
}

int
handle_dma_map_or_unmap(vu_ctx_t *vu_ctx, uint32_t size, bool map,
                        int *fds, int nr_fds,
                        struct vfio_user_dma_region *dma_regions)
{
    int nr_dma_regions;
    int fdi = 0;
    int ret, i;

    assert(vu_ctx != NULL);

    if (size % sizeof(struct vfio_user_dma_region) != 0) {
        vu_log(vu_ctx, VU_ERR, "bad size of DMA regions %d", size);
        return -EINVAL;
    }

    if (vu_ctx->dma == NULL) {
        return 0;
    }

    nr_dma_regions = (int)(size / sizeof(struct vfio_user_dma_region));

    for (i = 0; i < nr_dma_regions; i++) {
        if (map) {
            int fd;

            /*
             * FIXME: need a dma controller that allows non-fd region.
             */
            if (dma_regions[i].flags != VFIO_USER_F_DMA_REGION_MAPPABLE) {
                vu_log(vu_ctx, VU_INF,
                       "FIXME: ignored non-mappable DMA region "
                       "%#lx-%#lx offset=%#lx",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1,
                       dma_regions[i].offset);
                continue;
            }

            if (fdi >= nr_fds) {
                vu_log(vu_ctx, VU_ERR, "missing fd for mappable region %d", i);
                return -EINVAL;
            }

            fd = fds[fdi++];

            ret = dma_controller_add_region(vu_ctx->dma,
                                            dma_regions[i].addr,
                                            dma_regions[i].size,
                                            fd,
                                            dma_regions[i].offset);
            if (ret < 0) {
                vu_log(vu_ctx, VU_INF,
                       "failed to add DMA region %#lx-%#lx offset=%#lx fd=%d: %s",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1,
                       dma_regions[i].offset, fd,
                       strerror(-ret));
            } else {
                vu_log(vu_ctx, VU_DBG,
                       "added DMA region %#lx-%#lx offset=%#lx fd=%d",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1,
                       dma_regions[i].offset, fd);
            }
        } else {
            ret = dma_controller_remove_region(vu_ctx->dma,
                                               dma_regions[i].addr,
                                               dma_regions[i].size,
                                               vu_ctx->unmap_dma, vu_ctx->pvt);
            if (ret < 0) {
                vu_log(vu_ctx, VU_INF,
                       "failed to remove DMA region %#lx-%#lx: %s",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1,
                       strerror(-ret));
            } else {
                vu_log(vu_ctx, VU_DBG,
                       "removed DMA region %#lx-%#lx",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1);
            }
        }
        if (ret < 0) {
            return ret;
        }
        if (vu_ctx->map_dma != NULL) {
            vu_ctx->map_dma(vu_ctx->pvt, dma_regions[i].addr, dma_regions[i].size);
        }
    }
    return 0;
}

static int
handle_device_reset(vu_ctx_t *vu_ctx)
{
    vu_log(vu_ctx, VU_DBG, "Device reset called by client");
    if (vu_ctx->reset != NULL) {
        return vu_ctx->reset(vu_ctx->pvt);
    }
    return 0;
}

static int
validate_region_access(vu_ctx_t *vu_ctx, uint32_t size, uint16_t cmd,
                       struct vfio_user_region_access *region_access)
{
    assert(region_access != NULL);

    if (size < sizeof *region_access) {
        vu_log(vu_ctx, VU_ERR, "message size too small (%d)", size);
        return -EINVAL;
    }

    if (region_access->region > vu_ctx->nr_regions ||  region_access->count <= 0) {
        vu_log(vu_ctx, VU_ERR, "bad region %d and/or count %d",
               region_access->region, region_access->count);
        return -EINVAL;
    }

    if (device_is_stopped_and_copying(vu_ctx->migration) &&
        !is_migr_reg(vu_ctx, region_access->region)) {
        vu_log(vu_ctx, VU_ERR,
               "cannot access region %d while device in stop-and-copy state",
               region_access->region);
        return -EINVAL;
    }

    if (cmd == VFIO_USER_REGION_WRITE &&
        size - sizeof *region_access != region_access->count)
    {
        vu_log(vu_ctx, VU_ERR, "bad region access, expected %lu, actual %d",
               size - sizeof *region_access, region_access->count);
        return -EINVAL;
    }

    return 0;
}

static int
handle_region_access(vu_ctx_t *vu_ctx, uint32_t size, uint16_t cmd,
                     void **data, size_t *len,
                     struct vfio_user_region_access *region_access)
{
    uint64_t count, offset;
    int ret;
    char *buf;

    assert(vu_ctx != NULL);
    assert(data != NULL);
    assert(region_access != NULL);

    ret = validate_region_access(vu_ctx, size, cmd, region_access);
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

    ret = vu_access(vu_ctx, cmd == VFIO_USER_REGION_WRITE, buf, count, &offset);
    if (ret != (int)region_access->count) {
        vu_log(vu_ctx, VU_ERR, "failed to %s %#x-%#lx: %d",
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
handle_dirty_pages_get(vu_ctx_t *vu_ctx,
                       struct iovec **iovecs, size_t *nr_iovecs,
                       struct vfio_iommu_type1_dirty_bitmap_get *ranges,
                       uint32_t size)
{
    int ret = -EINVAL;
    size_t i;

    assert(vu_ctx != NULL);
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
        ret = dma_controller_dirty_page_get(vu_ctx->dma, r->iova, r->size,
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
handle_dirty_pages(vu_ctx_t *vu_ctx, uint32_t size,
                   struct iovec **iovecs, size_t *nr_iovecs,
                   struct vfio_iommu_type1_dirty_bitmap *dirty_bitmap)
{
    int ret;

    assert(vu_ctx != NULL);
    assert(iovecs != NULL);
    assert(nr_iovecs != NULL);
    assert(dirty_bitmap != NULL);

    if (size < sizeof *dirty_bitmap || size != dirty_bitmap->argsz) {
        vu_log(vu_ctx, VU_ERR, "invalid header size %u", size);
        return -EINVAL;
    }

    if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_START) {
        ret = dma_controller_dirty_page_logging_start(vu_ctx->dma,
                                                      migration_get_pgsize(vu_ctx->migration));
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP) {
        ret = dma_controller_dirty_page_logging_stop(vu_ctx->dma);
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP) {
        ret = handle_dirty_pages_get(vu_ctx, iovecs, nr_iovecs,
                                     (struct vfio_iommu_type1_dirty_bitmap_get*)(dirty_bitmap + 1),
                                     size - sizeof *dirty_bitmap);
    } else {
        vu_log(vu_ctx, VU_ERR, "bad flags %#x", dirty_bitmap->flags);
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
validate_header(vu_ctx_t *vu_ctx, struct vfio_user_header *hdr, size_t size)
{
    assert(hdr != NULL);

    if (size < sizeof hdr) {
        vu_log(vu_ctx, VU_ERR, "short header read %ld", size);
        return -EINVAL;
    }

    if (hdr->flags.type != VFIO_USER_F_TYPE_COMMAND) {
        vu_log(vu_ctx, VU_ERR, "header not a request");
        return -EINVAL;
    }

    if (hdr->msg_size < sizeof hdr) {
        vu_log(vu_ctx, VU_ERR, "bad size in header %d", hdr->msg_size);
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
static int
get_next_command(vu_ctx_t *vu_ctx, struct vfio_user_header *hdr, int *fds,
                 int *nr_fds)
{
    int ret;

    /* FIXME get request shouldn't set errno, it should return it as -errno */
    ret = vu_ctx->trans->get_request(vu_ctx, hdr, fds, nr_fds);
    if (unlikely(ret < 0)) {
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            return 0;
        }
        if (ret != -EINTR) {
            vu_log(vu_ctx, VU_ERR, "failed to receive request: %s",
                   strerror(-ret));
        }
        return ret;
    }
    if (unlikely(ret == 0)) {
        if (errno == EINTR) {
            return -EINTR;
        }
        if (errno == 0) {
            vu_log(vu_ctx, VU_INF, "vfio-user client closed connection");
        } else {
            vu_log(vu_ctx, VU_ERR, "end of file: %m");
        }
        return -ENOTCONN;
    }
    return ret;
}

static int
process_request(vu_ctx_t *vu_ctx)
{
    struct vfio_user_header hdr = { 0, };
    int ret;
    int *fds = NULL;
    int nr_fds;
    struct vfio_irq_info irq_info;
    struct vfio_device_info dev_info;
    struct vfio_region_info *dev_reg_info = NULL;
    struct iovec _iovecs[2] = { { 0, } };
    struct iovec *iovecs = NULL;
    size_t nr_iovecs = 0;
    bool free_iovec_data = true;
    void *cmd_data = NULL;

    assert(vu_ctx != NULL);

    if (device_is_stopped(vu_ctx->migration)) {
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

    nr_fds = vu_ctx->client_max_fds;
    fds = alloca(nr_fds * sizeof(int));

    ret = get_next_command(vu_ctx, &hdr, fds, &nr_fds);
    if (ret <= 0) {
        return ret;
    }

    ret = validate_header(vu_ctx, &hdr, ret);
    if (ret < 0) {
        return ret;
    }

    /*
     * TODO from now on if an error occurs we still need to reply. Move this
     * code into a separate function so that we don't have to use goto.
     */

    hdr.msg_size -= sizeof(hdr);
    if (hdr.msg_size > 0) {
        cmd_data = malloc(hdr.msg_size);
        if (cmd_data == NULL) {
            ret = -ENOMEM;
            goto reply;
        }
        // FIXME: should be transport op
        ret = recv(vu_ctx->conn_fd, cmd_data, hdr.msg_size, 0);
        if (ret < 0) {
            ret = -errno;
            goto reply;
        }
        if (ret != (int)hdr.msg_size) {
            vu_log(vu_ctx, VU_ERR, "short read, expected=%d, actual=%d",
                   hdr.msg_size, ret);
            ret = -EINVAL;
            goto reply;
        }
    }

    if (device_is_stopped_and_copying(vu_ctx->migration)
        && !(hdr.cmd == VFIO_USER_REGION_READ || hdr.cmd == VFIO_USER_REGION_WRITE)) {
        vu_log(vu_ctx, VU_ERR,
               "bad command %d while device in stop-and-copy state", hdr.cmd);
        ret = -EINVAL;
        goto reply;
    }

    switch (hdr.cmd) {
        case VFIO_USER_DMA_MAP:
        case VFIO_USER_DMA_UNMAP:
            ret = handle_dma_map_or_unmap(vu_ctx, hdr.msg_size,
                                          hdr.cmd == VFIO_USER_DMA_MAP,
                                          fds, nr_fds, cmd_data);
            break;
        case VFIO_USER_DEVICE_GET_INFO:
            ret = handle_device_get_info(vu_ctx, hdr.msg_size, &dev_info);
            if (ret >= 0) {
                _iovecs[1].iov_base = &dev_info;
                _iovecs[1].iov_len = dev_info.argsz;
                iovecs = _iovecs;
                nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_REGION_INFO:
            ret = handle_device_get_region_info(vu_ctx, hdr.msg_size, cmd_data,
                                                &dev_reg_info);
            if (ret == 0) {
                _iovecs[1].iov_base = dev_reg_info;
                _iovecs[1].iov_len = dev_reg_info->argsz;
                iovecs = _iovecs;
                nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_IRQ_INFO:
            ret = handle_device_get_irq_info(vu_ctx, hdr.msg_size, cmd_data,
                                             &irq_info);
            if (ret == 0) {
                _iovecs[1].iov_base = &irq_info;
                _iovecs[1].iov_len = sizeof irq_info;
                iovecs = _iovecs;
                nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_SET_IRQS:
            ret = handle_device_set_irqs(vu_ctx, hdr.msg_size, fds, nr_fds,
                                         cmd_data);
            break;
        case VFIO_USER_REGION_READ:
        case VFIO_USER_REGION_WRITE:
            iovecs = _iovecs;
            ret = handle_region_access(vu_ctx, hdr.msg_size, hdr.cmd,
                                       &iovecs[1].iov_base, &iovecs[1].iov_len,
                                       cmd_data);
            nr_iovecs = 2;
            break;
        case VFIO_USER_DEVICE_RESET:
            ret = handle_device_reset(vu_ctx);
            break;
        case VFIO_USER_DIRTY_PAGES:
            // FIXME: don't allow migration calls if migration == NULL
            ret = handle_dirty_pages(vu_ctx, hdr.msg_size, &iovecs, &nr_iovecs,
                                     cmd_data);
            if (ret >= 0) {
                free_iovec_data = false;
            }
            break;
        default:
            vu_log(vu_ctx, VU_ERR, "bad command %d", hdr.cmd);
            ret = -EINVAL;
            goto reply;
    }

reply:
    /*
     * TODO: In case of error during command handling set errno respectively
     * in the reply message.
     */
    if (ret < 0) {
        vu_log(vu_ctx, VU_ERR, "failed to handle command %d: %s", hdr.cmd,
               strerror(-ret));
    } else {
        ret = 0;
    }

    // FIXME: SPEC: should the reply include the command? I'd say yes?
    ret = vu_send_iovec(vu_ctx->conn_fd, hdr.msg_id, true,
                        0, iovecs, nr_iovecs, NULL, 0, -ret);
    if (unlikely(ret < 0)) {
        vu_log(vu_ctx, VU_ERR, "failed to complete command: %s",
                strerror(-ret));
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
    free(cmd_data);

    return ret;
}

static int prepare_ctx(vu_ctx_t *vu_ctx)
{
    vu_reg_info_t *cfg_reg;
    const vu_reg_info_t zero_reg = { 0 };
    int err;
    uint32_t max_ivs = 0, i;
    size_t size;

    if (vu_ctx->ready != 0) {
        return 0;
    }

    /*
     * With LIBVFIO_USER_FLAG_ATTACH_NB caller is always expected to call
     * vu_ctx_try_attach().
     */
    if ((vu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB) == 0) {
        vu_ctx->conn_fd = vu_ctx->trans->attach(vu_ctx);
        if (vu_ctx->conn_fd < 0) {
            err = vu_ctx->conn_fd;
            if (err != EINTR) {
                vu_log(vu_ctx, VU_ERR, "failed to attach: %s",
                       strerror(-err));
            }
            return err;
        }
    }

    cfg_reg = &vu_ctx->reg_info[VU_PCI_DEV_CFG_REGION_IDX];

    // Set a default config region if none provided.
    /* TODO should it be enough to check that the size of region is 0? */
    if (memcmp(cfg_reg, &zero_reg, sizeof(*cfg_reg)) == 0) {
        cfg_reg->flags = VU_REG_FLAG_RW;
        cfg_reg->size = PCI_CFG_SPACE_SIZE;
    }

    // This maybe allocated by vu_setup_pci_config_hdr().
    if (vu_ctx->pci_config_space == NULL) {
        vu_ctx->pci_config_space = calloc(1, cfg_reg->size);
        if (vu_ctx->pci_config_space == NULL) {
            return -ENOMEM;
        }
    }

    // Set type for region registers.
    for (i = 0; i < PCI_BARS_NR; i++) {
        if (!(vu_ctx->reg_info[i].flags & VU_REG_FLAG_MEM)) {
            vu_ctx->pci_config_space->hdr.bars[i].io.region_type |= 0x1;
        }
    }

    if (vu_ctx->irqs == NULL) {
        /*
         * FIXME need to check that the number of MSI and MSI-X IRQs are valid
         * (1, 2, 4, 8, 16 or 32 for MSI and up to 2048 for MSI-X).
         */

        // Work out highest count of irq vectors.
        for (i = 0; i < VU_DEV_NUM_IRQS; i++) {
            if (max_ivs < vu_ctx->irq_count[i]) {
                max_ivs = vu_ctx->irq_count[i];
            }
        }

        //FIXME: assert(max_ivs > 0)?
        size = sizeof(int) * max_ivs;
        vu_ctx->irqs = calloc(1, sizeof(vu_irqs_t) + size);
        if (vu_ctx->irqs == NULL) {
            // vu_ctx->pci_config_space should be free'ed by vu_destroy_ctx().
            return  -ENOMEM;
        }

        // Set context irq information.
        for (i = 0; i < max_ivs; i++) {
            vu_ctx->irqs->efds[i] = -1;
        }
        vu_ctx->irqs->err_efd = -1;
        vu_ctx->irqs->req_efd = -1;
        vu_ctx->irqs->type = IRQ_NONE;
        vu_ctx->irqs->max_ivs = max_ivs;

        // Reflect on the config space whether INTX is available.
        if (vu_ctx->irq_count[VU_DEV_INTX_IRQ] != 0) {
            vu_ctx->pci_config_space->hdr.intr.ipin = 1; // INTA#
        }
    }

    if (vu_ctx->caps != NULL) {
        vu_ctx->pci_config_space->hdr.sts.cl = 0x1;
        vu_ctx->pci_config_space->hdr.cap = PCI_STD_HEADER_SIZEOF;
    }
    vu_ctx->ready = 1;

    return 0;
}

int
vu_ctx_drive(vu_ctx_t *vu_ctx)
{
    int err;

    if (vu_ctx == NULL) {
        return ERROR(EINVAL);
    }

    err = prepare_ctx(vu_ctx);
    if (err < 0) {
        return ERROR(-err);
    }

    do {
        err = process_request(vu_ctx);
    } while (err >= 0);

    return err;
}

int
vu_ctx_poll(vu_ctx_t *vu_ctx)
{
    int err;

    if (unlikely((vu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB) == 0)) {
        return -ENOTSUP;
    }

    assert(vu_ctx->ready == 1);
    err = process_request(vu_ctx);

    return err >= 0 ? 0 : err;
}

/* FIXME this is not enough anymore ? */
void *
vu_mmap(vu_ctx_t *vu_ctx, off_t offset, size_t length)
{
    if ((vu_ctx == NULL) || (length == 0) || !PAGE_ALIGNED(offset)) {
        if (vu_ctx != NULL) {
            vu_log(vu_ctx, VU_DBG, "bad device mmap region %#lx-%#lx\n",
                   offset, offset + length);
        }
        errno = EINVAL;
        return MAP_FAILED;
    }

    return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED,
                vu_ctx->fd, offset);
}

static void
free_sparse_mmap_areas(vu_ctx_t *vu_ctx)
{
    int i;

    assert(vu_ctx != NULL);

    for (i = 0; i < (int)vu_ctx->nr_regions; i++) {
        free(vu_ctx->reg_info[i].mmap_areas);
    }
}

void
vu_ctx_destroy(vu_ctx_t *vu_ctx)
{

    if (vu_ctx == NULL) {
        return;
    }

    free(vu_ctx->uuid);
    free(vu_ctx->pci_config_space);
    if (vu_ctx->trans->detach != NULL) {
        vu_ctx->trans->detach(vu_ctx);
    }
    if (vu_ctx->dma != NULL) {
        dma_controller_destroy(vu_ctx->dma);
    }
    free_sparse_mmap_areas(vu_ctx);
    free(vu_ctx->reg_info);
    free(vu_ctx->caps);
    free(vu_ctx->migration);
    free(vu_ctx->irqs);
    free(vu_ctx);
    // FIXME: Maybe close any open irq efds? Unmap stuff?
}

struct vu_sparse_mmap_areas*
copy_sparse_mmap_area(struct vu_sparse_mmap_areas *src)
{
    struct vu_sparse_mmap_areas *dest;
    size_t size;

    assert(src != NULL);

    size = sizeof(*dest) + (src->nr_mmap_areas * sizeof(struct vu_mmap_area));
    dest = calloc(1, size);
    if (dest != NULL) {
        memcpy(dest, src, size);
    }
    return dest;
}

int
vu_ctx_try_attach(vu_ctx_t *vu_ctx)
{
    int err;

    assert(vu_ctx != NULL);

    if ((vu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB) == 0) {
        return ERROR(EINVAL);
    }

    err = prepare_ctx(vu_ctx);
    if (err < 0) {
        return ERROR(-err);
    }

    return vu_ctx->trans->attach(vu_ctx);
}

vu_ctx_t *vu_create_ctx(vu_trans_t trans, const char *path, int flags,
                        void *pvt)
{
    vu_ctx_t *vu_ctx = NULL;
    int err = 0;

    if (trans != VU_TRANS_SOCK) {
        errno = ENOTSUP;
        return NULL;
    }

    vu_ctx = calloc(1, sizeof(vu_ctx_t));
    if (vu_ctx == NULL) {
        return NULL;
    }
    vu_ctx->trans = &sock_transport_ops;

    //FIXME: Validate arguments.
    // Set other context data.
    vu_ctx->pvt = pvt;
    vu_ctx->flags = flags;
    vu_ctx->log_lvl = VU_ERR;

    vu_ctx->uuid = strdup(path);
    if (vu_ctx->uuid == NULL) {
        err = errno;
        goto out;
    }

    /*
     * FIXME: Now we always allocate for migration region. Check if its better
     * to seperate migration region from standard regions in vu_ctx.reg_info
     * and move it into vu_ctx.migration.
     */
    vu_ctx->nr_regions = VU_PCI_DEV_NUM_REGIONS + 1;
    vu_ctx->reg_info = calloc(vu_ctx->nr_regions, sizeof *vu_ctx->reg_info);
    if (vu_ctx->reg_info == NULL) {
        err = -ENOMEM;
        goto out;
    }

    if (vu_ctx->trans->init != NULL) {
        err = vu_ctx->trans->init(vu_ctx);
        if (err < 0) {
            goto out;
        }
        vu_ctx->fd = err;
    }
    err = 0;

out:
    if (err != 0) {
        if (vu_ctx != NULL) {
            vu_ctx_destroy(vu_ctx);
            vu_ctx = NULL;
        }
        errno = -err;
    }

    return vu_ctx;
}

int vu_setup_log(vu_ctx_t *vu_ctx, vu_log_fn_t *log, vu_log_lvl_t log_lvl)
{

    if (log_lvl != VU_ERR && log_lvl != VU_INF && log_lvl != VU_DBG) {
        return ERROR(EINVAL);
    }

    vu_ctx->log = log;
    vu_ctx->log_lvl = log_lvl;

    return 0;
}

int vu_pci_setup_config_hdr(vu_ctx_t *vu_ctx, vu_pci_hdr_id_t id,
                            vu_pci_hdr_ss_t ss, vu_pci_hdr_cc_t cc,
                            UNUSED bool extended)
{
    vu_pci_config_space_t *config_space;

    assert(vu_ctx != NULL);

    if (vu_ctx->pci_config_space != NULL) {
        vu_log(vu_ctx, VU_ERR, "pci header already setup");
        return ERROR(EEXIST);
    }

    /* TODO: supported extended PCI config space. */

    // Allocate a buffer for the config space.
    config_space = calloc(1, PCI_CFG_SPACE_SIZE);
    if (config_space == NULL) {
        return ERROR(ENOMEM);
    }

    config_space->hdr.id = id;
    config_space->hdr.ss = ss;
    config_space->hdr.cc = cc;
    vu_ctx->pci_config_space = config_space;

    return 0;
}

int vu_pci_setup_caps(vu_ctx_t *vu_ctx, vu_cap_t **caps, int nr_caps)
{
    int ret;

    assert(vu_ctx != NULL);

    if (vu_ctx->caps != NULL) {
        vu_log(vu_ctx, VU_ERR, "capabilities are already setup");
        return ERROR(EEXIST);
    }

    if (caps == NULL || nr_caps == 0) {
        vu_log(vu_ctx, VU_ERR, "Invalid args passed");
        return ERROR(EINVAL);
    }

    vu_ctx->caps = caps_create(vu_ctx, caps, nr_caps, &ret);
    if (vu_ctx->caps == NULL) {
        vu_log(vu_ctx, VU_ERR, "failed to create PCI capabilities: %s",
               strerror(ret));
        return ERROR(ret);
    }

    return 0;
}

static int
copy_sparse_mmap_areas(vu_reg_info_t *reg_info,
                       struct vu_sparse_mmap_areas *mmap_areas)
{
    int nr_mmap_areas;
    size_t size;

    if (mmap_areas == NULL) {
        return 0;
    }

    nr_mmap_areas = mmap_areas->nr_mmap_areas;
    size = sizeof(*mmap_areas) + (nr_mmap_areas * sizeof(struct vu_mmap_area));
    reg_info->mmap_areas = calloc(1, size);
    if (reg_info->mmap_areas == NULL) {
        return -ENOMEM;
    }

    memcpy(reg_info->mmap_areas, mmap_areas, size);

    return 0;
}

static inline bool is_valid_pci_config_space_region(int flags, size_t size)
{
    return flags == VU_REG_FLAG_RW && (size ==  PCI_CFG_SPACE_SIZE
            || size == PCI_CFG_SPACE_EXP_SIZE);
}

int vu_setup_region(vu_ctx_t *vu_ctx, int region_idx, size_t size,
                    vu_region_access_cb_t *region_access, int flags,
                    struct vu_sparse_mmap_areas *mmap_areas,
                    vu_map_region_cb_t *map)
{
    int ret;

    assert(vu_ctx != NULL);

    switch(region_idx) {
    case VU_PCI_DEV_BAR0_REGION_IDX ... VU_PCI_DEV_VGA_REGION_IDX:
        // Validate the config region provided.
        if (region_idx == VU_PCI_DEV_CFG_REGION_IDX &&
            !is_valid_pci_config_space_region(flags, size)) {
                return ERROR(EINVAL);
        }

        vu_ctx->reg_info[region_idx].flags = flags;
        vu_ctx->reg_info[region_idx].size = size;
        vu_ctx->reg_info[region_idx].fn = region_access;

        if (map != NULL) {
            vu_ctx->reg_info[region_idx].map = map;
        }
        if (mmap_areas) {
            ret = copy_sparse_mmap_areas(&vu_ctx->reg_info[region_idx],
                                         mmap_areas);
            if (ret < 0) {
                return ERROR(-ret);
            }
        }
        break;
    default:
        vu_log(vu_ctx, VU_ERR, "Invalid region index %d", region_idx);
        return ERROR(EINVAL);
    }

    return 0;
}

int vu_setup_device_reset_cb(vu_ctx_t *vu_ctx, vu_reset_cb_t *reset)
{

    assert(vu_ctx != NULL);
    vu_ctx->reset = reset;

    return 0;
}

int vu_setup_device_dma_cb(vu_ctx_t *vu_ctx, vu_map_dma_cb_t *map_dma,
                           vu_unmap_dma_cb_t *unmap_dma)
{

    assert(vu_ctx != NULL);

    vu_ctx->map_dma = map_dma;
    vu_ctx->unmap_dma = unmap_dma;

    // Create the internal DMA controller.
    if (vu_ctx->unmap_dma != NULL) {
        vu_ctx->dma = dma_controller_create(vu_ctx, VU_DMA_REGIONS);
        if (vu_ctx->dma == NULL) {
            return ERROR(ENOMEM);
        }
    }

    return 0;
}

int vu_setup_device_nr_irqs(vu_ctx_t *vu_ctx, enum vu_dev_irq_type type,
                            uint32_t count)
{

    assert(vu_ctx != NULL);

    if (type < VU_DEV_INTX_IRQ || type > VU_DEV_REQ_IRQ) {
        vu_log(vu_ctx, VU_ERR, "Invalid IRQ index %d, should be between "
               "(%d to %d)", type, VU_DEV_INTX_IRQ,
               VU_DEV_REQ_IRQ);
        return ERROR(EINVAL);
    }

    vu_ctx->irq_count[type] = count;

    return 0;
}

int vu_setup_device_migration(vu_ctx_t *vu_ctx, vu_migration_t *migration)
{
    vu_reg_info_t   *migr_reg;
    int ret = 0;

    assert(vu_ctx != NULL);

    //FIXME: Validate args.

    if (vu_ctx->migr_reg != NULL) {
        vu_log(vu_ctx, VU_ERR, "device migration is already setup");
        return ERROR(EEXIST);
    }

    /* FIXME hacky, find a more robust way to allocate a region index */
    migr_reg = &vu_ctx->reg_info[(vu_ctx->nr_regions - 1)];

    /* FIXME: Are there sparse areas need to be setup flags accordingly */
    ret = copy_sparse_mmap_areas(migr_reg, migration->mmap_areas);
    if (ret < 0) {
        return ERROR(-ret);
    }

    migr_reg->flags = VU_REG_FLAG_RW;
    migr_reg->size = sizeof(struct vfio_device_migration_info) + migration->size;

    vu_ctx->migration = init_migration(migration, &ret);
    if (vu_ctx->migration == NULL) {
        vu_log(vu_ctx, VU_ERR, "failed to initialize device migration");
        free(migr_reg->mmap_areas);
        return ERROR(ret);
    }
    vu_ctx->migr_reg = migr_reg;

    return 0;
}

/*
 * Returns a pointer to the standard part of the PCI configuration space.
 */
inline vu_pci_config_space_t *
vu_pci_get_config_space(vu_ctx_t *vu_ctx)
{
    assert(vu_ctx != NULL);
    return vu_ctx->pci_config_space;
}

/*
 * Returns a pointer to the non-standard part of the PCI configuration space.
 */
inline uint8_t *
vu_get_pci_non_std_config_space(vu_ctx_t *vu_ctx)
{
    assert(vu_ctx != NULL);
    return (uint8_t *)&vu_ctx->pci_config_space->non_std;
}

inline vu_reg_info_t *
vu_get_region_info(vu_ctx_t *vu_ctx)
{
    assert(vu_ctx != NULL);
    return vu_ctx->reg_info;
}

inline int
vu_addr_to_sg(vu_ctx_t *vu_ctx, dma_addr_t dma_addr,
              uint32_t len, dma_sg_t *sg, int max_sg, int prot)
{
    assert(vu_ctx != NULL);

    if (unlikely(vu_ctx->unmap_dma == NULL)) {
        errno = EINVAL;
        return -1;
    }
    return dma_addr_to_sg(vu_ctx->dma, dma_addr, len, sg, max_sg, prot);
}

inline int
vu_map_sg(vu_ctx_t *vu_ctx, const dma_sg_t *sg,
	  struct iovec *iov, int cnt)
{
    if (unlikely(vu_ctx->unmap_dma == NULL)) {
        errno = EINVAL;
        return -1;
    }
    return dma_map_sg(vu_ctx->dma, sg, iov, cnt);
}

inline void
vu_unmap_sg(vu_ctx_t *vu_ctx, const dma_sg_t *sg, struct iovec *iov, int cnt)
{
    if (unlikely(vu_ctx->unmap_dma == NULL)) {
        return;
    }
    return dma_unmap_sg(vu_ctx->dma, sg, iov, cnt);
}

uint8_t *
vu_ctx_get_cap(vu_ctx_t *vu_ctx, uint8_t id)
{
    assert(vu_ctx != NULL);

    return cap_find_by_id(vu_ctx, id);
}

int
vu_dma_read(vu_ctx_t *vu_ctx, dma_sg_t *sg, void *data)
{
    struct vfio_user_dma_region_access *dma_recv;
    struct vfio_user_dma_region_access dma_send;
    int recv_size;
    int msg_id = 1, ret;

    assert(vu_ctx != NULL);
    assert(sg != NULL);

    recv_size = sizeof(*dma_recv) + sg->length;

    dma_recv = calloc(recv_size, 1);
    if (dma_recv == NULL) {
        return -ENOMEM;
    }

    dma_send.addr = sg->dma_addr;
    dma_send.count = sg->length;
    ret = vu_msg(vu_ctx->conn_fd, msg_id, VFIO_USER_DMA_READ,
                 &dma_send, sizeof dma_send, NULL,
                 dma_recv, recv_size);
    memcpy(data, dma_recv->data, sg->length); /* FIXME no need for memcpy */
    free(dma_recv);

    return ret;
}

int
vu_dma_write(vu_ctx_t *vu_ctx, dma_sg_t *sg, void *data)
{
    struct vfio_user_dma_region_access *dma_send, dma_recv;
    int send_size = sizeof(*dma_send) + sg->length;
    int msg_id = 1, ret;

    assert(vu_ctx != NULL);
    assert(sg != NULL);

    dma_send = calloc(send_size, 1);
    if (dma_send == NULL) {
        return -ENOMEM;
    }
    dma_send->addr = sg->dma_addr;
    dma_send->count = sg->length;
    memcpy(dma_send->data, data, sg->length); /* FIXME no need to copy! */
    ret = vu_msg(vu_ctx->conn_fd, msg_id, VFIO_USER_DMA_WRITE,
                 dma_send, send_size, NULL,
                 &dma_recv, sizeof(dma_recv));
    free(dma_send);

    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
