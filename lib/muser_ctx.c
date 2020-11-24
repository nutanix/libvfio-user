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
#include "muser.h"
#include "muser_priv.h"
#include "tran_sock.h"
#include "migration.h"
#include "irq.h"


void
lm_log(lm_ctx_t *lm_ctx, lm_log_lvl_t lvl, const char *fmt, ...)
{
    va_list ap;
    char buf[BUFSIZ];
    int _errno = errno;

    assert(lm_ctx != NULL);

    if (lm_ctx->log == NULL || lvl > lm_ctx->log_lvl || fmt == NULL) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    lm_ctx->log(lm_ctx->pvt, lvl, buf);
    errno = _errno;
}

static inline int ERROR(int err)
{
    errno = err;
    return -1;
}

static size_t
get_vfio_caps_size(bool is_migr_reg, struct lm_sparse_mmap_areas *m)
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
dev_get_caps(lm_ctx_t *lm_ctx, lm_reg_info_t *lm_reg, bool is_migr_reg,
             struct vfio_region_info *vfio_reg)
{
    struct vfio_info_cap_header *header;
    struct vfio_region_info_cap_type *type = NULL;
    struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
    struct lm_sparse_mmap_areas *mmap_areas;

    assert(lm_ctx != NULL);
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

    if (lm_reg->mmap_areas != NULL) {
        int i, nr_mmap_areas = lm_reg->mmap_areas->nr_mmap_areas;
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

        mmap_areas = lm_reg->mmap_areas;
        for (i = 0; i < nr_mmap_areas; i++) {
            sparse->areas[i].offset = mmap_areas->areas[i].start;
            sparse->areas[i].size = mmap_areas->areas[i].size;
            lm_log(lm_ctx, LM_DBG, "%s: area %d %#llx-%#llx", __func__,
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

#define LM_REGION_SHIFT 40
#define LM_REGION_MASK  ((1ULL << LM_REGION_SHIFT) - 1)

uint64_t
region_to_offset(uint32_t region)
{
    return (uint64_t)region << LM_REGION_SHIFT;
}

uint32_t
offset_to_region(uint64_t offset)
{
    return (offset >> LM_REGION_SHIFT) & LM_REGION_MASK;
}

#ifdef LM_VERBOSE_LOGGING
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
is_migr_reg(lm_ctx_t *lm_ctx, int index)
{
    return &lm_ctx->reg_info[index] == lm_ctx->migr_reg;
}

static long
dev_get_reginfo(lm_ctx_t *lm_ctx, uint32_t index,
                struct vfio_region_info **vfio_reg)
{
    lm_reg_info_t *lm_reg;
    size_t caps_size;
    uint32_t argsz;

    assert(lm_ctx != NULL);
    assert(vfio_reg != NULL);

    lm_reg = &lm_ctx->reg_info[index];

    if (index >= lm_ctx->nr_regions) {
        lm_log(lm_ctx, LM_DBG, "bad region index %d", index);
        return -EINVAL;
    }

    caps_size = get_vfio_caps_size(is_migr_reg(lm_ctx, index), lm_reg->mmap_areas);
    argsz = caps_size + sizeof(struct vfio_region_info);
    *vfio_reg = calloc(1, argsz);
    if (!*vfio_reg) {
        return -ENOMEM;
    }
    /* FIXME document in the protocol that vfio_req->argsz is ignored */
    (*vfio_reg)->argsz = argsz;
    (*vfio_reg)->flags = lm_reg->flags;
    (*vfio_reg)->index = index;
    (*vfio_reg)->offset = region_to_offset((*vfio_reg)->index);
    (*vfio_reg)->size = lm_reg->size;

    if (caps_size > 0) {
        dev_get_caps(lm_ctx, lm_reg, is_migr_reg(lm_ctx, index), *vfio_reg);
    }

    lm_log(lm_ctx, LM_DBG, "region_info[%d] offset %#llx flags %#x size %llu "
           "argsz %u",
           (*vfio_reg)->index, (*vfio_reg)->offset, (*vfio_reg)->flags,
           (*vfio_reg)->size, (*vfio_reg)->argsz);

    return 0;
}

int
lm_get_region(loff_t pos, size_t count, loff_t *off)
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
region_size(lm_ctx_t *lm_ctx, int region)
{
        assert(region >= LM_DEV_BAR0_REG_IDX && region <= LM_DEV_VGA_REG_IDX);
        return lm_ctx->reg_info[region].size;
}

static uint32_t
pci_config_space_size(lm_ctx_t *lm_ctx)
{
    return region_size(lm_ctx, LM_DEV_CFG_REG_IDX);
}

static ssize_t
handle_pci_config_space_access(lm_ctx_t *lm_ctx, char *buf, size_t count,
                               loff_t pos, bool is_write)
{
    int ret;

    count = MIN(pci_config_space_size(lm_ctx), count);
    if (is_write) {
        ret = cap_maybe_access(lm_ctx, lm_ctx->caps, buf, count, pos);
        if (ret < 0) {
            lm_log(lm_ctx, LM_ERR, "bad access to capabilities %#lx-%#lx\n",
                   pos, pos + count);
            return ret;
        }
    } else {
        memcpy(buf, lm_ctx->pci_config_space->raw + pos, count);
    }
    return count;
}

static ssize_t
do_access(lm_ctx_t *lm_ctx, char *buf, uint8_t count, uint64_t pos, bool is_write)
{
    int idx;
    loff_t offset;

    assert(lm_ctx != NULL);
    assert(buf != NULL);
    assert(count == 1 || count == 2 || count == 4 || count == 8);

    idx = lm_get_region(pos, count, &offset);
    if (idx < 0) {
        lm_log(lm_ctx, LM_ERR, "invalid region %d", idx);
        return idx;
    }

    if (idx < 0 || idx >= (int)lm_ctx->nr_regions) {
        lm_log(lm_ctx, LM_ERR, "bad region %d", idx);
        return -EINVAL;
    }

    if (idx == LM_DEV_CFG_REG_IDX) {
        return handle_pci_config_space_access(lm_ctx, buf, count, offset,
                                              is_write);
    }

    if (is_migr_reg(lm_ctx, idx)) {
        if (offset + count > lm_ctx->reg_info[idx].size) {
            lm_log(lm_ctx, LM_ERR, "read %#lx-%#lx past end of migration region (%#x)",
                   offset, offset + count - 1,
                   lm_ctx->reg_info[idx].size);
            return -EINVAL;
        }
        return handle_migration_region_access(lm_ctx, lm_ctx->pvt,
                                              lm_ctx->migration,
                                              buf, count, offset, is_write);
    }

    /*
     * Checking whether a callback exists might sound expensive however this
     * code is not performance critical. This works well when we don't expect a
     * region to be used, so the user of the library can simply leave the
     * callback NULL in lm_create_ctx.
     */
    if (lm_ctx->reg_info[idx].fn != NULL) {
        return lm_ctx->reg_info[idx].fn(lm_ctx->pvt, buf, count, offset,
                                          is_write);
    }

    lm_log(lm_ctx, LM_ERR, "no callback for region %d", idx);

    return -EINVAL;
}

/*
 * Returns the number of bytes processed on success or a negative number on
 * error.
 *
 * TODO function name same lm_access_t, fix
 * FIXME we must be able to return values up to uint32_t bit, or negative on
 * error. Better to make return value an int and return the number of bytes
 * processed via an argument.
 */
ssize_t
lm_access(lm_ctx_t *lm_ctx, char *buf, uint32_t count, uint64_t *ppos,
          bool is_write)
{
    uint32_t done = 0;
    int ret;

    assert(lm_ctx != NULL);
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
        ret = do_access(lm_ctx, buf, size, *ppos, is_write);
        if (ret <= 0) {
            lm_log(lm_ctx, LM_ERR, "failed to %s %#lx-%#lx: %s",
                   is_write ? "write to" : "read from", *ppos, *ppos + size - 1,
                   strerror(-ret));
            /*
             * TODO if ret < 0 then it might contain a legitimate error code, why replace it with EFAULT?
             */
            return -EFAULT;
        }
        if (ret != (int)size) {
            lm_log(lm_ctx, LM_DBG, "bad read %d != %ld", ret, size);
        }
        count -= size;
        done += size;
        *ppos += size;
        buf += size;
    }
    return done;
}

static inline int
muser_access(lm_ctx_t *lm_ctx, bool is_write, char *rwbuf, uint32_t count,
             uint64_t *pos)
{
    uint32_t processed = 0, _count;
    int ret;

    assert(lm_ctx != NULL);
    assert(rwbuf != NULL);
    assert(pos != NULL);

    lm_log(lm_ctx, LM_DBG, "%s %#lx-%#lx", is_write ? "W" : "R", *pos,
           *pos + count - 1);

#ifdef LM_VERBOSE_LOGGING
    if (is_write) {
        dump_buffer("buffer write", rwbuf, count);
    }
#endif

    _count = count;
    ret = muser_pci_hdr_access(lm_ctx, &_count, pos, is_write, rwbuf);
    if (ret != 0) {
        /* FIXME shouldn't we fail here? */
        lm_log(lm_ctx, LM_ERR, "failed to access PCI header: %s",
               strerror(-ret));
#ifdef LM_VERBOSE_LOGGING
        dump_buffer("buffer write", rwbuf, _count);
#endif
    }

    /*
     * count is how much has been processed by muser_pci_hdr_access,
     * _count is how much there's left to be processed by lm_access
     */
    processed = count - _count;
    ret = lm_access(lm_ctx, rwbuf + processed, _count, pos, is_write);
    if (ret >= 0) {
        ret += processed;
#ifdef LM_VERBOSE_LOGGING
        if (!is_write && err == ret) {
            dump_buffer("buffer read", rwbuf, ret);
        }
#endif
    }

    return ret;
}

/* TODO merge with dev_get_reginfo */
static int
handle_device_get_region_info(lm_ctx_t *lm_ctx, uint32_t size,
                              struct vfio_region_info *reg_info_in,
                              struct vfio_region_info **reg_info_out)
{
    if (size != sizeof(*reg_info_in) || size != reg_info_in->argsz) {
        return -EINVAL;
    }

    return dev_get_reginfo(lm_ctx, reg_info_in->index, reg_info_out);
}

static int
handle_device_get_info(lm_ctx_t *lm_ctx, uint32_t size,
                       struct vfio_device_info *dev_info)
{
    assert(lm_ctx != NULL);
    assert(dev_info != NULL);

    if (size != sizeof *dev_info) {
        return -EINVAL;
    }

    dev_info->argsz = sizeof *dev_info;
    dev_info->flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
    dev_info->num_regions = lm_ctx->nr_regions;
    dev_info->num_irqs = LM_DEV_NUM_IRQS;

    lm_log(lm_ctx, LM_DBG, "sent devinfo flags %#x, num_regions %d, num_irqs"
           " %d", dev_info->flags, dev_info->num_regions, dev_info->num_irqs);

    return 0;
}

static int
handle_dma_map_or_unmap(lm_ctx_t *lm_ctx, uint32_t size, bool map,
                        int *fds, int nr_fds,
                        struct vfio_user_dma_region *dma_regions)
{
    int ret, i;
    int nr_dma_regions;

    assert(lm_ctx != NULL);

    if (size % sizeof(struct vfio_user_dma_region) != 0) {
        lm_log(lm_ctx, LM_ERR, "bad size of DMA regions %d", size);
        return -EINVAL;
    }

    nr_dma_regions = (int)(size / sizeof(struct vfio_user_dma_region));
    if (map && nr_dma_regions != nr_fds) {
        lm_log(lm_ctx, LM_ERR, "expected %d fds but got %d instead",
               nr_dma_regions, nr_fds);
        return -EINVAL;
    }

    if (lm_ctx->dma == NULL) {
        return 0;
    }

    for (i = 0; i < nr_dma_regions; i++) {
        if (map) {
            if (dma_regions[i].flags != VFIO_USER_F_DMA_REGION_MAPPABLE) {
                /*
                 * FIXME implement non-mappable DMA regions. This requires changing
                 * dma.c to not take a file descriptor.
                 */
                assert(false);
            }

            ret = dma_controller_add_region(lm_ctx->dma,
                                            dma_regions[i].addr,
                                            dma_regions[i].size,
                                            fds[i],
                                            dma_regions[i].offset);
            if (ret < 0) {
                lm_log(lm_ctx, LM_INF,
                       "failed to add DMA region %#lx-%#lx offset=%#lx fd=%d: %s",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1,
                       dma_regions[i].offset, fds[i],
                       strerror(-ret));
            } else {
                lm_log(lm_ctx, LM_DBG,
                       "added DMA region %#lx-%#lx offset=%#lx fd=%d",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1,
                       dma_regions[i].offset, fds[i]);
            }
        } else {
            ret = dma_controller_remove_region(lm_ctx->dma,
                                               dma_regions[i].addr,
                                               dma_regions[i].size,
                                               lm_ctx->unmap_dma, lm_ctx->pvt);
            if (ret < 0) {
                lm_log(lm_ctx, LM_INF,
                       "failed to remove DMA region %#lx-%#lx: %s",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1,
                       strerror(-ret));
            } else {
                lm_log(lm_ctx, LM_DBG,
                       "removed DMA region %#lx-%#lx",
                       dma_regions[i].addr,
                       dma_regions[i].addr + dma_regions[i].size - 1);
            }
        }
        if (ret < 0) {
            return ret;
        }
        if (lm_ctx->map_dma != NULL) {
            lm_ctx->map_dma(lm_ctx->pvt, dma_regions[i].addr, dma_regions[i].size);
        }
    }
    return 0;
}

static int
handle_device_reset(lm_ctx_t *lm_ctx)
{
    lm_log(lm_ctx, LM_DBG, "Device reset called by client");
    if (lm_ctx->reset != NULL) {
        return lm_ctx->reset(lm_ctx->pvt);
    }
    return 0;
}

static int
validate_region_access(lm_ctx_t *lm_ctx, uint32_t size, uint16_t cmd,
                       struct vfio_user_region_access *region_access)
{
    assert(region_access != NULL);

    if (size < sizeof *region_access) {
        lm_log(lm_ctx, LM_ERR, "message size too small (%d)", size);
        return -EINVAL;
    }

    if (region_access->region > lm_ctx->nr_regions ||  region_access->count <= 0) {
        lm_log(lm_ctx, LM_ERR, "bad region %d and/or count %d",
               region_access->region, region_access->count);
        return -EINVAL;
    }

    if (device_is_stopped_and_copying(lm_ctx->migration) &&
        !is_migr_reg(lm_ctx, region_access->region)) {
        lm_log(lm_ctx, LM_ERR,
               "cannot access region %d while device in stop-and-copy state",
               region_access->region);
        return -EINVAL;
    }

    if (cmd == VFIO_USER_REGION_WRITE &&
        size - sizeof *region_access != region_access->count)
    {
        lm_log(lm_ctx, LM_ERR, "bad region access, expected %lu, actual %d",
               size - sizeof *region_access, region_access->count);
        return -EINVAL;
    }

    return 0;
}

static int
handle_region_access(lm_ctx_t *lm_ctx, uint32_t size, uint16_t cmd,
                     void **data, size_t *len,
                     struct vfio_user_region_access *region_access)
{
    uint64_t count, offset;
    int ret;
    char *buf;

    assert(lm_ctx != NULL);
    assert(data != NULL);
    assert(region_access != NULL);

    ret = validate_region_access(lm_ctx, size, cmd, region_access);
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

    ret = muser_access(lm_ctx, cmd == VFIO_USER_REGION_WRITE,
                       buf, count, &offset);
    if (ret != (int)region_access->count) {
        lm_log(lm_ctx, LM_ERR, "failed to %s %#x-%#lx: %d",
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
handle_dirty_pages_get(lm_ctx_t *lm_ctx,
                       struct iovec **iovecs, size_t *nr_iovecs,
                       struct vfio_iommu_type1_dirty_bitmap_get *ranges,
                       uint32_t size)
{
    int ret = -EINVAL;
    size_t i;

    assert(lm_ctx != NULL);
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
        ret = dma_controller_dirty_page_get(lm_ctx->dma, r->iova, r->size,
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
handle_dirty_pages(lm_ctx_t *lm_ctx, uint32_t size,
                   struct iovec **iovecs, size_t *nr_iovecs,
                   struct vfio_iommu_type1_dirty_bitmap *dirty_bitmap)
{
    int ret;

    assert(lm_ctx != NULL);
    assert(iovecs != NULL);
    assert(nr_iovecs != NULL);
    assert(dirty_bitmap != NULL);

    if (size < sizeof *dirty_bitmap || size != dirty_bitmap->argsz) {
        lm_log(lm_ctx, LM_ERR, "invalid header size %u", size);
        return -EINVAL;
    }

    if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_START) {
        ret = dma_controller_dirty_page_logging_start(lm_ctx->dma,
                                                      migration_get_pgsize(lm_ctx->migration));
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP) {
        ret = dma_controller_dirty_page_logging_stop(lm_ctx->dma);
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP) {
        ret = handle_dirty_pages_get(lm_ctx, iovecs, nr_iovecs,
                                     (struct vfio_iommu_type1_dirty_bitmap_get*)(dirty_bitmap + 1),
                                     size - sizeof *dirty_bitmap);
    } else {
        lm_log(lm_ctx, LM_ERR, "bad flags %#x", dirty_bitmap->flags);
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
validate_header(lm_ctx_t *lm_ctx, struct vfio_user_header *hdr, size_t size)
{
    assert(hdr != NULL);

    if (size < sizeof hdr) {
        lm_log(lm_ctx, LM_ERR, "short header read %ld", size);
        return -EINVAL;
    }

    if (hdr->flags.type != VFIO_USER_F_TYPE_COMMAND) {
        lm_log(lm_ctx, LM_ERR, "header not a request");
        return -EINVAL;
    }

    if (hdr->msg_size < sizeof hdr) {
        lm_log(lm_ctx, LM_ERR, "bad size in header %d", hdr->msg_size);
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
get_next_command(lm_ctx_t *lm_ctx, struct vfio_user_header *hdr, int *fds,
                 int *nr_fds)
{
    int ret;

    /* FIXME get request shouldn't set errno, it should return it as -errno */
    ret = lm_ctx->trans->get_request(lm_ctx, hdr, fds, nr_fds);
    if (unlikely(ret < 0)) {
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            return 0;
        }
        if (ret != -EINTR) {
            lm_log(lm_ctx, LM_ERR, "failed to receive request: %s",
                   strerror(-ret));
        }
        return ret;
    }
    if (unlikely(ret == 0)) {
        if (errno == EINTR) {
            return -EINTR;
        }
        if (errno == 0) {
            lm_log(lm_ctx, LM_INF, "vfio-user client closed connection");
        } else {
            lm_log(lm_ctx, LM_ERR, "end of file: %m");
        }
        return -ENOTCONN;
    }
    return ret;
}

static int
process_request(lm_ctx_t *lm_ctx)
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

    assert(lm_ctx != NULL);

    if (device_is_stopped(lm_ctx->migration)) {
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

    nr_fds = lm_ctx->client_max_fds;
    fds = alloca(nr_fds * sizeof(int));

    ret = get_next_command(lm_ctx, &hdr, fds, &nr_fds);
    if (ret <= 0) {
        return ret;
    }

    ret = validate_header(lm_ctx, &hdr, ret);
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
        ret = recv(lm_ctx->conn_fd, cmd_data, hdr.msg_size, 0);
        if (ret < 0) {
            ret = -errno;
            goto reply;
        }
        if (ret != (int)hdr.msg_size) {
            lm_log(lm_ctx, LM_ERR, "short read, expected=%d, actual=%d",
                   hdr.msg_size, ret);
            ret = -EINVAL;
            goto reply;
        }
    }

    if (device_is_stopped_and_copying(lm_ctx->migration)
        && !(hdr.cmd == VFIO_USER_REGION_READ || hdr.cmd == VFIO_USER_REGION_WRITE)) {
        lm_log(lm_ctx, LM_ERR,
               "bad command %d while device in stop-and-copy state", hdr.cmd);
        ret = -EINVAL;
        goto reply;
    }

    switch (hdr.cmd) {
        case VFIO_USER_DMA_MAP:
        case VFIO_USER_DMA_UNMAP:
            ret = handle_dma_map_or_unmap(lm_ctx, hdr.msg_size,
                                          hdr.cmd == VFIO_USER_DMA_MAP,
                                          fds, nr_fds, cmd_data);
            break;
        case VFIO_USER_DEVICE_GET_INFO:
            ret = handle_device_get_info(lm_ctx, hdr.msg_size, &dev_info);
            if (ret >= 0) {
                _iovecs[1].iov_base = &dev_info;
                _iovecs[1].iov_len = dev_info.argsz;
                iovecs = _iovecs;
                nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_REGION_INFO:
            ret = handle_device_get_region_info(lm_ctx, hdr.msg_size, cmd_data,
                                                &dev_reg_info);
            if (ret == 0) {
                _iovecs[1].iov_base = dev_reg_info;
                _iovecs[1].iov_len = dev_reg_info->argsz;
                iovecs = _iovecs;
                nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_GET_IRQ_INFO:
            ret = handle_device_get_irq_info(lm_ctx, hdr.msg_size, cmd_data,
                                             &irq_info);
            if (ret == 0) {
                _iovecs[1].iov_base = &irq_info;
                _iovecs[1].iov_len = sizeof irq_info;
                iovecs = _iovecs;
                nr_iovecs = 2;
            }
            break;
        case VFIO_USER_DEVICE_SET_IRQS:
            ret = handle_device_set_irqs(lm_ctx, hdr.msg_size, fds, nr_fds,
                                         cmd_data);
            break;
        case VFIO_USER_REGION_READ:
        case VFIO_USER_REGION_WRITE:
            iovecs = _iovecs;
            ret = handle_region_access(lm_ctx, hdr.msg_size, hdr.cmd,
                                       &iovecs[1].iov_base, &iovecs[1].iov_len,
                                       cmd_data);
            nr_iovecs = 2;
            break;
        case VFIO_USER_DEVICE_RESET:
            ret = handle_device_reset(lm_ctx);
            break;
        case VFIO_USER_DIRTY_PAGES:
            // FIXME: don't allow migration calls if migration == NULL
            ret = handle_dirty_pages(lm_ctx, hdr.msg_size, &iovecs, &nr_iovecs,
                                     cmd_data);
            if (ret >= 0) {
                free_iovec_data = false;
            }
            break;
        default:
            lm_log(lm_ctx, LM_ERR, "bad command %d", hdr.cmd);
            ret = -EINVAL;
            goto reply;
    }

reply:
    /*
     * TODO: In case of error during command handling set errno respectively
     * in the reply message.
     */
    if (ret < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to handle command %d: %s", hdr.cmd,
               strerror(-ret));
    } else {
        ret = 0;
    }

    // FIXME: SPEC: should the reply include the command? I'd say yes?
    ret = vfio_user_send_iovec(lm_ctx->conn_fd, hdr.msg_id, true,
                               0, iovecs, nr_iovecs, NULL, 0, -ret);
    if (unlikely(ret < 0)) {
        lm_log(lm_ctx, LM_ERR, "failed to complete command: %s",
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

static int prepare_ctx(lm_ctx_t *lm_ctx)
{
    lm_reg_info_t *cfg_reg;
    const lm_reg_info_t zero_reg = { 0 };
    int err;
    uint32_t max_ivs = 0, i;
    size_t size;

    if (lm_ctx->ready != 0) {
        return 0;
    }

    // Attach to the muser control device. With LM_FLAG_ATTACH_NB caller is
    // always expected to call lm_ctx_try_attach().
    if ((lm_ctx->flags & LM_FLAG_ATTACH_NB) == 0) {
        lm_ctx->conn_fd = lm_ctx->trans->attach(lm_ctx);
        if (lm_ctx->conn_fd < 0) {
            err = lm_ctx->conn_fd;
            if (err != EINTR) {
                lm_log(lm_ctx, LM_ERR, "failed to attach: %s",
                       strerror(-err));
            }
            return err;
        }
    }

    cfg_reg = &lm_ctx->reg_info[LM_DEV_CFG_REG_IDX];

    // Set a default config region if none provided.
    /* TODO should it be enough to check that the size of region is 0? */
    if (memcmp(cfg_reg, &zero_reg, sizeof(*cfg_reg)) == 0) {
        cfg_reg->flags = LM_REG_FLAG_RW;
        cfg_reg->size = PCI_CFG_SPACE_SIZE;
    }

    // This maybe allocated by lm_setup_pci_config_hdr().
    if (lm_ctx->pci_config_space == NULL) {
        lm_ctx->pci_config_space = calloc(1, cfg_reg->size);
        if (lm_ctx->pci_config_space == NULL) {
            return -ENOMEM;
        }
    }

    // Set type for region registers.
    for (i = 0; i < PCI_BARS_NR; i++) {
        if (!(lm_ctx->reg_info[i].flags & LM_REG_FLAG_MEM)) {
            lm_ctx->pci_config_space->hdr.bars[i].io.region_type |= 0x1;
        }
    }

    if (lm_ctx->irqs == NULL) {
        /*
         * FIXME need to check that the number of MSI and MSI-X IRQs are valid
         * (1, 2, 4, 8, 16 or 32 for MSI and up to 2048 for MSI-X).
         */

        // Work out highest count of irq vectors.
        for (i = 0; i < LM_DEV_NUM_IRQS; i++) {
            if (max_ivs < lm_ctx->irq_count[i]) {
                max_ivs = lm_ctx->irq_count[i];
            }
        }

        //FIXME: assert(max_ivs > 0)?
        size = sizeof(int) * max_ivs;
        lm_ctx->irqs = calloc(1, sizeof(lm_irqs_t) + size);
        if (lm_ctx->irqs == NULL) {
            // lm_ctx->pci_config_space should be free'ed by lm_destroy_ctx().
            return  -ENOMEM;
        }

        // Set context irq information.
        for (i = 0; i < max_ivs; i++) {
            lm_ctx->irqs->efds[i] = -1;
        }
        lm_ctx->irqs->err_efd = -1;
        lm_ctx->irqs->req_efd = -1;
        lm_ctx->irqs->type = IRQ_NONE;
        lm_ctx->irqs->max_ivs = max_ivs;

        // Reflect on the config space whether INTX is available.
        if (lm_ctx->irq_count[LM_DEV_INTX_IRQ_IDX] != 0) {
            lm_ctx->pci_config_space->hdr.intr.ipin = 1; // INTA#
        }
    }

    if (lm_ctx->caps != NULL) {
        lm_ctx->pci_config_space->hdr.sts.cl = 0x1;
        lm_ctx->pci_config_space->hdr.cap = PCI_STD_HEADER_SIZEOF;
    }
    lm_ctx->ready = 1;

    return 0;
}

int
lm_ctx_drive(lm_ctx_t *lm_ctx)
{
    int err;

    if (lm_ctx == NULL) {
        return ERROR(EINVAL);
    }

    err = prepare_ctx(lm_ctx);
    if (err < 0) {
        return ERROR(-err);
    }

    do {
        err = process_request(lm_ctx);
    } while (err >= 0);

    return err;
}

int
lm_ctx_poll(lm_ctx_t *lm_ctx)
{
    int err;

    if (unlikely((lm_ctx->flags & LM_FLAG_ATTACH_NB) == 0)) {
        return -ENOTSUP;
    }

    assert(lm_ctx->ready == 1);
    err = process_request(lm_ctx);

    return err >= 0 ? 0 : err;
}

/* FIXME this is not enough anymore, check muser_mmap */
void *
lm_mmap(lm_ctx_t *lm_ctx, off_t offset, size_t length)
{
    if ((lm_ctx == NULL) || (length == 0) || !PAGE_ALIGNED(offset)) {
        if (lm_ctx != NULL) {
            lm_log(lm_ctx, LM_DBG, "bad device mmap region %#lx-%#lx\n",
                   offset, offset + length);
        }
        errno = EINVAL;
        return MAP_FAILED;
    }

    return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED,
                lm_ctx->fd, offset);
}

static void
free_sparse_mmap_areas(lm_ctx_t *lm_ctx)
{
    int i;

    assert(lm_ctx != NULL);

    for (i = 0; i < (int)lm_ctx->nr_regions; i++)
        free(lm_ctx->reg_info[i].mmap_areas);
}

void
lm_ctx_destroy(lm_ctx_t *lm_ctx)
{

    if (lm_ctx == NULL) {
        return;
    }

    free(lm_ctx->uuid);
    free(lm_ctx->pci_config_space);
    if (lm_ctx->trans->detach != NULL) {
        lm_ctx->trans->detach(lm_ctx);
    }
    if (lm_ctx->dma != NULL) {
        dma_controller_destroy(lm_ctx->dma);
    }
    free_sparse_mmap_areas(lm_ctx);
    free(lm_ctx->reg_info);
    free(lm_ctx->caps);
    free(lm_ctx->migration);
    free(lm_ctx->irqs);
    free(lm_ctx);
    // FIXME: Maybe close any open irq efds? Unmap stuff?
}

struct lm_sparse_mmap_areas*
copy_sparse_mmap_area(struct lm_sparse_mmap_areas *src)
{
    struct lm_sparse_mmap_areas *dest;
    size_t size;

    assert(src != NULL);

    size = sizeof(*dest) + (src->nr_mmap_areas * sizeof(struct lm_mmap_area));
    dest = calloc(1, size);
    if (dest != NULL) {
        memcpy(dest, src, size);
    }
    return dest;
}

int
lm_ctx_try_attach(lm_ctx_t *lm_ctx)
{
    int err;

    assert(lm_ctx != NULL);

    if ((lm_ctx->flags & LM_FLAG_ATTACH_NB) == 0) {
        return ERROR(EINVAL);
    }

    err = prepare_ctx(lm_ctx);
    if (err < 0) {
        return ERROR(-err);
    }

    return lm_ctx->trans->attach(lm_ctx);
}

lm_ctx_t *lm_create_ctx(const char *path, int flags, lm_log_fn_t *log,
                        lm_log_lvl_t log_lvl, lm_trans_t trans, void *pvt)
{
    lm_ctx_t *lm_ctx = NULL;
    int err = 0;

    if (trans != LM_TRANS_SOCK) {
        errno = ENOTSUP;
        return NULL;
    }

    lm_ctx = calloc(1, sizeof(lm_ctx_t));
    if (lm_ctx == NULL) {
        return NULL;
    }
    lm_ctx->trans = &sock_transport_ops;

    //FIXME: Validate arguments.
    // Set other context data.
    lm_ctx->pvt = pvt;
    lm_ctx->log = log;
    lm_ctx->log_lvl = log_lvl;
    lm_ctx->flags = flags;

    lm_ctx->uuid = strdup(path);
    if (lm_ctx->uuid == NULL) {
        err = errno;
        goto out;
    }

    /*
     * FIXME: Now we always allocate for migration region. Check if its better
     * to seperate migration region from standard regions in lm_ctx.reg_info
     * and move it into lm_ctx.migration.
     */
    lm_ctx->nr_regions = LM_DEV_NUM_REGS + 1;
    lm_ctx->reg_info = calloc(lm_ctx->nr_regions, sizeof *lm_ctx->reg_info);
    if (lm_ctx->reg_info == NULL) {
        err = -ENOMEM;
        goto out;
    }

    if (lm_ctx->trans->init != NULL) {
        err = lm_ctx->trans->init(lm_ctx);
        if (err < 0) {
            goto out;
        }
        lm_ctx->fd = err;
    }
    err = 0;

out:
    if (err != 0) {
        if (lm_ctx != NULL) {
            lm_ctx_destroy(lm_ctx);
            lm_ctx = NULL;
        }
        errno = -err;
    }

    return lm_ctx;
}

int lm_setup_pci_config_hdr(lm_ctx_t *lm_ctx, lm_pci_hdr_id_t id,
                            lm_pci_hdr_ss_t ss, lm_pci_hdr_cc_t cc,
                            UNUSED bool extended)
{
    lm_pci_config_space_t *config_space;

    assert(lm_ctx != NULL);

    if (lm_ctx->pci_config_space != NULL) {
        lm_log(lm_ctx, LM_ERR, "pci header already setup");
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
    lm_ctx->pci_config_space = config_space;

    return 0;
}

int lm_setup_pci_caps(lm_ctx_t *lm_ctx, lm_cap_t **caps, int nr_caps)
{
    int ret;

    assert(lm_ctx != NULL);

    if (lm_ctx->caps != NULL) {
        lm_log(lm_ctx, LM_ERR, "capabilities are already setup");
        return ERROR(EEXIST);
    }

    if (caps == NULL || nr_caps == 0) {
        lm_log(lm_ctx, LM_ERR, "Invalid args passed");
        return ERROR(EINVAL);
    }

    lm_ctx->caps = caps_create(lm_ctx, caps, nr_caps, &ret);
    if (lm_ctx->caps == NULL) {
        lm_log(lm_ctx, LM_ERR, "failed to create PCI capabilities: %s",
               strerror(ret));
        return ERROR(ret);
    }

    return 0;
}

static int
copy_sparse_mmap_areas(lm_reg_info_t *reg_info,
                       struct lm_sparse_mmap_areas *mmap_areas)
{
    int nr_mmap_areas;
    size_t size;

    if (mmap_areas == NULL) {
        return 0;
    }

    nr_mmap_areas = mmap_areas->nr_mmap_areas;
    size = sizeof(*mmap_areas) + (nr_mmap_areas * sizeof(struct lm_mmap_area));
    reg_info->mmap_areas = calloc(1, size);
    if (reg_info->mmap_areas == NULL) {
        return -ENOMEM;
    }

    memcpy(reg_info->mmap_areas, mmap_areas, size);

    return 0;
}

static inline bool is_valid_pci_config_space_region(int flags, size_t size)
{
    return flags == LM_REG_FLAG_RW && (size ==  PCI_CFG_SPACE_SIZE
            || size == PCI_CFG_SPACE_EXP_SIZE);
}

int lm_setup_region(lm_ctx_t *lm_ctx, int region_idx, size_t size,
                    lm_region_access_cb_t *region_access, int flags,
                    struct lm_sparse_mmap_areas *mmap_areas,
                    lm_map_region_cb_t *map)
{
    int ret;

    assert(lm_ctx != NULL);

    switch(region_idx) {
    case LM_DEV_BAR0_REG_IDX ... LM_DEV_VGA_REG_IDX:
        // Validate the config region provided.
        if (region_idx == LM_DEV_CFG_REG_IDX &&
            !is_valid_pci_config_space_region(flags, size)) {
                return ERROR(EINVAL);
        }

        lm_ctx->reg_info[region_idx].flags = flags;
        lm_ctx->reg_info[region_idx].size = size;
        lm_ctx->reg_info[region_idx].fn = region_access;

        if (map != NULL) {
            lm_ctx->reg_info[region_idx].map = map;
        }
        if (mmap_areas) {
            ret = copy_sparse_mmap_areas(&lm_ctx->reg_info[region_idx],
                                         mmap_areas);
            if (ret < 0) {
                return ERROR(-ret);
            }
        }
        break;
    default:
        lm_log(lm_ctx, LM_ERR, "Invalid region index %d", region_idx);
        return ERROR(EINVAL);
    }

    return 0;
}

int lm_setup_device_cb(lm_ctx_t *lm_ctx, lm_reset_cb_t *reset,
                       lm_map_dma_cb_t *map_dma, lm_unmap_dma_cb_t *unmap_dma)
{

    assert(lm_ctx != NULL);

    lm_ctx->reset = reset;
    lm_ctx->map_dma = map_dma;
    lm_ctx->unmap_dma = unmap_dma;

    // Create the internal DMA controller.
    if (lm_ctx->unmap_dma != NULL) {
        lm_ctx->dma = dma_controller_create(lm_ctx, LM_DMA_REGIONS);
        if (lm_ctx->dma == NULL) {
            return ERROR(ENOMEM);
        }
    }

    return 0;
}

int lm_setup_device_irq_counts(lm_ctx_t *lm_ctx, int irq_idx,
                               uint32_t irq_count)
{

    assert(lm_ctx != NULL);

    if (irq_idx < LM_DEV_INTX_IRQ_IDX || irq_idx > LM_DEV_REQ_IRQ_INDEX) {
        lm_log(lm_ctx, LM_ERR, "Invalid IRQ index %d, should be between "
               "(%d to %d)", irq_idx, LM_DEV_INTX_IRQ_IDX,
               LM_DEV_REQ_IRQ_INDEX);
        return ERROR(EINVAL);
    }

    lm_ctx->irq_count[irq_idx] = irq_count;

    return 0;
}

int lm_setup_device_migration(lm_ctx_t *lm_ctx, lm_migration_t *migration)
{
    lm_reg_info_t   *migr_reg;
    int ret = 0;

    assert(lm_ctx != NULL);

    //FIXME: Validate args.

    if (lm_ctx->migr_reg != NULL) {
        lm_log(lm_ctx, LM_ERR, "device migration is already setup");
        return ERROR(EEXIST);
    }

    /* FIXME hacky, find a more robust way to allocate a region index */
    migr_reg = &lm_ctx->reg_info[(lm_ctx->nr_regions - 1)];

    /* FIXME: Are there sparse areas need to be setup flags accordingly */
    ret = copy_sparse_mmap_areas(migr_reg, migration->mmap_areas);
    if (ret < 0) {
        return ERROR(-ret);
    }

    migr_reg->flags = LM_REG_FLAG_RW;
    migr_reg->size = sizeof(struct vfio_device_migration_info) + migration->size;

    lm_ctx->migration = init_migration(migration, &ret);
    if (lm_ctx->migration == NULL) {
        lm_log(lm_ctx, LM_ERR, "failed to initialize device migration");
        free(migr_reg->mmap_areas);
        return ERROR(ret);
    }
    lm_ctx->migr_reg = migr_reg;

    return 0;
}

/*
 * Returns a pointer to the standard part of the PCI configuration space.
 */
inline lm_pci_config_space_t *
lm_get_pci_config_space(lm_ctx_t *lm_ctx)
{
    assert(lm_ctx != NULL);
    return lm_ctx->pci_config_space;
}

/*
 * Returns a pointer to the non-standard part of the PCI configuration space.
 */
inline uint8_t *
lm_get_pci_non_std_config_space(lm_ctx_t *lm_ctx)
{
    assert(lm_ctx != NULL);
    return (uint8_t *)&lm_ctx->pci_config_space->non_std;
}

inline lm_reg_info_t *
lm_get_region_info(lm_ctx_t *lm_ctx)
{
    assert(lm_ctx != NULL);
    return lm_ctx->reg_info;
}

inline int
lm_addr_to_sg(lm_ctx_t *lm_ctx, dma_addr_t dma_addr,
              uint32_t len, dma_sg_t *sg, int max_sg, int prot)
{
    assert(lm_ctx != NULL);

    if (unlikely(lm_ctx->unmap_dma == NULL)) {
        errno = EINVAL;
        return -1;
    }
    return dma_addr_to_sg(lm_ctx->dma, dma_addr, len, sg, max_sg, prot);
}

inline int
lm_map_sg(lm_ctx_t *lm_ctx, const dma_sg_t *sg,
	  struct iovec *iov, int cnt)
{
    if (unlikely(lm_ctx->unmap_dma == NULL)) {
        errno = EINVAL;
        return -1;
    }
    return dma_map_sg(lm_ctx->dma, sg, iov, cnt);
}

inline void
lm_unmap_sg(lm_ctx_t *lm_ctx, const dma_sg_t *sg, struct iovec *iov, int cnt)
{
    if (unlikely(lm_ctx->unmap_dma == NULL)) {
        return;
    }
    return dma_unmap_sg(lm_ctx->dma, sg, iov, cnt);
}

uint8_t *
lm_ctx_get_cap(lm_ctx_t *lm_ctx, uint8_t id)
{
    assert(lm_ctx != NULL);

    return cap_find_by_id(lm_ctx, id);
}

int
lm_dma_read(lm_ctx_t *lm_ctx, dma_sg_t *sg, void *data)
{
    struct vfio_user_dma_region_access *dma_recv;
    struct vfio_user_dma_region_access dma_send;
    int recv_size;
    int msg_id = 1, ret;

    assert(lm_ctx != NULL);
    assert(sg != NULL);

    recv_size = sizeof(*dma_recv) + sg->length;

    dma_recv = calloc(recv_size, 1);
    if (dma_recv == NULL) {
        return -ENOMEM;
    }

    dma_send.addr = sg->dma_addr;
    dma_send.count = sg->length;
    ret = vfio_user_msg(lm_ctx->conn_fd, msg_id, VFIO_USER_DMA_READ,
                        &dma_send, sizeof dma_send, NULL,
                        dma_recv, recv_size);
    memcpy(data, dma_recv->data, sg->length); /* FIXME no need for memcpy */
    free(dma_recv);

    return ret;
}

int
lm_dma_write(lm_ctx_t *lm_ctx, dma_sg_t *sg, void *data)
{
    struct vfio_user_dma_region_access *dma_send, dma_recv;
    int send_size = sizeof(*dma_send) + sg->length;
    int msg_id = 1, ret;

    assert(lm_ctx != NULL);
    assert(sg != NULL);

    dma_send = calloc(send_size, 1);
    if (dma_send == NULL) {
        return -ENOMEM;
    }
    dma_send->addr = sg->dma_addr;
    dma_send->count = sg->length;
    memcpy(dma_send->data, data, sg->length); /* FIXME no need to copy! */
    ret = vfio_user_msg(lm_ctx->conn_fd, msg_id, VFIO_USER_DMA_WRITE,
                        dma_send, send_size, NULL,
                        &dma_recv, sizeof(dma_recv));
    free(dma_send);

    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
