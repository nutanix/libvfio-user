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
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdarg.h>

#include "../kmod/muser.h"
#include "muser.h"
#include "muser_priv.h"
#include "dma.h"
#include "cap.h"

typedef enum {
    IRQ_NONE = 0,
    IRQ_INTX,
    IRQ_MSI,
    IRQ_MSIX,
} irq_type_t;

typedef struct {
    irq_type_t  type;		/* irq type this device is using */
    int		    err_efd;	/* eventfd for irq err */
    int		    req_efd;	/* eventfd for irq req */
    uint32_t	max_ivs;	/* maximum number of ivs supported */
    int		    efds[0];	/* XXX must be last */
} lm_irqs_t;

/*
 * Macro that ensures that a particular struct member is last. Doesn't work for
 * flexible array members.
 */
#define MUST_BE_LAST(s, m, t) \
    _Static_assert(sizeof(s) - offsetof(s, m) == sizeof(t), \
        #t " " #m " must be last member in " #s)

struct lm_ctx {
    void			        *pvt;
    dma_controller_t		*dma;
    int				        fd;
    bool                    extended;
    int (*reset)            (void *pvt);
    lm_log_lvl_t		    log_lvl;
    lm_log_fn_t			    *log;
    lm_pci_info_t           pci_info;
    lm_pci_config_space_t	*pci_config_space;
    struct caps             *caps;
    lm_irqs_t			    irqs; /* XXX must be last */
};
MUST_BE_LAST(struct lm_ctx, irqs, lm_irqs_t);

#define LM2VFIO_IRQT(type) (type - 1)

void lm_log(const lm_ctx_t * const ctx, const lm_log_lvl_t lvl,
	    const char *const fmt, ...)
{
    va_list ap;
    char buf[BUFSIZ];

    assert(ctx);

    if (!ctx->log || lvl > ctx->log_lvl || !fmt) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    ctx->log(ctx->pvt, buf);
}

static long irqs_disable(lm_ctx_t * lm_ctx, uint32_t index)
{
    int *irq_efd = NULL;
    uint32_t i;

    assert(lm_ctx != NULL);
    assert(index < LM_DEV_NUM_IRQS);

    switch (index) {
    case VFIO_PCI_INTX_IRQ_INDEX:
    case VFIO_PCI_MSI_IRQ_INDEX:
    case VFIO_PCI_MSIX_IRQ_INDEX:
        lm_ctx->irqs.type = IRQ_NONE;
        for (i = 0; i < lm_ctx->irqs.max_ivs; i++) {
            if (lm_ctx->irqs.efds[i] >= 0) {
                (void) close(lm_ctx->irqs.efds[i]);
                lm_ctx->irqs.efds[i] = -1;
            }
        }
        return 0;
    case VFIO_PCI_ERR_IRQ_INDEX:
        irq_efd = &lm_ctx->irqs.err_efd;
        break;
    case VFIO_PCI_REQ_IRQ_INDEX:
        irq_efd = &lm_ctx->irqs.req_efd;
        break;
    }

    if (irq_efd != NULL) {
        (void)close(*irq_efd);
        *irq_efd = -1;
        return 0;
    }

    return -EINVAL;
}

static int irqs_set_data_none(lm_ctx_t *lm_ctx, struct vfio_irq_set *irq_set)
{
    int efd, i;
    long ret;
    eventfd_t val;

    for (i = irq_set->start; i < irq_set->start + irq_set->count; i++) {
        efd = lm_ctx->irqs.efds[i];
        if (efd >= 0) {
            val = 1;
            ret = eventfd_write(efd, val);
            if (ret == -1) {
                return -errno;
            }
        }
    }

    return 0;
}

static int
irqs_set_data_bool(lm_ctx_t *lm_ctx, struct vfio_irq_set *irq_set, void *data)
{
    uint8_t *d8;
    int efd, i;
    long ret;
    eventfd_t val;

    assert(data != NULL);
    for (i = irq_set->start, d8 = data; i < irq_set->start + irq_set->count;
         i++, d8++) {
        efd = lm_ctx->irqs.efds[i];
        if (efd >= 0 && *d8 == 1) {
            val = 1;
            ret = eventfd_write(efd, val);
            if (ret == -1) {
                return -errno;
            }
        }
    }

    return 0;
}

static int
irqs_set_data_eventfd(lm_ctx_t *lm_ctx, struct vfio_irq_set *irq_set, void *data)
{
    int32_t *d32;
    int efd, i;

    assert(data != NULL);
    for (i = irq_set->start, d32 = data; i < irq_set->start + irq_set->count;
         i++, d32++) {
        efd = lm_ctx->irqs.efds[i];
        if (efd >= 0) {
            (void) close(efd);
            lm_ctx->irqs.efds[i] = -1;
        }
        if (*d32 >= 0) {
            lm_ctx->irqs.efds[i] = *d32;
        }
    }

    return 0;
}

static long
irqs_trigger(lm_ctx_t * lm_ctx, struct vfio_irq_set *irq_set, void *data)
{
    int err = 0;

    assert(lm_ctx != NULL);
    assert(irq_set != NULL);

    if (irq_set->count == 0) {
        return irqs_disable(lm_ctx, irq_set->index);
    }

    switch (irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
    case VFIO_IRQ_SET_DATA_NONE:
        err = irqs_set_data_none(lm_ctx, irq_set);
        break;
    case VFIO_IRQ_SET_DATA_BOOL:
        err = irqs_set_data_bool(lm_ctx, irq_set, data);
        break;
    case VFIO_IRQ_SET_DATA_EVENTFD:
        err = irqs_set_data_eventfd(lm_ctx, irq_set, data);
        break;
    }

    return err;
}

static long
dev_set_irqs_validate(lm_ctx_t *lm_ctx, struct vfio_irq_set *irq_set)
{
    lm_pci_info_t *pci_info = &lm_ctx->pci_info;
    uint32_t a_type, d_type;

    assert(lm_ctx != NULL);
    assert(irq_set != NULL);

    // Separate action and data types from flags.
    a_type = (irq_set->flags & VFIO_IRQ_SET_ACTION_TYPE_MASK);
    d_type = (irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK);

    // Ensure index is within bounds.
    if (irq_set->index >= LM_DEV_NUM_IRQS) {
        return -EINVAL;
    }

    /* TODO make each condition a function */

    // Only one of MASK/UNMASK/TRIGGER is valid.
    if ((a_type != VFIO_IRQ_SET_ACTION_MASK) &&
        (a_type != VFIO_IRQ_SET_ACTION_UNMASK) &&
        (a_type != VFIO_IRQ_SET_ACTION_TRIGGER)) {
        return -EINVAL;
    }
    // Only one of NONE/BOOL/EVENTFD is valid.
    if ((d_type != VFIO_IRQ_SET_DATA_NONE) &&
        (d_type != VFIO_IRQ_SET_DATA_BOOL) &&
        (d_type != VFIO_IRQ_SET_DATA_EVENTFD)) {
        return -EINVAL;
    }
    // Ensure irq_set's start and count are within bounds.
    if ((irq_set->start >= pci_info->irq_count[irq_set->index]) ||
        (irq_set->start + irq_set->count > pci_info->irq_count[irq_set->index])) {
        return -EINVAL;
    }
    // Only TRIGGER is valid for ERR/REQ.
    if (((irq_set->index == VFIO_PCI_ERR_IRQ_INDEX) ||
         (irq_set->index == VFIO_PCI_REQ_IRQ_INDEX)) &&
        (a_type != VFIO_IRQ_SET_ACTION_TRIGGER)) {
        return -EINVAL;
    }
    // count == 0 is only valid with ACTION_TRIGGER and DATA_NONE.
    if ((irq_set->count == 0) && ((a_type != VFIO_IRQ_SET_ACTION_TRIGGER) ||
                                  (d_type != VFIO_IRQ_SET_DATA_NONE))) {
        return -EINVAL;
    }
    // If IRQs are set, ensure index matches what's enabled for the device.
    if ((irq_set->count != 0) && (lm_ctx->irqs.type != IRQ_NONE) &&
        (irq_set->index != LM2VFIO_IRQT(lm_ctx->irqs.type))) {
        return -EINVAL;
    }

    return 0;
}

static long
dev_set_irqs(lm_ctx_t * lm_ctx, struct vfio_irq_set *irq_set, void *data)
{
    long ret;

    assert(lm_ctx != NULL);
    assert(irq_set != NULL);

    // Ensure irq_set is valid.
    ret = dev_set_irqs_validate(lm_ctx, irq_set);
    if (ret != 0) {
        return ret;
    }

    switch (irq_set->flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
    case VFIO_IRQ_SET_ACTION_MASK:     // fallthrough
    case VFIO_IRQ_SET_ACTION_UNMASK:
        // We're always edge-triggered without un/mask support.
        return 0;
    }

    return irqs_trigger(lm_ctx, irq_set, data);
}

static long dev_get_irqinfo(lm_ctx_t * lm_ctx, struct vfio_irq_info *irq_info)
{
    assert(lm_ctx != NULL);
    assert(irq_info != NULL);
    lm_pci_info_t *pci_info = &lm_ctx->pci_info;

    // Ensure provided argsz is sufficiently big and index is within bounds.
    if ((irq_info->argsz < sizeof(struct vfio_irq_info)) ||
        (irq_info->index >= LM_DEV_NUM_IRQS)) {
        return -EINVAL;
    }

    irq_info->count = pci_info->irq_count[irq_info->index];
    irq_info->flags = VFIO_IRQ_INFO_EVENTFD;

    return 0;
}

/*
 * Populate the sparse mmap capability information to vfio-client.
 * kernel/muser constructs the response for VFIO_DEVICE_GET_REGION_INFO
 * accommodating sparse mmap information.
 * Sparse mmap information stays after struct vfio_region_info and cap_offest
 * points accordingly.
 */
static int
dev_get_sparse_mmap_cap(lm_ctx_t *lm_ctx, lm_reg_info_t *lm_reg,
                        struct vfio_region_info *vfio_reg)
{
    struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
    struct lm_sparse_mmap_areas *mmap_areas;
    int nr_mmap_areas, i;
    size_t size;
    ssize_t ret;

    if (!lm_reg->mmap_areas)
        return -EINVAL;

    nr_mmap_areas = lm_reg->mmap_areas->nr_mmap_areas;
    size = sizeof(*sparse) + (nr_mmap_areas * sizeof(*sparse->areas));

    /*
     * If vfio_reg does not have enough space to accommodate  sparse info then
     * set the argsz with the expected size and return. Vfio client will call
     * back after reallocating the vfio_reg
     */

    if (vfio_reg->argsz < size + sizeof(*vfio_reg)) {
        vfio_reg->argsz = size + sizeof(*vfio_reg);
        vfio_reg->cap_offset = 0;
        return 0;
    }

    lm_log(lm_ctx, LM_DBG, "%s: size %llu, nr_mmap_areas %u\n", __func__, size,
           nr_mmap_areas);
    sparse = calloc(1, size);
    if (!sparse)
        return -ENOMEM;
    sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
    sparse->header.version = 1;
    sparse->header.next = 0;
    sparse->nr_areas = nr_mmap_areas;

    mmap_areas = lm_reg->mmap_areas;
    for (i = 0; i < nr_mmap_areas; i++) {
        sparse->areas[i].offset = mmap_areas->areas[i].start;
        sparse->areas[i].size = mmap_areas->areas[i].size;
    }

    /* write the sparse mmap cap info to vfio-client user pages */
    ret = write(lm_ctx->fd, sparse, size);
    if (ret != size) {
        free(sparse);
        return -EIO;
    }

    vfio_reg->flags |= VFIO_REGION_INFO_FLAG_MMAP | VFIO_REGION_INFO_FLAG_CAPS;
    vfio_reg->cap_offset = sizeof(*vfio_reg);

    free(sparse);
    return 0;
}

static long
dev_get_reginfo(lm_ctx_t * lm_ctx, struct vfio_region_info *vfio_reg)
{
    lm_reg_info_t *lm_reg;
    int err;

    assert(lm_ctx != NULL);
    assert(vfio_reg != NULL);
    lm_reg = &lm_ctx->pci_info.reg_info[vfio_reg->index];

    // Ensure provided argsz is sufficiently big and index is within bounds.
    if ((vfio_reg->argsz < sizeof(struct vfio_region_info)) ||
        (vfio_reg->index >= LM_DEV_NUM_REGS)) {
        return -EINVAL;
    }

    vfio_reg->offset = lm_reg->offset;
    vfio_reg->flags = lm_reg->flags;
    vfio_reg->size = lm_reg->size;

    if (lm_reg->mmap_areas)
        err = dev_get_sparse_mmap_cap(lm_ctx, lm_reg, vfio_reg);

    lm_log(lm_ctx, LM_DBG, "region_info[%d]\n", vfio_reg->index);
    dump_buffer(lm_ctx, "", (unsigned char *)vfio_reg, sizeof *vfio_reg);

    return 0;
}

static long dev_get_info(struct vfio_device_info *dev_info)
{
    assert(dev_info != NULL);

    // Ensure provided argsz is sufficiently big.
    if (dev_info->argsz < sizeof(struct vfio_device_info)) {
        return -EINVAL;
    }

    dev_info->flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
    dev_info->num_regions = LM_DEV_NUM_REGS;
    dev_info->num_irqs = LM_DEV_NUM_IRQS;

    return 0;
}

static long
do_muser_ioctl(lm_ctx_t * lm_ctx, struct muser_cmd_ioctl *cmd_ioctl, void *data)
{
    int err = -ENOTSUP;

    assert(lm_ctx != NULL);
    switch (cmd_ioctl->vfio_cmd) {
    case VFIO_DEVICE_GET_INFO:
        err = dev_get_info(&cmd_ioctl->data.dev_info);
        break;
    case VFIO_DEVICE_GET_REGION_INFO:
        err = dev_get_reginfo(lm_ctx, &cmd_ioctl->data.reg_info);
        break;
    case VFIO_DEVICE_GET_IRQ_INFO:
        err = dev_get_irqinfo(lm_ctx, &cmd_ioctl->data.irq_info);
        break;
    case VFIO_DEVICE_SET_IRQS:
        err = dev_set_irqs(lm_ctx, &cmd_ioctl->data.irq_set, data);
        break;
    case VFIO_DEVICE_RESET:
        if (lm_ctx->reset) {
            return lm_ctx->reset(lm_ctx->pvt);
        }
    }

    return err;
}

static int muser_dma_unmap(lm_ctx_t * lm_ctx, struct muser_cmd *cmd)
{
    int err;

    lm_log(lm_ctx, LM_INF, "removing DMA region %lx-%lx\n",
           cmd->mmap.request.start, cmd->mmap.request.end);

    if (lm_ctx->dma == NULL) {
        lm_log(lm_ctx, LM_ERR, "DMA not initialized\n");
        cmd->mmap.response.addr = -1;
        return -1;
    }

    err = dma_controller_remove_region(lm_ctx->dma,
                                       cmd->mmap.request.start,
                                       cmd->mmap.request.end -
                                       cmd->mmap.request.start, lm_ctx->fd);
    if (err != 0) {
        lm_log(lm_ctx, LM_ERR, "failed to remove DMA region %lx-%lx: %s\n",
               cmd->mmap.request.start, cmd->mmap.request.end, strerror(err));
    }

    cmd->mmap.response.addr = err;

    return err;
}

static int muser_dma_map(lm_ctx_t * lm_ctx, struct muser_cmd *cmd)
{
    int err;

    lm_log(lm_ctx, LM_INF, "adding DMA region %lx-%lx\n",
           cmd->mmap.request.start, cmd->mmap.request.end);

    if (lm_ctx->dma == NULL) {
        lm_log(lm_ctx, LM_ERR, "DMA not initialized\n");
        cmd->mmap.response.addr = -1;
        return -1;
    }

    if (cmd->mmap.request.start >= cmd->mmap.request.end) {
        lm_log(lm_ctx, LM_ERR, "bad DMA region %lx-%lx\n",
               cmd->mmap.request.start, cmd->mmap.request.end);
        cmd->mmap.response.addr = -1;
        return -1;
    }
    err = dma_controller_add_region(lm_ctx, lm_ctx->dma,
                                    cmd->mmap.request.start,
                                    cmd->mmap.request.end -
                                    cmd->mmap.request.start, lm_ctx->fd, 0);
    if (err < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to add DMA region %lx-%lx: %d\n",
               cmd->mmap.request.start, cmd->mmap.request.end, err);
        cmd->mmap.response.addr = -1;
        return -1;
    }

    // TODO: Are we just abusing response.addr as a rc?
    cmd->mmap.response.addr = 0;

    return 0;
}

/*
 * Callback that is executed when device memory is to be memory mapped.
 */
static int muser_mmap(lm_ctx_t * lm_ctx, struct muser_cmd *cmd)
{
    int region, err = 0;
    unsigned long addr;
    unsigned long len = cmd->mmap.request.len;
    unsigned long pgoff = cmd->mmap.request.pgoff;

    region = lm_get_region(lm_ctx, pgoff, len, &pgoff);
    if (region < 0) {
        lm_log(lm_ctx, LM_ERR, "bad region %d\n", region);
        err = region;
        goto out;
    }

    if (!lm_ctx->pci_info.reg_info[region].map) {
        lm_log(lm_ctx, LM_ERR, "region not mmapable\n");
        err = -EINVAL;
        goto out;
    }

    if (lm_ctx->pci_info.reg_info[region].map) {
        addr = lm_ctx->pci_info.reg_info[region].map(lm_ctx->pvt, pgoff, len);
        if ((void *)addr == MAP_FAILED) {
            lm_log(lm_ctx, LM_ERR, "failed to mmap: %m\n");
	        err = -errno;
            goto out;
        }
        cmd->mmap.response.addr = addr;
    } else
        err = -ENOTSUP;

out:
    if (err) {
        lm_log(lm_ctx, LM_ERR, "failed to mmap device memory %x@%lx: %s\n",
               len, pgoff, strerror(-errno));
        cmd->err = err;
        err = -1;
    }

    return err;
}

static int
post_read(lm_ctx_t * const lm_ctx, struct muser_cmd *const cmd, ssize_t ret)
{
    if (ret != cmd->rw.count) {
        /* FIXME shouldn't we still reply to the kernel in case of error? */
        lm_log(lm_ctx, LM_ERR, "%s: bad read: %d/%d, %s\n",
               __func__, ret, cmd->rw.count, strerror(errno));
#ifdef LM_CRASH_ON_BAD_READ
        abort();
#endif
        return ret;
    }

    ret = write(lm_ctx->fd, cmd->rw.buf, cmd->rw.count);
    if ((int)ret != cmd->rw.count) {
        lm_log(lm_ctx, LM_ERR, "%s: bad muser write: %d/%d, %s\n",
               __func__, ret, cmd->rw.count, strerror(errno));
    }
    return ret;
}

int
lm_get_region(lm_ctx_t * const lm_ctx, const loff_t pos, const size_t count,
              loff_t * const off)
{
    assert(lm_ctx);
    assert(off);
    lm_pci_info_t *pci_info = &lm_ctx->pci_info;

    int i;

    for (i = 0; i < LM_DEV_NUM_REGS; i++) {
        const lm_reg_info_t * const reg_info = &pci_info->reg_info[i];
        if (pos >= reg_info->offset) {
            if (pos - reg_info->offset + count <= reg_info->size) {
                *off = pos - reg_info->offset;
                return i;
            }
        }
    }
    return -ENOENT;
}

static ssize_t
handle_pci_config_space_access(lm_ctx_t *lm_ctx, char *buf, size_t count,
                               loff_t pos, bool is_write,
                               lm_region_access_t *pci_config_fn)
{
    int r1, r2 = 0;

    r1 = cap_maybe_access(lm_ctx->caps, lm_ctx->pvt, buf, count, pos, is_write);
    if (r1 < 0) {
        lm_log(lm_ctx, LM_ERR, "bad access to capabilities %u@%ld\n", count, pos);
        return r1;
    }
    buf += r1;
    pos += r1;
    count -= r1;
    if (pci_config_fn && count > 0) {
        r2 = pci_config_fn(lm_ctx->pvt, buf, count, pos, is_write);
        if (r2 < 0) {
            return r2;
        }
    }
    return r1 + r2;
}

static ssize_t
do_access(lm_ctx_t * const lm_ctx, char * const buf, size_t count, loff_t pos,
          const bool is_write)
{
    int idx;
    loff_t offset;
    lm_pci_info_t *pci_info;

    assert(lm_ctx != NULL);
    assert(buf != NULL);
    assert(count > 0);

    pci_info = &lm_ctx->pci_info;
    idx = lm_get_region(lm_ctx, pos, count, &offset);
    if (idx < 0) {
        lm_log(lm_ctx, LM_ERR, "invalid region %d\n", idx);
        return idx;
    }

    if (idx < 0 || idx >= LM_DEV_NUM_REGS) {
        lm_log(lm_ctx, LM_ERR, "bad region %d\n", idx);
        return -EINVAL;
    } 
    if (idx == LM_DEV_CFG_REG_IDX) {
        return handle_pci_config_space_access(lm_ctx, buf, count, offset,
                                              is_write, pci_info->reg_info[idx].fn);
    }
    /*
     * Checking whether a callback exists might sound expensive however this
     * code is not performance critical. This works well when we don't expect a
     * region to be used, so the user of the library can simply leave the
     * callback NULL in lm_ctx_create.
     */
    if (pci_info->reg_info[idx].fn) {
        return pci_info->reg_info[idx].fn(lm_ctx->pvt, buf, count, offset,
                                          is_write);
    }

    lm_log(lm_ctx, LM_ERR, "no callback for region %d\n", idx);

    return -EINVAL;
}

/*
 * TODO function name same lm_access_t, fix
 */
ssize_t
lm_access(lm_ctx_t * const lm_ctx, char *buf, size_t count,
          loff_t * const ppos, const bool is_write)
{
    unsigned int done = 0;
    int ret;

    assert(lm_ctx != NULL);
    /* buf and ppos can be NULL if count is 0 */

    while (count) {
        size_t size;
        /*
         * Limit accesses to qword and enforce alignment. Figure out whether
         * the PCI spec requires this.
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
            lm_log(lm_ctx, LM_ERR, "failed to %s %llx@%lx: %s\n",
                   is_write ? "write" : "read", size, *ppos, strerror(-ret));
            return -EFAULT;
	    }
        count -= size;
        done += size;
        *ppos += size;
        buf += size;
    }
    return done;
}


static inline int
muser_access(lm_ctx_t * const lm_ctx, struct muser_cmd *const cmd,
             const bool is_write)
{
    char *data;
    int err;
    unsigned int i;
    size_t count = 0;
    ssize_t ret;

    /* TODO how big do we expect count to be? Can we use alloca(3) instead? */
    data = calloc(1, cmd->rw.count);
    if (data == NULL) {
        lm_log(lm_ctx, LM_ERR, "failed to allocate memory\n");
        return -1;
    }

    lm_log(lm_ctx, LM_DBG, "%s %x@%lx\n", is_write ? "W" : "R", cmd->rw.count,
           cmd->rw.pos);

    /* copy data to be written from kernel to user space */
    if (is_write) {
        err = read(lm_ctx->fd, data, cmd->rw.count);
        /*
         * FIXME this is wrong, we should be checking for
         * err != cmd->rw.count
         */
        if (err < 0) {
            lm_log(lm_ctx, LM_ERR, "failed to read from kernel: %s\n",
                   strerror(errno));
            goto out;
        }
        err = 0;
        dump_buffer(lm_ctx, "buffer write", data, cmd->rw.count);
    }

    count = cmd->rw.count;
    cmd->err = muser_pci_hdr_access(lm_ctx, &cmd->rw.count, &cmd->rw.pos,
                                    is_write, data);
    if (cmd->err) {
        lm_log(lm_ctx, LM_ERR, "failed to access PCI header: %d\n", cmd->err);
    }
    count -= cmd->rw.count;
    ret = lm_access(lm_ctx, data + count, cmd->rw.count, &cmd->rw.pos,
                    is_write);
    if (!is_write) {
        cmd->rw.buf = data;
        err = post_read(lm_ctx, cmd, ret);
        dump_buffer(lm_ctx, "buffer read", cmd->rw.buf, cmd->rw.count);
    }

out:
    free(data);

    return err;
}

static int
muser_ioctl(lm_ctx_t * lm_ctx, struct muser_cmd *cmd)
{
    void *data = NULL;
    size_t size = 0;
    int ret;

    /* TODO make this a function that returns the size */
    if (cmd->ioctl.vfio_cmd == VFIO_DEVICE_SET_IRQS) {
        uint32_t flags = cmd->ioctl.data.irq_set.flags;
        switch ((flags & VFIO_IRQ_SET_DATA_TYPE_MASK)) {
        case VFIO_IRQ_SET_DATA_EVENTFD:
            size = sizeof(int32_t) * cmd->ioctl.data.irq_set.count;
            break;
        case VFIO_IRQ_SET_DATA_BOOL:
            size = sizeof(uint8_t) * cmd->ioctl.data.irq_set.count;
            break;
        }
    }

    if (size != 0) {
        data = calloc(1, size);
        if (data == NULL) {
#ifdef DEBUG
            perror("calloc");
#endif
            return -1;
        }

        ret = read(lm_ctx->fd, data, size);
        if (ret < 0) {
#ifdef DEBUG
            perror("read failed");
#endif
            goto out;
        }
    }

    ret = (int)do_muser_ioctl(lm_ctx, &cmd->ioctl, data);

out:

    free(data);
    return ret;
}

static int drive_loop(lm_ctx_t *lm_ctx)
{
    struct muser_cmd cmd = { 0 };
    int err;
    size_t size;
    unsigned int i;

    do {
        err = ioctl(lm_ctx->fd, MUSER_DEV_CMD_WAIT, &cmd);
        if (err < 0) {
            return err;
        }

        switch (cmd.type) {
        case MUSER_IOCTL:
            err = muser_ioctl(lm_ctx, &cmd);
            break;
        case MUSER_READ:
        case MUSER_WRITE:
            err = muser_access(lm_ctx, &cmd, cmd.type == MUSER_WRITE);
            break;
        case MUSER_MMAP:
            err = muser_mmap(lm_ctx, &cmd);
            break;
        case MUSER_DMA_MMAP:
            err = muser_dma_map(lm_ctx, &cmd);
            break;
        case MUSER_DMA_MUNMAP:
            err = muser_dma_unmap(lm_ctx, &cmd);
            break;
        default:
            lm_log(lm_ctx, LM_ERR, "bad command %d\n", cmd.type);
            continue;
        }
        cmd.err = err;
        err = ioctl(lm_ctx->fd, MUSER_DEV_CMD_DONE, &cmd);
        if (err < 0) {
            lm_log(lm_ctx, LM_ERR, "failed to complete command: %s\n",
                   strerror(errno));
        }
        // TODO: Figure out a clean way to get out of the loop.
    } while (1);

    return err;
}

int
lm_ctx_drive(lm_ctx_t * lm_ctx)
{

    if (lm_ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    return drive_loop(lm_ctx);
}

static int
dev_detach(int dev_fd)
{
    return close(dev_fd);
}

static int
dev_attach(const char *uuid)
{
    char *path;
    int dev_fd;
    int err;

    err = asprintf(&path, "/dev/" MUSER_DEVNODE "/%s", uuid);
    if (err != (int)(strlen(MUSER_DEVNODE) + strlen(uuid) + 6)) {
        return -1;
    }

    dev_fd = open(path, O_RDWR);

    free(path);

    return dev_fd;
}

void *
lm_mmap(lm_ctx_t * lm_ctx, off_t offset, size_t length)
{
    off_t lm_off;

    if ((lm_ctx == NULL) || (length == 0) || !PAGE_ALIGNED(offset)) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    lm_off = offset | BIT(63);
    return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED,
                lm_ctx->fd, lm_off);
}

int
lm_irq_trigger(lm_ctx_t * lm_ctx, uint32_t vector)
{
    eventfd_t val = 1;

    if ((lm_ctx == NULL) || (vector >= lm_ctx->irqs.max_ivs)) {
        errno = EINVAL;
        return -1;
    }

    if (lm_ctx->irqs.efds[vector] == -1) {
        errno = ENOENT;
        return -1;
    }

    return eventfd_write(lm_ctx->irqs.efds[vector], val);
}

void
lm_ctx_destroy(lm_ctx_t * lm_ctx)
{
    if (lm_ctx == NULL) {
        return;
    }

    free(lm_ctx->pci_config_space);
    dev_detach(lm_ctx->fd);
    if (lm_ctx->dma != NULL) {
        dma_controller_destroy(lm_ctx, lm_ctx->dma);
    }
    free(lm_ctx);
    // FIXME: Maybe close any open irq efds? Unmap stuff?
}

static void
init_pci_hdr(lm_pci_hdr_t * const hdr, const lm_pci_hdr_id_t * const id,
    const lm_pci_hdr_cc_t * const cc)
{
    assert(hdr);
    assert(id);
    assert(cc);

    hdr->id = *id;
    hdr->cc = *cc;

    hdr->ss.vid = hdr->id.vid;
    hdr->ss.sid = hdr->id.did;

}

static int copy_sparse_mmap_areas(lm_reg_info_t *dst, lm_reg_info_t *src)
{
    struct lm_sparse_mmap_areas *mmap_areas;
    int nr_mmap_areas;
    size_t size;
    int i;

    for (i = 0; i < LM_DEV_NUM_REGS; i++) {
        if (!src[i].mmap_areas)
            continue;

        nr_mmap_areas = src[i].mmap_areas->nr_mmap_areas;
        size = sizeof(*mmap_areas) + (nr_mmap_areas * sizeof(struct lm_mmap_area));
        mmap_areas = calloc(1, size);
        if (!mmap_areas)
            return -ENOMEM;

        memcpy(mmap_areas, src[i].mmap_areas, size);
        dst[i].mmap_areas = mmap_areas;
    }

    return 0;
}

static void free_sparse_mmap_areas(lm_reg_info_t *reg_info)
{
    int i;

    for (i = 0; i < LM_DEV_NUM_REGS; i++)
        free(reg_info[i].mmap_areas);
}

static int
lm_caps_init(lm_ctx_t *lm_ctx, lm_cap_t *caps, int nr_caps)
{
    int err;

    assert(lm_ctx);
    assert(caps);

    if (!nr_caps) {
        return 0;
    }

    lm_ctx->caps = caps_create(caps, nr_caps);
    if (!lm_ctx->caps) {
        err = errno;
        lm_log(lm_ctx, LM_ERR, "failed to create PCI capabilities: %m\n");
        return err;
    }

    lm_ctx->pci_config_space->hdr.sts.cl = 0x1;
    lm_ctx->pci_config_space->hdr.cap = PCI_STD_HEADER_SIZEOF; 

    return 0;
}

lm_ctx_t *
lm_ctx_create(lm_dev_info_t * const dev_info)
{
    lm_ctx_t *lm_ctx = NULL;
    uint32_t max_ivs = 0, nr_mmap_areas = 0;
    uint32_t i;
    int err = 0;
    size_t size = 0;

    if (dev_info == NULL) {
        errno = EINVAL;
        return NULL;
    }

    for (i = 0; i < LM_DEV_NUM_IRQS; i++) {
        if (max_ivs < dev_info->pci_info.irq_count[i]) {
            max_ivs = dev_info->pci_info.irq_count[i];
        }
    }

    size += sizeof(int) * max_ivs;
    lm_ctx = calloc(1, sizeof(lm_ctx_t) + size);
    if (lm_ctx == NULL)
        return NULL;

    memcpy(&lm_ctx->pci_info, &dev_info->pci_info, sizeof(lm_pci_info_t));
    err = copy_sparse_mmap_areas(lm_ctx->pci_info.reg_info,
                                 dev_info->pci_info.reg_info);
    if (err)
	    goto out;

    lm_ctx->fd = dev_attach(dev_info->uuid);
    if (lm_ctx->fd == -1) {
        err = errno;
        goto out;
    }

    lm_ctx->dma = dma_controller_create(LM_DMA_REGIONS);
    if (lm_ctx->dma == NULL) {
        err = errno;
        goto out;
    }

    lm_ctx->pci_info.irq_count[LM_DEV_ERR_IRQ_IDX] = 1;
    lm_ctx->pci_info.irq_count[LM_DEV_REQ_IRQ_IDX] = 1;

    lm_ctx->extended = dev_info->extended;
    if (lm_ctx->extended) {
        size = PCI_CFG_SPACE_EXP_SIZE;
    } else {
        size = PCI_CFG_SPACE_SIZE;
    }
    lm_ctx->pci_config_space = calloc(PCI_CFG_SPACE_EXP_SIZE, 1);
    if (!lm_ctx->pci_config_space) {
        err = errno;
        goto out;
    }

    init_pci_hdr(&lm_ctx->pci_config_space->hdr, &dev_info->pci_info.id,
        &dev_info->pci_info.cc);
    for (i = 0; i < ARRAY_SIZE(lm_ctx->pci_config_space->hdr.bars); i++) {
        if ((dev_info->pci_info.reg_info[i].flags & LM_REG_FLAG_MEM) == 0) {
            lm_ctx->pci_config_space->hdr.bars[i].io.region_type |= 0x1;
        }
    }

    lm_ctx->reset = dev_info->reset;
    lm_ctx->pvt = dev_info->pvt;

    for (i = 0; i < max_ivs; i++) {
        lm_ctx->irqs.efds[i] = -1;
    }
    lm_ctx->irqs.err_efd = -1;
    lm_ctx->irqs.req_efd = -1;
    lm_ctx->irqs.type = IRQ_NONE;
    lm_ctx->irqs.max_ivs = max_ivs;

    lm_ctx->log = dev_info->log;
    lm_ctx->log_lvl = dev_info->log_lvl;

    err = lm_caps_init(lm_ctx, dev_info->caps, dev_info->nr_caps);

out:
    if (err) {
        if (lm_ctx) {
            dev_detach(lm_ctx->fd);
            free_sparse_mmap_areas(lm_ctx->pci_info.reg_info);
            free(lm_ctx->pci_config_space);
            free(lm_ctx);
            lm_ctx = NULL;
        }
        errno = err;
    }
    return lm_ctx;
}

void
dump_buffer(lm_ctx_t const *const lm_ctx, char const *const prefix,
            unsigned char const *const buf, const uint32_t count)
{
#ifdef DEBUG
    int i;
    const size_t bytes_per_line = 0x8;

    if (strcmp(prefix, "")) {
        lm_log(lm_ctx, LM_DBG, "%s\n", prefix);
    }
    for (i = 0; i < (int)count; i++) {
        if (i % bytes_per_line != 0) {
            lm_log(lm_ctx, LM_DBG, " ");
        }
        /* TODO valgrind emits a warning if count is 1 */
        lm_log(lm_ctx, LM_DBG, "0x%02x", *(buf + i));
        if ((i + 1) % bytes_per_line == 0) {
            lm_log(lm_ctx, LM_DBG, "\n");
        }
    }
    if (i % bytes_per_line != 0) {
        lm_log(lm_ctx, LM_DBG, "\n");
    }
#endif
}

/*
 * Returns a pointer to the standard part of the PCI configuration space.
 */
inline lm_pci_config_space_t *
lm_get_pci_config_space(lm_ctx_t * const lm_ctx)
{
    assert(lm_ctx != NULL);
    return lm_ctx->pci_config_space;
}

/*
 * Returns a pointer to the non-standard part of the PCI configuration space.
 */
inline uint8_t *
lm_get_pci_non_std_config_space(lm_ctx_t * const lm_ctx)
{
    assert(lm_ctx != NULL);
    return (uint8_t *) & lm_ctx->pci_config_space->non_std;
}

inline lm_reg_info_t *
lm_get_region_info(lm_ctx_t * const lm_ctx)
{
    assert(lm_ctx != NULL);
    return lm_ctx->pci_info.reg_info;
}

inline int
lm_addr_to_sg(lm_ctx_t * const lm_ctx, dma_addr_t dma_addr,
              uint32_t len, dma_sg_t * sg, int max_sg)
{
    return dma_addr_to_sg(lm_ctx, lm_ctx->dma, dma_addr, len, sg, max_sg);
}

inline int
lm_map_sg(lm_ctx_t * const lm_ctx, int prot,
          const dma_sg_t * sg, struct iovec *iov, int cnt)
{
    return dma_map_sg(lm_ctx->dma, prot, sg, iov, cnt);
}

inline void
lm_unmap_sg(lm_ctx_t * const lm_ctx, const dma_sg_t * sg,
            struct iovec *iov, int cnt)
{
    return dma_unmap_sg(lm_ctx->dma, sg, iov, cnt);
}

int
lm_ctx_run(lm_ctx_t * const lm_ctx)
{
    int ret = lm_ctx_drive(lm_ctx);

    lm_ctx_destroy(lm_ctx);
    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
