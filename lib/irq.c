/*
 * Copyright (c) 2020 Nutanix Inc. All rights reserved.
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

#include <errno.h>
#include <limits.h>
#include <sys/eventfd.h>

#include "irq.h"
#include "tran_sock.h"

#define LM2VFIO_IRQT(type) (type - 1)

static const char *
vfio_irq_idx_to_str(int index)
{
    switch (index) {
    case VFIO_PCI_INTX_IRQ_INDEX: return "INTx";
    case VFIO_PCI_MSI_IRQ_INDEX: return "MSI";
    case VFIO_PCI_MSIX_IRQ_INDEX: return "MSI-X";
    case VFIO_PCI_ERR_IRQ_INDEX: return "ERR";
    case VFIO_PCI_REQ_IRQ_INDEX: return "REQ";
    default:
        abort();
    }
}

static long
irqs_disable(vfu_ctx_t *vfu_ctx, uint32_t index)
{
    int *irq_efd = NULL;
    uint32_t i;

    assert(vfu_ctx != NULL);
    assert(index < VFU_DEV_NUM_IRQS);

    switch (index) {
    case VFIO_PCI_INTX_IRQ_INDEX:
    case VFIO_PCI_MSI_IRQ_INDEX:
    case VFIO_PCI_MSIX_IRQ_INDEX:
        vfu_log(vfu_ctx, LOG_DEBUG, "disabling IRQ %s",
                vfio_irq_idx_to_str(index));
        vfu_ctx->irqs->type = IRQ_NONE;
        for (i = 0; i < vfu_ctx->irqs->max_ivs; i++) {
            if (vfu_ctx->irqs->efds[i] >= 0) {
                if (close(vfu_ctx->irqs->efds[i]) == -1) {
                    vfu_log(vfu_ctx, LOG_DEBUG, "failed to close IRQ fd %d: %m",
                           vfu_ctx->irqs->efds[i]);
                }
                vfu_ctx->irqs->efds[i] = -1;
            }
        }
        return 0;
    case VFIO_PCI_ERR_IRQ_INDEX:
        irq_efd = &vfu_ctx->irqs->err_efd;
        break;
    case VFIO_PCI_REQ_IRQ_INDEX:
        irq_efd = &vfu_ctx->irqs->req_efd;
        break;
    }

    if (irq_efd != NULL) {
        if (*irq_efd != -1) {
            if (close(*irq_efd) == -1) {
                vfu_log(vfu_ctx, LOG_DEBUG, "failed to close IRQ fd %d: %m",
                       *irq_efd);
            }
            *irq_efd = -1;
        }
        return 0;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "failed to disable IRQs");
    return -EINVAL;
}

static int
irqs_set_data_none(vfu_ctx_t *vfu_ctx, struct vfio_irq_set *irq_set)
{
    int efd;
    __u32 i;
    long ret;
    eventfd_t val;

    for (i = irq_set->start; i < (irq_set->start + irq_set->count); i++) {
        efd = vfu_ctx->irqs->efds[i];
        if (efd >= 0) {
            val = 1;
            ret = eventfd_write(efd, val);
            if (ret == -1) {
                vfu_log(vfu_ctx, LOG_DEBUG,
                        "IRQ: failed to set data to none: %m");
                return -errno;
            }
        }
    }

    return 0;
}

static int
irqs_set_data_bool(vfu_ctx_t *vfu_ctx, struct vfio_irq_set *irq_set, void *data)
{
    uint8_t *d8;
    int efd;
    __u32 i;
    long ret;
    eventfd_t val;

    assert(data != NULL);
    for (i = irq_set->start, d8 = data; i < (irq_set->start + irq_set->count);
         i++, d8++) {
        efd = vfu_ctx->irqs->efds[i];
        if (efd >= 0 && *d8 == 1) {
            val = 1;
            ret = eventfd_write(efd, val);
            if (ret == -1) {
                vfu_log(vfu_ctx, LOG_DEBUG,
                        "IRQ: failed to set data to bool: %m");
                return -errno;
            }
        }
    }

    return 0;
}

static int
irqs_set_data_eventfd(vfu_ctx_t *vfu_ctx, struct vfio_irq_set *irq_set,
                      int *data)
{
    int efd;
    __u32 i;
    size_t j;

    assert(data != NULL);
    for (i = irq_set->start, j = 0; i < (irq_set->start + irq_set->count);
         i++, j++) {
        efd = vfu_ctx->irqs->efds[i];
        if (efd >= 0) {
            if (close(efd) == -1) {
                vfu_log(vfu_ctx, LOG_DEBUG, "failed to close IRQ fd %d: %m", efd);
            }

            vfu_ctx->irqs->efds[i] = -1;
        }
        assert(data[j] >= 0);
        /*
         * We've already checked in handle_device_set_irqs that
         * nr_fds == irq_set->count.
         */
        vfu_ctx->irqs->efds[i] = consume_fd(data, irq_set->count, j);
        vfu_log(vfu_ctx, LOG_DEBUG, "event fd[%d]=%d", i, vfu_ctx->irqs->efds[i]);
    }

    return 0;
}

static long
irqs_trigger(vfu_ctx_t *vfu_ctx, struct vfio_irq_set *irq_set, void *data)
{
    int err = 0;

    assert(vfu_ctx != NULL);
    assert(irq_set != NULL);

    if (irq_set->count == 0) {
        return irqs_disable(vfu_ctx, irq_set->index);
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "setting IRQ %s flags=%#x",
            vfio_irq_idx_to_str(irq_set->index), irq_set->flags);

    switch (irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
    case VFIO_IRQ_SET_DATA_NONE:
        err = irqs_set_data_none(vfu_ctx, irq_set);
        break;
    case VFIO_IRQ_SET_DATA_BOOL:
        err = irqs_set_data_bool(vfu_ctx, irq_set, data);
        break;
    case VFIO_IRQ_SET_DATA_EVENTFD:
        err = irqs_set_data_eventfd(vfu_ctx, irq_set, data);
        break;
    }

    return err;
}

static long
dev_set_irqs_validate(vfu_ctx_t *vfu_ctx, struct vfio_irq_set *irq_set)
{
    uint32_t a_type, d_type;

    assert(vfu_ctx != NULL);
    assert(irq_set != NULL);

    // Separate action and data types from flags.
    a_type = (irq_set->flags & VFIO_IRQ_SET_ACTION_TYPE_MASK);
    d_type = (irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK);

    // Ensure index is within bounds.
    if (irq_set->index >= VFU_DEV_NUM_IRQS) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad IRQ index %d\n", irq_set->index);
        return -EINVAL;
    }

    /* TODO make each condition a function */

    // Only one of MASK/UNMASK/TRIGGER is valid.
    if ((a_type != VFIO_IRQ_SET_ACTION_MASK) &&
        (a_type != VFIO_IRQ_SET_ACTION_UNMASK) &&
        (a_type != VFIO_IRQ_SET_ACTION_TRIGGER)) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad IRQ action mask %d\n", a_type);
        return -EINVAL;
    }
    // Only one of NONE/BOOL/EVENTFD is valid.
    if ((d_type != VFIO_IRQ_SET_DATA_NONE) &&
        (d_type != VFIO_IRQ_SET_DATA_BOOL) &&
        (d_type != VFIO_IRQ_SET_DATA_EVENTFD)) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad IRQ data %d\n", d_type);
        return -EINVAL;
    }
    // Ensure irq_set's start and count are within bounds.
    if ((irq_set->start >= vfu_ctx->irq_count[irq_set->index]) ||
        (irq_set->start + irq_set->count > vfu_ctx->irq_count[irq_set->index])) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad IRQ start/count\n");
        return -EINVAL;
    }
    // Only TRIGGER is valid for ERR/REQ.
    if (((irq_set->index == VFIO_PCI_ERR_IRQ_INDEX) ||
         (irq_set->index == VFIO_PCI_REQ_IRQ_INDEX)) &&
        (a_type != VFIO_IRQ_SET_ACTION_TRIGGER)) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad IRQ trigger w/o ERR/REQ\n");
        return -EINVAL;
    }
    // count == 0 is only valid with ACTION_TRIGGER and DATA_NONE.
    if ((irq_set->count == 0) && ((a_type != VFIO_IRQ_SET_ACTION_TRIGGER) ||
                                  (d_type != VFIO_IRQ_SET_DATA_NONE))) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad IRQ count %d\n", irq_set->count);
        return -EINVAL;
    }
    // If IRQs are set, ensure index matches what's enabled for the device.
    if ((irq_set->count != 0) && (vfu_ctx->irqs->type != IRQ_NONE) &&
        (irq_set->index != LM2VFIO_IRQT(vfu_ctx->irqs->type))) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad IRQ index\n");
        return -EINVAL;
    }

    return 0;
}

static long
dev_set_irqs(vfu_ctx_t *vfu_ctx, struct vfio_irq_set *irq_set, void *data)
{
    long ret;

    assert(vfu_ctx != NULL);
    assert(irq_set != NULL);

    // Ensure irq_set is valid.
    ret = dev_set_irqs_validate(vfu_ctx, irq_set);
    if (ret != 0) {
        return ret;
    }

    switch (irq_set->flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
    case VFIO_IRQ_SET_ACTION_MASK:     // fallthrough
    case VFIO_IRQ_SET_ACTION_UNMASK:
        // We're always edge-triggered without un/mask support.
        return 0;
    }

    return irqs_trigger(vfu_ctx, irq_set, data);
}

static long
dev_get_irqinfo(vfu_ctx_t *vfu_ctx, struct vfio_irq_info *irq_info_in,
                struct vfio_irq_info *irq_info_out)
{
    assert(vfu_ctx != NULL);
    assert(irq_info_in != NULL);
    assert(irq_info_out != NULL);

    // Ensure provided argsz is sufficiently big and index is within bounds.
    if ((irq_info_in->argsz < sizeof(struct vfio_irq_info)) ||
        (irq_info_in->index >= VFU_DEV_NUM_IRQS)) {
        vfu_log(vfu_ctx, LOG_DEBUG, "bad irq_info (size=%d index=%d)\n",
                irq_info_in->argsz, irq_info_in->index);
        return -EINVAL;
    }

    irq_info_out->count = vfu_ctx->irq_count[irq_info_in->index];
    irq_info_out->flags = VFIO_IRQ_INFO_EVENTFD;

    return 0;
}

int
handle_device_get_irq_info(vfu_ctx_t *vfu_ctx, uint32_t size,
                           struct vfio_irq_info *irq_info_in,
                           struct vfio_irq_info *irq_info_out)
{
    assert(vfu_ctx != NULL);
    assert(irq_info_in != NULL);
    assert(irq_info_out != NULL);

    if (size != sizeof(*irq_info_in) || size != irq_info_in->argsz) {
        vfu_log(vfu_ctx, LOG_WARNING, "IRQ info size %d", size);
        return -EINVAL;
    }

    return dev_get_irqinfo(vfu_ctx, irq_info_in, irq_info_out);
}

int
handle_device_set_irqs(vfu_ctx_t *vfu_ctx, uint32_t size,
                       int *fds, size_t nr_fds, struct vfio_irq_set *irq_set)
{
    void *data = NULL;

    assert(vfu_ctx != NULL);
    assert(irq_set != NULL);

    if (size < sizeof(*irq_set) || size != irq_set->argsz) {
        vfu_log(vfu_ctx, LOG_ERR, "bad size %d", size);
        return -EINVAL;
    }

    switch (irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
        case VFIO_IRQ_SET_DATA_EVENTFD:
            data = fds;
            if (nr_fds != irq_set->count) {
                vfu_log(vfu_ctx, LOG_ERR,
                        "bad number of FDs, expected=%u, actual=%d", nr_fds,
                        irq_set->count);
                return -EINVAL;
            }
            break;
        case VFIO_IRQ_SET_DATA_BOOL:
            data = irq_set + 1;
            break;
        default:
            vfu_log(vfu_ctx, LOG_ERR, "invalid IRQ type %d",
                    irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK);
            return -EINVAL;
    }

    return dev_set_irqs(vfu_ctx, irq_set, data);
}

static bool
validate_irq_subindex(vfu_ctx_t *vfu_ctx, uint32_t subindex)
{
    if (vfu_ctx == NULL) {
        return false;
    }

    if ((subindex >= vfu_ctx->irqs->max_ivs)) {
        vfu_log(vfu_ctx, LOG_ERR, "bad IRQ %d, max=%d\n", subindex,
               vfu_ctx->irqs->max_ivs);
        return false;
    }

    return true;
}

int
vfu_irq_trigger(vfu_ctx_t *vfu_ctx, uint32_t subindex)
{
    eventfd_t val = 1;

    if (!validate_irq_subindex(vfu_ctx, subindex)) {
        return ERROR_INT(EINVAL);
    }

    if (vfu_ctx->irqs->efds[subindex] == -1) {
        vfu_log(vfu_ctx, LOG_ERR, "no fd for interrupt %d\n", subindex);
        return ERROR_INT(ENOENT);
    }

    return eventfd_write(vfu_ctx->irqs->efds[subindex], val);
}

int
vfu_irq_message(vfu_ctx_t *vfu_ctx, uint32_t subindex)
{
    int ret, msg_id = 1;
    struct vfio_user_irq_info irq_info;

    if (!validate_irq_subindex(vfu_ctx, subindex)) {
        return ERROR_INT(EINVAL);
    }

    irq_info.subindex = subindex;
    ret = vfu_ctx->tran->send_msg(vfu_ctx, msg_id,
                                  VFIO_USER_VM_INTERRUPT,
                                  &irq_info, sizeof(irq_info),
                                  NULL, NULL, 0);
    if (ret < 0) {
	    return ERROR_INT(-ret);
    }

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
