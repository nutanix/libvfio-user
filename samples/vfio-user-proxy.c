/*
 * Copyright (c) 2026, Red Hat Inc. All rights reserved.
 *     Author: Jesse Taube <jtaubepe@redhat.com>
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

/*
 * vfio-user proxy: exposes a kernel VFIO device as a vfio-user server.
 *
 * Opens a real PCI device via the kernel VFIO interface and proxies all
 * region accesses (config space, BARs, ROM) and interrupts over a
 * vfio-user socket so that a vfio-user client (e.g. QEMU) can drive the
 * physical device. This allows for the possibility of using PCI devices
 * across the network.
 *
 * The device must be bound to vfio-pci before running this program.
 *
 * Usage:
 *   vfio-user-proxy [-vv] [-R] <socketpath> <device-bdf>
 *     -R  disable ROM BAR
 * Example:
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/e1000e/unbind
 *   echo vfio-pci > /sys/bus/pci/devices/0000:03:00.0/driver_override
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
 *   vfio-user-proxy /tmp/proxy.sock 0000:03:00.0
 *
 * Limitations:
 *   - Many PCI capabilities are not reported as they are not copied.
 *   - No DMA support
 *   - No ERR_IRQ or REQ_IRQ support
 *   - No migration state support
 *   - No memory mapping support
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/vfio.h>

#include "common.h"
#include "libvfio-user.h"
#include "pci_defs.h"

/*
 * ERR and REQ IRQs are not supported. Omit them from
 * the supported IRQ count.
 */
#define SUPPORTED_DEV_NUM_IRQS (VFU_DEV_MSIX_IRQ + 1)

enum vfu_irq_type {
    VFU_INVALID_IRQ = -1,
    VFU_INTX_IRQ,
    VFU_MSI_IRQ,
    VFU_MSIX_IRQ,
    VFU_ERR_IRQ,
    VFU_REQ_IRQ,
    VFU_NUM_IRQS,
};

struct proxy_data {
    vfu_ctx_t *vfu_ctx;

    int container_fd;
    int group_fd;
    int device_fd;
    bool supports_reset;
    bool no_rom;
    int log_level;

    struct {
        uint64_t size;
        uint64_t offset;
        uint32_t flags;
    } regions[VFIO_PCI_NUM_REGIONS];

    enum vfu_irq_type active_irq_type;
    uint32_t irq_count[SUPPORTED_DEV_NUM_IRQS];

    size_t poll_fds_count;
    /*
     * Index 0 is the VFU context fd, the rest are IRQs.
     */
    struct pollfd *poll_fds;
};

static const char *
vfu_irq_idx_to_str(enum vfu_irq_type index)
{
    switch (index) {
    case VFU_INVALID_IRQ: return "INVALID";
    case VFU_INTX_IRQ: return "INTx";
    case VFU_MSI_IRQ: return "MSI";
    case VFU_MSIX_IRQ: return "MSI-X";
    case VFU_ERR_IRQ: return "ERR";
    case VFU_REQ_IRQ: return "REQ";
    case VFU_NUM_IRQS:
    default:
        abort();
    }
}

static const char *
log_level_str(int level)
{
    switch (level) {
    case LOG_ERR:     return "ERROR";
    case LOG_WARNING: return "WARN ";
    case LOG_INFO:    return "INFO ";
    case LOG_DEBUG:   return "DEBUG";
    default:          return "?????";
    }
}

static void
proxy_log(vfu_ctx_t *vfu_ctx, int level, char const *msg)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);

    if (level > p->log_level) {
        return;
    }

    fprintf(stderr, "proxy[%s]: %s\n", log_level_str(level), msg);
}

static ssize_t access_common(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                  loff_t offset, bool is_write, uint64_t region_offset,
                  const char *region_name)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t vfio_off = region_offset + offset;
    ssize_t ret;

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %s %zu bytes at %#llx (vfio_off %#llx)",
            region_name, is_write ? "write" : "read",
            count, (unsigned long long)offset, (unsigned long long)vfio_off);

    if (is_write) {
        ret = pwrite(p->device_fd, buf, count, vfio_off);
    } else {
        ret = pread(p->device_fd, buf, count, vfio_off);
    }

    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "%s %s %zu bytes at %#llx (vfio_off %#llx): %m",
            region_name, is_write ? "write" : "read",
            count, (unsigned long long)offset, (unsigned long long)vfio_off);
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %s %zu bytes at %#llx (vfio_off %#llx) returned %zd",
            region_name, is_write ? "write" : "read",
            count, (unsigned long long)offset, (unsigned long long)vfio_off, ret);

    return ret;
}

#define DEFINE_BAR_CB(n) \
static ssize_t \
bar##n##_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, \
                loff_t offset, bool is_write) \
{ \
    struct proxy_data *p = vfu_get_private(vfu_ctx); \
    uint64_t region_offset = p->regions[VFIO_PCI_BAR0_REGION_INDEX + n].offset; \
    const char region_name[] = "BAR" #n; \
\
    return access_common(vfu_ctx, buf, count, offset, is_write, region_offset, region_name); \
}

DEFINE_BAR_CB(0)
DEFINE_BAR_CB(1)
DEFINE_BAR_CB(2)
DEFINE_BAR_CB(3)
DEFINE_BAR_CB(4)
DEFINE_BAR_CB(5)

static vfu_region_access_cb_t *bar_cbs[PCI_BARS_NR] = {
    bar0_access, bar1_access, bar2_access,
    bar3_access, bar4_access, bar5_access,
};

static ssize_t
cfg_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t region_offset = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;

    return access_common(vfu_ctx, buf, count, offset, is_write,
                region_offset, "config");
}

static ssize_t
rom_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t region_offset = p->regions[VFIO_PCI_ROM_REGION_INDEX].offset;

    if (is_write) {
        vfu_log(vfu_ctx, LOG_WARNING, "ROM write rejected (read-only) at %#llx+%zu",
                (unsigned long long)offset, count);
        errno = EPERM;
        return -1;
    }

    return access_common(vfu_ctx, buf, count, offset, false, region_offset, "ROM");
}

static int
device_reset(vfu_ctx_t *vfu_ctx, vfu_reset_type_t type)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);

    vfu_log(vfu_ctx, LOG_INFO, "device reset requested (type=%d)", type);

    if (!p->supports_reset) {
        vfu_log(vfu_ctx, LOG_WARNING, "device does not support reset, ignoring");
        return 0;
    }

    if (ioctl(p->device_fd, VFIO_DEVICE_RESET) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_DEVICE_RESET: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_INFO, "device reset successful");
    return 0;
}

static void setup_regions(struct proxy_data *p, uint32_t i)
{
    vfu_ctx_t *vfu_ctx = p->vfu_ctx;
    struct vfio_region_info ri = {
        .argsz = sizeof(ri),
        .index = i,
    };

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_REGION_INFO, &ri) == 0) {
        p->regions[i].size = ri.size;
        p->regions[i].offset = ri.offset;
        p->regions[i].flags = ri.flags;
        if (ri.size > 0) {
            vfu_log(vfu_ctx, LOG_DEBUG,
                   "region %u: size=%#llx offset=%#llx flags=%#x",
                   i, (unsigned long long)ri.size, (unsigned long long)ri.offset,
                   ri.flags);
            }
    } else {
        vfu_log(vfu_ctx, LOG_WARNING, "region %u: get info failed: %m", i);
    }
}

static int
setup_vfio(struct proxy_data *p, int group_num, const char *bdf)
{
    struct vfio_group_status gs = { .argsz = sizeof(gs) };
    struct vfio_device_info di = { .argsz = sizeof(di) };
    vfu_ctx_t *vfu_ctx = p->vfu_ctx;
    char path[64];
    uint32_t i;

    vfu_log(vfu_ctx, LOG_DEBUG, "opening VFIO container /dev/vfio/vfio");

    p->container_fd = open("/dev/vfio/vfio", O_RDWR);
    if (p->container_fd < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "/dev/vfio/vfio: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "container fd=%d", p->container_fd);

    if (ioctl(p->container_fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO API version mismatch");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "VFIO API version OK");

    snprintf(path, sizeof(path), "/dev/vfio/%d", group_num);
    p->group_fd = open(path, O_RDWR);
    if (p->group_fd < 0) {
        vfu_log(vfu_ctx, LOG_DEBUG, "%s not found, trying noiommu-%d",
                path, group_num);
        snprintf(path, sizeof(path), "/dev/vfio/noiommu-%d", group_num);
        p->group_fd = open(path, O_RDWR);
        if (p->group_fd < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "VFIO group %d: %m", group_num);
            return -1;
        }
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "opened group %s fd=%d", path, p->group_fd);

    if (ioctl(p->group_fd, VFIO_GROUP_GET_STATUS, &gs) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_GROUP_GET_STATUS: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "group status flags=%#x", gs.flags);

    if (!(gs.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        vfu_log(vfu_ctx, LOG_ERR,
                "VFIO group not viable (all devices bound to vfio-pci?)");
        return -1;
    }

    if (ioctl(p->group_fd, VFIO_GROUP_SET_CONTAINER, &p->container_fd) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_GROUP_SET_CONTAINER: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "group attached to container");

    if (ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "IOMMU set to TYPE1v2");
    } else if (ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "IOMMU set to TYPE1");
    } else if (ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_NOIOMMU_IOMMU) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "IOMMU set to NOIOMMU");
    } else {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_SET_IOMMU: %m");
        return -1;
    }

    p->device_fd = ioctl(p->group_fd, VFIO_GROUP_GET_DEVICE_FD, bdf);
    if (p->device_fd < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_GROUP_GET_DEVICE_FD(%s): %m", bdf);
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "device %s fd=%d", bdf, p->device_fd);

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_INFO, &di) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_DEVICE_GET_INFO: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG,
            "device info: flags=%#x num_regions=%u num_irqs=%u",
            di.flags, di.num_regions, di.num_irqs);

    if (!(di.flags & VFIO_DEVICE_FLAGS_PCI)) {
        vfu_log(vfu_ctx, LOG_ERR, "%s is not a PCI device", bdf);
        return -1;
    }

    p->supports_reset = !!(di.flags & VFIO_DEVICE_FLAGS_RESET);
    vfu_log(vfu_ctx, LOG_DEBUG, "device supports reset: %s",
            p->supports_reset ? "yes" : "no");

    for (i = 0; i < di.num_regions && i < VFIO_PCI_NUM_REGIONS; i++) {
        setup_regions(p, i);
    }

    return 0;
}

/*
 * Because INTx irqs are level-triggered, the kernel will
 * automatically mask the interrupt after it is fired.
 * The vfio-user client will then unmask already unmask
 * irqs.
 */
static void
vfio_intx_unmask(struct proxy_data *p)
{
    struct vfio_irq_set unmask = {
        .argsz = sizeof(unmask),
        .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK,
        .index = VFIO_PCI_INTX_IRQ_INDEX,
        .start = 0,
        .count = 1,
    };

    if (ioctl(p->device_fd, VFIO_DEVICE_SET_IRQS, &unmask) < 0) {
        vfu_log(p->vfu_ctx, LOG_ERR, "INTx kernel unmask failed: %m");
    }
}

/*
 * Common callback function for vfu_setup_irq_state_callback.
 * allows using the same function for all IRQ types.
 * Callback assumes VFIO_IRQ_SET_DATA_NONE is set as it is
 * not possible to check.
 * Qemu will always set this flag when unmasking an IRQ.
 */
static void
proxy_irq_set_state(vfu_ctx_t *vfu_ctx, enum vfu_irq_type index, uint32_t start,
                    uint32_t count, bool mask)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    size_t set_sz;
    struct vfio_irq_set *irq_set;
    int *fds;
    size_t i, k;

    /*
     * Kernel VFIO only supports unmasking with.
     * (flags & VFIO_IRQ_SET_DATA_NONE && start == 0 && count == 1)
     */
    if (start != 0 || count != 1) {
        vfu_log(vfu_ctx, LOG_ERR,
                "IRQ type %s: start=%u count=%u not supported",
                vfu_irq_idx_to_str(index), start, count);
        return;
    }

    if (mask) {
        if (p->active_irq_type == VFU_INVALID_IRQ) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "IRQ type %s cannot be masked because no IRQ type is active",
                    vfu_irq_idx_to_str(index));
            return;
        }

        /*
         * Start at 1 to account for the first element
         * which is used for the vfu_ctx fd.
         */
        for (i = 1; i < p->poll_fds_count; i++) {
            close_safely(&p->poll_fds[i].fd);
            p->poll_fds[i].fd = -1;
        }

        vfu_log(vfu_ctx, LOG_DEBUG, "IRQ type %s masked.", vfu_irq_idx_to_str(index));
        return;
    }

    /*
     * Ensure all IRQs are masked before changing to a new IRQ type.
     */
    if (p->active_irq_type != VFU_INVALID_IRQ && p->active_irq_type != index) {
        for (i = 1; i < p->poll_fds_count; i++) {
            if (p->poll_fds[i].fd > 0) {
                vfu_log(vfu_ctx, LOG_ERR,
                        "IRQ type %s unmasked while type %s is still active",
                        vfu_irq_idx_to_str(index), vfu_irq_idx_to_str(p->active_irq_type));
                return;
            }
        }
    }

    p->active_irq_type = index;

    /*
     * INTx allows unmasking already unmasking irqs.
     * to avoid closing then recreating the eventfd. Call vfio_intx_unmask()
     * if any INTx irqs are any unmasked (fd > 0).
     */
    if (index == VFU_INTX_IRQ) {
        for (i = 1; i < p->poll_fds_count; i++) {
            if (p->poll_fds[i].fd > 0) {
                vfio_intx_unmask(p);
                return;
            }
        }
    }

    set_sz = sizeof(*irq_set) + p->irq_count[index] * sizeof(int);
    irq_set = calloc(1, set_sz);
    if (irq_set == NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "IRQ type %s calloc failed: %m", vfu_irq_idx_to_str(index));
        assert(0 && "IRQ type calloc failed");
        return;
    }

    irq_set->argsz = set_sz;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = index;
    irq_set->start = 0;
    irq_set->count = p->irq_count[index];
    fds = (int *)(irq_set->data);

    for (i = 0; i < p->irq_count[index]; i++) {
        k = i + 1; /* account for first element which is vfu_ctx fd */
        if (p->poll_fds[k].fd > 0) {
            vfu_log(vfu_ctx, LOG_WARNING,
                    "IRQ type %s vec %zu already unmasked (fd=%d)",
                    vfu_irq_idx_to_str(index), i, p->poll_fds[k].fd);
            goto out_free;
        }
        p->poll_fds[k].fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (p->poll_fds[k].fd < 0) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "eventfd creation failed for IRQ type %s vec %zu: %m",
                    vfu_irq_idx_to_str(index), i);
            goto out_free;
        }
        p->poll_fds[k].events = POLLIN;
        fds[i] = p->poll_fds[k].fd;
    }

    if (ioctl(p->device_fd, VFIO_DEVICE_SET_IRQS, irq_set) < 0) {
        vfu_log(vfu_ctx, LOG_ERR,
                "VFIO_DEVICE_SET_IRQS type %s failed: %m", vfu_irq_idx_to_str(index));
    } else {
        vfu_log(vfu_ctx, LOG_DEBUG, "IRQ type %s unmasked", vfu_irq_idx_to_str(index));
    }

out_free:
    free(irq_set);
}

#define DEFINE_IRQ_STATE_CB(name, irq_type) \
static void \
name##_state_cb(vfu_ctx_t *vfu_ctx, uint32_t start, \
                uint32_t count, bool mask) \
{ \
    proxy_irq_set_state(vfu_ctx, irq_type, start, count, mask); \
}

DEFINE_IRQ_STATE_CB(intx, VFU_INTX_IRQ)
DEFINE_IRQ_STATE_CB(msi, VFU_MSI_IRQ)
DEFINE_IRQ_STATE_CB(msix, VFU_MSIX_IRQ)

static vfu_dev_irq_state_cb_t *irq_state_cbs[SUPPORTED_DEV_NUM_IRQS] = {
    intx_state_cb, msi_state_cb, msix_state_cb,
};

static int
setup_irq_type(vfu_ctx_t *vfu_ctx, enum vfu_irq_type index)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    struct vfio_irq_info irq = {
        .argsz = sizeof(irq),
        .index = index,
    };

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq) < 0) {
        vfu_log(vfu_ctx, LOG_WARNING, "IRQ info query failed for type %s: %m", vfu_irq_idx_to_str(index));
        return -1;
    }

    if (irq.count == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "IRQ type %s not available (count=0)", vfu_irq_idx_to_str(index));
        return 0;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "IRQ type %s info: count=%u flags=%#x",
            vfu_irq_idx_to_str(index), irq.count, irq.flags);

    if (vfu_setup_device_nr_irqs(vfu_ctx, (enum vfu_dev_irq_type)index, irq.count) < 0) {
        vfu_log(vfu_ctx, LOG_ERR,
                "IRQ type %s vfu_setup_device_nr_irqs: %m", vfu_irq_idx_to_str(index));
        return -1;
    }

    p->irq_count[index] = irq.count;

    vfu_setup_irq_state_callback(vfu_ctx, (enum vfu_dev_irq_type)index, irq_state_cbs[index]);

    vfu_log(vfu_ctx, LOG_INFO, "IRQ type %s registered (count=%u)",
            vfu_irq_idx_to_str(index), irq.count);

    return 0;
}

static int
setup_irqs(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint32_t i, max_count = 0;
    enum vfu_irq_type irq;

    for (irq = 0; irq < SUPPORTED_DEV_NUM_IRQS; irq++) {
        if (setup_irq_type(vfu_ctx, irq) < 0) {
            return -1;
        }
        if (p->irq_count[irq] > max_count) {
            max_count = p->irq_count[irq];
        }
    }

    p->poll_fds = calloc(1 + max_count, sizeof(struct pollfd));
    if (p->poll_fds == NULL) {
        vfu_log(vfu_ctx, LOG_ERR, "setup_irqs calloc failed: %m");
        return -1;
    }
    p->poll_fds_count = 1 + max_count;

    for (i = 0; i < p->poll_fds_count; i++) {
        p->poll_fds[i].fd = -1;
    }

    for (irq = 0; irq < SUPPORTED_DEV_NUM_IRQS; irq++) {
        if (p->irq_count[irq] > 0) {
            p->active_irq_type = irq;
            break;
        }
    }

    return 0;
}

static int
pci_flags_to_vfu_flags(uint32_t bar_val)
{
    int vfu_flags = VFU_REGION_FLAG_RW;

    if (!(bar_val & PCI_BASE_ADDRESS_SPACE_IO)) {
        vfu_flags |= VFU_REGION_FLAG_MEM;

        if ((bar_val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
              PCI_BASE_ADDRESS_MEM_TYPE_64) {
            vfu_flags |= VFU_REGION_FLAG_64_BITS;
        }

        if (bar_val & PCI_BASE_ADDRESS_MEM_PREFETCH) {
            vfu_flags |= VFU_REGION_FLAG_PREFETCH;
        }
    }

    return vfu_flags;
}

static int
setup_bars(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t cfg_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
    int ret, flags, i;
    uint32_t bar_val;

    for (i = 0; i < PCI_BARS_NR; i++) {
        if (p->regions[i].size == 0) {
            vfu_log(vfu_ctx, LOG_DEBUG, "BAR%d is zero size.", i);
            continue;
        }

        if (pread(p->device_fd, &bar_val, 4,
                  cfg_off + PCI_BASE_ADDRESS_0 + i * 4) != 4) {
            vfu_log(vfu_ctx, LOG_WARNING, "failed to read BAR%d config: %m", i);
            continue;
        }

        flags = pci_flags_to_vfu_flags(bar_val);

        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX + i,
                               p->regions[i].size, bar_cbs[i], flags,
                               NULL, 0, -1, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to setup BAR%d: %m", i);
            return -1;
        }

        vfu_log(vfu_ctx, LOG_DEBUG, "BAR%d size=%#llx flags=%#x",
                i, (unsigned long long)p->regions[i].size, flags);

        /* 64-bit BARs span two consecutive indices; skip the upper half. */
        if (flags & VFU_REGION_FLAG_64_BITS) {
            i++;
        }
    }
    return 0;
}

static int
setup_pci_id(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t cfg_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
    vfu_pci_config_space_t *cs = vfu_pci_get_config_space(vfu_ctx);
    uint16_t vendor_id, device_id, subsys_vid, subsys_id;
    uint8_t class_info[3];

    if (pread(p->device_fd, cs->raw, PCI_CFG_SPACE_SIZE, cfg_off) !=
        PCI_CFG_SPACE_SIZE) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to read PCI config space");
        return -1;
    }

    vendor_id = *(uint16_t *)&cs->raw[PCI_VENDOR_ID];
    device_id = *(uint16_t *)&cs->raw[PCI_DEVICE_ID];
    subsys_vid = *(uint16_t *)&cs->raw[PCI_SUBSYSTEM_VENDOR_ID];
    subsys_id = *(uint16_t *)&cs->raw[PCI_SUBSYSTEM_ID];
    memcpy(class_info, &cs->raw[PCI_CLASS_PROG], 3);

    vfu_log(vfu_ctx, LOG_INFO, "PCI ID [%04x:%04x] subsys [%04x:%04x] "
            "class %02x%02x%02x",
            vendor_id, device_id, subsys_vid, subsys_id,
            class_info[2], class_info[1], class_info[0]);

    vfu_pci_set_id(vfu_ctx, vendor_id, device_id, subsys_vid, subsys_id);
    vfu_pci_set_class(vfu_ctx, class_info[2], class_info[1], class_info[0]);

    return 0;
}

static int
setup_device(vfu_ctx_t *vfu_ctx, bool no_rom)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    int ret;

    if (!no_rom && p->regions[VFIO_PCI_ROM_REGION_INDEX].size > 0) {
        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_ROM_REGION_IDX,
                               p->regions[VFIO_PCI_ROM_REGION_INDEX].size,
                               &rom_access, VFU_REGION_FLAG_READ,
                               NULL, 0, -1, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_WARNING, "ROM region setup failed: %m");
            return -1;
        }
    }
    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_CFG_REGION_IDX,
                           PCI_CFG_SPACE_SIZE, &cfg_access,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_ALWAYS_CB,
                           NULL, 0, -1, 0);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "config region setup: %m");
        return -1;
    }

    ret = vfu_setup_device_reset_cb(vfu_ctx, &device_reset);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_setup_device_reset_cb: %m");
        return -1;
    }

    ret = setup_irqs(vfu_ctx);
    if (ret < 0) {
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "realizing context");
    ret = vfu_realize_ctx(vfu_ctx);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_realize_ctx: %m");
        return -1;
    }
    vfu_log(vfu_ctx, LOG_INFO, "context realized");

    vfu_log(vfu_ctx, LOG_DEBUG, "waiting for client connection");
    ret = vfu_attach_ctx(vfu_ctx);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_attach_ctx: %m");
        return -1;
    }

    p->poll_fds[0].fd = vfu_get_poll_fd(vfu_ctx);
    p->poll_fds[0].events = POLLIN;

    vfu_log(vfu_ctx, LOG_INFO, "client connected");

    return 0;
}

static int
proxy_run(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t val;
    size_t i;
    ssize_t n;
    int ret;

    for (;;) {
        ret = poll(p->poll_fds, p->poll_fds_count, -1);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            vfu_log(vfu_ctx, LOG_ERR, "poll: %m");
            return -1;
        }

        /*
         * First trigger any IRQs by looping through
         * all the IRQ file descriptors.
         */
        for (i = 1; i < p->poll_fds_count; i++) {
            if (p->poll_fds[i].fd < 0 || !(p->poll_fds[i].revents & POLLIN)) {
                continue;
            }
            n = read(p->poll_fds[i].fd, &val, sizeof(val));
            if (n == (ssize_t)sizeof(val)) {
                vfu_log(vfu_ctx, LOG_DEBUG,
                        "IRQ type %s vec %zu fired (count=%llu)",
                        vfu_irq_idx_to_str(p->active_irq_type),
                        i - 1, (unsigned long long)val);
                ret = vfu_irq_trigger(vfu_ctx, (uint32_t)(i - 1));
                if (ret < 0) {
                    vfu_log(vfu_ctx, LOG_ERR, "vfu_irq_trigger: %m");
                    return -1;
                }
                /*
                 * Unmask the interrupt if it's an INTx  (level triggered) interrupt.
                 */
                if (p->active_irq_type == VFU_INTX_IRQ) {
                    vfio_intx_unmask(p);
                }
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                vfu_log(vfu_ctx, LOG_ERR, "IRQ eventfd read: %m");
                return -1;
            }
        }

        /*
         * Let device proccess ant incoming messages.
         */
        if (p->poll_fds[0].revents & POLLIN) {
            ret = vfu_run_ctx(vfu_ctx);
            if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                if (errno == ENOTCONN) {
                    vfu_log(vfu_ctx, LOG_INFO, "client disconnected");
                    return 0;
                }
                vfu_log(vfu_ctx, LOG_ERR, "vfu_run_ctx: %m");
                return -1;
            }
        }

        if (p->poll_fds[0].revents & POLLHUP) {
            vfu_log(vfu_ctx, LOG_INFO, "poll fd hangup");
            return 0;
        }
        if (p->poll_fds[0].revents & POLLERR) {
            vfu_log(vfu_ctx, LOG_INFO, "poll fd error");
            return 0;
        }
    }
}

static int
get_iommu_group(const char *bdf)
{
    char target[PATH_MAX];
    char path[PATH_MAX];
    ssize_t len;

    snprintf(path, sizeof(path),
             "/sys/bus/pci/devices/%s/iommu_group", bdf);
    len = readlink(path, target, sizeof(target) - 1);
    if (len < 0 || len >= (ssize_t)(sizeof(target) - 1)) {
        err(EXIT_FAILURE, "readlink %s", path);
    }

    target[len] = '\0';
    return atoi(basename(target));
}

struct proxy_opts {
    const char *sock_path;
    const char *bdf;
    int log_level;
    bool no_rom;
};

static void __attribute__((noreturn))
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-vv] [-R] <socketpath> <device-bdf>\n"
            "  -R  disable ROM BAR\n",
            prog);
    exit(EXIT_FAILURE);
}

static struct proxy_opts
parse_args(int argc, char *argv[])
{
    struct proxy_opts opts = {
        .log_level = LOG_ERR,
    };
    int opt;

    while ((opt = getopt(argc, argv, "vR")) != -1) {
        switch (opt) {
        case 'v':
            if (opts.log_level < LOG_DEBUG) {
                opts.log_level++;
            }
            break;
        case 'R':
            opts.no_rom = true;
            break;
        default:
            usage(argv[0]);
        }
    }

    if (argc - optind < 2) {
        usage(argv[0]);
    }

    opts.sock_path = argv[optind];
    opts.bdf = argv[optind + 1];
    return opts;
}

int
main(int argc, char *argv[])
{
    struct proxy_data proxy = {
        .container_fd = -1,
        .group_fd = -1,
        .device_fd = -1,
        .active_irq_type = VFU_INVALID_IRQ,
        .log_level = LOG_ERR,
    };
    struct proxy_opts opts;
    int group_num, ret;
    size_t i;

    opts = parse_args(argc, argv);
    group_num = get_iommu_group(opts.bdf);
    proxy.log_level = opts.log_level;

    proxy.vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, opts.sock_path,
                             LIBVFIO_USER_FLAG_RUN_CTX_NB, &proxy,
                             VFU_DEV_TYPE_PCI);
    if (proxy.vfu_ctx == NULL) {
        err(EXIT_FAILURE, "vfu_create_ctx");
    }

    ret = vfu_setup_log(proxy.vfu_ctx, proxy_log, proxy.log_level);
    if (ret < 0) {
        warn("vfu_setup_log");
        goto cleanup;
    }

    vfu_log(proxy.vfu_ctx, LOG_DEBUG, "creating vfu context on %s", opts.sock_path);

    ret = setup_vfio(&proxy, group_num, opts.bdf);
    if (ret < 0) {
        goto cleanup;
    }

    if (proxy.regions[VFIO_PCI_CONFIG_REGION_INDEX].size == 0) {
        vfu_log(proxy.vfu_ctx, LOG_ERR, "%s: no config region", opts.bdf);
        ret = -1;
        goto cleanup;
    }

    ret = vfu_pci_init(proxy.vfu_ctx, VFU_PCI_TYPE_CONVENTIONAL,
                       PCI_HEADER_TYPE_NORMAL, 0);
    if (ret < 0) {
        vfu_log(proxy.vfu_ctx, LOG_ERR, "vfu_pci_init: %m");
        goto cleanup;
    }

    ret = setup_pci_id(proxy.vfu_ctx);
    if (ret < 0) {
        goto cleanup;
    }

    ret = setup_bars(proxy.vfu_ctx);
    if (ret < 0) {
        goto cleanup;
    }

    ret = setup_device(proxy.vfu_ctx, opts.no_rom);
    if (ret < 0) {
        goto cleanup;
    }

    vfu_log(proxy.vfu_ctx, LOG_INFO, "serving %s on %s", opts.bdf, opts.sock_path);

    ret = proxy_run(proxy.vfu_ctx);
    vfu_log(proxy.vfu_ctx, LOG_DEBUG, "main loop exited (ret=%d)", ret);

cleanup:
    if (proxy.poll_fds != NULL) {
        for (i = 1; i < proxy.poll_fds_count; i++) {
            close_safely(&proxy.poll_fds[i].fd);
        }
        free(proxy.poll_fds);
    }

    vfu_log(proxy.vfu_ctx, LOG_DEBUG, "cleaning up vfu context");
    vfu_destroy_ctx(proxy.vfu_ctx);

    close_safely(&proxy.device_fd);
    close_safely(&proxy.group_fd);
    close_safely(&proxy.container_fd);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
