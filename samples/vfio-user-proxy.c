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
 * region accesses (config space, BARs, ROM) and INTx interrupts over a
 * vfio-user socket so that a vfio-user client (e.g. QEMU) can drive the
 * physical device.
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
 *   - Only INTx interrupt forwarding is implemented.  MSI/MSI-X vectors
 *     are not forwarded; extending this requires setting up per-vector
 *     eventfds and monitoring them with epoll.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/vfio.h>

#include "common.h"
#include "libvfio-user.h"
#include "pci_defs.h"

struct proxy_data {
    int container_fd;
    int group_fd;
    int device_fd;
    bool supports_reset;
    int log_level;

    struct {
        uint64_t size;
        uint64_t offset;
        uint32_t flags;
    } regions[VFIO_PCI_NUM_REGIONS];

    int intx_eventfd;
    pthread_t irq_thread;
    bool irq_thread_running;
    bool no_rom;
    vfu_ctx_t *vfu_ctx;
};

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
proxy_log(vfu_ctx_t *vfu_ctx UNUSED, UNUSED int level, char const *msg)
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

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %s %zu bytes at %#lx (vfio_off %#lx)",
            region_name, is_write ? "write" : "read",
            count, (unsigned long)offset, (unsigned long)vfio_off);

    if (is_write) {
        ret = pwrite(p->device_fd, buf, count, vfio_off);
    } else {
        ret = pread(p->device_fd, buf, count, vfio_off);
    }

    if (ret < 0) {
        ret = errno;
        vfu_log(vfu_ctx, LOG_ERR, "%s %s %zu bytes at %#lx (vfio_off %#lx): %m",
            region_name, is_write ? "write" : "read",
            count, (unsigned long)offset, (unsigned long)vfio_off);
        errno = ret;
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %s %zu bytes at %#lx (vfio_off %#lx) returned %d",
            region_name, is_write ? "write" : "read",
            count, (unsigned long)offset, (unsigned long)vfio_off, (int)ret);

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
        vfu_log(vfu_ctx, LOG_WARNING, "ROM write rejected (read-only) at %#lx+%zu",
                (unsigned long)offset, count);
        errno = EPERM;
        return -1;
    }

    return access_common(vfu_ctx, buf, count, offset, false, region_offset, "ROM");
}

static void *
irq_thread_fn(void *arg)
{
    struct proxy_data *p = arg;
    uint64_t val;
    ssize_t ret;

    vfu_log(p->vfu_ctx, LOG_DEBUG, "IRQ thread started (eventfd=%d)",
            p->intx_eventfd);

    while (p->irq_thread_running) {
        ret = read(p->intx_eventfd, &val, sizeof(val));
        if (ret != (ssize_t)sizeof(val)) {
            if (errno == EINTR) {
                vfu_log(p->vfu_ctx, LOG_DEBUG,
                        "IRQ thread: eventfd read interrupted, retrying");
                continue;
            }
            vfu_log(p->vfu_ctx, LOG_ERR,
                    "IRQ thread: eventfd read failed (%zd): %m", ret);
            break;
        }
        vfu_log(p->vfu_ctx, LOG_DEBUG,
                "IRQ thread: forwarding INTx (count=%lu)",
                (unsigned long)val);
        vfu_irq_trigger(p->vfu_ctx, 0);
    }

    vfu_log(p->vfu_ctx, LOG_DEBUG, "IRQ thread exiting");
    return NULL;
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
                   "region %u: size=%#lx offset=%#lx flags=%#x",
                   i, (unsigned long)ri.size, (unsigned long)ri.offset,
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

static int
setup_intx(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    struct vfio_irq_info irq = {
        .argsz = sizeof(irq),
        .index = VFIO_PCI_INTX_IRQ_INDEX,
    };
    struct {
        struct vfio_irq_set hdr;
        int32_t fd;
    } irq_set;

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq) < 0) {
        vfu_log(vfu_ctx, LOG_INFO, "INTx IRQ info query failed: %m");
        return -1;
    }

    if (irq.count == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "INTx not available (count=0)");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "INTx info: count=%u flags=%#x",
            irq.count, irq.flags);

    p->intx_eventfd = eventfd(0, EFD_CLOEXEC);
    if (p->intx_eventfd < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "eventfd creation failed: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "INTx eventfd=%d", p->intx_eventfd);

    memset(&irq_set, 0, sizeof(irq_set));
    irq_set.hdr.argsz = sizeof(irq_set);
    irq_set.hdr.flags = VFIO_IRQ_SET_DATA_EVENTFD |
                         VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set.hdr.index = VFIO_PCI_INTX_IRQ_INDEX;
    irq_set.hdr.start = 0;
    irq_set.hdr.count = 1;
    irq_set.fd = p->intx_eventfd;

    if (ioctl(p->device_fd, VFIO_DEVICE_SET_IRQS, &irq_set) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_DEVICE_SET_IRQS failed: %m");
        close(p->intx_eventfd);
        p->intx_eventfd = -1;
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "INTx eventfd armed");

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

static void
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
            vfu_log(vfu_ctx, LOG_ERR, "failed to read BAR%d config: %m", i);
            continue;
        }

        flags = pci_flags_to_vfu_flags(bar_val);

        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX + i,
                               p->regions[i].size, bar_cbs[i], flags,
                               NULL, 0, -1, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to setup BAR%d: %m", i);
            continue;
        }

        vfu_log(vfu_ctx, LOG_DEBUG, "BAR%d size=%#lx flags=%#x",
                i, (unsigned long)p->regions[i].size, flags);

        /* 64-bit BARs span two consecutive indices; skip the upper half. */
        if (flags & VFU_REGION_FLAG_64_BITS) {
            i++;
        }
    }
}

static int
setup_pci_id(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t cfg_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
    uint16_t vendor_id, device_id, subsys_vid, subsys_id;
    uint8_t class_info[3];

    if (pread(p->device_fd, &vendor_id, 2, cfg_off + PCI_VENDOR_ID) != 2 ||
        pread(p->device_fd, &device_id, 2, cfg_off + PCI_DEVICE_ID) != 2 ||
        pread(p->device_fd, &subsys_vid, 2, cfg_off + PCI_SUBSYSTEM_VENDOR_ID) != 2 ||
        pread(p->device_fd, &subsys_id, 2, cfg_off + PCI_SUBSYSTEM_ID) != 2 ||
        pread(p->device_fd, class_info, 3, cfg_off + PCI_CLASS_PROG) != 3) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to read PCI config identity fields");
        return -1;
    }

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

    ret = vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_INTX_IRQ, 1);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_setup_device_nr_irqs: %m");
        return -1;
    }

    if (setup_intx(vfu_ctx) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "INTx forwarding enabled");
    } else {
        vfu_log(vfu_ctx, LOG_INFO, "INTx forwarding not available");
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
    vfu_log(vfu_ctx, LOG_INFO, "client connected");

    return 0;
}

static int
proxy_run(vfu_ctx_t *vfu_ctx)
{
    int ret;

    do {
        ret = vfu_run_ctx(vfu_ctx);
        if (ret == -1 && errno == EINTR) {
            vfu_log(vfu_ctx, LOG_DEBUG, "vfu_run_ctx interrupted, retrying");
            ret = 0;
        } else if (ret == -1 && errno == ENOTCONN) {
            vfu_log(vfu_ctx, LOG_INFO, "client disconnected");
            ret = 0;
            break;
        } else if (ret == -1) {
            vfu_log(vfu_ctx, LOG_ERR, "vfu_run_ctx returned error: %m");
        }
    } while (ret == 0);

    return ret;
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
        .intx_eventfd = -1,
        .log_level = LOG_ERR,
    };
    struct proxy_opts opts;
    vfu_ctx_t *vfu_ctx;
    int group_num, ret;

    opts = parse_args(argc, argv);
    group_num = get_iommu_group(opts.bdf);
    proxy.log_level = opts.log_level;

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, opts.sock_path, 0, &proxy,
                             VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL) {
        err(EXIT_FAILURE, "vfu_create_ctx");
    }

    proxy.vfu_ctx = vfu_ctx;

    ret = vfu_setup_log(vfu_ctx, proxy_log, proxy.log_level);
    if (ret < 0) {
        warn("vfu_setup_log");
        goto cleanup;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "creating vfu context on %s", opts.sock_path);

    ret = setup_vfio(&proxy, group_num, opts.bdf);
    if (ret < 0) {
        goto cleanup;
    }

    if (proxy.regions[VFIO_PCI_CONFIG_REGION_INDEX].size == 0) {
        vfu_log(vfu_ctx, LOG_ERR, "%s: no config region", opts.bdf);
        ret = -1;
        goto cleanup;
    }

    ret = vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_CONVENTIONAL,
                       PCI_HEADER_TYPE_NORMAL, 0);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_pci_init: %m");
        goto cleanup;
    }

    ret = setup_pci_id(vfu_ctx);
    if (ret < 0) {
        goto cleanup;
    }

    setup_bars(vfu_ctx);

    ret = setup_device(vfu_ctx, opts.no_rom);
    if (ret < 0) {
        goto cleanup;
    }

    if (proxy.intx_eventfd >= 0) {
        vfu_log(vfu_ctx, LOG_DEBUG, "starting IRQ forwarding thread");
        proxy.irq_thread_running = true;
        /*
         * Use a separate thread instead of the non-blocking mode
         * simply because it does the job and we don't (currently) need the extra complexity.
         */
        ret = pthread_create(&proxy.irq_thread, NULL, irq_thread_fn, &proxy);
        if (ret != 0) {
            proxy.irq_thread_running = false;
            errno = ret;
            vfu_log(vfu_ctx, LOG_ERR, "pthread_create: %m");
            goto cleanup;
        }
    }

    vfu_log(vfu_ctx, LOG_INFO, "serving %s on %s", opts.bdf, opts.sock_path);

    ret = proxy_run(vfu_ctx);
    vfu_log(vfu_ctx, LOG_DEBUG, "main loop exited (ret=%d)", ret);

cleanup:
    if (proxy.irq_thread_running) {
        proxy.irq_thread_running = false;
        if (vfu_ctx != NULL) {
            vfu_log(vfu_ctx, LOG_DEBUG, "stopping IRQ thread");
        }
        pthread_cancel(proxy.irq_thread);
        pthread_join(proxy.irq_thread, NULL);
    }
    if (proxy.intx_eventfd >= 0)
        close(proxy.intx_eventfd);

    vfu_log(vfu_ctx, LOG_DEBUG, "cleaning up vfu context");
    vfu_destroy_ctx(vfu_ctx);

    close_safely(&proxy.device_fd);
    close_safely(&proxy.group_fd);
    close_safely(&proxy.container_fd);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
