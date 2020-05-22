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
#include <linux/vfio.h>
#include <sys/param.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "../kmod/muser.h"
#include "muser.h"
#include "muser_priv.h"
#include "dma.h"
#include "cap.h"

#define IOMMU_GRP_NAME "iommu_group"

typedef enum {
    IRQ_NONE = 0,
    IRQ_INTX,
    IRQ_MSI,
    IRQ_MSIX,
} irq_type_t;

typedef struct {
    irq_type_t  type;       /* irq type this device is using */
    int         err_efd;    /* eventfd for irq err */
    int         req_efd;    /* eventfd for irq req */
    uint32_t    max_ivs;    /* maximum number of ivs supported */
    int         efds[0];    /* XXX must be last */
} lm_irqs_t;

/*
 * Macro that ensures that a particular struct member is last. Doesn't work for
 * flexible array members.
 */
#define MUST_BE_LAST(s, m, t) \
    _Static_assert(sizeof(s) - offsetof(s, m) == sizeof(t), \
        #t " " #m " must be last member in " #s)

struct lm_ctx {
    void                    *pvt;
    dma_controller_t        *dma;
    int                     fd;
    int (*reset)            (void *pvt);
    lm_log_lvl_t            log_lvl;
    lm_log_fn_t             *log;
    lm_pci_info_t           pci_info;
    lm_pci_config_space_t   *pci_config_space;
    lm_trans_t              trans;
    struct caps             *caps;
    
    /* LM_TRANS_SOCK */
    char                    *iommu_dir;
    int                     iommu_dir_fd;

    lm_irqs_t               irqs; /* XXX must be last */
} __attribute__((packed)); /* FIXME packed required to make below macro work */
MUST_BE_LAST(struct lm_ctx, irqs, lm_irqs_t);


/* function prototypes */
static int
muser_dma_map(lm_ctx_t*, struct muser_cmd*);

static int
muser_dma_unmap(lm_ctx_t*, struct muser_cmd*);

static void
free_sparse_mmap_areas(lm_reg_info_t*);

static int
dev_detach(int dev_fd)
{
    int ret = 0;

    if (dev_fd != -1) {
        ret = close(dev_fd);
    }
    return ret;
}

static int
dev_attach(lm_ctx_t *lm_ctx __attribute__((unused)), const char *uuid)
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

static int
get_request_kernel(int fd, struct muser_cmd *cmd)
{
    return ioctl(fd, MUSER_DEV_CMD_WAIT, &cmd);
}

static int
send_response_kernel(int fd, struct muser_cmd *cmd)
{
    return ioctl(fd, MUSER_DEV_CMD_DONE, &cmd);
}

/**
 * lm_ctx: libmuser context
 * iommu_dir: full path to the IOMMU group to create. All parent directories must
 *            already exist.
 */
static int
open_sock(lm_ctx_t *lm_ctx, const char *iommu_dir)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int ret, fd;
    unsigned long iommu_grp;
    char *endptr;
    mode_t mode;

    assert(lm_ctx != NULL);
    assert(iommu_dir != NULL);

    /* FIXME implement clean up in error case */

    /*
     * Validate that IOMMU group is a number. Maybe it's not necessary for us
     * to do so.
     */
    iommu_grp = strtoul(basename(iommu_dir), &endptr, 10);
    if (*endptr != '\0' || (iommu_grp == ULONG_MAX && errno == ERANGE)) {
        errno = EINVAL;
        return -1;
    }

    lm_ctx->iommu_dir = strdup(iommu_dir);
    if (!lm_ctx->iommu_dir) {
        return -1;
    }

    /* FIXME SPDK can't easily run as non-root */
    mode =  umask(0000);

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return fd;
    }

    if ((lm_ctx->iommu_dir_fd = open(lm_ctx->iommu_dir, O_DIRECTORY)) == -1) {
        return -1;
    }

    /* TODO this could be done by the control stack */
    /* crealte symlink /dev/vfio/<IOMMU group>/iommu_group -> ../<IOMMU group> */
    if ((ret = symlinkat(lm_ctx->iommu_dir, lm_ctx->iommu_dir_fd, IOMMU_GRP_NAME)) == -1) {
        return -1;
    }

    /* create control socket */
    if ((ret = openat(lm_ctx->iommu_dir_fd, MUSER_SOCK, O_WRONLY | O_CREAT, 0666)) == -1) {
        return -1;
    }

    ret = snprintf(addr.sun_path, sizeof addr.sun_path, "%s/" MUSER_SOCK, lm_ctx->iommu_dir);
    if (ret >= (int)sizeof addr.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (ret < 0) {
        return ret;
    }

    /* start listening business */
    if ((ret = unlink(addr.sun_path)) == -1 && errno != ENOENT) {
        return -1;
    }
    if ((ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr))) == -1) {
        return ret;
    }
    if ((ret = listen(fd, 0)) == -1) {
        return ret;
    }

    umask(mode);
    
    return accept(fd, NULL, NULL);
}

static int
get_request_sock(int fd, struct muser_cmd *cmd)
{
    return read(fd, cmd, sizeof *cmd);
}

static int
send_response_sock(int fd, struct muser_cmd *cmd)
{
    return write(fd, cmd, sizeof *cmd);
}

static void
get_path_from_fd(int fd, char *buf)
{
    int err;
    ssize_t ret;
    char pathname[PATH_MAX];

    err = snprintf(pathname, PATH_MAX, "/proc/self/fd/%d", fd);
    if (err >= PATH_MAX || err == -1) {
        buf[0] = '\0';
    }
    ret = readlink(pathname, buf, PATH_MAX);
    if (ret == -1) {
        ret = 0;
    } else if (ret == PATH_MAX) {
        ret -= 1;
    }
    buf[ret] = '\0';
}

ssize_t recv_fds_sock(int fd, void *buf, size_t size)
{
    ssize_t ret = muser_recv_fds(fd, buf, size / sizeof(int));
    if (ret < 0) {
	    return ret;
    }
    return ret * sizeof(int);
}

static struct transport_ops {
    int (*attach)(lm_ctx_t*, const char*);
    int(*detach)(int fd);
    int (*get_request)(int fd, struct muser_cmd*);
    int (*send_response)(int fd, struct muser_cmd*);
    ssize_t (*recv_fds)(int fd, void *buf, size_t size);
} transports_ops[] = {
    [LM_TRANS_KERNEL] = {
        .attach = dev_attach,
        .detach = dev_detach,
        .recv_fds = read,
        .get_request = get_request_kernel,
        .send_response = send_response_kernel
    },
    [LM_TRANS_SOCK] = {
        .attach = open_sock,
        .detach = close,
        .recv_fds = recv_fds_sock,
        .get_request = get_request_sock,
        .send_response = send_response_sock
    }
};

#define LM2VFIO_IRQT(type) (type - 1)

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
    lm_ctx->log(lm_ctx->pvt, buf);
    errno = _errno;
}

static const char *
vfio_irq_idx_to_str(int index) {
    static const char *s[] = {
        [VFIO_PCI_INTX_IRQ_INDEX] = "INTx",
        [VFIO_PCI_MSI_IRQ_INDEX]  = "MSI",
        [VFIO_PCI_MSIX_IRQ_INDEX] = "MSI-X",
    };

    assert(index < LM_DEV_NUM_IRQS);

    return s[index];
}

static long
irqs_disable(lm_ctx_t *lm_ctx, uint32_t index)
{
    int *irq_efd = NULL;
    uint32_t i;

    assert(lm_ctx != NULL);
    assert(index < LM_DEV_NUM_IRQS);

    switch (index) {
    case VFIO_PCI_INTX_IRQ_INDEX:
    case VFIO_PCI_MSI_IRQ_INDEX:
    case VFIO_PCI_MSIX_IRQ_INDEX:
        lm_log(lm_ctx, LM_DBG, "disabling IRQ %s\n", vfio_irq_idx_to_str(index));
        lm_ctx->irqs.type = IRQ_NONE;
        for (i = 0; i < lm_ctx->irqs.max_ivs; i++) {
            if (lm_ctx->irqs.efds[i] >= 0) {
                if (close(lm_ctx->irqs.efds[i]) == -1) {
                    lm_log(lm_ctx, LM_DBG, "failed to close IRQ fd %d: %m\n",
                           lm_ctx->irqs.efds[i]);
                }
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
        if (*irq_efd != -1) {
            if (close(*irq_efd) == -1) {
                lm_log(lm_ctx, LM_DBG, "failed to close IRQ fd %d: %m\n",
                       *irq_efd);
            }
            *irq_efd = -1;
        }
        return 0;
    }

    lm_log(lm_ctx, LM_DBG, "failed to disable IRQs\n");
    return -EINVAL;
}

static int
irqs_set_data_none(lm_ctx_t *lm_ctx, struct vfio_irq_set *irq_set)
{
    int efd;
    __u32 i;
    long ret;
    eventfd_t val;

    for (i = irq_set->start; i < (irq_set->start + irq_set->count); i++) {
        efd = lm_ctx->irqs.efds[i];
        if (efd >= 0) {
            val = 1;
            ret = eventfd_write(efd, val);
            if (ret == -1) {
                lm_log(lm_ctx, LM_DBG, "IRQ: failed to set data to none: %m\n");
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
    int efd;
    __u32 i;
    long ret;
    eventfd_t val;

    assert(data != NULL);

    for (i = irq_set->start, d8 = data; i < (irq_set->start + irq_set->count);
         i++, d8++) {
        efd = lm_ctx->irqs.efds[i];
        if (efd >= 0 && *d8 == 1) {
            val = 1;
            ret = eventfd_write(efd, val);
            if (ret == -1) {
                lm_log(lm_ctx, LM_DBG, "IRQ: failed to set data to bool: %m\n");
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
    int efd;
    __u32 i;

    assert(data != NULL);
    for (i = irq_set->start, d32 = data; i < (irq_set->start + irq_set->count);
         i++, d32++) {
        efd = lm_ctx->irqs.efds[i];
        if (efd >= 0) {
            if (close(efd) == -1) {
                lm_log(lm_ctx, LM_DBG, "failed to close IRQ fd %d: %m\n", efd);
            }

            lm_ctx->irqs.efds[i] = -1;
        }
        if (*d32 >= 0) {
            lm_ctx->irqs.efds[i] = *d32;
        }
        lm_log(lm_ctx, LM_DBG, "event fd[%d]=%d\n", i, lm_ctx->irqs.efds[i]);
    }

    return 0;
}

static long
irqs_trigger(lm_ctx_t *lm_ctx, struct vfio_irq_set *irq_set, void *data)
{
    int err = 0;

    assert(lm_ctx != NULL);
    assert(irq_set != NULL);

    if (irq_set->count == 0) {
        return irqs_disable(lm_ctx, irq_set->index);
    }

    lm_log(lm_ctx, LM_DBG, "setting IRQ %s flags=0x%x\n",
           vfio_irq_idx_to_str(irq_set->index), irq_set->flags);

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
        lm_log(lm_ctx, LM_DBG, "bad IRQ index %d\n", irq_set->index);
        return -EINVAL;
    }

    /* TODO make each condition a function */

    // Only one of MASK/UNMASK/TRIGGER is valid.
    if ((a_type != VFIO_IRQ_SET_ACTION_MASK) &&
        (a_type != VFIO_IRQ_SET_ACTION_UNMASK) &&
        (a_type != VFIO_IRQ_SET_ACTION_TRIGGER)) {
        lm_log(lm_ctx, LM_DBG, "bad IRQ action mask %d\n", a_type);
        return -EINVAL;
    }
    // Only one of NONE/BOOL/EVENTFD is valid.
    if ((d_type != VFIO_IRQ_SET_DATA_NONE) &&
        (d_type != VFIO_IRQ_SET_DATA_BOOL) &&
        (d_type != VFIO_IRQ_SET_DATA_EVENTFD)) {
        lm_log(lm_ctx, LM_DBG, "bad IRQ data %d\n", d_type);
        return -EINVAL;
    }
    // Ensure irq_set's start and count are within bounds.
    if ((irq_set->start >= pci_info->irq_count[irq_set->index]) ||
        (irq_set->start + irq_set->count > pci_info->irq_count[irq_set->index])) {
        lm_log(lm_ctx, LM_DBG, "bad IRQ start/count\n");
        return -EINVAL;
    }
    // Only TRIGGER is valid for ERR/REQ.
    if (((irq_set->index == VFIO_PCI_ERR_IRQ_INDEX) ||
         (irq_set->index == VFIO_PCI_REQ_IRQ_INDEX)) &&
        (a_type != VFIO_IRQ_SET_ACTION_TRIGGER)) {
        lm_log(lm_ctx, LM_DBG, "bad IRQ trigger w/o ERR/REQ\n");
        return -EINVAL;
    }
    // count == 0 is only valid with ACTION_TRIGGER and DATA_NONE.
    if ((irq_set->count == 0) && ((a_type != VFIO_IRQ_SET_ACTION_TRIGGER) ||
                                  (d_type != VFIO_IRQ_SET_DATA_NONE))) {
        lm_log(lm_ctx, LM_DBG, "bad IRQ count %d\n");
        return -EINVAL;
    }
    // If IRQs are set, ensure index matches what's enabled for the device.
    if ((irq_set->count != 0) && (lm_ctx->irqs.type != IRQ_NONE) &&
        (irq_set->index != LM2VFIO_IRQT(lm_ctx->irqs.type))) {
        lm_log(lm_ctx, LM_DBG, "bad IRQ index\n");
        return -EINVAL;
    }

    return 0;
}

static long
dev_set_irqs(lm_ctx_t *lm_ctx, struct vfio_irq_set *irq_set, void *data)
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

static long
dev_get_irqinfo(lm_ctx_t *lm_ctx, struct vfio_irq_info *irq_info)
{
    assert(lm_ctx != NULL);
    assert(irq_info != NULL);
    lm_pci_info_t *pci_info = &lm_ctx->pci_info;

    // Ensure provided argsz is sufficiently big and index is within bounds.
    if ((irq_info->argsz < sizeof(struct vfio_irq_info)) ||
        (irq_info->index >= LM_DEV_NUM_IRQS)) {
        lm_log(lm_ctx, LM_DBG, "bad irq_info (size=%d index=%d)\n",
               irq_info->argsz, irq_info->index);
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

    if (lm_reg->mmap_areas == NULL) {
        lm_log(lm_ctx, LM_DBG, "bad mmap_areas\n");
        return -EINVAL;
    }

    nr_mmap_areas = lm_reg->mmap_areas->nr_mmap_areas;
    size = sizeof(*sparse) + (nr_mmap_areas * sizeof(*sparse->areas));

    /*
     * If vfio_reg does not have enough space to accommodate  sparse info then
     * set the argsz with the expected size and return. Vfio client will call
     * back after reallocating the vfio_reg
     */

    if (vfio_reg->argsz < size + sizeof(*vfio_reg)) {
        lm_log(lm_ctx, LM_DBG, "vfio_reg too small=%d\n", vfio_reg->argsz);
        vfio_reg->argsz = size + sizeof(*vfio_reg);
        vfio_reg->cap_offset = 0;
        return 0;
    }

    lm_log(lm_ctx, LM_DBG, "%s: size %llu, nr_mmap_areas %u\n", __func__, size,
           nr_mmap_areas);
    sparse = calloc(1, size);
    if (sparse == NULL)
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
    if (ret != (ssize_t)size) {
        free(sparse);
        return -EIO;
    }

    vfio_reg->flags |= VFIO_REGION_INFO_FLAG_MMAP | VFIO_REGION_INFO_FLAG_CAPS;
    vfio_reg->cap_offset = sizeof(*vfio_reg);

    free(sparse);
    return 0;
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

static long
dev_get_reginfo(lm_ctx_t *lm_ctx, struct vfio_region_info *vfio_reg)
{
    lm_reg_info_t *lm_reg;
    int err;

    assert(lm_ctx != NULL);
    assert(vfio_reg != NULL);
    lm_reg = &lm_ctx->pci_info.reg_info[vfio_reg->index];

    // Ensure provided argsz is sufficiently big and index is within bounds.
    if ((vfio_reg->argsz < sizeof(struct vfio_region_info)) ||
        (vfio_reg->index >= LM_DEV_NUM_REGS)) {
        lm_log(lm_ctx, LM_DBG, "bad args argsz=%d index=%d\n", vfio_reg->argsz,
               vfio_reg->index);
        return -EINVAL;
    }

    vfio_reg->offset = region_to_offset(vfio_reg->index);
    vfio_reg->flags = lm_reg->flags;
    vfio_reg->size = lm_reg->size;

    if (lm_reg->mmap_areas != NULL) {
        err = dev_get_sparse_mmap_cap(lm_ctx, lm_reg, vfio_reg);
        if (err) {
            return err;
        }
    }

    lm_log(lm_ctx, LM_DBG, "region_info[%d]\n", vfio_reg->index);
    dump_buffer(lm_ctx, "", (char*)vfio_reg, sizeof *vfio_reg);

    return 0;
}

static long
dev_get_info(struct vfio_device_info *dev_info)
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
do_muser_ioctl(lm_ctx_t *lm_ctx, struct muser_cmd_ioctl *cmd_ioctl, void *data)
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
        if (lm_ctx->reset != NULL) {
            return lm_ctx->reset(lm_ctx->pvt);
        }
        lm_log(lm_ctx, LM_DBG, "reset called but not reset function present\n");
        err = 0;
        break;
    case VFIO_GROUP_GET_STATUS:
        cmd_ioctl->data.group_status.flags = VFIO_GROUP_FLAGS_VIABLE;
        err = 0;
        break;
    case VFIO_GET_API_VERSION:
        cmd_ioctl->data.vfio_api_version = VFIO_API_VERSION;
        err = 0;
        break;
    case VFIO_CHECK_EXTENSION:
        if (cmd_ioctl->data.vfio_extension == VFIO_TYPE1v2_IOMMU) {
            err = 0;
        }
        break;
    case VFIO_IOMMU_GET_INFO:
        cmd_ioctl->data.iommu_type1_info.flags = VFIO_IOMMU_INFO_PGSIZES;
        cmd_ioctl->data.iommu_type1_info.iova_pgsizes = sysconf(_SC_PAGESIZE);
        err = 0;
        break;
    case VFIO_IOMMU_MAP_DMA:
        {
            struct muser_cmd muser_cmd = {
                .type = MUSER_DMA_MMAP,
                .mmap.request.fd = *((int*)data),
                .mmap.request.addr = cmd_ioctl->data.dma_map.iova,
                .mmap.request.len = cmd_ioctl->data.dma_map.size,
                .mmap.request.offset = cmd_ioctl->data.dma_map.vaddr
            };
            err = muser_dma_map(lm_ctx, &muser_cmd);
        }
        break;
    case VFIO_IOMMU_UNMAP_DMA:
        {
            struct muser_cmd muser_cmd = {
                .type = MUSER_DMA_MUNMAP,
                .mmap.request.addr = cmd_ioctl->data.dma_unmap.iova,
                .mmap.request.len = cmd_ioctl->data.dma_unmap.size
            };
            err = muser_dma_unmap(lm_ctx, &muser_cmd);
        }
        break;
        /* FIXME */
    case VFIO_GROUP_SET_CONTAINER:
    case VFIO_GROUP_UNSET_CONTAINER:
    case VFIO_SET_IOMMU:
        err = 0;
        break;
    default:
        lm_log(lm_ctx, LM_ERR, "bad comamnd %d", cmd_ioctl->vfio_cmd);
    }

    return err;
}

static int
muser_dma_unmap(lm_ctx_t *lm_ctx, struct muser_cmd *cmd)
{
    int err;

    lm_log(lm_ctx, LM_INF, "removing DMA region iova=%#lx-%#lx\n",
           cmd->mmap.request.addr,
           cmd->mmap.request.addr + cmd->mmap.request.len);

    if (lm_ctx->dma == NULL) {
        lm_log(lm_ctx, LM_ERR, "DMA not initialized\n");
        return -EINVAL;
    }

    err = dma_controller_remove_region(lm_ctx, lm_ctx->dma,
                                       cmd->mmap.request.addr,
                                       cmd->mmap.request.len);
    if (err != 0 && err != -ENOENT) {
        lm_log(lm_ctx, LM_ERR, "failed to remove DMA region %#lx-%#lx: %s\n",
               cmd->mmap.request.addr,
               cmd->mmap.request.addr + cmd->mmap.request.len,
               strerror(-err));
    }

    return err;
}

static int
muser_dma_map(lm_ctx_t *lm_ctx, struct muser_cmd *cmd)
{
    int err;
    char buf[PATH_MAX];

    get_path_from_fd(cmd->mmap.request.fd, buf);

    lm_log(lm_ctx, LM_INF, "adding DMA region fd=%d path=%s iova=%#lx-%#lx offset=%#lx\n",
           cmd->mmap.request.fd, buf, cmd->mmap.request.addr,
           cmd->mmap.request.addr + cmd->mmap.request.len,
           cmd->mmap.request.offset);

    if (lm_ctx->dma == NULL) {
        lm_log(lm_ctx, LM_ERR, "DMA not initialized\n");
        return -EINVAL;
    }

    err = dma_controller_add_region(lm_ctx, lm_ctx->dma,
                                    cmd->mmap.request.addr,
                                    cmd->mmap.request.len,
                                    cmd->mmap.request.fd,
                                    cmd->mmap.request.offset);
    if (err < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to add DMA region fd=%d path=%s %#lx-%#lx: %d\n",
               cmd->mmap.request.fd, buf, cmd->mmap.request.addr,
               cmd->mmap.request.addr + cmd->mmap.request.len, err);
    } else {
        err = 0;
    }

    return err;
}

int
muser_send_fds(int sock, int *fds, size_t count) {
	struct msghdr msg = { 0 };
	size_t size = count * sizeof *fds;
	char buf[CMSG_SPACE(size)];
	memset(buf, '\0', sizeof(buf));

	/* XXX requires at least one byte */
	struct iovec io = { .iov_base = "\0", .iov_len = 1 };

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(size);
	memcpy(CMSG_DATA(cmsg), fds, size);
	msg.msg_controllen = CMSG_SPACE(size);
	return sendmsg(sock, &msg, 0);
}

ssize_t
muser_recv_fds(int sock, int *fds, size_t count)
{
    int ret;
    struct cmsghdr *cmsg;
    size_t fds_size;
    char msg_buf[sysconf(_SC_PAGESIZE)];
    struct iovec io = {.iov_base = msg_buf, .iov_len = sizeof(msg_buf)};
    char cmsg_buf[sysconf(_SC_PAGESIZE)];
    struct msghdr msg = {
        .msg_iov = &io,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf)
    };

    if (fds == NULL || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        return ret;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL) {
        errno = EINVAL;
        return -1;
    }
    fds_size = cmsg->cmsg_len - sizeof *cmsg;
    if ((fds_size % sizeof(int)) != 0 || fds_size / sizeof (int) > count) {
        errno = EINVAL;
        return -1;
    }
    memcpy((void*)fds, CMSG_DATA(cmsg), cmsg->cmsg_len - sizeof *cmsg);

    return fds_size / sizeof(int);
}

/*
 * Callback that is executed when device memory is to be mmap'd.
 *
 * TODO vfio-over-socket: each PCI region can be sparsely memory mapped, so
 * there can be multiple mapped regions per PCI region. We need to make these
 * mapped regions persistent. One way would be to store each sparse region as
 * an individual file named after the memory range, e.g.
 * /dev/shm/muser/<UUID>/<region>/<offset>-<length> (the <region> can be <bar0>,
 * <rom> etc.).
 *
 * Another way would be to create one file per PCI region and then
 * tell libvfio which offset of each file corresponds to each region. The
 * mapping between sparse regions and file offsets can be 1:1, so there can be
 * large gaps in file which should be fine since it will be sparsely allocated.
 * Alternatively, each sparse region can be put right next to each other so
 * we'll need some kind of translation.
 *
 * However this functionality is implemented, it must be provided by libmuser.
 * For now we don't do anything (except for receiving the file descriptors)
 * and leave it to the device implementation to handle.
 */
static int
muser_mmap(lm_ctx_t *lm_ctx, struct muser_cmd *cmd)
{
    int region, err = 0;
    unsigned long addr;
    unsigned long len = cmd->mmap.request.len;
    loff_t offset = cmd->mmap.request.addr;

    region = lm_get_region(offset, len, &offset);
    if (region < 0) {
        lm_log(lm_ctx, LM_ERR, "bad region %d\n", region);
        err = EINVAL;
        goto out;
    }

    if (lm_ctx->pci_info.reg_info[region].map == NULL) {
        lm_log(lm_ctx, LM_ERR, "region not mmapable\n");
        err = ENOTSUP;
        goto out;
    }

    addr = lm_ctx->pci_info.reg_info[region].map(lm_ctx->pvt, offset, len);
    if ((void *)addr == MAP_FAILED) {
        err = errno;
        lm_log(lm_ctx, LM_ERR, "failed to mmap: %m\n");
        goto out;
    }
    cmd->mmap.response = addr;

    /* FIXME */
    if (lm_ctx->trans == LM_TRANS_SOCK) {
        err = muser_send_fds(lm_ctx->fd, (int*)&addr, 1);
	    if (err == -1) {
		    lm_log(lm_ctx, LM_ERR, "failed to send fd=%d: %d, %m\n",
                   *((int*)&addr), err);
        }
	    err = 0;
    }

out:
    if (err != 0) {
        lm_log(lm_ctx, LM_ERR, "failed to mmap device memory %#x-%#lx: %s\n",
               offset, offset + len, strerror(err));
    }

    return -err;
}

/*
 * Returns the number of bytes communicated to the kernel (may be less than
 * ret), or a negative number on error.
 */
static int
post_read(lm_ctx_t *lm_ctx, char *rwbuf, ssize_t count)
{
    ssize_t ret;

    ret = write(lm_ctx->fd, rwbuf, count);
    if (ret != count) {
        lm_log(lm_ctx, LM_ERR, "%s: bad muser write: %lu/%lu, %s\n",
               __func__, ret, count, strerror(errno));
    }

    return ret;
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
        return lm_ctx->pci_info.reg_info[region].size;
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
    ret = cap_maybe_access(lm_ctx->caps, lm_ctx->pvt, buf, count, pos, is_write);
    if (ret < 0) {
        lm_log(lm_ctx, LM_ERR, "bad access to capabilities %u@%#x\n", count,
               pos);
        return ret;
    }
    return count;
}

static ssize_t
do_access(lm_ctx_t *lm_ctx, char *buf, size_t count, loff_t pos, bool is_write)
{
    int idx;
    loff_t offset;
    lm_pci_info_t *pci_info;

    assert(lm_ctx != NULL);
    assert(buf != NULL);
    assert(count > 0);

    pci_info = &lm_ctx->pci_info;
    idx = lm_get_region(pos, count, &offset);
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
                                              is_write);
    }

    /*
     * Checking whether a callback exists might sound expensive however this
     * code is not performance critical. This works well when we don't expect a
     * region to be used, so the user of the library can simply leave the
     * callback NULL in lm_ctx_create.
     */
    if (pci_info->reg_info[idx].fn != NULL) {
        return pci_info->reg_info[idx].fn(lm_ctx->pvt, buf, count, offset,
                                          is_write);
    }

    lm_log(lm_ctx, LM_ERR, "no callback for region %d\n", idx);

    return -EINVAL;
}

/*
 * Returns the number of bytes processed on success or a negative number on
 * error.
 *
 * TODO function name same lm_access_t, fix
 */
ssize_t
lm_access(lm_ctx_t *lm_ctx, char *buf, size_t count, loff_t *ppos,
          bool is_write)
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
            /*
             * TODO if ret < 0 then it might contain a legitimate error code, why replace it with EFAULT?
             */
            return -EFAULT;
        }
        if (ret != (int)size) {
            lm_log(lm_ctx, LM_DBG, "bad read %d != %d\n", ret, size);
        }
        count -= size;
        done += size;
        *ppos += size;
        buf += size;
    }
    return done;
}

static inline int
muser_access(lm_ctx_t *lm_ctx, struct muser_cmd *cmd, bool is_write)
{
    char *rwbuf;
    int err;
    size_t count = 0, _count;
    ssize_t ret;

    /* TODO how big do we expect count to be? Can we use alloca(3) instead? */
    rwbuf = calloc(1, cmd->rw.count);
    if (rwbuf == NULL) {
        lm_log(lm_ctx, LM_ERR, "failed to allocate memory\n");
        return -1;
    }

    lm_log(lm_ctx, LM_DBG, "%s %#lx-%#lx\n", is_write ? "W" : "R", cmd->rw.pos,
           cmd->rw.pos + cmd->rw.count);

    /* copy data to be written from kernel to user space */
    if (is_write) {
        err = read(lm_ctx->fd, rwbuf, cmd->rw.count);
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
#ifndef LM_TERSE_LOGGING
        dump_buffer(lm_ctx, "buffer write", rwbuf, cmd->rw.count);
#endif
    }

    count = _count = cmd->rw.count;
    cmd->err = muser_pci_hdr_access(lm_ctx, &_count, &cmd->rw.pos,
                                    is_write, rwbuf);
    if (cmd->err) {
        lm_log(lm_ctx, LM_ERR, "failed to access PCI header: %s\n",
               strerror(-cmd->err));
#ifndef LM_TERSE_LOGGING
        dump_buffer(lm_ctx, "buffer write", rwbuf, _count);
#endif
    }

    /*
     * count is how much has been processed by muser_pci_hdr_access,
     * _count is how much there's left to be processed by lm_access
     */
    count -= _count;
    ret = lm_access(lm_ctx, rwbuf + count, _count, &cmd->rw.pos,
                    is_write);
    if (!is_write && ret >= 0) {
        ret += count;
        err = post_read(lm_ctx, rwbuf, ret);
        if (!LM_TERSE_LOGGING && err == ret) {
            dump_buffer(lm_ctx, "buffer read", rwbuf, ret);
        }
    }

out:
    free(rwbuf);

    return err;
}

static int
muser_ioctl(lm_ctx_t *lm_ctx, struct muser_cmd *cmd)
{
    void *data = NULL;
    size_t size = 0;
    int ret;
    uint32_t flags;

    /* TODO make this a function that returns the size */
    switch (cmd->ioctl.vfio_cmd) {
    case VFIO_DEVICE_SET_IRQS:
        flags = cmd->ioctl.data.irq_set.flags;
        switch ((flags & VFIO_IRQ_SET_DATA_TYPE_MASK)) {
        case VFIO_IRQ_SET_DATA_EVENTFD:
            size = sizeof(int32_t) * cmd->ioctl.data.irq_set.count;
            break;
        case VFIO_IRQ_SET_DATA_BOOL:
            size = sizeof(uint8_t) * cmd->ioctl.data.irq_set.count;
            break;
        }
        break;
    case VFIO_IOMMU_MAP_DMA:
        size = sizeof(int);
        break;
    }

    if (size != 0) {
        data = calloc(1, size); /* TODO use alloca */
        if (data == NULL) {
#ifdef DEBUG
            perror("calloc");
#endif
            return -1;
        }
        ret = transports_ops[lm_ctx->trans].recv_fds(lm_ctx->fd, data, size);
        if (ret < 0) {
            goto out;
        }
        if (ret != (int)size) {
            lm_log(lm_ctx, LM_ERR, "short read for fds\n");
            return -EINVAL;
        }
    }

    ret = (int)do_muser_ioctl(lm_ctx, &cmd->ioctl, data);

out:

    free(data);
    return ret;
}

static int
drive_loop(lm_ctx_t *lm_ctx)
{
    struct muser_cmd cmd = { 0 };
    int err;

    do {
        err = transports_ops[lm_ctx->trans].get_request(lm_ctx->fd, &cmd);
        if (err < 0) {
            lm_log(lm_ctx, LM_ERR, "failed to receive request: %m\n");
            return err;
        }
        if (err == 0) {
            lm_log(lm_ctx, LM_INF, "end of file: %m\n");
            break;
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
            /*
             * TODO should respond with something here instead of ignoring the
             * command.
             */
            err = -EINVAL;
        }
        cmd.err = err;
        err = transports_ops[lm_ctx->trans].send_response(lm_ctx->fd, &cmd);
        if (err < 0) {
            lm_log(lm_ctx, LM_ERR, "failed to complete command: %s\n",
                   strerror(errno));
        }
        // TODO: Figure out a clean way to get out of the loop.
    } while (1);

    return err;
}

int
lm_ctx_drive(lm_ctx_t *lm_ctx)
{
    if (lm_ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    return drive_loop(lm_ctx);
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

int
lm_irq_trigger(lm_ctx_t *lm_ctx, uint32_t vector)
{
    eventfd_t val = 1;

    if ((lm_ctx == NULL) || (vector >= lm_ctx->irqs.max_ivs)) {
        lm_log(lm_ctx, LM_ERR, "bad IRQ %d, max=%d\n", vector,
               lm_ctx->irqs.max_ivs);
        errno = EINVAL;
        return -1;
    }

    if (lm_ctx->irqs.efds[vector] == -1) {
        lm_log(lm_ctx, LM_ERR, "no fd for interrupt %d\n", vector);
        errno = ENOENT;
        return -1;
    }

    if (vector == LM_DEV_INTX_IRQ_IDX && !lm_ctx->pci_config_space->hdr.cmd.id) {
        lm_log(lm_ctx, LM_ERR, "failed to trigger INTx IRQ, INTx disabled\n");
        errno = EINVAL;
        return -1;
    } else if (vector == LM_DEV_MSIX_IRQ_IDX) {
        /*
         * FIXME must check that MSI-X capability exists during creation time
         * FIXME need to check that MSI-X is enabled and that it's not masked.
         * Currently that's not possible because libmuser doesn't care about
         * the internals of a capability.
         */
    }

    return eventfd_write(lm_ctx->irqs.efds[vector], val);
}

void
lm_ctx_destroy(lm_ctx_t *lm_ctx)
{
    if (lm_ctx == NULL) {
        return;
    }

    /*
     * FIXME The following cleanup can be dangerous depending on how lm_ctx_destroy
     * is called since it might delete files it did not create. Improve by
     * acquiring a lock on the directory.
     */
    if (lm_ctx->trans == LM_TRANS_SOCK) {
        int ret;

        if (lm_ctx->iommu_dir_fd != -1) {
            if ((ret = unlinkat(lm_ctx->iommu_dir_fd, IOMMU_GRP_NAME, 0)) == -1 && errno != ENOENT) {
                lm_log(lm_ctx, LM_DBG, "failed to remove " IOMMU_GRP_NAME ": %m\n");
            }
            if ((ret = unlinkat(lm_ctx->iommu_dir_fd, MUSER_SOCK, 0)) == -1 && errno != ENOENT) {
                lm_log(lm_ctx, LM_DBG, "failed to remove " MUSER_SOCK ": %m\n");
            }
            if (close(lm_ctx->iommu_dir_fd) == -1) {
                lm_log(lm_ctx, LM_DBG, "failed to close IOMMU dir fd %d: %m\n",
                       lm_ctx->iommu_dir_fd);
            }
        }
        if (lm_ctx->iommu_dir != NULL) {
            if ((ret = rmdir(lm_ctx->iommu_dir)) == -1 && errno != ENOENT) {
                lm_log(lm_ctx, LM_DBG, "failed to remove %s: %m\n", lm_ctx->iommu_dir);
            }
            free(lm_ctx->iommu_dir);
        }
    }

    free(lm_ctx->pci_config_space);
    transports_ops[lm_ctx->trans].detach(lm_ctx->fd);
    if (lm_ctx->dma != NULL) {
        dma_controller_destroy(lm_ctx, lm_ctx->dma);
    }
    free_sparse_mmap_areas(lm_ctx->pci_info.reg_info);
    free(lm_ctx);
    // FIXME: Maybe close any open irq efds? Unmap stuff?
}

static int
copy_sparse_mmap_areas(lm_reg_info_t *dst, const lm_reg_info_t *src)
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

static void
free_sparse_mmap_areas(lm_reg_info_t *reg_info)
{
    int i;

    for (i = 0; i < LM_DEV_NUM_REGS; i++)
        free(reg_info[i].mmap_areas);
}

static int
pci_config_setup(lm_ctx_t *lm_ctx, const lm_dev_info_t *dev_info)
{
    lm_reg_info_t *cfg_reg;
    const lm_reg_info_t zero_reg = { 0 };
    int i;

    assert(lm_ctx != NULL);
    assert(dev_info != NULL);

    // Convenience pointer.
    cfg_reg = &lm_ctx->pci_info.reg_info[LM_DEV_CFG_REG_IDX];

    // Set a default config region if none provided.
    if (memcmp(cfg_reg, &zero_reg, sizeof(*cfg_reg)) == 0) {
        cfg_reg->flags = LM_REG_FLAG_RW;
        cfg_reg->size = PCI_CFG_SPACE_SIZE;
    } else {
        // Validate the config region provided.
        if ((cfg_reg->flags != LM_REG_FLAG_RW) ||
            ((cfg_reg->size != PCI_CFG_SPACE_SIZE) &&
             (cfg_reg->size != PCI_CFG_SPACE_EXP_SIZE))) {
            return EINVAL;
        }
    }

    // Allocate a buffer for the config space.
    lm_ctx->pci_config_space = calloc(1, cfg_reg->size);
    if (lm_ctx->pci_config_space == NULL) {
        return -1;
    }

    // Bounce misc PCI basic header data.
    lm_ctx->pci_config_space->hdr.id = dev_info->pci_info.id;
    lm_ctx->pci_config_space->hdr.cc = dev_info->pci_info.cc;
    lm_ctx->pci_config_space->hdr.ss = dev_info->pci_info.ss;

    // Reflect on the config space whether INTX is available.
    if (dev_info->pci_info.irq_count[LM_DEV_INTX_IRQ_IDX] != 0) {
        lm_ctx->pci_config_space->hdr.intr.ipin = 1; // INTA#
    }

    // Set type for region registers.
    for (i = 0; i < PCI_BARS_NR; i++) {
        if ((dev_info->pci_info.reg_info[i].flags & LM_REG_FLAG_MEM) == 0) {
            lm_ctx->pci_config_space->hdr.bars[i].io.region_type |= 0x1;
        }
    }

    // Initialise capabilities.
    if (dev_info->nr_caps > 0) {
        lm_ctx->caps = caps_create(dev_info->caps, dev_info->nr_caps);
        if (lm_ctx->caps == NULL) {
            lm_log(lm_ctx, LM_ERR, "failed to create PCI capabilities: %m\n");
            goto err;
        }

        lm_ctx->pci_config_space->hdr.sts.cl = 0x1;
        lm_ctx->pci_config_space->hdr.cap = PCI_STD_HEADER_SIZEOF;
    }

    return 0;

err:
    free(lm_ctx->pci_config_space);
    lm_ctx->pci_config_space = NULL;

    return -1;
}

lm_ctx_t *
lm_ctx_create(const lm_dev_info_t *dev_info)
{
    lm_ctx_t *lm_ctx = NULL;
    uint32_t max_ivs = 0;
    uint32_t i;
    int err = 0;
    size_t size = 0;

    if (dev_info == NULL) {
        errno = EINVAL;
        return NULL;
    }

    if (dev_info->trans < 0 || dev_info->trans >= LM_TRANS_MAX) {
            errno = EINVAL;
            return NULL;
    }

    /*
     * FIXME need to check that the number of MSI and MSI-X IRQs are valid
     * (1, 2, 4, 8, 16 or 32 for MSI and up to 2048 for MSI-X).
     */

    // Work out highest count of irq vectors.
    for (i = 0; i < LM_DEV_NUM_IRQS; i++) {
        if (max_ivs < dev_info->pci_info.irq_count[i]) {
            max_ivs = dev_info->pci_info.irq_count[i];
        }
    }

    // Allocate an lm_ctx with room for the irq vectors.
    size += sizeof(int) * max_ivs;
    lm_ctx = calloc(1, sizeof(lm_ctx_t) + size);
    if (lm_ctx == NULL) {
        return NULL;
    }
    lm_ctx->trans = dev_info->trans;

    lm_ctx->iommu_dir_fd = -1;

    // Set context irq information.
    for (i = 0; i < max_ivs; i++) {
        lm_ctx->irqs.efds[i] = -1;
    }
    lm_ctx->irqs.err_efd = -1;
    lm_ctx->irqs.req_efd = -1;
    lm_ctx->irqs.type = IRQ_NONE;
    lm_ctx->irqs.max_ivs = max_ivs;

    // Set other context data.
    lm_ctx->pvt = dev_info->pvt;
    lm_ctx->log = dev_info->log;
    lm_ctx->log_lvl = dev_info->log_lvl;
    lm_ctx->reset = dev_info->reset;

    // Bounce the provided pci_info into the context.
    memcpy(&lm_ctx->pci_info, &dev_info->pci_info, sizeof(lm_pci_info_t));

    // Setup the PCI config space for this context.
    err = pci_config_setup(lm_ctx, dev_info);
    if (err != 0) {
        goto out;
    }

    // Bounce info for the sparse mmap areas.
    err = copy_sparse_mmap_areas(lm_ctx->pci_info.reg_info,
                                 dev_info->pci_info.reg_info);
    if (err) {
        goto out;
    }

    // Attach to the muser control device.
    lm_ctx->fd = transports_ops[dev_info->trans].attach(lm_ctx, dev_info->uuid);
    if (lm_ctx->fd == -1) {
        err = errno;
        if (errno != EINTR) {
            lm_log(lm_ctx, LM_ERR, "failed to attach: %m\n");
        }
        goto out;
    }

    // Create the internal DMA controller.
    lm_ctx->dma = dma_controller_create(LM_DMA_REGIONS);
    if (lm_ctx->dma == NULL) {
        err = errno;
        goto out;
    }

out:
    if (err != 0) {
        if (lm_ctx != NULL) {
            lm_ctx_destroy(lm_ctx);
            lm_ctx = NULL;
        }
        errno = err;
    }

    return lm_ctx;
}

#ifdef DEBUG
static void
dump_buffer(lm_ctx_t *lm_ctx, const char *prefix,
            const char *buf, uint32_t count)
{
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
}
#else
#define dump_buffer(lm_ctx, prefix, buf, count)
#endif

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
    return lm_ctx->pci_info.reg_info;
}

inline int
lm_addr_to_sg(lm_ctx_t *lm_ctx, dma_addr_t dma_addr,
              uint32_t len, dma_sg_t *sg, int max_sg)
{
    return dma_addr_to_sg(lm_ctx->dma, dma_addr, len, sg, max_sg);
}

inline int
lm_map_sg(lm_ctx_t *lm_ctx, const dma_sg_t *sg,
	  struct iovec *iov, int cnt)
{
    return dma_map_sg(lm_ctx->dma, sg, iov, cnt);
}

inline void
lm_unmap_sg(lm_ctx_t *lm_ctx, const dma_sg_t *sg, struct iovec *iov, int cnt)
{
    return dma_unmap_sg(lm_ctx->dma, sg, iov, cnt);
}

int
lm_ctx_run(lm_dev_info_t *dev_info)
{
    int ret;

    lm_ctx_t *lm_ctx = lm_ctx_create(dev_info);
    if (lm_ctx == NULL) {
        return -1;
    }
    ret = lm_ctx_drive(lm_ctx);
    lm_ctx_destroy(lm_ctx);
    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
