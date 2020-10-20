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
#include <sys/select.h>

#include "../kmod/muser.h"
#include "muser.h"
#include "muser_priv.h"
#include "dma.h"
#include "cap.h"

#define MAX_FDS 8

#define IOMMU_GRP_NAME "iommu_group"

typedef enum {
    IRQ_NONE = 0,
    IRQ_INTX,
    IRQ_MSI,
    IRQ_MSIX,
} irq_type_t;

char *irq_to_str[] = {
    [LM_DEV_INTX_IRQ_IDX] = "INTx",
    [LM_DEV_MSI_IRQ_IDX] = "MSI",
    [LM_DEV_MSIX_IRQ_IDX] = "MSI-X",
    [LM_DEV_ERR_IRQ_INDEX] = "ERR",
    [LM_DEV_REQ_IRQ_INDEX] = "REQ"
};

typedef struct {
    irq_type_t  type;       /* irq type this device is using */
    int         err_efd;    /* eventfd for irq err */
    int         req_efd;    /* eventfd for irq req */
    uint32_t    max_ivs;    /* maximum number of ivs supported */
    int         efds[0];    /* XXX must be last */
} lm_irqs_t;

struct lm_ctx {
    void                    *pvt;
    dma_controller_t        *dma;
    int                     fd;
    int                     conn_fd;
    int (*reset)            (void *pvt);
    lm_log_lvl_t            log_lvl;
    lm_log_fn_t             *log;
    lm_pci_info_t           pci_info;
    lm_pci_config_space_t   *pci_config_space;
    lm_trans_t              trans;
    struct caps             *caps;
    uint64_t                flags;
    char                    *uuid;
    void (*map_dma)         (void *pvt, uint64_t iova, uint64_t len);
    int (*unmap_dma)        (void *pvt, uint64_t iova);

    /* TODO there should be a void * variable to store transport-specific stuff */
    /* LM_TRANS_SOCK */
    char                    *iommu_dir;
    int                     iommu_dir_fd;
    int                     sock_flags;

    int                     client_max_fds;

    lm_irqs_t               irqs; /* XXX must be last */
};


/* function prototypes */
static int
muser_dma_map(lm_ctx_t*, struct muser_cmd*);

static int
muser_dma_unmap(lm_ctx_t*, struct muser_cmd*);

static void
free_sparse_mmap_areas(lm_reg_info_t*);

static inline int recv_blocking(int sock, void *buf, size_t len, int flags)
{
    int f = fcntl(sock, F_GETFL, 0);
    int ret, fret;

    fret = fcntl(sock, F_SETFL, f & ~O_NONBLOCK);
    assert(fret != -1);

    ret = recv(sock, buf, len, flags);

    fret = fcntl(sock, F_SETFL, f);
    assert(fret != -1);

    return ret;
}

static int
dev_detach(lm_ctx_t *lm_ctx)
{
    int ret = 0;

    if (lm_ctx->fd != -1) {
        ret = close(lm_ctx->fd);
    }
    return ret;
}

static int
dev_attach(lm_ctx_t *lm_ctx)
{
    char *path;
    int dev_fd;
    int err;

    assert(lm_ctx != NULL);

    err = asprintf(&path, "/dev/" MUSER_DEVNODE "/%s", lm_ctx->uuid);
    if (err != (int)(strlen(MUSER_DEVNODE) + strlen(lm_ctx->uuid) + 6)) {
        return -1;
    }

    dev_fd = open(path, O_RDWR);

    free(path);

    return dev_fd;
}

static ssize_t
recv_fds_kernel(lm_ctx_t *lm_ctx, void *buf, size_t size)
{
    return read(lm_ctx->fd, buf, size);
}

static int
get_request_kernel(lm_ctx_t *lm_ctx, struct vfio_user_header *cmd,
                   int *fds __attribute__((unused)),
                   int *nr_fds __attribute__((unused)))
{
    assert(false);
    return ioctl(lm_ctx->fd, MUSER_DEV_CMD_WAIT, &cmd);
}

static int
init_sock(lm_ctx_t *lm_ctx)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int ret, unix_sock;
    unsigned long iommu_grp;
    char *endptr;
    mode_t mode;

    assert(lm_ctx != NULL);

    iommu_grp = strtoul(basename(lm_ctx->uuid), &endptr, 10);
    if (*endptr != '\0' || (iommu_grp == ULONG_MAX && errno == ERANGE)) {
        return -EINVAL;
    }

    lm_ctx->iommu_dir = strdup(lm_ctx->uuid);
    if (!lm_ctx->iommu_dir) {
        return -ENOMEM;
    }

    /* FIXME SPDK can't easily run as non-root */
    mode =  umask(0000);

    if ((unix_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	    ret = errno;
	    goto free_iommu_dir;
    }

    if (lm_ctx->flags & LM_FLAG_ATTACH_NB) {
        ret = fcntl(unix_sock, F_SETFL,
                    fcntl(unix_sock, F_GETFL, 0) | O_NONBLOCK);
        if (ret < 0) {
            ret = errno;
            goto close_unix_sock;
        }
        lm_ctx->sock_flags = MSG_DONTWAIT | MSG_WAITALL;
    } else {
        lm_ctx->sock_flags = 0;
    }

    lm_ctx->iommu_dir_fd = open(lm_ctx->iommu_dir, O_DIRECTORY);
    if (lm_ctx->iommu_dir_fd < 0) {
        ret = errno;
        goto close_unix_sock;
    }

    ret = snprintf(addr.sun_path, sizeof addr.sun_path, "%s/" MUSER_SOCK,
		   lm_ctx->iommu_dir);
    if (ret >= (int)sizeof addr.sun_path) {
        ret = ENAMETOOLONG;
        goto close_iommu_dir_fd;
    }
    if (ret < 0) {
        goto close_iommu_dir_fd;
    }

    /* start listening business */
    ret = bind(unix_sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
	    ret = errno;
        goto close_iommu_dir_fd;
    }

    ret = listen(unix_sock, 0);
    if (ret < 0) {
        ret = errno;
        goto close_iommu_dir_fd;
    }

    umask(mode);
    return unix_sock;

close_iommu_dir_fd:
    close(lm_ctx->iommu_dir_fd);
close_unix_sock:
    close(unix_sock);
free_iommu_dir:
    free(lm_ctx->iommu_dir);

    return -ret;
}

static void
__free_s(char **p)
{
    free(*p);
}

int
send_vfio_user_msg(int sock, uint16_t msg_id, bool is_reply,
                   enum vfio_user_command cmd, void *data, int len,
                   int *fds, int count)
{
    int ret;
    struct vfio_user_header hdr = {.msg_id = msg_id};
    struct iovec iov[2];
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));

    if (is_reply) {
        hdr.flags.type = VFIO_USER_F_TYPE_REPLY;
    } else {
        hdr.cmd = cmd;
        hdr.flags.type = VFIO_USER_F_TYPE_COMMAND;
    }

    if (data != NULL && len == 0) {
        return -EINVAL;
    }

    hdr.msg_size = sizeof(hdr) + len;

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);
    msg.msg_iovlen = 1;

    if (data != NULL) {
        msg.msg_iovlen++;
        iov[1].iov_base = data;
        iov[1].iov_len = len;
    }

    msg.msg_iov = iov;

    if (fds != NULL) {
        size_t size = count * sizeof *fds;
        char *buf = alloca(CMSG_SPACE(size));

        msg.msg_control = buf;
        msg.msg_controllen = CMSG_SPACE(size);

        struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(size);
        memcpy(CMSG_DATA(cmsg), fds, size);
    }

    ret = sendmsg(sock, &msg, 0);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

int
send_version(int sock, int major, int minor, uint16_t msg_id, bool is_reply,
             char *caps)
{
    int ret;
    char *data __attribute__((__cleanup__(__free_s))) = NULL;

    ret  = asprintf(&data, "{version: {\"major\": %d, \"minor\": %d}, capabilities: %s}",
                    major, minor, caps != NULL ? caps : "{}");
    if (ret == -1) {
        data = NULL;
        return -1;
    }

    return send_vfio_user_msg(sock, msg_id, is_reply, VFIO_USER_VERSION, data,
                              ret, NULL, 0);
}

int
recv_vfio_user_msg(int sock, struct vfio_user_header *hdr, bool is_reply,
                   uint16_t *msg_id, void *data, int *len)
{
    int ret;

    ret = recv_blocking(sock, hdr, sizeof(*hdr), 0);
    if (ret == -1) {
        return -errno;
    }
    if (ret < (int)sizeof(*hdr)) {
        return -EINVAL;
    }

    if (is_reply) {
        if (hdr->msg_id != *msg_id) {
            return -EINVAL;
        }

        if (hdr->flags.type != VFIO_USER_F_TYPE_REPLY) {
            return -EINVAL;
        }

        if (hdr->flags.error == 1U) {
            if (hdr->error_no <= 0) {
                hdr->error_no = EINVAL;
            }
            return -hdr->error_no;
        }
    } else {
        if (hdr->flags.type != VFIO_USER_F_TYPE_COMMAND) {
            return -EINVAL;
        }
        *msg_id = hdr->msg_id;
    }

    if (len != NULL && *len > 0 && hdr->msg_size > sizeof *hdr) {
        ret = recv_blocking(sock, data, MIN(hdr->msg_size - sizeof *hdr, *len),
                            0);
        if (ret < 0) {
            return ret;
        }
        if (*len != ret) { /* FIXME we should allow receiving less */
            return -EINVAL;
        }
        *len = ret;
    }
    return 0;
}

int
recv_version(int sock, int *major, int *minor, uint16_t *msg_id, bool is_reply,
             int *max_fds)
{
    int ret;
    struct vfio_user_header hdr;
    char *data __attribute__((__cleanup__(__free_s))) = NULL;

    ret = recv_vfio_user_msg(sock, &hdr, is_reply, msg_id, NULL, NULL);
    if (ret < 0) {
        return ret;
    }

    hdr.msg_size -= sizeof(hdr);
    data = malloc(hdr.msg_size);
    if (data == NULL) {
        return -errno;
    }
    ret = recv_blocking(sock, data, hdr.msg_size, 0);
    if (ret == -1) {
        return -errno;
    }
    if (ret < (int)hdr.msg_size) {
        return -EINVAL;
    }

    /* FIXME use proper parsing */
    ret = sscanf(data,
                 "{version: {\"major\": %d, \"minor\": %d}, capabilities: {max_fds: %d}}",
                 major, minor, max_fds);
    if (ret != 3) {
        return -EINVAL;
    }
    return 0;
}

int
send_recv_vfio_user_msg(int sock, uint16_t msg_id, enum vfio_user_command cmd,
                        void *send_data, int send_len,
                        int *send_fds, int fd_count,
                        struct vfio_user_header *hdr,
                        void *recv_data, int recv_len)
{
    int ret = send_vfio_user_msg(sock, msg_id, false, cmd, send_data, send_len,
                                 send_fds, fd_count);
    if (ret < 0) {
        return ret;
    }
    if (hdr == NULL) {
        hdr = alloca(sizeof *hdr);
    }
    return recv_vfio_user_msg(sock, hdr, true, &msg_id, recv_data, &recv_len);
}

static int
set_version(lm_ctx_t *lm_ctx, int sock)
{
    int ret;
    int client_mj, client_mn;
    uint16_t msg_id = 0;
    char *server_caps;

    ret = asprintf(&server_caps, "{max_fds: %d}", MAX_FDS);
    if (ret == -1) {
        return -ENOMEM;
    }

    ret = send_version(sock, LIB_MUSER_VFIO_USER_VERS_MJ,
                       LIB_MUSER_VFIO_USER_VERS_MN, msg_id, false, server_caps);
    if (ret < 0) {
        lm_log(lm_ctx, LM_DBG, "failed to send version: %s", strerror(-ret));
        goto out;
    }

    ret = recv_version(sock, &client_mj, &client_mn, &msg_id, true,
                       &lm_ctx->client_max_fds);
    if (ret < 0) {
        lm_log(lm_ctx, LM_DBG, "failed to receive version: %s", strerror(-ret));
        goto out;
    }
    if (client_mj != LIB_MUSER_VFIO_USER_VERS_MJ ||
        client_mn != LIB_MUSER_VFIO_USER_VERS_MN) {
        lm_log(lm_ctx, LM_DBG, "version mismatch,  server=%d.%d, client=%d.%d",
               LIB_MUSER_VFIO_USER_VERS_MJ, LIB_MUSER_VFIO_USER_VERS_MN,
               client_mj, client_mn);
        ret = -EINVAL;
    }
out:
    free(server_caps);
    return ret;
}

/**
 * lm_ctx: libmuser context
 * iommu_dir: full path to the IOMMU group to create. All parent directories
 *            must already exist.
 */
static int
open_sock(lm_ctx_t *lm_ctx)
{
    int ret;
    int conn_fd;

    assert(lm_ctx != NULL);

    conn_fd = accept(lm_ctx->fd, NULL, NULL);
    if (conn_fd == -1) {
        return conn_fd;
    }

    /* send version and caps */
    ret = set_version(lm_ctx, conn_fd);
    if (ret < 0) {
        return ret;
    }
    return conn_fd;
}

static int
close_sock(lm_ctx_t *lm_ctx)
{
    return close(lm_ctx->conn_fd);
}

static int
get_request_sock(lm_ctx_t *lm_ctx, struct vfio_user_header *hdr,
                 int *fds, int *nr_fds)
{
    int ret;
    struct iovec iov = {.iov_base = hdr, .iov_len = sizeof *hdr};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    struct cmsghdr *cmsg;

    msg.msg_controllen = CMSG_SPACE(sizeof(int) * *nr_fds);
    msg.msg_control = alloca(msg.msg_controllen);

    /*
     * TODO ideally we should set O_NONBLOCK on the fd so that the syscall is
     * faster (?). I tried that and get short reads, so we need to store the
     * partially received buffer somewhere and retry.
     */
    ret = recvmsg(lm_ctx->conn_fd, &msg, lm_ctx->sock_flags);
    if (ret == -1) {
        return -errno;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        if (cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
            return -EINVAL;
        }
        int size = cmsg->cmsg_len - CMSG_LEN(0);
        if (size % sizeof(int) != 0) {
            return -EINVAL;
        }
        int i;
        *nr_fds = (int)(size / sizeof(int));
        for (i = 0; i < *nr_fds; i++) {
           //memcpy(fds[i], CMSG_DATA(cmsg) + sizeof(int) * i, sizeof *fds);
            fds[i] = *(CMSG_DATA(cmsg) + sizeof(int) * i);
        }
    }

    return ret;
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

static ssize_t
recv_fds_sock(lm_ctx_t *lm_ctx, void *buf, size_t size)
{
    ssize_t ret = muser_recv_fds(lm_ctx->conn_fd, buf, size / sizeof(int));
    if (ret < 0) {
	    return ret;
    }
    return ret * sizeof(int);
}

static struct transport_ops {
    int (*init)(lm_ctx_t*);
    int (*attach)(lm_ctx_t*);
    int(*detach)(lm_ctx_t*);
    int (*get_request)(lm_ctx_t*, struct vfio_user_header*, int *fds, int *nr_fds);
    ssize_t (*recv_fds)(lm_ctx_t*, void *buf, size_t size);
} transports_ops[] = {
    [LM_TRANS_KERNEL] = {
        .init = NULL,
        .attach = dev_attach,
        .detach = dev_detach,
        .recv_fds = recv_fds_kernel,
        .get_request = get_request_kernel,
    },
    [LM_TRANS_SOCK] = {
        .init = init_sock,
        .attach = open_sock,
        .detach = close_sock,
        .recv_fds = recv_fds_sock,
        .get_request = get_request_sock,
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
    lm_ctx->log(lm_ctx->pvt, lvl, buf);
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

static int
device_reset(lm_ctx_t *lm_ctx)
{
    lm_log(lm_ctx, LM_DBG, "Device reset called by client");
    if (lm_ctx->reset != NULL) {
        return lm_ctx->reset(lm_ctx->pvt);
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
 * Sparse mmap information stays after struct vfio_region_info and cap_offest
 * points accordingly.
 */
static int
dev_get_sparse_mmap_cap(lm_ctx_t *lm_ctx, lm_reg_info_t *lm_reg,
                        struct vfio_region_info **vfio_reg, bool is_kernel)
{
    struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
    struct lm_sparse_mmap_areas *mmap_areas;
    int nr_mmap_areas, i;
    size_t sparse_size;
    ssize_t ret;
    void *cap_ptr;

    if (lm_reg->mmap_areas == NULL) {
        lm_log(lm_ctx, LM_DBG, "bad mmap_areas\n");
        return -EINVAL;
    }

    nr_mmap_areas = lm_reg->mmap_areas->nr_mmap_areas;
    sparse_size = sizeof(*sparse) + (nr_mmap_areas * sizeof(*sparse->areas));

    /*
     * If vfio_reg does not have enough space to accommodate  sparse info then
     * set the argsz with the expected size and return. This behaviour
     * is only for kernel/muser.ko, where the request comes from kernel/vfio.
     */

    if ((*vfio_reg)->argsz < sparse_size + sizeof(**vfio_reg) && is_kernel) {
        lm_log(lm_ctx, LM_DBG, "vfio_reg too small=%d\n", (*vfio_reg)->argsz);
        (*vfio_reg)->argsz = sparse_size + sizeof(**vfio_reg);
        (*vfio_reg)->cap_offset = 0;
        return 0;
    }

    sparse = calloc(1, sparse_size);
    if (sparse == NULL)
        return -ENOMEM;
    sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
    sparse->header.version = 1;
    sparse->header.next = 0;
    sparse->nr_areas = nr_mmap_areas;

    lm_log(lm_ctx, LM_DBG, "%s: capsize %llu, nr_mmap_areas %u", __func__,
           sparse_size, nr_mmap_areas);
    mmap_areas = lm_reg->mmap_areas;
    for (i = 0; i < nr_mmap_areas; i++) {
        sparse->areas[i].offset = mmap_areas->areas[i].start;
        sparse->areas[i].size = mmap_areas->areas[i].size;
        lm_log(lm_ctx, LM_DBG, "%s: area %d offset %#lx size %llu", __func__,
               i, sparse->areas[i].offset, sparse->areas[i].size);
    }

    (*vfio_reg)->flags |= VFIO_REGION_INFO_FLAG_MMAP | VFIO_REGION_INFO_FLAG_CAPS;
    (*vfio_reg)->cap_offset = sizeof(**vfio_reg);

    if (is_kernel) {
        /* write the sparse mmap cap info to vfio-client user pages */
        ret = write(lm_ctx->conn_fd, sparse, sparse_size);
        if (ret != (ssize_t)sparse_size) {
            free(sparse);
            return -EIO;
        }
    } else {
        (*vfio_reg)->argsz = sparse_size + sizeof(**vfio_reg);
        *vfio_reg = realloc(*vfio_reg, (*vfio_reg)->argsz);
        if (*vfio_reg == NULL) {
            free(sparse);
            return -ENOMEM;
        }

        cap_ptr = (char *)*vfio_reg + (*vfio_reg)->cap_offset;
        memcpy(cap_ptr, sparse, sparse_size);
    }

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

static long
dev_get_reginfo(lm_ctx_t *lm_ctx, struct vfio_region_info **vfio_reg,
                bool is_kernel)
{
    lm_reg_info_t *lm_reg;
    int err;

    assert(lm_ctx != NULL);
    assert(*vfio_reg != NULL);
    lm_reg = &lm_ctx->pci_info.reg_info[(*vfio_reg)->index];

    // Ensure provided argsz is sufficiently big and index is within bounds.
    if (((*vfio_reg)->argsz < sizeof(struct vfio_region_info)) ||
        ((*vfio_reg)->index >= LM_DEV_NUM_REGS)) {
        lm_log(lm_ctx, LM_DBG, "bad args argsz=%d index=%d",
               (*vfio_reg)->argsz, (*vfio_reg)->index);
        return -EINVAL;
    }

    (*vfio_reg)->offset = region_to_offset((*vfio_reg)->index);
    (*vfio_reg)->flags = lm_reg->flags;
    (*vfio_reg)->size = lm_reg->size;

    if (lm_reg->mmap_areas != NULL) {
        err = dev_get_sparse_mmap_cap(lm_ctx, lm_reg, vfio_reg, is_kernel);
        if (err) {
            return err;
        }
    }

    lm_log(lm_ctx, LM_DBG, "region_info[%d] offset %#lx flags %#x size %llu "
           "argsz %llu",
           (*vfio_reg)->index, (*vfio_reg)->offset, (*vfio_reg)->flags,
           (*vfio_reg)->size, (*vfio_reg)->argsz);

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
    struct vfio_region_info *reg_info;
    int err = -ENOTSUP;

    assert(lm_ctx != NULL);
    switch (cmd_ioctl->vfio_cmd) {
    case VFIO_DEVICE_GET_INFO:
        err = dev_get_info(&cmd_ioctl->data.dev_info);
        break;
    case VFIO_DEVICE_GET_REGION_INFO:
        reg_info = &cmd_ioctl->data.reg_info;
        err = dev_get_reginfo(lm_ctx, &reg_info, true);
        break;
    case VFIO_DEVICE_GET_IRQ_INFO:
        err = dev_get_irqinfo(lm_ctx, &cmd_ioctl->data.irq_info);
        break;
    case VFIO_DEVICE_SET_IRQS:
        err = dev_set_irqs(lm_ctx, &cmd_ioctl->data.irq_set, data);
        break;
    case VFIO_DEVICE_RESET:
        err = device_reset(lm_ctx);
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

    if (lm_ctx->unmap_dma == NULL) {
        return 0;
    }

    if (lm_ctx->dma == NULL) {
        lm_log(lm_ctx, LM_ERR, "DMA not initialized\n");
        return -EINVAL;
    }

    err = dma_controller_remove_region(lm_ctx->dma,
                                       cmd->mmap.request.addr,
                                       cmd->mmap.request.len,
                                       lm_ctx->unmap_dma, lm_ctx->pvt);
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

    lm_log(lm_ctx, LM_INF, "%s DMA region fd=%d path=%s iova=%#lx-%#lx "
           "offset=%#lx\n", lm_ctx->unmap_dma == NULL ? "ignoring" : "adding",
           cmd->mmap.request.fd, buf, cmd->mmap.request.addr,
           cmd->mmap.request.addr + cmd->mmap.request.len,
           cmd->mmap.request.offset);

    if (lm_ctx->unmap_dma == NULL) {
        return 0;
    }

    if (lm_ctx->dma == NULL) {
        lm_log(lm_ctx, LM_ERR, "DMA not initialized\n");
        return -EINVAL;
    }

    err = dma_controller_add_region(lm_ctx->dma,
                                    cmd->mmap.request.addr,
                                    cmd->mmap.request.len,
                                    cmd->mmap.request.fd,
                                    cmd->mmap.request.offset);
    if (err < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to add DMA region fd=%d path=%s %#lx-%#lx: "
               "%d\n", cmd->mmap.request.fd, buf, cmd->mmap.request.addr,
               cmd->mmap.request.addr + cmd->mmap.request.len, err);
    } else {
        err = 0;
    }

    if (lm_ctx->map_dma != NULL) {
        lm_ctx->map_dma(lm_ctx->pvt, cmd->mmap.request.addr,
                        cmd->mmap.request.len);
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
__attribute__((unused)) muser_mmap(lm_ctx_t *lm_ctx, struct muser_cmd *cmd)
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
        err = muser_send_fds(lm_ctx->conn_fd, (int*)&addr, 1);
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

    ret = write(lm_ctx->conn_fd, rwbuf, count);
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
    if (is_write) {
        ret = cap_maybe_access(lm_ctx, lm_ctx->caps, buf, count, pos);
        if (ret < 0) {
            lm_log(lm_ctx, LM_ERR, "bad access to capabilities %u@%#x\n", count,
                   pos);
            return ret;
        }
    } else {
        memcpy(buf, lm_ctx->pci_config_space->raw + pos, count);
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
muser_access(lm_ctx_t *lm_ctx, struct muser_cmd *cmd, bool is_write,
             void **data)
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
           cmd->rw.pos + cmd->rw.count - 1);

    /* copy data to be written from kernel to user space */
    if (is_write) {
        err = read(lm_ctx->conn_fd, rwbuf, cmd->rw.count);
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
#ifdef LM_VERBOSE_LOGGING
        dump_buffer("buffer write", rwbuf, cmd->rw.count);
#endif
    }

    count = _count = cmd->rw.count;
    cmd->err = muser_pci_hdr_access(lm_ctx, &_count, &cmd->rw.pos,
                                    is_write, rwbuf);
    if (cmd->err) {
        lm_log(lm_ctx, LM_ERR, "failed to access PCI header: %s\n",
               strerror(-cmd->err));
#ifdef LM_VERBOSE_LOGGING
        dump_buffer("buffer write", rwbuf, _count);
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
        if (data != NULL) {
            *data = rwbuf;
            return ret;
        } else {
            err = post_read(lm_ctx, rwbuf, ret);
#ifdef LM_VERBOSE_LOGGING
            if (err == ret) {
                dump_buffer("buffer read", rwbuf, ret);
            }
#endif
        }
    }

out:
    free(rwbuf);

    return ret;
}

static int
__attribute__((unused)) muser_ioctl(lm_ctx_t *lm_ctx, struct muser_cmd *cmd)
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
        ret = transports_ops[lm_ctx->trans].recv_fds(lm_ctx, data, size);
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

static int handle_device_get_region_info(lm_ctx_t *lm_ctx,
                                         struct vfio_user_header *hdr,
                                         struct vfio_region_info **dev_reg_info)
{
    struct vfio_region_info *reg_info;
    int ret;

    reg_info = calloc(sizeof(*reg_info), 1);
    if (reg_info == NULL) {
        return -ENOMEM;
    }

    if ((hdr->msg_size - sizeof(*hdr)) != sizeof(*reg_info)) {
        free(reg_info);
        return -EINVAL;
    }

    ret = recv(lm_ctx->conn_fd, reg_info, sizeof(*reg_info), 0);
    if (ret < 0) {
        free(reg_info);
        return -errno;
    }

    ret = dev_get_reginfo(lm_ctx, &reg_info, false);
    if (ret < 0) {
        free(reg_info);
        return ret;
    }
    *dev_reg_info = reg_info;

    return 0;
}

static int handle_device_get_info(lm_ctx_t *lm_ctx,
                                  struct vfio_user_header *hdr,
                                  struct vfio_device_info *dev_info)
{
    int ret;

    if ((hdr->msg_size - sizeof(*hdr)) != sizeof(*dev_info)) {
        return -EINVAL;
    }

    ret = recv(lm_ctx->conn_fd, dev_info, sizeof(*dev_info), 0);
    if (ret < 0) {
        return -errno;
    }

    ret = dev_get_info(dev_info);
    if (ret < 0) {
        return ret;
    }

    lm_log(lm_ctx, LM_DBG, "sent devinfo flags %#x, num_regions %d, num_irqs"
           " %d", dev_info->flags, dev_info->num_regions, dev_info->num_irqs);
    return ret;
}

static int
handle_device_get_irq_info(lm_ctx_t *lm_ctx, struct vfio_user_header *hdr,
                           struct vfio_irq_info *irq_info)
{
    int ret;

    assert(lm_ctx != NULL);
    assert(irq_info != NULL);

    hdr->msg_size -= sizeof *hdr;

    if (hdr->msg_size != sizeof *irq_info) {
        return -EINVAL;
    }

    ret = recv(lm_ctx->conn_fd, irq_info, hdr->msg_size, 0);
    if (ret < 0) {
        return -errno;
    }
    if (ret != (int)hdr->msg_size) {
        assert(false); /* FIXME */
    }

    return dev_get_irqinfo(lm_ctx, irq_info);
}

static int
handle_device_set_irqs(lm_ctx_t *lm_ctx, struct vfio_user_header *hdr,
                       int *fds, int nr_fds)
{
    int ret;
    struct vfio_irq_set *irq_set;
    void *data;

    assert(lm_ctx != NULL);
    assert(hdr != NULL);

    hdr->msg_size -= sizeof *hdr;

    if (hdr->msg_size < sizeof *irq_set) {
        return -EINVAL;
    }

    irq_set = alloca(hdr->msg_size); /* FIXME */

    ret = recv(lm_ctx->conn_fd, irq_set, hdr->msg_size, 0);
    if (ret < 0) {
        return -errno;
    }
    if (ret != (int)hdr->msg_size) {
        assert(false); /* FIXME */
    }
    if (ret != (int)irq_set->argsz) {
        assert(false); /* FIXME */
    }
    switch (irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
        case VFIO_IRQ_SET_DATA_EVENTFD:
            data = fds;
            if (nr_fds != (int)irq_set->count) {
                return -EINVAL;
            }
            break;
        case VFIO_IRQ_SET_DATA_BOOL:
            data = irq_set + 1;
            break;
    }

    return dev_set_irqs(lm_ctx, irq_set, data);
}

static int
handle_dma_map_or_unmap(lm_ctx_t *lm_ctx, struct vfio_user_header *hdr, bool map,
                        int *fds, int nr_fds)
{
    int ret, i;
    int nr_dma_regions;
    struct vfio_user_dma_region *dma_regions;

    assert(lm_ctx != NULL);
    assert(hdr != NULL);

    hdr->msg_size -= sizeof *hdr;

    if (hdr->msg_size % sizeof(struct vfio_user_dma_region) != 0) {
        lm_log(lm_ctx, LM_ERR, "bad size of DMA regions %d", hdr->msg_size);
        return -EINVAL;
    }

    nr_dma_regions = (int)(hdr->msg_size / sizeof(struct vfio_user_dma_region));
    if (map && nr_dma_regions != nr_fds) {
        lm_log(lm_ctx, LM_ERR, "expected %d fds but got %d instead",
               nr_dma_regions, nr_fds);
        return -EINVAL;
    }

    dma_regions = alloca(nr_dma_regions * sizeof(*dma_regions));

    ret = recv(lm_ctx->conn_fd, dma_regions, hdr->msg_size, 0);
    if (ret == -1) {
        lm_log(lm_ctx, LM_ERR, "failed to receive DMA region entries: %m");
        return -errno;
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
    return device_reset(lm_ctx);
}

static int
handle_region_access(lm_ctx_t *lm_ctx, struct vfio_user_header *hdr,
                     void **data, int *len)
{
    struct vfio_user_region_access region_access;
    struct muser_cmd muser_cmd = {};
    int ret;

    assert(lm_ctx != NULL);
    assert(hdr != NULL);
    assert(data != NULL);

    /* 
     * TODO if muser_access doesn't need to handle the kernel case, then we can
     * avoid having to do an additional read/recv inside muser_access (one recv
     * for struct region_access and another for the write data) by doing a
     * single recvmsg here with an iovec where the first element of the array
     * will be struct vfio_user_region_access and the second a buffer if it's a
     * write.  The size of the write buffer is:
     * hdr->msg_size - sizeof *hdr - sizeof region_access,
     * and should be equal to region_access.count.
     */

    hdr->msg_size -= sizeof *hdr;
    if (hdr->msg_size < sizeof region_access) {
        return -EINVAL;
    }

    ret = recv(lm_ctx->conn_fd, &region_access, sizeof region_access, 0);
    if (ret == -1) {
        return -errno;
    }
    if (ret != sizeof region_access) {
        return -EINVAL;
    }
    if (region_access.region >= LM_DEV_NUM_REGS || region_access.count <= 0 ) {
        return -EINVAL;
    }
    muser_cmd.rw.count = region_access.count;
    muser_cmd.rw.pos = region_to_offset(region_access.region) + region_access.offset;

    ret = muser_access(lm_ctx, &muser_cmd, hdr->cmd == VFIO_USER_REGION_WRITE,
                       data);
    if (ret != (int)region_access.count) {
        assert(false); /* FIXME */
    }
    assert(muser_cmd.err == 0);

    *len = region_access.count;

    return 0;
}

/*
 * FIXME return value is messed up, sometimes we return -1 and set errno while
 * other times we return -errno. Fix.
 */

static int
process_request(lm_ctx_t *lm_ctx)
{
    struct vfio_user_header hdr = {};
    int ret;
    int *fds = NULL;
    int nr_fds;
    struct vfio_irq_info irq_info;
    struct vfio_device_info dev_info;
    struct vfio_region_info *dev_reg_info = NULL;
    void *data = NULL;
    bool free_data = false;
    int len;

    assert(lm_ctx != NULL);

    nr_fds = lm_ctx->client_max_fds;
    fds = alloca(nr_fds * sizeof(int));

    ret = transports_ops[lm_ctx->trans].get_request(lm_ctx, &hdr, fds, &nr_fds);
    if (unlikely(ret < 0)) {
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            return 0;
        }
        if (ret != -EINTR) {
            lm_log(lm_ctx, LM_ERR, "failed to receive request: %s", strerror(-ret));
        }
        return ret;
    }
    if (unlikely(ret == 0)) {
        if (errno == EINTR) {
            return -EINTR;
        }
        if (errno == 0) {
            lm_log(lm_ctx, LM_INF, "VFIO client closed connection");
        } else {
            lm_log(lm_ctx, LM_ERR, "end of file: %m");
        }
        return -ENOTCONN;
    }

    if (ret < (int)sizeof hdr) {
        lm_log(lm_ctx, LM_ERR, "short header read %d", ret);
        return -EINVAL;
    }

    if (hdr.flags.type != VFIO_USER_F_TYPE_COMMAND) {
        lm_log(lm_ctx, LM_ERR, "header not a request");
        return -EINVAL;
    }

    if (hdr.msg_size < sizeof hdr) {
        lm_log(lm_ctx, LM_ERR, "bad size in header %d", hdr.msg_size);
        return -EINVAL;
    }

    switch (hdr.cmd) {
        case VFIO_USER_DMA_MAP:
        case VFIO_USER_DMA_UNMAP:
            ret = handle_dma_map_or_unmap(lm_ctx, &hdr,
                                          hdr.cmd == VFIO_USER_DMA_MAP,
                                          fds, nr_fds);
            break;
        case VFIO_USER_DEVICE_GET_INFO:
            ret = handle_device_get_info(lm_ctx, &hdr, &dev_info);
            if (ret == 0) {
                data = &dev_info;
                len = dev_info.argsz;
            }
            break;
        case VFIO_USER_DEVICE_GET_REGION_INFO:
            ret = handle_device_get_region_info(lm_ctx, &hdr, &dev_reg_info);
            if (ret == 0) {
                data = dev_reg_info;
                len = dev_reg_info->argsz;
                free_data = true;
            }
            break;
        case VFIO_USER_DEVICE_GET_IRQ_INFO:
            ret = handle_device_get_irq_info(lm_ctx, &hdr, &irq_info);
            if (ret == 0) {
                data = &irq_info;
                len = sizeof irq_info;
            }
            break;
        case VFIO_USER_DEVICE_SET_IRQS:
            ret = handle_device_set_irqs(lm_ctx, &hdr, fds, nr_fds);
            break;
        case VFIO_USER_REGION_READ:
        case VFIO_USER_REGION_WRITE:
            ret = handle_region_access(lm_ctx, &hdr, &data, &len);
            free_data = true;
            break;
        case VFIO_USER_DEVICE_RESET:
            ret = handle_device_reset(lm_ctx);
            break;
        default:
            lm_log(lm_ctx, LM_ERR, "bad command %d", hdr.cmd);
            return -EINVAL;
    }

    /*
     * TODO: In case of error during command handling set errno respectively
     * in the reply message.
     */
    ret = send_vfio_user_msg(lm_ctx->conn_fd, hdr.msg_id, true,
                             0, data, len, NULL, 0);
    if (unlikely(ret < 0)) {
        lm_log(lm_ctx, LM_ERR, "failed to complete command: %s\n",
                strerror(-ret));
    }
    if (free_data) {
        free(data);
    }

    return ret;
}

int
lm_ctx_drive(lm_ctx_t *lm_ctx)
{
    int err;

    if (lm_ctx == NULL) {
        errno = EINVAL;
        return -1;
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

static int validate_irq_vector(lm_ctx_t *lm_ctx, uint32_t vector)
{

    if ((lm_ctx == NULL) || (vector >= lm_ctx->irqs.max_ivs)) {
        lm_log(lm_ctx, LM_ERR, "bad IRQ %d, max=%d\n", vector,
               lm_ctx->irqs.max_ivs);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int
lm_irq_trigger(lm_ctx_t *lm_ctx, uint32_t subindex)
{
    int ret;
    eventfd_t val = 1;

    ret = validate_irq_vector(lm_ctx, subindex);
    if (ret < 0) {
        return ret;
    }

    if (lm_ctx->irqs.efds[subindex] == -1) {
        lm_log(lm_ctx, LM_ERR, "no fd for interrupt %d\n", subindex);
        errno = ENOENT;
        return -1;
    }

    return eventfd_write(lm_ctx->irqs.efds[subindex], val);
}

int
lm_irq_message(lm_ctx_t *lm_ctx, uint32_t subindex)
{
    int ret, msg_id = 1;
    struct vfio_user_irq_info irq_info;

    ret = validate_irq_vector(lm_ctx, subindex);
    if (ret < 0) {
        return -1;
    }

    irq_info.subindex = subindex;
    ret = send_recv_vfio_user_msg(lm_ctx->conn_fd, msg_id,
                                  VFIO_USER_VM_INTERRUPT, &irq_info,
                                  sizeof(irq_info), NULL, 0, NULL, NULL, 0);
    if (ret < 0) {
	    errno = -ret;
	    return -1;
    }

    return 0;
}

void
lm_ctx_destroy(lm_ctx_t *lm_ctx)
{
    if (lm_ctx == NULL) {
        return;
    }

    free(lm_ctx->uuid);

    /*
     * FIXME The following cleanup can be dangerous depending on how lm_ctx_destroy
     * is called since it might delete files it did not create. Improve by
     * acquiring a lock on the directory.
     */
    if (lm_ctx->trans == LM_TRANS_SOCK) {
        int ret;

        if (lm_ctx->iommu_dir_fd != -1) {
            if ((ret = unlinkat(lm_ctx->iommu_dir_fd, IOMMU_GRP_NAME, 0)) == -1
                && errno != ENOENT) {
                lm_log(lm_ctx, LM_DBG, "failed to remove " IOMMU_GRP_NAME ": "
                       "%m\n");
            }
            if ((ret = unlinkat(lm_ctx->iommu_dir_fd, MUSER_SOCK, 0)) == -1 &&
                errno != ENOENT) {
                lm_log(lm_ctx, LM_DBG, "failed to remove " MUSER_SOCK ": %m\n");
            }
            if (close(lm_ctx->iommu_dir_fd) == -1) {
                lm_log(lm_ctx, LM_DBG, "failed to close IOMMU dir fd %d: %m\n",
                       lm_ctx->iommu_dir_fd);
            }
        }
        if (lm_ctx->iommu_dir != NULL) {
            if ((ret = rmdir(lm_ctx->iommu_dir)) == -1 && errno != ENOENT) {
                lm_log(lm_ctx, LM_DBG, "failed to remove %s: %m\n",
                       lm_ctx->iommu_dir);
            }
            free(lm_ctx->iommu_dir);
        }
    }

    free(lm_ctx->pci_config_space);
    transports_ops[lm_ctx->trans].detach(lm_ctx);
    if (lm_ctx->dma != NULL) {
        dma_controller_destroy(lm_ctx->dma);
    }
    free_sparse_mmap_areas(lm_ctx->pci_info.reg_info);
    free(lm_ctx->caps);
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
        lm_ctx->caps = caps_create(lm_ctx, dev_info->caps, dev_info->nr_caps);
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

int
lm_ctx_try_attach(lm_ctx_t *lm_ctx)
{
    assert(lm_ctx != NULL);

    if ((lm_ctx->flags & LM_FLAG_ATTACH_NB) == 0) {
        errno = EINVAL;
        return -1;
    }
    return transports_ops[lm_ctx->trans].attach(lm_ctx);
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

    if ((dev_info->flags & LM_FLAG_ATTACH_NB) != 0 &&
        dev_info->trans != LM_TRANS_SOCK) {
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
    lm_ctx->flags = dev_info->flags;

    lm_ctx->uuid = strdup(dev_info->uuid);
    if (lm_ctx->uuid == NULL) {
        err = errno;
        goto out;
    }

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

    if (transports_ops[dev_info->trans].init != NULL) {
        err = transports_ops[dev_info->trans].init(lm_ctx);
        if (err < 0) {
            goto out;
        }
        lm_ctx->fd = err;
    }
    err = 0;

    // Attach to the muser control device. With LM_FLAG_ATTACH_NB caller is
    // always expected to call lm_ctx_try_attach().
    if ((dev_info->flags & LM_FLAG_ATTACH_NB) == 0) {
        lm_ctx->conn_fd = transports_ops[dev_info->trans].attach(lm_ctx);
        if (lm_ctx->conn_fd < 0) {
                err = lm_ctx->conn_fd;
                if (err != EINTR) {
                    lm_log(lm_ctx, LM_ERR, "failed to attach: %s",
                           strerror(-err));
                }
                goto out;
        }
    }

    lm_ctx->map_dma = dev_info->map_dma;
    lm_ctx->unmap_dma = dev_info->unmap_dma;

    // Create the internal DMA controller.
    if (lm_ctx->unmap_dma != NULL) {
        lm_ctx->dma = dma_controller_create(lm_ctx, LM_DMA_REGIONS);
        if (lm_ctx->dma == NULL) {
            err = errno;
            goto out;
        }
    }

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
    if (unlikely(lm_ctx->unmap_dma == NULL)) {
        errno = EINVAL;
        return -1;
    }
    return dma_addr_to_sg(lm_ctx->dma, dma_addr, len, sg, max_sg);
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

uint8_t *
lm_ctx_get_cap(lm_ctx_t *lm_ctx, uint8_t id)
{
    assert(lm_ctx != NULL);

    return cap_find_by_id(lm_ctx, id);
}

int
lm_dma_read(lm_ctx_t *lm_ctx, dma_addr_t addr, size_t count, void *data)
{
    struct vfio_user_dma_region_access *dma_recv;
    struct vfio_user_dma_region_access dma_send = {
        .addr = addr,
        .count = count
    };
    int recv_size = sizeof(*dma_recv) + count;
    int msg_id = 1, ret;

    if (!dma_controller_region_valid(lm_ctx->dma, addr, count)) {
        lm_log(lm_ctx, LM_ERR, "DMA region addr %#lx count %llu doest not "
               "exists", addr, count);
        return -ENOENT;
    }

    dma_recv = calloc(recv_size, 1);
    if (dma_recv == NULL) {
        return -ENOMEM;
    }

    dma_recv->addr = addr;
    dma_recv->count = count;
    ret = send_recv_vfio_user_msg(lm_ctx->conn_fd, msg_id, VFIO_USER_DMA_READ,
                                  &dma_send, sizeof(dma_send), NULL, 0, NULL,
                                  dma_recv, recv_size);
    memcpy(data, dma_recv->data, count);
    free(dma_recv);

    return ret;
}

int
lm_dma_write(lm_ctx_t *lm_ctx, dma_addr_t addr, size_t count, void *data)
{
    struct vfio_user_dma_region_access *dma_send, dma_recv;
    int send_size = sizeof(*dma_send) + count;
    int msg_id = 1, ret;

    if (!dma_controller_region_valid(lm_ctx->dma, addr, count)) {
        lm_log(lm_ctx, LM_ERR, "DMA region addr %#lx count %llu does not "
               "exists", addr, count);
        return -ENOENT;
    }

    dma_send = calloc(send_size, 1);
    if (dma_send == NULL) {
        return -ENOMEM;
    }
    dma_send->addr = addr;
    dma_send->count = count;
    memcpy(dma_send->data, data, count);

    ret = send_recv_vfio_user_msg(lm_ctx->conn_fd, msg_id, VFIO_USER_DMA_WRITE,
                                  dma_send, send_size, NULL, 0, NULL, &dma_recv,
                                  sizeof(dma_recv));
    free(dma_send);

    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
