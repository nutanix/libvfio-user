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

#include "muser.h"
#include "muser_priv.h"
#include "dma.h"
#include "cap.h"

#define MAX_FDS 8

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

enum migration_iteration_state {
    VFIO_USER_MIGRATION_ITERATION_STATE_INITIAL,
    VFIO_USER_MIGRATION_ITERATION_STATE_STARTED,
    VFIO_USER_MIGRATION_ITERATION_STATE_DATA_PREPARED,
    VFIO_USER_MIGRATION_ITERATION_STATE_FINISHED
};

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
    int                     sock_flags;

    int                     client_max_fds;

    struct {
        struct vfio_device_migration_info info;
        size_t pgsize;
        lm_migration_callbacks_t callbacks;
        struct {
            enum migration_iteration_state state;
            __u64 offset;
            __u64 size;
        } iter;
    } migration;

    lm_irqs_t               irqs; /* XXX must be last */
};


/* function prototypes */
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
init_sock(lm_ctx_t *lm_ctx)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int ret, unix_sock;
    mode_t mode;

    assert(lm_ctx != NULL);

    /* FIXME SPDK can't easily run as non-root */
    mode =  umask(0000);

    if ((unix_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	    ret = -errno;
        goto out;
    }

    if (lm_ctx->flags & LM_FLAG_ATTACH_NB) {
        ret = fcntl(unix_sock, F_SETFL,
                    fcntl(unix_sock, F_GETFL, 0) | O_NONBLOCK);
        if (ret < 0) {
            ret = -errno;
            goto out;
        }
        lm_ctx->sock_flags = MSG_DONTWAIT | MSG_WAITALL;
    } else {
        lm_ctx->sock_flags = 0;
    }

    ret = snprintf(addr.sun_path, sizeof addr.sun_path, "%s", lm_ctx->uuid);
    if (ret >= (int)sizeof addr.sun_path) {
        ret = -ENAMETOOLONG;
    }
    if (ret < 0) {
        goto out;
    }

    /* start listening business */
    ret = bind(unix_sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
	    ret = errno;
    }

    ret = listen(unix_sock, 0);
    if (ret < 0) {
        ret = -errno;
    }

out:
    umask(mode);
    if (ret != 0) {
        close(unix_sock);
        return ret;
    }
    return unix_sock;
}

static void
__free_s(char **p)
{
    free(*p);
}

int
_send_vfio_user_msg(int sock, uint16_t msg_id, bool is_reply,
                   enum vfio_user_command cmd,
                   struct iovec *iovecs, size_t nr_iovecs,
                   int *fds, int count)
{
    int ret;
    struct vfio_user_header hdr = {.msg_id = msg_id};
    struct msghdr msg;
    size_t i;

    if (nr_iovecs == 0) {
        iovecs = alloca(sizeof(*iovecs));
        nr_iovecs = 1;
    }

    memset(&msg, 0, sizeof(msg));

    if (is_reply) {
        hdr.flags.type = VFIO_USER_F_TYPE_REPLY;
    } else {
        hdr.cmd = cmd;
        hdr.flags.type = VFIO_USER_F_TYPE_COMMAND;
    }

    iovecs[0].iov_base = &hdr;
    iovecs[0].iov_len = sizeof(hdr);

    for (i = 0; i < nr_iovecs; i++) {
        hdr.msg_size += iovecs[i].iov_len;
    }

    msg.msg_iovlen = nr_iovecs;
    msg.msg_iov = iovecs;

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
send_vfio_user_msg(int sock, uint16_t msg_id, bool is_reply,
                   enum vfio_user_command cmd,
                   void *data, size_t data_len,
                   int *fds, size_t count) {

    struct iovec iovecs[2] = {
        [1] = {
            .iov_base = data,
            .iov_len = data_len
        }
    };
    return _send_vfio_user_msg(sock, msg_id, is_reply, cmd, iovecs,
                               ARRAY_SIZE(iovecs), fds, count);
}

int
send_version(int sock, int major, int minor, uint16_t msg_id, bool is_reply,
             char *caps)
{
    int ret;
    char *data;

    ret  = asprintf(&data,
                    "{version: {\"major\": %d, \"minor\": %d}, capabilities: %s}",
                    major, minor, caps != NULL ? caps : "{}");
    if (ret == -1) {
        return -1;
    }
    ret = send_vfio_user_msg(sock, msg_id, is_reply, VFIO_USER_VERSION, data,
                             ret, NULL, 0);
    free(data);
    return ret;
}

int
recv_vfio_user_msg(int sock, struct vfio_user_header *hdr, bool is_reply,
                   uint16_t *msg_id, void *data, size_t *len)
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
        if (*len != (size_t)ret) { /* FIXME we should allow receiving less */
            return -EINVAL;
        }
        *len = ret;
    }
    return 0;
}

int
recv_version(int sock, int *major, int *minor, uint16_t *msg_id, bool is_reply,
             int *max_fds, size_t *pgsize)
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
                 "{version: {\"major\": %d, \"minor\": %d}, capabilities: {max_fds: %d, migration: {pgsize: %lu}}}",
                 major, minor, max_fds, pgsize);
    if (ret != 4) {
        return -EINVAL;
    }
    return 0;
}

int
_send_recv_vfio_user_msg(int sock, uint16_t msg_id, enum vfio_user_command cmd,
                         struct iovec *iovecs, size_t nr_iovecs,
                         int *send_fds, size_t fd_count,
                         struct vfio_user_header *hdr,
                         void *recv_data, size_t recv_len)
{
    int ret = _send_vfio_user_msg(sock, msg_id, false, cmd, iovecs, nr_iovecs,
                                  send_fds, fd_count);
    if (ret < 0) {
        return ret;
    }
    if (hdr == NULL) {
        hdr = alloca(sizeof *hdr);
    }
    return recv_vfio_user_msg(sock, hdr, true, &msg_id, recv_data, &recv_len);
}

int
send_recv_vfio_user_msg(int sock, uint16_t msg_id, enum vfio_user_command cmd,
                        void *send_data, size_t send_len,
                        int *send_fds, size_t fd_count,
                        struct vfio_user_header *hdr,
                        void *recv_data, size_t recv_len)
{
    struct iovec iovecs[2] = {
        [1] = {
            .iov_base = send_data,
            .iov_len = send_len
        }
    };
    return _send_recv_vfio_user_msg(sock, msg_id, cmd, iovecs,
                                    ARRAY_SIZE(iovecs), send_fds, fd_count,
                                    hdr, recv_data, recv_len);
}

static int
set_version(lm_ctx_t *lm_ctx, int sock)
{
    int ret;
    int client_mj, client_mn;
    uint16_t msg_id = 0;
    char *server_caps;

    ret = asprintf(&server_caps, "{max_fds: %d, migration: {pgsize: %ld}}",
                   MAX_FDS, sysconf(_SC_PAGESIZE));
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
                       &lm_ctx->client_max_fds, &lm_ctx->migration.pgsize);
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
        goto out;
    }
    if (lm_ctx->migration.pgsize == 0) {
        lm_log(lm_ctx, LM_ERR, "bad migration page size");
        ret = -EINVAL;
        goto out;
    }

    /* FIXME need to check max_fds */

    lm_ctx->migration.pgsize = MIN(lm_ctx->migration.pgsize,
                                   sysconf(_SC_PAGESIZE));
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

    lm_ctx->conn_fd = conn_fd;
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
        *nr_fds = (int)(size / sizeof(int));
        memcpy(fds, CMSG_DATA(cmsg), *nr_fds * sizeof(int));
        break;
    }

    return ret;
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
        lm_log(lm_ctx, LM_DBG, "disabling IRQ %s", vfio_irq_idx_to_str(index));
        lm_ctx->irqs.type = IRQ_NONE;
        for (i = 0; i < lm_ctx->irqs.max_ivs; i++) {
            if (lm_ctx->irqs.efds[i] >= 0) {
                if (close(lm_ctx->irqs.efds[i]) == -1) {
                    lm_log(lm_ctx, LM_DBG, "failed to close IRQ fd %d: %m",
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
                lm_log(lm_ctx, LM_DBG, "failed to close IRQ fd %d: %m",
                       *irq_efd);
            }
            *irq_efd = -1;
        }
        return 0;
    }

    lm_log(lm_ctx, LM_DBG, "failed to disable IRQs");
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
                lm_log(lm_ctx, LM_DBG, "IRQ: failed to set data to none: %m");
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
                lm_log(lm_ctx, LM_DBG, "IRQ: failed to set data to bool: %m");
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
                lm_log(lm_ctx, LM_DBG, "failed to close IRQ fd %d: %m", efd);
            }

            lm_ctx->irqs.efds[i] = -1;
        }
        if (*d32 >= 0) {
            lm_ctx->irqs.efds[i] = *d32;
        }
        lm_log(lm_ctx, LM_DBG, "event fd[%d]=%d", i, lm_ctx->irqs.efds[i]);
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

    lm_log(lm_ctx, LM_DBG, "setting IRQ %s flags=%#lx",
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
dev_get_irqinfo(lm_ctx_t *lm_ctx, struct vfio_irq_info *irq_info_in,
                struct vfio_irq_info *irq_info_out)
{
    assert(lm_ctx != NULL);
    assert(irq_info_in != NULL);
    assert(irq_info_out != NULL);

    lm_pci_info_t *pci_info = &lm_ctx->pci_info;

    // Ensure provided argsz is sufficiently big and index is within bounds.
    if ((irq_info_in->argsz < sizeof(struct vfio_irq_info)) ||
        (irq_info_in->index >= LM_DEV_NUM_IRQS)) {
        lm_log(lm_ctx, LM_DBG, "bad irq_info (size=%d index=%d)\n",
               irq_info_in->argsz, irq_info_in->index);
        return -EINVAL;
    }

    irq_info_out->count = pci_info->irq_count[irq_info_in->index];
    irq_info_out->flags = VFIO_IRQ_INFO_EVENTFD;

    return 0;
}

static size_t
get_vfio_caps_size(uint32_t reg_index, struct lm_sparse_mmap_areas *m)
{
    size_t type_size = 0;
    size_t sparse_size = 0;

    if (reg_index == LM_DEV_MIGRATION_REG_IDX) {
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
dev_get_caps(lm_ctx_t *lm_ctx, lm_reg_info_t *lm_reg, int reg_index,
             struct vfio_region_info *vfio_reg)
{
    struct vfio_info_cap_header *header;
    struct vfio_region_info_cap_type *type = NULL;
    struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
    struct lm_sparse_mmap_areas *mmap_areas;

    assert(lm_ctx != NULL);
    assert(vfio_reg != NULL);

    header = (struct vfio_info_cap_header*)(vfio_reg + 1);

    if (reg_index == LM_DEV_MIGRATION_REG_IDX) {
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
            lm_log(lm_ctx, LM_DBG, "%s: area %d offset %#lx size %llu", __func__,
                   i, sparse->areas[i].offset, sparse->areas[i].size);
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

static long
dev_get_reginfo(lm_ctx_t *lm_ctx, uint32_t index,
                struct vfio_region_info **vfio_reg)
{
    lm_reg_info_t *lm_reg;
    size_t caps_size;
    uint32_t argsz;

    assert(lm_ctx != NULL);
    assert(vfio_reg != NULL);

    lm_reg = &lm_ctx->pci_info.reg_info[index];

    if (index >= LM_DEV_NUM_REGS) {
        lm_log(lm_ctx, LM_DBG, "bad region index %d", index);
        return -EINVAL;
    }

    caps_size = get_vfio_caps_size(index, lm_reg->mmap_areas);
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
        dev_get_caps(lm_ctx, lm_reg, index, *vfio_reg);
    }

    lm_log(lm_ctx, LM_DBG, "region_info[%d] offset %#lx flags %#x size %llu "
           "argsz %llu",
           (*vfio_reg)->index, (*vfio_reg)->offset, (*vfio_reg)->flags,
           (*vfio_reg)->size, (*vfio_reg)->argsz);

    return 0;
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

/* valid migration state transitions */
__u32 migration_states[VFIO_DEVICE_STATE_MASK] = {
    [VFIO_DEVICE_STATE_STOP] = 1 << VFIO_DEVICE_STATE_STOP,
    [VFIO_DEVICE_STATE_RUNNING] = /* running */
        (1 << VFIO_DEVICE_STATE_STOP) |
        (1 << VFIO_DEVICE_STATE_RUNNING) |
        (1 << VFIO_DEVICE_STATE_SAVING) |
        (1 << (VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING)) |
        (1 << VFIO_DEVICE_STATE_RESUMING),
    [VFIO_DEVICE_STATE_SAVING] = /* stop-and-copy */
        (1 << VFIO_DEVICE_STATE_STOP) |
        (1 << VFIO_DEVICE_STATE_SAVING),
    [VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING] = /* pre-copy */
        (1 << VFIO_DEVICE_STATE_SAVING) |
        (1 << VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING),
    [VFIO_DEVICE_STATE_RESUMING] = /* resuming */
        (1 << VFIO_DEVICE_STATE_RUNNING) |
        (1 << VFIO_DEVICE_STATE_RESUMING)
};

static bool
_migration_state_transition_is_valid(__u32 from, __u32 to)
{
    return migration_states[from] & (1 << to);
}

static ssize_t
handle_migration_device_state(lm_ctx_t *lm_ctx, __u32 *device_state,
                              bool is_write) {

    int ret;

    assert(lm_ctx != NULL);
    assert(device_state != NULL);

    if (!is_write) {
        *device_state = lm_ctx->migration.info.device_state;
        return 0;
    }

    if (*device_state & ~VFIO_DEVICE_STATE_MASK) {
        return -EINVAL;
    }

    if (!_migration_state_transition_is_valid(lm_ctx->migration.info.device_state,
                                              *device_state)) {
        return -EINVAL;
    }

    switch (*device_state) {
        case VFIO_DEVICE_STATE_STOP:
            ret = lm_ctx->migration.callbacks.transition(lm_ctx->pvt,
                                                         LM_MIGR_STATE_STOP);
            break;
        case VFIO_DEVICE_STATE_RUNNING:
            ret = lm_ctx->migration.callbacks.transition(lm_ctx->pvt,
                                                         LM_MIGR_STATE_START);
            break;
        case VFIO_DEVICE_STATE_SAVING:
            /*
             * FIXME How should the device operate during the stop-and-copy
             * phase? Should we only allow the migration data to be read from
             * the migration region? E.g. Access to any other region should be
             * failed? This might be a good question to send to LKML.
             */
            ret = lm_ctx->migration.callbacks.transition(lm_ctx->pvt,
                                                         LM_MIGR_STATE_STOP_AND_COPY);
            break;
        case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
            ret = lm_ctx->migration.callbacks.transition(lm_ctx->pvt,
                                                         LM_MIGR_STATE_PRE_COPY);
            break;
        case VFIO_DEVICE_STATE_RESUMING:
            ret = lm_ctx->migration.callbacks.transition(lm_ctx->pvt,
                                                         LM_MIGR_STATE_RESUME);
            break;
        default:
            ret = -EINVAL;
    }

    if (ret == 0) {
        lm_ctx->migration.info.device_state = *device_state;
    }

    return ret;
}

static ssize_t
handle_migration_pending_bytes(lm_ctx_t *lm_ctx, __u64 *pending_bytes,
                               bool is_write)
{
    assert(lm_ctx != NULL);
    assert(pending_bytes != NULL);

    if (is_write) {
        return -EINVAL;
    }

    if (lm_ctx->migration.iter.state == VFIO_USER_MIGRATION_ITERATION_STATE_FINISHED) {
        *pending_bytes = 0;
        return 0;
    }

    *pending_bytes = lm_ctx->migration.callbacks.get_pending_bytes(lm_ctx->pvt);

    switch (lm_ctx->migration.iter.state) {
        case VFIO_USER_MIGRATION_ITERATION_STATE_INITIAL:
        case VFIO_USER_MIGRATION_ITERATION_STATE_DATA_PREPARED:
            /*
             * FIXME what happens if data haven't been consumed in the previous
             * iteration? Ask on LKML.
             */
            if (*pending_bytes == 0) {
                lm_ctx->migration.iter.state = VFIO_USER_MIGRATION_ITERATION_STATE_FINISHED;
            } else {
                lm_ctx->migration.iter.state = VFIO_USER_MIGRATION_ITERATION_STATE_STARTED;
            }
            break;
        case VFIO_USER_MIGRATION_ITERATION_STATE_STARTED:
            /*
             * Repeated reads of pending_bytes should not have any side effects.
             * FIXME does it have to be the same as the previous value? Can it
             * increase or even decrease? I suppose it can't be lower than
             * data_size? Ask on LKML.
             */
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static ssize_t
handle_migration_data_offset(lm_ctx_t *lm_ctx, __u64 *offset, bool is_write)
{
    int ret;

    assert(lm_ctx != NULL);
    assert(offset != NULL);

    if (is_write) {
        /* FIXME RO register means that we simply ignore the write, right? */
        return -EINVAL;
    }

    switch (lm_ctx->migration.iter.state) {
    case VFIO_USER_MIGRATION_ITERATION_STATE_STARTED:
        ret = lm_ctx->migration.callbacks.prepare_data(lm_ctx->pvt,
                                                       &lm_ctx->migration.iter.offset,
                                                       &lm_ctx->migration.iter.size);
        if (ret < 0) {
            return ret;
        }
        break;
    case VFIO_USER_MIGRATION_ITERATION_STATE_DATA_PREPARED:
        /*
         * data_offset is invariant during an iteration.
         */
        break;        
    default:
        /*
         * reading data_offset is undefined out of sequence
         */
        *offset = ULLONG_MAX;
        return -EINVAL;
    }

    
    *offset = lm_ctx->migration.iter.offset + sizeof(struct vfio_device_migration_info);

    return ret;
}

static ssize_t
handle_migration_data_size(lm_ctx_t *lm_ctx, __u64 *size, bool is_write)
{
    assert(lm_ctx != NULL);
    assert(size != NULL);

    if (is_write) {
        /* FIXME RO register means that we simply ignore the write, right? */
        return -EINVAL;
    }

    switch (lm_ctx->migration.iter.state) {
    case VFIO_USER_MIGRATION_ITERATION_STATE_STARTED:
    case VFIO_USER_MIGRATION_ITERATION_STATE_DATA_PREPARED:
        break;
    default:
        /*
         * reading data_size is undefined out of sequence
         */
        *size = ULLONG_MAX;
        return -EINVAL;
    }

    *size = lm_ctx->migration.iter.size;

    return 0;
}

static ssize_t
handle_migration_region_access(lm_ctx_t *lm_ctx, char *buf, size_t count,
                               loff_t pos, bool is_write)
{
    int ret;

    assert(lm_ctx != NULL);
    assert(buf != NULL);

    if (pos + count > lm_ctx->pci_info.reg_info[LM_DEV_MIGRATION_REG_IDX].size) {
        lm_log(lm_ctx, LM_ERR, "read %#x-%#x past end of migration region",
               pos, pos + count - 1);
        return -EINVAL;
    }
    switch (pos) {
        case offsetof(struct vfio_device_migration_info, device_state):
            if (count != sizeof(lm_ctx->migration.info.device_state)) {
                return -EINVAL;
            }
            ret = handle_migration_device_state(lm_ctx, (__u32*)buf,
                                                 is_write);
            break;
        case offsetof(struct vfio_device_migration_info, pending_bytes):
            if (count != sizeof(lm_ctx->migration.info.pending_bytes)) {
                return -EINVAL;
            }
            ret = handle_migration_pending_bytes(lm_ctx, (__u64*)buf, is_write);
            break;
        case offsetof(struct vfio_device_migration_info, data_offset):
            if (count != sizeof(lm_ctx->migration.info.data_offset)) {
                return -EINVAL;
            }
            ret = handle_migration_data_offset(lm_ctx, (__u64*)buf, is_write);
            break;
        case offsetof(struct vfio_device_migration_info, data_size):
            if (count != sizeof(lm_ctx->migration.info.data_size)) {
                return -EINVAL;
            }
            ret = handle_migration_data_size(lm_ctx, (__u64*)buf, is_write);
            break;
        default:
            if (is_write) {
                /* FIXME how do we handle the offset? */
                ret = lm_ctx->migration.callbacks.write_data(lm_ctx->pvt,
                                                             buf, count);
            } else {
                ret = lm_ctx->migration.callbacks.read_data(lm_ctx->pvt,
                                                            buf, count,
                                                            pos - sizeof(struct vfio_device_migration_info));
            }
    }

    if (ret == 0) {
        ret = count;
    }
    return ret;
}

static ssize_t
do_access(lm_ctx_t *lm_ctx, char *buf, uint8_t count, uint64_t pos, bool is_write)
{
    int idx;
    loff_t offset;
    lm_pci_info_t *pci_info;

    assert(lm_ctx != NULL);
    assert(buf != NULL);
    assert(count == 1 || count == 2 || count == 4 || count == 8);

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

    if (idx == LM_DEV_MIGRATION_REG_IDX) {
        return handle_migration_region_access(lm_ctx, buf, count, offset,
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
            lm_log(lm_ctx, LM_DBG, "bad read %d != %d", ret, size);
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
    if (size != sizeof(*reg_info_in)) {
        return -EINVAL;
    }

    return dev_get_reginfo(lm_ctx, reg_info_in->index, reg_info_out);
}

static void
handle_device_get_info(lm_ctx_t *lm_ctx, struct vfio_device_info *dev_info)
{
    assert(lm_ctx != NULL);
    assert(dev_info != NULL);

    dev_info->argsz = sizeof *dev_info;
    dev_info->flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
    dev_info->num_regions = LM_DEV_NUM_REGS;
    dev_info->num_irqs = LM_DEV_NUM_IRQS;

    lm_log(lm_ctx, LM_DBG, "sent devinfo flags %#x, num_regions %d, num_irqs"
           " %d", dev_info->flags, dev_info->num_regions, dev_info->num_irqs);
}

static int
handle_device_get_irq_info(lm_ctx_t *lm_ctx, uint32_t size,
                           struct vfio_irq_info *irq_info_in,
                           struct vfio_irq_info *irq_info_out)
{
    assert(lm_ctx != NULL);
    assert(irq_info_in != NULL);
    assert(irq_info_out != NULL);

    if (size != sizeof *irq_info_in) {
        return -EINVAL;
    }

    return dev_get_irqinfo(lm_ctx, irq_info_in, irq_info_out);
}

static int
handle_device_set_irqs(lm_ctx_t *lm_ctx, uint32_t size,
                       int *fds, int nr_fds, struct vfio_irq_set *irq_set)
{
    void *data;

    assert(lm_ctx != NULL);
    assert(irq_set != NULL);

    if (size < sizeof *irq_set || size != irq_set->argsz) {
        return -EINVAL;
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

static bool
migration_available(lm_ctx_t *lm_ctx)
{
    assert(lm_ctx != NULL);

    return lm_ctx->pci_info.reg_info[LM_DEV_MIGRATION_REG_IDX].size > 0;
}

static bool
migration_is_stop_and_copy(lm_ctx_t *lm_ctx)
{
    assert(lm_ctx != NULL);

    return migration_available(lm_ctx) &&
           lm_ctx->migration.info.device_state == VFIO_DEVICE_STATE_SAVING;
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

    if (region_access->region >= LM_DEV_NUM_REGS || region_access->count <= 0 ) {
        lm_log(lm_ctx, LM_ERR, "bad region %d and/or count %d",
               region_access->region, region_access->count);
        return -EINVAL;
    }

    if (migration_is_stop_and_copy(lm_ctx) &&
        region_access->region != LM_DEV_MIGRATION_REG_IDX) {
        lm_log(lm_ctx, LM_ERR,
               "cannot access region %d while device in stop-and-copy state",
               region_access->region);
        return -EINVAL;
    }

    if (cmd == VFIO_USER_REGION_WRITE &&
        size - sizeof *region_access != region_access->count)
    {
        lm_log(lm_ctx, LM_ERR, "bad region access, expected %d, actual %d",
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
        lm_log(lm_ctx, LM_ERR, "failed to %s %#lx-%#lx: %d",
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
    int ret;
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

    if (size < sizeof *dirty_bitmap) {
        lm_log(lm_ctx, LM_ERR, "invalid header size %lu", size);
        return -EINVAL;
    }

    /* FIXME must also check argsz */

    if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_START) {
        ret = dma_controller_dirty_page_logging_start(lm_ctx->dma,
                                                      lm_ctx->migration.pgsize);
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP) {
        ret = dma_controller_dirty_page_logging_stop(lm_ctx->dma);
    } else if (dirty_bitmap->flags & VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP) {
        ret = handle_dirty_pages_get(lm_ctx, iovecs, nr_iovecs,
                                     (struct vfio_iommu_type1_dirty_bitmap_get*)(dirty_bitmap + 1),
                                     size - sizeof *dirty_bitmap);
    } else {
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
        lm_log(lm_ctx, LM_ERR, "short header read %u", size);
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
    ret = transports_ops[lm_ctx->trans].get_request(lm_ctx, hdr, fds, nr_fds);
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

    if (migration_available(lm_ctx) &&
        lm_ctx->migration.info.device_state == VFIO_DEVICE_STATE_STOP) {
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
        ret = recv(lm_ctx->conn_fd, cmd_data, hdr.msg_size, 0);
        if (ret < 0) {
            ret = -errno;
            goto reply;
        }
    }

    /* FIXME in most of the following function we check that hdr.count is >=
     * than the command-specific struct and there is an additional recv(2) for
     * that data. We should eliminate duplicating this common code and move it
     * here.
     */

    if (migration_is_stop_and_copy(lm_ctx)
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
            handle_device_get_info(lm_ctx, &dev_info);
            _iovecs[1].iov_base = &dev_info;
            _iovecs[1].iov_len = dev_info.argsz;
            iovecs = _iovecs;
            nr_iovecs = 2;
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
        assert(false); /* FIXME */
    }
    ret = _send_vfio_user_msg(lm_ctx->conn_fd, hdr.msg_id, true,
                             0, iovecs, nr_iovecs, NULL, 0);
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

static int validate_irq_subindex(lm_ctx_t *lm_ctx, uint32_t subindex)
{

    if ((lm_ctx == NULL) || (subindex >= lm_ctx->irqs.max_ivs)) {
        lm_log(lm_ctx, LM_ERR, "bad IRQ %d, max=%d\n", subindex,
               lm_ctx->irqs.max_ivs);
        /* FIXME should return -errno */
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

    ret = validate_irq_subindex(lm_ctx, subindex);
    if (ret < 0) {
        return ret;
    }

    if (lm_ctx->irqs.efds[subindex] == -1) {
        lm_log(lm_ctx, LM_ERR, "no fd for interrupt %d\n", subindex);
        /* FIXME should return -errno */
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

    ret = validate_irq_subindex(lm_ctx, subindex);
    if (ret < 0) {
        return -1;
    }

    irq_info.subindex = subindex;
    ret = send_recv_vfio_user_msg(lm_ctx->conn_fd, msg_id,
                                  VFIO_USER_VM_INTERRUPT,
                                  &irq_info, sizeof irq_info,
                                  NULL, 0, NULL, NULL, 0);
    if (ret < 0) {
        /* FIXME should return -errno */
	    errno = -ret;
	    return -1;
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

void
lm_ctx_destroy(lm_ctx_t *lm_ctx)
{

    if (lm_ctx == NULL) {
        return;
    }

    free(lm_ctx->uuid);
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

static int
pci_config_setup(lm_ctx_t *lm_ctx, const lm_dev_info_t *dev_info)
{
    lm_reg_info_t *cfg_reg;
    const lm_reg_info_t zero_reg = { 0 };
    lm_reg_info_t *migr_reg;
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

    /*
     * Check the migration region.
     */
    migr_reg = &lm_ctx->pci_info.reg_info[LM_DEV_MIGRATION_REG_IDX];
    if (migr_reg->size > 0) {
        if (migr_reg->size < sizeof(struct vfio_device_migration_info)) {
            return -EINVAL;
        }

        /* FIXME this should be done in lm_ctx_run or poll */
        lm_ctx->migration.info.device_state = VFIO_DEVICE_STATE_RUNNING; 

        lm_ctx->migration.callbacks = dev_info->migration_callbacks;
        if (lm_ctx->migration.callbacks.transition == NULL ||
            lm_ctx->migration.callbacks.get_pending_bytes == NULL ||
            lm_ctx->migration.callbacks.prepare_data == NULL ||
            lm_ctx->migration.callbacks.read_data == NULL ||
            lm_ctx->migration.callbacks.write_data == NULL) {
            return -EINVAL;
        }
    }

    return 0;

err:
    free(lm_ctx->pci_config_space);
    lm_ctx->pci_config_space = NULL;

    return -1;
}

static void
pci_info_bounce(lm_pci_info_t *dst, const lm_pci_info_t *src)
{
    int i;

    for (i = 0; i < LM_DEV_NUM_IRQS; i++) {
        dst->irq_count[i] = src->irq_count[i];
    }

    for (i = 0; i < LM_DEV_NUM_REGS; i++) {
        dst->reg_info[i].flags = src->reg_info[i].flags;
        dst->reg_info[i].size  = src->reg_info[i].size;
        dst->reg_info[i].fn    = src->reg_info[i].fn;
        dst->reg_info[i].map   = src->reg_info[i].map;
        // Sparse map data copied by copy_sparse_mmap_areas().
    }

    dst->id = src->id;
    dst->ss = src->ss;
    dst->cc = src->cc;
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

    if (dev_info->trans != LM_TRANS_SOCK) {
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
    pci_info_bounce(&lm_ctx->pci_info, &dev_info->pci_info);

    /*
     * FIXME above memcpy also copies reg_info->mmap_areas. If pci_config_setup
     * fails then we try to free reg_info->mmap_areas, which is wrong because
     * this is a user pointer.
     */
    for (i = 0; i < ARRAY_SIZE(lm_ctx->pci_info.reg_info); i++) {
        lm_ctx->pci_info.reg_info[i].mmap_areas = NULL;
    }

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
    ret = send_recv_vfio_user_msg(lm_ctx->conn_fd, msg_id, VFIO_USER_DMA_READ,
                                  &dma_send, sizeof dma_send, NULL, 0, NULL,
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
    ret = send_recv_vfio_user_msg(lm_ctx->conn_fd, msg_id, VFIO_USER_DMA_WRITE,
                                  dma_send, send_size,
                                  NULL, 0, NULL, &dma_recv, sizeof(dma_recv));
    free(dma_send);

    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
