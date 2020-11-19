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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "muser.h"
#include "muser_priv.h"
#include "tran_sock.h"
#include "migration.h"

#define MAX_FDS 8

static inline int
recv_blocking(int sock, void *buf, size_t len, int flags)
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
        goto out;
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

int
_send_vfio_user_msg(int sock, uint16_t msg_id, bool is_reply,
                    enum vfio_user_command cmd,
                    struct iovec *iovecs, size_t nr_iovecs,
                    int *fds, int count, int err)
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
        // FIXME: SPEC: should the reply include the command? I'd say yes?
        hdr.flags.type = VFIO_USER_F_TYPE_REPLY;
        if (err != 0) {
            hdr.flags.error = 1U;
            hdr.error_no = err;
        }
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

    // FIXME: this doesn't check the entire data was sent?
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
                   int *fds, size_t count)
{
    /* [0] is for the header. */
    struct iovec iovecs[2] = {
        [1] = {
            .iov_base = data,
            .iov_len = data_len
        }
    };
    return _send_vfio_user_msg(sock, msg_id, is_reply, cmd, iovecs,
                               ARRAY_SIZE(iovecs), fds, count, 0);
}

/*
 * Receive a vfio-user message.  If "len" is set to non-zero, the message should
 * include data of that length, which is stored in the pre-allocated "data"
 * pointer.
 *
 * FIXME: in general, sort out negative err returns - they should only be used
 * when we're going to return > 0 on success, and even then "errno" might be
 * better.
 */
int
recv_vfio_user_msg(int sock, struct vfio_user_header *hdr, bool is_reply,
                   uint16_t *msg_id, void *data, size_t *len)
{
    int ret;

    /* FIXME if ret == -1 then fcntl can overwrite recv's errno */

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

/*
 * Like recv_vfio_user_msg(), but will automatically allocate reply data.
 *
 * FIXME: this does an unconstrained alloc of client-supplied data.
 */
int
recv_vfio_user_msg_alloc(int sock, struct vfio_user_header *hdr, bool is_reply,
                         uint16_t *msg_id, void **datap, size_t *lenp)
{
    void *data;
    size_t len;
    int ret;

    ret = recv_vfio_user_msg(sock, hdr, is_reply, msg_id, NULL, NULL);

    if (ret != 0) {
        return ret;
    }

    assert(hdr->msg_size >= sizeof (*hdr));

    len = hdr->msg_size - sizeof (*hdr);

    if (len == 0) {
        *datap = NULL;
        *lenp = 0;
        return 0;
    }

    data = calloc(1, len);

    if (data == NULL) {
        return -errno;
    }

    ret = recv_blocking(sock, data, len, 0);
    if (ret < 0) {
        free(data);
        return -errno;
    }

    if (len != (size_t)ret) {
        free(data);
        return -EINVAL;
    }

    *datap = data;
    *lenp = len;
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
                                  send_fds, fd_count, 0);
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
    /* [0] is for the header. */
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

int
recv_version(lm_ctx_t *lm_ctx, int sock, uint16_t *msg_idp,
             struct vfio_user_version **versionp)
{
    struct vfio_user_version *cversion = NULL;
    struct vfio_user_header hdr;
    size_t vlen = 0;
    int ret;

    *versionp = NULL;

    ret = recv_vfio_user_msg_alloc(sock, &hdr, false, msg_idp,
                                   (void **)&cversion, &vlen);

    if (ret < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to receive version: %s", strerror(-ret));
        goto out;
    }

    if (hdr.cmd != VFIO_USER_VERSION) {
        lm_log(lm_ctx, LM_ERR, "msg%hx: invalid cmd %hu (expected %hu)",
               *msg_idp, hdr.cmd, VFIO_USER_VERSION);
        ret = -EINVAL;
        goto out;
    }

    if (vlen < sizeof (*cversion)) {
        lm_log(lm_ctx, LM_ERR, "msg%hx (VFIO_USER_VERSION): invalid size %lu",
               *msg_idp, vlen);
        ret = -EINVAL;
        goto out;
    }

    /* FIXME: oracle qemu code has major of 1 currently */
#if 0
    if (cversion->major != LIB_MUSER_VFIO_USER_VERS_MJ) {
        lm_log(lm_ctx, LM_ERR, "unsupported client major %hu (must be %hu)",
               cversion->major, LIB_MUSER_VFIO_USER_VERS_MJ);
        ret = -ENOTSUP;
        goto out;
    }
#endif

    lm_ctx->client_max_fds = 1;

    if (vlen > sizeof (*cversion)) {
        lm_log(lm_ctx, LM_DBG, "ignoring JSON \"%s\"", cversion->data);
        // FIXME: don't ignore it.
        lm_ctx->client_max_fds = 128;
    }

out:
    if (ret != 0) {
        free(cversion);
        cversion = NULL;
    }

    *versionp = cversion;
    return ret;
}

int
send_version(lm_ctx_t *lm_ctx, int sock, uint16_t msg_id,
             struct vfio_user_version *cversion)
{
    struct vfio_user_version *sversion = NULL;
    char *server_caps = NULL;
    size_t len;
    int ret;

    ret = asprintf(&server_caps, "{"
                   "\"capabilities\":{"
                       "\"max_fds\":%u,"
                       "\"migration\":{"
                           "\"pgsize\":%zu"
                       "}"
                   "}"
               "}", MAX_FDS, migration_get_pgsize(lm_ctx->migration));

    if (ret == -1) {
        ret = -ENOMEM;
        goto out;
    }

    len = sizeof (*sversion) + ret + 1;
    sversion = calloc(1, len);

    if (sversion == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    // FIXME: we should save the client minor here, and check that before trying
    // to send unsupported things.
    sversion->major =  LIB_MUSER_VFIO_USER_VERS_MJ;
    sversion->minor = MIN(cversion->minor, LIB_MUSER_VFIO_USER_VERS_MN);

    // FIXME: strcpy sucks
    strcpy(((char *)sversion) + offsetof(struct vfio_user_version, data),
           server_caps);

    ret = send_vfio_user_msg(sock, msg_id, true, VFIO_USER_VERSION, sversion,
                             len, NULL, 0);

out:
    free(server_caps);
    free(sversion);
    return ret;
}

static int
negotiate(lm_ctx_t *lm_ctx, int sock)
{
    struct vfio_user_version *client_version = NULL;
    uint16_t msg_id;
    int ret;

    ret = recv_version(lm_ctx, sock, &msg_id, &client_version);

    if (ret < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to recv version: %s", strerror(-ret));
        return ret;
    }

    ret = send_version(lm_ctx, sock, msg_id, client_version);

    free(client_version);

    if (ret < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to send version: %s", strerror(-ret));
    }

    return ret;
}

/**
 * lm_ctx: libmuser context
 * FIXME: this shouldn't be happening as part of lm_ctx_create().
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

    ret = negotiate(lm_ctx, conn_fd);
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

struct transport_ops sock_transport_ops = {
    .init = init_sock,
    .attach = open_sock,
    .detach = close_sock,
    .get_request = get_request_sock,
};

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
