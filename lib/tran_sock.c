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
#include <json.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "libvfio-user.h"
#include "migration.h"
#include "private.h"
#include "tran_sock.h"

// FIXME: is this the value we want?
#define SERVER_MAX_FDS 8

static inline int
recv_blocking(int sock, void *buf, size_t len, int flags)
{
    int f = fcntl(sock, F_GETFL, 0);
    int ret, fret;

    fret = fcntl(sock, F_SETFL, f & ~O_NONBLOCK);
    assert(fret != -1);

    // FIXME: be more explicit about EOF

    ret = recv(sock, buf, len, flags);

    fret = fcntl(sock, F_SETFL, f);
    assert(fret != -1);

    return ret;
}

static int
init_sock(vu_ctx_t *vu_ctx)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int ret, unix_sock;
    mode_t mode;

    assert(vu_ctx != NULL);

    /* FIXME SPDK can't easily run as non-root */
    mode =  umask(0000);

    if ((unix_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	    ret = -errno;
        goto out;
    }

    if (vu_ctx->flags & LIBVFIO_USER_FLAG_ATTACH_NB) {
        ret = fcntl(unix_sock, F_SETFL,
                    fcntl(unix_sock, F_GETFL, 0) | O_NONBLOCK);
        if (ret < 0) {
            ret = -errno;
            goto out;
        }
        vu_ctx->sock_flags = MSG_DONTWAIT | MSG_WAITALL;
    } else {
        vu_ctx->sock_flags = 0;
    }

    ret = snprintf(addr.sun_path, sizeof addr.sun_path, "%s", vu_ctx->uuid);
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
        if (unix_sock >= 0) {
            close(unix_sock);
        }
        return ret;
    }
    return unix_sock;
}

int
vu_send_iovec(int sock, uint16_t msg_id, bool is_reply,
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
vu_send(int sock, uint16_t msg_id, bool is_reply,
        enum vfio_user_command cmd,
        void *data, size_t data_len)
{
    /* [0] is for the header. */
    struct iovec iovecs[2] = {
        [1] = {
            .iov_base = data,
            .iov_len = data_len
        }
    };
    return vu_send_iovec(sock, msg_id, is_reply, cmd, iovecs,
                         ARRAY_SIZE(iovecs), NULL, 0, 0);
}

int
send_vfio_user_error(int sock, uint16_t msg_id,
                     enum vfio_user_command cmd,
                     int error)
{
    return vu_send_iovec(sock, msg_id, true, cmd,
                         NULL, 0, NULL, 0, error);
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
vu_recv(int sock, struct vfio_user_header *hdr, bool is_reply,
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
 * Like vu_recv(), but will automatically allocate reply data.
 *
 * FIXME: this does an unconstrained alloc of client-supplied data.
 */
int
vu_recv_alloc(int sock, struct vfio_user_header *hdr, bool is_reply,
              uint16_t *msg_id, void **datap, size_t *lenp)
{
    void *data;
    size_t len;
    int ret;

    ret = vu_recv(sock, hdr, is_reply, msg_id, NULL, NULL);

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

/*
 * FIXME: all these send/recv handlers need to be made robust against async
 * messages.
 */
int
vu_msg_iovec(int sock, uint16_t msg_id, enum vfio_user_command cmd,
             struct iovec *iovecs, size_t nr_iovecs,
             int *send_fds, size_t fd_count,
             struct vfio_user_header *hdr,
             void *recv_data, size_t recv_len)
{
    int ret = vu_send_iovec(sock, msg_id, false, cmd, iovecs, nr_iovecs,
                            send_fds, fd_count, 0);
    if (ret < 0) {
        return ret;
    }
    if (hdr == NULL) {
        hdr = alloca(sizeof *hdr);
    }
    return vu_recv(sock, hdr, true, &msg_id, recv_data, &recv_len);
}

int
vu_msg(int sock, uint16_t msg_id, enum vfio_user_command cmd,
       void *send_data, size_t send_len,
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
    return vu_msg_iovec(sock, msg_id, cmd, iovecs, ARRAY_SIZE(iovecs),
                        NULL, 0, hdr, recv_data, recv_len);
}

/*
 * Expected JSON is of the form:
 *
 * {
 *     "capabilities": {
 *         "max_fds": 32,
 *         "migration": {
 *             "pgsize": 4096
 *         }
 *     }
 * }
 *
 * with everything being optional. Note that json_object_get_uint64() is only
 * available in newer library versions, so we don't use it.
 */
int
vu_parse_version_json(const char *json_str,
                      int *client_max_fdsp, size_t *pgsizep)
{
    struct json_object *jo_caps = NULL;
    struct json_object *jo_top = NULL;
    struct json_object *jo = NULL;
    int ret = -EINVAL;

    if ((jo_top = json_tokener_parse(json_str)) == NULL) {
        goto out;
    }

    if (!json_object_object_get_ex(jo_top, "capabilities", &jo_caps)) {
        ret = 0;
        goto out;
    }

    if (json_object_get_type(jo_caps) != json_type_object) {
        goto out;
    }

    if (json_object_object_get_ex(jo_caps, "max_fds", &jo)) {
        if (json_object_get_type(jo) != json_type_int) {
            goto out;
        }

        errno = 0;
        *client_max_fdsp = (int)json_object_get_int64(jo);

        if (errno != 0) {
            goto out;
        }
    }

    if (json_object_object_get_ex(jo_caps, "migration", &jo)) {
        struct json_object *jo2 = NULL;

        if (json_object_get_type(jo) != json_type_object) {
            goto out;
        }

        if (json_object_object_get_ex(jo, "pgsize", &jo2)) {
            if (json_object_get_type(jo2) != json_type_int) {
                goto out;
            }

            errno = 0;
            *pgsizep = (size_t)json_object_get_int64(jo2);

            if (errno != 0) {
                goto out;
            }
        }
    }

    ret = 0;

out:
    /* We just need to put our top-level object. */
    json_object_put(jo_top);
    return ret;
}

int
recv_version(vu_ctx_t *vu_ctx, int sock, uint16_t *msg_idp,
             struct vfio_user_version **versionp)
{
    struct vfio_user_version *cversion = NULL;
    struct vfio_user_header hdr;
    size_t vlen = 0;
    int ret;

    *versionp = NULL;

    ret = vu_recv_alloc(sock, &hdr, false, msg_idp,
                        (void **)&cversion, &vlen);

    if (ret < 0) {
        vu_log(vu_ctx, VU_ERR, "failed to receive version: %s", strerror(-ret));
        return ret;
    }

    if (hdr.cmd != VFIO_USER_VERSION) {
        vu_log(vu_ctx, VU_ERR, "msg%hx: invalid cmd %hu (expected %hu)",
               *msg_idp, hdr.cmd, VFIO_USER_VERSION);
        ret = -EINVAL;
        goto out;
    }

    if (vlen < sizeof (*cversion)) {
        vu_log(vu_ctx, VU_ERR, "msg%hx (VFIO_USER_VERSION): invalid size %lu",
               *msg_idp, vlen);
        ret = -EINVAL;
        goto out;
    }

    if (cversion->major != LIB_VFIO_USER_MAJOR) {
        vu_log(vu_ctx, VU_ERR, "unsupported client major %hu (must be %hu)",
               cversion->major, LIB_VFIO_USER_MAJOR);
        ret = -ENOTSUP;
        goto out;
    }

    vu_ctx->client_max_fds = 1;

    if (vlen > sizeof (*cversion)) {
        const char *json_str = (const char *)cversion->data;
        size_t len = vlen - sizeof (*cversion);
        size_t pgsize = 0;

        if (json_str[len - 1] != '\0') {
            vu_log(vu_ctx, VU_ERR, "ignoring invalid JSON from client");
            ret = -EINVAL;
            goto out;
        }

        ret = vu_parse_version_json(json_str, &vu_ctx->client_max_fds,
                                    &pgsize);

        if (ret < 0) {
            /* No client-supplied strings in the log for release build. */
#ifdef DEBUG
            vu_log(vu_ctx, VU_ERR, "failed to parse client JSON \"%s\"",
                   json_str);
#else
            vu_log(vu_ctx, VU_ERR, "failed to parse client JSON");
#endif
            goto out;
        }

        if (vu_ctx->migration != NULL && pgsize != 0) {
            ret = migration_set_pgsize(vu_ctx->migration, pgsize);

            if (ret != 0) {
                vu_log(vu_ctx, VU_ERR, "refusing client page size of %zu",
                       pgsize);
                goto out;
            }
        }

        // FIXME: is the code resilient against ->client_max_fds == 0?
        if (vu_ctx->client_max_fds < 0 ||
            vu_ctx->client_max_fds > VFIO_USER_CLIENT_MAX_FDS_LIMIT) {
            vu_log(vu_ctx, VU_ERR, "refusing client max_fds of %d",
                   vu_ctx->client_max_fds);
            ret = -EINVAL;
            goto out;
        }
    }

out:
    if (ret != 0) {
        // FIXME: spec, is it OK to just have the header?
        (void) send_vfio_user_error(sock, *msg_idp, hdr.cmd, ret);
        free(cversion);
        cversion = NULL;
    }

    *versionp = cversion;
    return ret;
}

int
send_version(vu_ctx_t *vu_ctx, int sock, uint16_t msg_id,
             struct vfio_user_version *cversion)
{
    struct vfio_user_version sversion = { 0 };
    struct iovec iovecs[3] = { { 0 } };
    char server_caps[1024];
    int slen;

    if (vu_ctx->migration == NULL) {
        slen = snprintf(server_caps, sizeof (server_caps),
            "{"
                "\"capabilities\":{"
                    "\"max_fds\":%u"
                "}"
             "}", SERVER_MAX_FDS);
    } else {
        slen = snprintf(server_caps, sizeof (server_caps),
            "{"
                "\"capabilities\":{"
                    "\"max_fds\":%u,"
                    "\"migration\":{"
                        "\"pgsize\":%zu"
                    "}"
                "}"
             "}", SERVER_MAX_FDS, migration_get_pgsize(vu_ctx->migration));
    }

    // FIXME: we should save the client minor here, and check that before trying
    // to send unsupported things.
    sversion.major =  LIB_VFIO_USER_MAJOR;
    sversion.minor = MIN(cversion->minor, LIB_VFIO_USER_MINOR);

    /* [0] is for the header. */
    iovecs[1].iov_base = &sversion;
    iovecs[1].iov_len = sizeof (sversion);
    iovecs[2].iov_base = server_caps;
    /* Include the NUL. */
    iovecs[2].iov_len = slen + 1;

    return vu_send_iovec(sock, msg_id, true, VFIO_USER_VERSION,
                         iovecs, ARRAY_SIZE(iovecs), NULL, 0, 0);
}

static int
negotiate(vu_ctx_t *vu_ctx, int sock)
{
    struct vfio_user_version *client_version = NULL;
    uint16_t msg_id = 1;
    int ret;

    ret = recv_version(vu_ctx, sock, &msg_id, &client_version);

    if (ret < 0) {
        vu_log(vu_ctx, VU_ERR, "failed to recv version: %s", strerror(-ret));
        return ret;
    }

    ret = send_version(vu_ctx, sock, msg_id, client_version);

    free(client_version);

    if (ret < 0) {
        vu_log(vu_ctx, VU_ERR, "failed to send version: %s", strerror(-ret));
    }

    return ret;
}

/**
 * vu_ctx: libvfio-user context
 * FIXME: this shouldn't be happening as part of vu_ctx_create().
 */
static int
open_sock(vu_ctx_t *vu_ctx)
{
    int ret;
    int conn_fd;

    assert(vu_ctx != NULL);

    conn_fd = accept(vu_ctx->fd, NULL, NULL);
    if (conn_fd == -1) {
        return conn_fd;
    }

    ret = negotiate(vu_ctx, conn_fd);
    if (ret < 0) {
        close(conn_fd);
        return ret;
    }

    vu_ctx->conn_fd = conn_fd;
    return conn_fd;
}

static int
close_sock(vu_ctx_t *vu_ctx)
{
    return close(vu_ctx->conn_fd);
}

static int
get_request_sock(vu_ctx_t *vu_ctx, struct vfio_user_header *hdr,
                 int *fds, int *nr_fds)
{
    int ret;
    struct iovec iov = {.iov_base = hdr, .iov_len = sizeof *hdr};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    struct cmsghdr *cmsg;

    msg.msg_controllen = CMSG_SPACE(sizeof(int) * *nr_fds);
    msg.msg_control = alloca(msg.msg_controllen);

    *nr_fds = 0;

    /*
     * TODO ideally we should set O_NONBLOCK on the fd so that the syscall is
     * faster (?). I tried that and get short reads, so we need to store the
     * partially received buffer somewhere and retry.
     */
    ret = recvmsg(vu_ctx->conn_fd, &msg, vu_ctx->sock_flags);
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
