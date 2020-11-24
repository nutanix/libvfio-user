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

#ifndef TRAN_SOCK_H
#define TRAN_SOCK_H

#include "muser.h"

/*
 * These are not public routines, but for convenience, they are used by the
 * sample/test code as well as privately within libmuser.
 *
 * Note there is currently only one transport - talking over a UNIX socket.
 */

/* The largest number of fd's we are prepared to receive. */
// FIXME: value?
#define MUSER_CLIENT_MAX_FDS_LIMIT (1024)

extern struct transport_ops sock_transport_ops;

int
parse_version_json(const char *json_str, int *client_max_fdsp, size_t *pgsizep);

int
_send_vfio_user_msg(int sock, uint16_t msg_id, bool is_reply,
                   enum vfio_user_command cmd,
                   struct iovec *iovecs, size_t nr_iovecs,
                   int *fds, int count, int err);

int
send_vfio_user_msg(int sock, uint16_t msg_id, bool is_reply,
                   enum vfio_user_command cmd,
                   void *data, size_t data_len,
                   int *fds, size_t count);


int
recv_vfio_user_msg(int sock, struct vfio_user_header *hdr, bool is_reply,
                   uint16_t *msg_id, void *data, size_t *len);

int
recv_vfio_user_msg_alloc(int sock, struct vfio_user_header *hdr, bool is_reply,
                   uint16_t *msg_id, void **datap, size_t *lenp);

int
_send_recv_vfio_user_msg(int sock, uint16_t msg_id, enum vfio_user_command cmd,
                         struct iovec *iovecs, size_t nr_iovecs,
                         int *send_fds, size_t fd_count,
                         struct vfio_user_header *hdr,
                         void *recv_data, size_t recv_len);

int
send_recv_vfio_user_msg(int sock, uint16_t msg_id, enum vfio_user_command cmd,
                        void *send_data, size_t send_len,
                        int *send_fds, size_t fd_count,
                        struct vfio_user_header *hdr,
                        void *recv_data, size_t recv_len);

#endif /* TRAN_SOCK_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
