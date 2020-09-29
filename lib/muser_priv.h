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

#ifndef MUSER_PRIV_H
#define MUSER_PRIV_H

#include "muser.h"

extern char *irq_to_str[];

int
muser_pci_hdr_access(lm_ctx_t *lm_ctx, size_t *count,
                     loff_t *pos, bool write, char *buf);

lm_reg_info_t *
lm_get_region_info(lm_ctx_t *lm_ctx);

uint64_t
region_to_offset(uint32_t region);

int
send_vfio_user_msg(int sock, uint16_t msg_id, bool is_reply,
                   enum vfio_user_command cmd, void *data, int len, int *fds,
                   int count);

int
recv_vfio_user_msg(int sock, struct vfio_user_header *hdr, bool is_reply,
                   uint16_t *msg_id, void *data, int *len);

int
send_version(int sock, int major, int minor, uint16_t msg_id, bool is_reply,
             char *caps);

int
recv_version(int sock, int *major, int *minor, uint16_t *msg_id, bool is_reply,
             int *max_fds);

int
send_recv_vfio_user_msg(int sock, uint16_t msg_id, enum vfio_user_command cmd,
                        void *send_data, int send_len,
                        int *send_fds, int fd_count,
                        struct vfio_user_header *hdr,
                        void *recv_data, int recv_len);

#endif /* MUSER_PRIV_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
