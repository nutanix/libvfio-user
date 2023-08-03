/*
 * Copyright (c) 2021 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
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

#ifndef LIB_VFIO_USER_MIGRATION_PRIV_H
#define LIB_VFIO_USER_MIGRATION_PRIV_H

#include <linux/vfio.h>

struct migration {
    uint64_t flags;
    enum vfio_user_device_mig_state state;
    size_t pgsize;
    vfu_migration_callbacks_t callbacks;
};

/*
 * valid migration state transitions
 * each number corresponds to a FROM state and each bit a TO state
 * if the bit is set then the transition is allowed
 * the indices of each state are those in the vfio_user_device_mig_state enum
 */
static const char transitions[8] = {
    0b00000000, // ERROR        -> {}
    0b00011100, // STOP         -> {RUNNING, STOP_COPY, RESUMING}
    0b01000010, // RUNNING      -> {STOP, PRE_COPY}
    0b00000010, // STOP_COPY    -> {STOP}
    0b00000010, // RESUMING     -> {STOP}
    0b00000000, // RUNNING_P2P  -> {}
    0b00001100, // PRE_COPY     -> {RUNNING, STOP_COPY}
    0b00000000  // PRE_COPY_P2P -> {}
};

/*
 * The spec dictates that, if no direct transition is allowed, and the
 * transition is not one of the explicitly disallowed ones (i.e. anything to
 * ERROR, anything from ERROR, and STOP_COPY -> PRE_COPY), we should take the
 * shortest allowed path.
 * 
 * This can be indexed as `next_state[current][target] == next`. If next is
 * ERROR, then the transition is not allowed.
 */
static const uint32_t next_state[VFIO_USER_DEVICE_NUM_STATES][VFIO_USER_DEVICE_NUM_STATES] = {
    [VFIO_USER_DEVICE_STATE_ERROR] = {0, 0, 0, 0, 0, 0, 0, 0},
    [VFIO_USER_DEVICE_STATE_STOP] = {
        [VFIO_USER_DEVICE_STATE_ERROR] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_STOP] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RUNNING] = VFIO_USER_DEVICE_STATE_RUNNING,
        [VFIO_USER_DEVICE_STATE_STOP_COPY] = VFIO_USER_DEVICE_STATE_STOP_COPY,
        [VFIO_USER_DEVICE_STATE_RESUMING] = VFIO_USER_DEVICE_STATE_RESUMING,
        [VFIO_USER_DEVICE_STATE_RUNNING_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_PRE_COPY] = VFIO_USER_DEVICE_STATE_RUNNING,
        [VFIO_USER_DEVICE_STATE_PRE_COPY_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
    },
    [VFIO_USER_DEVICE_STATE_RUNNING] = {
        [VFIO_USER_DEVICE_STATE_ERROR] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_STOP] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RUNNING] = VFIO_USER_DEVICE_STATE_RUNNING,
        [VFIO_USER_DEVICE_STATE_STOP_COPY] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RESUMING] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RUNNING_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_PRE_COPY] = VFIO_USER_DEVICE_STATE_PRE_COPY,
        [VFIO_USER_DEVICE_STATE_PRE_COPY_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
    },
    [VFIO_USER_DEVICE_STATE_STOP_COPY] = {
        [VFIO_USER_DEVICE_STATE_ERROR] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_STOP] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RUNNING] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_STOP_COPY] = VFIO_USER_DEVICE_STATE_STOP_COPY,
        [VFIO_USER_DEVICE_STATE_RESUMING] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RUNNING_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_PRE_COPY] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_PRE_COPY_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
    },
    [VFIO_USER_DEVICE_STATE_RESUMING] = {
        [VFIO_USER_DEVICE_STATE_ERROR] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_STOP] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RUNNING] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_STOP_COPY] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_RESUMING] = VFIO_USER_DEVICE_STATE_RESUMING,
        [VFIO_USER_DEVICE_STATE_RUNNING_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_PRE_COPY] = VFIO_USER_DEVICE_STATE_STOP,
        [VFIO_USER_DEVICE_STATE_PRE_COPY_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
    },
    [VFIO_USER_DEVICE_STATE_RUNNING_P2P] = {0, 0, 0, 0, 0, 0, 0, 0},
    [VFIO_USER_DEVICE_STATE_PRE_COPY] = {
        [VFIO_USER_DEVICE_STATE_ERROR] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_STOP] = VFIO_USER_DEVICE_STATE_RUNNING,
        [VFIO_USER_DEVICE_STATE_RUNNING] = VFIO_USER_DEVICE_STATE_RUNNING,
        [VFIO_USER_DEVICE_STATE_STOP_COPY] = VFIO_USER_DEVICE_STATE_STOP_COPY,
        [VFIO_USER_DEVICE_STATE_RESUMING] = VFIO_USER_DEVICE_STATE_RUNNING,
        [VFIO_USER_DEVICE_STATE_RUNNING_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
        [VFIO_USER_DEVICE_STATE_PRE_COPY] = VFIO_USER_DEVICE_STATE_PRE_COPY,
        [VFIO_USER_DEVICE_STATE_PRE_COPY_P2P] = VFIO_USER_DEVICE_STATE_ERROR,
    },
    [VFIO_USER_DEVICE_STATE_PRE_COPY_P2P] = {0, 0, 0, 0, 0, 0, 0, 0},
};

MOCK_DECLARE(vfu_migr_state_t, migr_state_vfio_to_vfu, uint32_t device_state);

MOCK_DECLARE(int, state_trans_notify, vfu_ctx_t *vfu_ctx,
             int (*fn)(vfu_ctx_t *, vfu_migr_state_t),
             uint32_t vfio_device_state);

#endif

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */