/*
 * Copyright (c) 2020 Nutanix Inc. All rights reserved.
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "migration.h"
#include "private.h"
#include "migration_priv.h"

/*
 * This defines valid migration state transitions. Each element in the array
 * corresponds to a FROM state and each bit of the element to a TO state. If the
 * bit is set, then the transition is allowed.
 * 
 * The indices of each state are those in the vfio_user_device_mig_state enum.
 */
static const char transitions[VFIO_USER_DEVICE_NUM_STATES] = {
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
static const uint32_t
next_state[VFIO_USER_DEVICE_NUM_STATES][VFIO_USER_DEVICE_NUM_STATES] = {
    [VFIO_USER_DEVICE_STATE_ERROR] = { 0, 0, 0, 0, 0, 0, 0, 0 },
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
        [VFIO_USER_DEVICE_STATE_PRE_COPY] = VFIO_USER_DEVICE_STATE_ERROR,
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
    [VFIO_USER_DEVICE_STATE_RUNNING_P2P] = { 0, 0, 0, 0, 0, 0, 0, 0 },
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
    [VFIO_USER_DEVICE_STATE_PRE_COPY_P2P] = { 0, 0, 0, 0, 0, 0, 0, 0 },
};

bool
MOCK_DEFINE(vfio_migr_state_transition_is_valid)(uint32_t from, uint32_t to)
{
    return from < VFIO_USER_DEVICE_NUM_STATES
        && to < VFIO_USER_DEVICE_NUM_STATES
        && (transitions[from] & (1 << to)) != 0;
}

/*
 * TODO no need to dynamically allocate memory, we can keep struct migration
 * in vfu_ctx_t.
 */
struct migration *
init_migration(const vfu_migration_callbacks_t *callbacks, int *err)
{
    struct migration *migr;

    migr = calloc(1, sizeof(*migr));
    if (migr == NULL) {
        *err = ENOMEM;
        return NULL;
    }

    /*
     * FIXME: incorrect, if the client doesn't give a pgsize value, it means "no
     * migration support", handle this
     * FIXME must be available even if migration callbacks aren't used
     */
    migr->pgsize = sysconf(_SC_PAGESIZE);

    /* FIXME this should be done in vfu_ctx_realize */
    migr->state = VFIO_USER_DEVICE_STATE_RUNNING;

    migr->callbacks = *callbacks;
    if (migr->callbacks.transition == NULL ||
        migr->callbacks.read_data == NULL ||
        migr->callbacks.write_data == NULL ||
        migr->callbacks.version != VFU_MIGR_CALLBACKS_VERS) {
        free(migr);
        *err = EINVAL;
        return NULL;
    }

    return migr;
}

void
MOCK_DEFINE(migr_state_transition)(struct migration *migr,
                                   enum vfio_user_device_mig_state state)
{
    assert(migr != NULL);
    migr->state = state;
}

vfu_migr_state_t
MOCK_DEFINE(migr_state_vfio_to_vfu)(enum vfio_user_device_mig_state state)
{
    switch (state) {
        case VFIO_USER_DEVICE_STATE_STOP:
            return VFU_MIGR_STATE_STOP;
        case VFIO_USER_DEVICE_STATE_RUNNING:
            return VFU_MIGR_STATE_RUNNING;
        case VFIO_USER_DEVICE_STATE_STOP_COPY:
            return VFU_MIGR_STATE_STOP_AND_COPY;
        case VFIO_USER_DEVICE_STATE_RESUMING:
            return VFU_MIGR_STATE_RESUME;
        case VFIO_USER_DEVICE_STATE_PRE_COPY:
            return VFU_MIGR_STATE_PRE_COPY;
        default:
            return -1;
    }
}

/**
 * Returns 0 on success, -1 on error setting errno.
 */
int
MOCK_DEFINE(state_trans_notify)(vfu_ctx_t *vfu_ctx,
                                 int (*fn)(vfu_ctx_t *, vfu_migr_state_t),
                                 uint32_t vfio_device_state)
{
    /*
     * We've already checked that device_state is valid by calling
     * vfio_migr_state_transition_is_valid.
     */
    return fn(vfu_ctx, migr_state_vfio_to_vfu(vfio_device_state));
}

/**
 * Returns 0 on success, -1 on failure setting errno.
 */
ssize_t
MOCK_DEFINE(migr_trans_to_valid_state)(vfu_ctx_t *vfu_ctx, struct migration *migr,
                                       uint32_t device_state, bool notify)
{
    if (notify) {
        int ret;
        assert(!vfu_ctx->in_cb);
        vfu_ctx->in_cb = CB_MIGR_STATE;
        ret = state_trans_notify(vfu_ctx, migr->callbacks.transition,
                                 device_state);
        vfu_ctx->in_cb = CB_NONE;

        if (ret != 0) {
            return ret;
        }
    }
    migr_state_transition(migr, device_state);
    return 0;
}

/**
 * Returns 0 on success, -1 on failure setting errno.
 */
ssize_t
MOCK_DEFINE(handle_device_state)(vfu_ctx_t *vfu_ctx, struct migration *migr,
                                 uint32_t device_state, bool notify)
{

    assert(vfu_ctx != NULL);
    assert(migr != NULL);

    if (!vfio_migr_state_transition_is_valid(migr->state, device_state)) {
        return ERROR_INT(EINVAL);
    }
    return migr_trans_to_valid_state(vfu_ctx, migr, device_state, notify);
}

size_t
migration_get_state(vfu_ctx_t *vfu_ctx)
{
    return vfu_ctx->migration->state;
}

ssize_t
migration_set_state(vfu_ctx_t *vfu_ctx, uint32_t device_state)
{
    struct migration *migr = vfu_ctx->migration;
    uint32_t state;
    ssize_t ret = 0;
    
    if (device_state > VFIO_USER_DEVICE_NUM_STATES) {
        return ERROR_INT(EINVAL);
    }
    
    while (migr->state != device_state && ret == 0) {
        state = next_state[migr->state][device_state];

        if (state == VFIO_USER_DEVICE_STATE_ERROR) {
            return ERROR_INT(EINVAL);
        }

        ret = handle_device_state(vfu_ctx, migr, state, true);
    };
    
    return ret;
}

ssize_t
handle_mig_data_read(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    if (msg->in.iov.iov_len < sizeof(struct vfio_user_mig_data)) {
        return ERROR_INT(EINVAL);
    }

    struct migration *migr = vfu_ctx->migration;
    struct vfio_user_mig_data *req = msg->in.iov.iov_base;

    if (vfu_ctx->migration == NULL) {
        return ERROR_INT(EINVAL);
    }

    if (migr->state != VFIO_USER_DEVICE_STATE_PRE_COPY
        && migr->state != VFIO_USER_DEVICE_STATE_STOP_COPY) {
        vfu_log(vfu_ctx, LOG_ERR, "bad migration state to read data: %d",
                migr->state);
        return ERROR_INT(EINVAL);
    }

    if (req->size > vfu_ctx->client_max_data_xfer_size) {
        vfu_log(vfu_ctx, LOG_ERR, "transfer size exceeds limit (%d > %ld)",
                req->size, vfu_ctx->client_max_data_xfer_size);
        return ERROR_INT(EINVAL);
    }

    if (req->argsz < sizeof(struct vfio_user_mig_data) + req->size) {
        vfu_log(vfu_ctx, LOG_ERR, "argsz too small (%d < %ld)",
                req->argsz, sizeof(struct vfio_user_mig_data) + req->size);
        return ERROR_INT(EINVAL);
    }

    msg->out.iov.iov_len = msg->in.iov.iov_len + req->size;
    msg->out.iov.iov_base = calloc(1, msg->out.iov.iov_len);

    if (msg->out.iov.iov_base == NULL) {
        return ERROR_INT(ENOMEM);
    }

    struct vfio_user_mig_data *res = msg->out.iov.iov_base;

    ssize_t ret = migr->callbacks.read_data(vfu_ctx, &res->data, req->size);

    if (ret < 0) {
        msg->out.iov.iov_len = 0;
        return ret;
    }

    res->size = ret;
    res->argsz = sizeof(struct vfio_user_mig_data) + ret;

    return 0;
}

ssize_t
handle_mig_data_write(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    if (msg->in.iov.iov_len < sizeof(struct vfio_user_mig_data)) {
        return ERROR_INT(EINVAL);
    }

    struct migration *migr = vfu_ctx->migration;
    struct vfio_user_mig_data *req = msg->in.iov.iov_base;

    if (vfu_ctx->migration == NULL) {
        return ERROR_INT(EINVAL);
    }

    if (migr->state != VFIO_USER_DEVICE_STATE_RESUMING) {
        vfu_log(vfu_ctx, LOG_ERR, "bad migration state to write data: %d",
                migr->state);
        return ERROR_INT(EINVAL);
    }

    if (req->size > vfu_ctx->client_max_data_xfer_size) {
        vfu_log(vfu_ctx, LOG_ERR, "transfer size exceeds limit (%d > %ld)",
                req->size, vfu_ctx->client_max_data_xfer_size);
        return ERROR_INT(EINVAL);
    }

    if (req->argsz < sizeof(struct vfio_user_mig_data) + req->size) {
        vfu_log(vfu_ctx, LOG_ERR, "argsz too small (%d < %ld)",
                req->argsz, sizeof(struct vfio_user_mig_data) + req->size);
        return ERROR_INT(EINVAL);
    }

    ssize_t ret = migr->callbacks.write_data(vfu_ctx, &req->data, req->size);

    if (ret < 0) {
        return ret;
    }

    return 0;
}

bool
MOCK_DEFINE(device_is_stopped_and_copying)(struct migration *migr)
{
    return migr != NULL && migr->state == VFIO_USER_DEVICE_STATE_STOP_COPY;
}

bool
MOCK_DEFINE(device_is_stopped)(struct migration *migr)
{
    return migr != NULL && migr->state == VFIO_USER_DEVICE_STATE_STOP;
}

size_t
migration_get_pgsize(struct migration *migr)
{
    assert(migr != NULL);

    return migr->pgsize;
}

int
migration_set_pgsize(struct migration *migr, size_t pgsize)
{
    assert(migr != NULL);

    // FIXME?
    if (pgsize != PAGE_SIZE) {
        return ERROR_INT(EINVAL);
    }

    migr->pgsize = pgsize;
    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
