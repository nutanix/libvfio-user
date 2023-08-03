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

bool
MOCK_DEFINE(vfio_migr_state_transition_is_valid)(uint32_t from, uint32_t to)
{
    return (transitions[from] & (1 << to)) != 0;
}

/*
 * TODO no need to dynamically allocate memory, we can keep struct migration
 * in vfu_ctx_t.
 */
struct migration *
init_migration(const vfu_migration_callbacks_t *callbacks,
               uint64_t flags, int *err)
{
    struct migration *migr;

    migr = calloc(1, sizeof(*migr));
    if (migr == NULL) {
        *err = ENOMEM;
        return NULL;
    }

    migr->flags = flags;

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
        migr->callbacks.write_data == NULL) {
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
    /* FIXME validate that state transition */
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
    migr_state_transition(migr, device_state); // TODO confused
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

bool
is_migration_feature(uint32_t feature) {
    switch (feature) {
        case VFIO_DEVICE_FEATURE_MIGRATION:
        case VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE:
            return true;
    }

    return false;
}

ssize_t
migration_feature_get(vfu_ctx_t *vfu_ctx, uint32_t feature, void *buf)
{
    assert(vfu_ctx != NULL);

    struct vfio_user_device_feature_migration *res;
    struct vfio_user_device_feature_mig_state *state;

    switch (feature) {
        case VFIO_DEVICE_FEATURE_MIGRATION:
            res = buf;
            // FIXME are these always supported? Can we consider to be
            // "supported" if said support is just an empty callback?
            //
            // We don't need to return RUNNING or ERROR since they are always
            // supported.
            res->flags = VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_PRE_COPY;

            return 0;
        case VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE:
            state = buf;
            state->device_state = vfu_ctx->migration->state;

            return 0;
        default:
            return -EINVAL;
    };
}

ssize_t
migration_feature_set(vfu_ctx_t *vfu_ctx, uint32_t feature, void *buf)
{
    assert(vfu_ctx != NULL);

    if (feature == VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE) {
        struct vfio_user_device_feature_mig_state *res = buf;
        struct migration *migr = vfu_ctx->migration;
        uint32_t state;
        ssize_t ret;
        
        do {
            state = next_state[migr->state][res->device_state];

            if (state == VFIO_USER_DEVICE_STATE_ERROR) {
                return -EINVAL;
            }

            ret = handle_device_state(vfu_ctx, migr, state, true);
        } while (migr->state != res->device_state && ret == 0);
        
        return ret;
    }

    return -EINVAL;
}

ssize_t
handle_mig_data_read(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    struct migration *migr = vfu_ctx->migration;
    struct vfio_user_mig_data *req = msg->in.iov.iov_base;

    if (vfu_ctx->migration == NULL) {
        return -EINVAL;
    }

    if (migr->state != VFIO_USER_DEVICE_STATE_PRE_COPY
        && migr->state != VFIO_USER_DEVICE_STATE_STOP_COPY) {
        vfu_log(vfu_ctx, LOG_ERR, "bad migration state to read data: %d",
                migr->state);
        return -EINVAL;
    }

    if (req->size > vfu_ctx->client_max_data_xfer_size) {
        vfu_log(vfu_ctx, LOG_ERR, "transfer size exceeds limit (%d > %ld)",
                req->size, vfu_ctx->client_max_data_xfer_size);
        return -EINVAL;
    }

    msg->out.iov.iov_len = msg->in.iov.iov_len + req->size;
    msg->out.iov.iov_base = calloc(1, msg->out.iov.iov_len);

    if (msg->out.iov.iov_base == NULL) {
        return -EINVAL;
    }

    struct vfio_user_mig_data *res = msg->out.iov.iov_base;

    ssize_t ret = migr->callbacks.read_data(vfu_ctx, &res->data, req->size);

    if (ret < 0) {
        msg->out.iov.iov_len = 0;
    } else {
        res->size = ret;
        res->argsz = sizeof(struct vfio_user_mig_data) + ret;
    }

    return ret;
}

ssize_t
handle_mig_data_write(vfu_ctx_t *vfu_ctx, vfu_msg_t *msg)
{
    assert(vfu_ctx != NULL);
    assert(msg != NULL);

    struct migration *migr = vfu_ctx->migration;
    struct vfio_user_mig_data *req = msg->in.iov.iov_base;

    if (vfu_ctx->migration == NULL) {
        return -EINVAL;
    }

    if (migr->state != VFIO_USER_DEVICE_STATE_RESUMING) {
        vfu_log(vfu_ctx, LOG_ERR, "bad migration state to write data: %d",
                migr->state);
        return -EINVAL;
    }

    return migr->callbacks.write_data(vfu_ctx, &req->data, req->size);
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
