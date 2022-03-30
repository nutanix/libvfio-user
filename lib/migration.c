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
    return migr_states[from].state & (1 << to);
}

/*
 * TODO no need to dynamically allocate memory, we can keep struct migration
 * in vfu_ctx_t.
 */
struct migration *
init_migration(const vfu_migration_callbacks_t * callbacks,
               uint64_t flags, int *err)
{
    struct migration *migr;

    if (flags & ~(VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_P2P)) {
        *err = EINVAL;
        return NULL;
    }

    migr = calloc(1, sizeof(*migr));
    if (migr == NULL) {
        *err = ENOMEM;
        return NULL;
    }

    /*
     * FIXME: incorrect, if the client doesn't give a pgsize value, it means "no
     * migration support", handle this
     */
    migr->pgsize = sysconf(_SC_PAGESIZE);

    migr->state = VFIO_DEVICE_STATE_STOP;

    migr->callbacks = *callbacks;
    if (migr->callbacks.transition == NULL ||
        migr->callbacks.read_data == NULL ||
        migr->callbacks.write_data == NULL) {
        free(migr);
        *err = EINVAL;
        return NULL;
    }

    migr->flags = flags;

    return migr;
}

vfu_migr_state_t
migr_state_vfio_to_vfu(uint32_t device_state)
{
    switch (device_state) {
        case VFIO_DEVICE_STATE_STOP:
            return VFU_MIGR_STATE_STOP;
        case VFIO_DEVICE_STATE_RUNNING:
            return VFU_MIGR_STATE_RUNNING;
        case VFIO_DEVICE_STATE_SAVING:
            /*
             * FIXME How should the device operate during the stop-and-copy
             * phase? Should we only allow the migration data to be read from
             * the migration region? E.g. Access to any other region should be
             * failed? This might be a good question to send to LKML.
             */
            return VFU_MIGR_STATE_STOP_AND_COPY;
        case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
            return VFU_MIGR_STATE_PRE_COPY;
        case VFIO_DEVICE_STATE_RESUMING:
            return VFU_MIGR_STATE_RESUME;
    }
    return -1;
}

/**
 * Returns 0 on success, -1 on error setting errno.
 */
int
state_trans_notify(vfu_ctx_t *vfu_ctx,
                   int (*fn)(vfu_ctx_t *, vfu_migr_state_t),
                   enum vfio_device_mig_state state)
{
    /*
     * We've already checked that device_state is valid by calling
     * vfio_migr_state_transition_is_valid.
     */
    return fn(vfu_ctx, migr_state_vfio_to_vfu(state));
}

/**
 * Returns 0 on success, -1 on failure setting errno.
 */
ssize_t
migr_trans_to_valid_state(vfu_ctx_t *vfu_ctx, struct migration *migr,
                          enum vfio_device_mig_state state, bool notify)
{
    if (notify) {
        int ret;
        assert(!vfu_ctx->in_cb);
        vfu_ctx->in_cb = CB_MIGR_STATE;
        ret = state_trans_notify(vfu_ctx, migr->callbacks.transition, state);
        vfu_ctx->in_cb = CB_NONE;

        if (ret != 0) {
            return ret;
        }
    }
    migr->state = state;
    return 0;
}

/**
 * Returns 0 on success, -1 on failure setting errno.
 */
ssize_t
handle_device_state(vfu_ctx_t *vfu_ctx, struct migration *migr,
                    enum vfio_device_mig_state state, bool notify)
{

    assert(migr != NULL);

    if (!vfio_migr_state_transition_is_valid(migr->state, state)) {
        return ERROR_INT(EINVAL);
    }
    return migr_trans_to_valid_state(vfu_ctx, migr, state, notify);
}

bool
device_is_stopped_and_copying(struct migration *migr)
{
    return migr != NULL && migr->state == VFIO_DEVICE_STATE_SAVING;
}

bool
device_is_stopped(struct migration *migr)
{
    return migr != NULL && migr->state == VFIO_DEVICE_STATE_STOP;
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

uint64_t
migration_get_flags(struct migration *migr)
{
    assert(migr != NULL);
    return migr->flags;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
