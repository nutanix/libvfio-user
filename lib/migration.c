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

#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "migration.h"

enum migr_iter_state {
    VFIO_USER_MIGR_ITER_STATE_INITIAL,
    VFIO_USER_MIGR_ITER_STATE_STARTED,
    VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED,
    VFIO_USER_MIGR_ITER_STATE_FINISHED
};

struct migration {
    struct vfio_device_migration_info info;
    size_t pgsize;
    lm_migration_callbacks_t callbacks;
    struct {
        enum migr_iter_state state;
        __u64 offset;
        __u64 size;
    } iter;
};

/* valid migration state transitions */
static const __u32 migr_states[VFIO_DEVICE_STATE_MASK] = {
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

struct migration*
init_migration(size_t size, const lm_migration_callbacks_t * const migr_callbacks)
{
    struct migration *migr;

    if (size < sizeof(struct vfio_device_migration_info)) {
        errno = EINVAL;
        return NULL;
    }

    migr = calloc(1, sizeof *migr);
    if (migr == NULL) {
        return NULL;
    }

    /*
     * FIXME: incorrect, if the client doesn't give a pgsize value, it means "no
     * migration support", handle this
     */
    migr->pgsize = sysconf(_SC_PAGESIZE);


    /* FIXME this should be done in lm_ctx_run or poll */
    migr->info.device_state = VFIO_DEVICE_STATE_RUNNING; 

    migr->callbacks = *migr_callbacks;
    if (migr->callbacks.transition == NULL ||
        migr->callbacks.get_pending_bytes == NULL ||
        migr->callbacks.prepare_data == NULL ||
        migr->callbacks.read_data == NULL ||
        migr->callbacks.write_data == NULL) {
        free(migr);
        errno = EINVAL;
        return NULL;
    }
    return migr;
}

static bool
_migr_state_transition_is_valid(__u32 from, __u32 to)
{
    return migr_states[from] & (1 << to);
}

static ssize_t
handle_device_state(lm_ctx_t *lm_ctx, void *pvt,
                              struct migration *migr, __u32 *device_state,
                              bool is_write) {

    int ret;

    assert(migr != NULL);
    assert(device_state != NULL);

    if (!is_write) {
        *device_state = migr->info.device_state;
        return 0;
    }

    if (*device_state & ~VFIO_DEVICE_STATE_MASK) {
        lm_log(lm_ctx, LM_ERR, "bad device state %#x", *device_state);
        return -EINVAL;
    }

    if (!_migr_state_transition_is_valid(migr->info.device_state,
                                              *device_state)) {
        /* TODO print descriptive device state names instead of raw value */
        lm_log(lm_ctx, LM_ERR, "bad transition from state %d to state %d",
               migr->info.device_state, *device_state);
        return -EINVAL;
    }

    switch (*device_state) {
        case VFIO_DEVICE_STATE_STOP:
            ret = migr->callbacks.transition(pvt, LM_MIGR_STATE_STOP);
            break;
        case VFIO_DEVICE_STATE_RUNNING:
            ret = migr->callbacks.transition(pvt, LM_MIGR_STATE_RUNNING);
            break;
        case VFIO_DEVICE_STATE_SAVING:
            /*
             * FIXME How should the device operate during the stop-and-copy
             * phase? Should we only allow the migration data to be read from
             * the migration region? E.g. Access to any other region should be
             * failed? This might be a good question to send to LKML.
             */
            ret = migr->callbacks.transition(pvt, LM_MIGR_STATE_STOP_AND_COPY);
            break;
        case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
            ret = migr->callbacks.transition(pvt, LM_MIGR_STATE_PRE_COPY);
            break;
        case VFIO_DEVICE_STATE_RESUMING:
            ret = migr->callbacks.transition(pvt, LM_MIGR_STATE_RESUME);
            break;
        default:
            assert(false);
    }

    if (ret == 0) {
        migr->info.device_state = *device_state;
    } else if (ret < 0) {
        lm_log(lm_ctx, LM_ERR, "failed to transition to state %d: %s",
               *device_state, strerror(-ret));
    }

    return ret;
}

static ssize_t
handle_pending_bytes(void *pvt, struct migration *migr,
                     __u64 *pending_bytes, bool is_write)
{
    assert(migr != NULL);
    assert(pending_bytes != NULL);

    if (is_write) {
        return -EINVAL;
    }

    if (migr->iter.state == VFIO_USER_MIGR_ITER_STATE_FINISHED) {
        *pending_bytes = 0;
        return 0;
    }

    *pending_bytes = migr->callbacks.get_pending_bytes(pvt);

    switch (migr->iter.state) {
        case VFIO_USER_MIGR_ITER_STATE_INITIAL:
        case VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED:
            /*
             * FIXME what happens if data haven't been consumed in the previous
             * iteration? Ask on LKML.
             */
            if (*pending_bytes == 0) {
                migr->iter.state = VFIO_USER_MIGR_ITER_STATE_FINISHED;
            } else {
                migr->iter.state = VFIO_USER_MIGR_ITER_STATE_STARTED;
            }
            break;
        case VFIO_USER_MIGR_ITER_STATE_STARTED:
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

/*
 * FIXME reading or writing migration registers with the wrong device state or
 * out of sequence is undefined, but should not result in EINVAL, it should
 * simply be ignored. However this way it's easier to catch development errors.
 * Make this behavior conditional.
 */

static ssize_t
handle_data_offset_when_saving(lm_ctx_t *lm_ctx, void *pvt,
                               struct migration *migr, bool is_write)
{
    int ret = 0;

    assert(migr != NULL);

    if (is_write) {
        lm_log(lm_ctx, LM_ERR, "data_offset is RO when saving");
        return -EINVAL;
    }

    switch (migr->iter.state) {
    case VFIO_USER_MIGR_ITER_STATE_STARTED:
        ret = migr->callbacks.prepare_data(pvt, &migr->iter.offset,
                                           &migr->iter.size);
        if (ret < 0) {
            return ret;
        }
        break;
    case VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED:
        /*
         * data_offset is invariant during an iteration.
         */
        break;
    default:
        lm_log(lm_ctx, LM_ERR, "reading data_offset out of sequence is undefined");
        return -EINVAL;
    }

    return 0;
}

static ssize_t
handle_data_offset(lm_ctx_t *lm_ctx, void *pvt, struct migration *migr,
                   __u64 *offset, bool is_write)
{
    int ret;

    assert(migr != NULL);
    assert(offset != NULL);

    switch (migr->info.device_state) {
    case VFIO_DEVICE_STATE_SAVING:
    case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
        ret = handle_data_offset_when_saving(lm_ctx, pvt, migr, is_write);
        break;
    case VFIO_DEVICE_STATE_RESUMING:
        if (is_write) {
            lm_log(lm_ctx, LM_ERR, "bad write to migration data_offset");
            ret = -EINVAL;
        } else {
            ret = 0;
        }
        break;
    default:
        /* TODO improve error message */
        lm_log(lm_ctx, LM_ERR, "bad access to migration data_offset in state %d",
                migr->info.device_state);
        ret = -EINVAL;
    }

    if (ret == 0 && !is_write) {
        *offset = migr->iter.offset + sizeof(struct vfio_device_migration_info);
    }

    return ret;
}

static ssize_t
handle_data_size_when_saving(lm_ctx_t *lm_ctx, struct migration *migr,
                             bool is_write)
{
    assert(migr != NULL);

    if (is_write) {
        /* TODO improve error message */
        lm_log(lm_ctx, LM_ERR, "data_size is RO when saving");
        return -EINVAL;
    }

    if (migr->iter.state != VFIO_USER_MIGR_ITER_STATE_STARTED &&
        migr->iter.state != VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED) {
        lm_log(lm_ctx, LM_ERR, "reading data_size ouf of sequence is undefined");
        return -EINVAL;
    }
    return 0;
}

static ssize_t
handle_data_size_when_resuming(void *pvt, struct migration *migr,
                               __u64 size, bool is_write)
{
    int ret = 0;

    assert(migr != NULL);

    if (is_write) {
        ret = migr->callbacks.data_written(pvt, size, migr->info.data_offset);
        migr->info.data_size = size;
        migr->info.data_offset += size;
    }
    return ret;
}

static ssize_t
handle_data_size(lm_ctx_t *lm_ctx, void *pvt, struct migration *migr,
                 __u64 *size, bool is_write)
{
    int ret;

    assert(lm_ctx != NULL);
    assert(size != NULL);

    switch (migr->info.device_state){
    case VFIO_DEVICE_STATE_SAVING:
    case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
        ret = handle_data_size_when_saving(lm_ctx, migr, is_write);
        break;
    case VFIO_DEVICE_STATE_RESUMING:
        ret = handle_data_size_when_resuming(pvt, migr, *size, is_write);
        break;
    default:
        /* TODO improve error message */
        lm_log(lm_ctx, LM_ERR, "bad access to data_size");
        ret = -EINVAL;
    }

    if (ret == 0 && !is_write) {
        *size = migr->iter.size;
    }

    return 0;
}

static ssize_t
handle_region_access_registers(lm_ctx_t *lm_ctx, void *pvt,
                               struct migration *migr, char *buf, size_t count,
                               loff_t pos, bool is_write)
{
    int ret;

    assert(migr != NULL);

    switch (pos) {
    case offsetof(struct vfio_device_migration_info, device_state):
        if (count != sizeof(migr->info.device_state)) {
            lm_log(lm_ctx, LM_ERR, "bad device_state access size %d", count);
            return -EINVAL;
        }
        ret = handle_device_state(lm_ctx, pvt, migr, (__u32*)buf, is_write);
        break;
    case offsetof(struct vfio_device_migration_info, pending_bytes):
        if (count != sizeof(migr->info.pending_bytes)) {
            lm_log(lm_ctx, LM_ERR, "bad pending_bytes access size %d", count);
            return -EINVAL;
        }
        ret = handle_pending_bytes(pvt, migr, (__u64*)buf, is_write);
        break;
    case offsetof(struct vfio_device_migration_info, data_offset):
        if (count != sizeof(migr->info.data_offset)) {
            lm_log(lm_ctx, LM_ERR, "bad data_offset access size %d", count);
            return -EINVAL;
        }
        ret = handle_data_offset(lm_ctx, pvt, migr, (__u64*)buf, is_write);
        break;
    case offsetof(struct vfio_device_migration_info, data_size):
        if (count != sizeof(migr->info.data_size)) {
            lm_log(lm_ctx, LM_ERR, "bad data_size access size %d", count);
            return -EINVAL;
        }
        ret = handle_data_size(lm_ctx, pvt, migr, (__u64*)buf, is_write);
        break;
    default:
        lm_log(lm_ctx, LM_ERR, "bad migration region register offset %#lx",
               pos);
        return -EINVAL;
    }
    return ret;
}

ssize_t
handle_migration_region_access(lm_ctx_t *lm_ctx, void *pvt,
                               struct migration *migr,
                               char *buf, size_t count,
                               loff_t pos, bool is_write)
{
    int ret = -EINVAL;

    assert(migr != NULL);
    assert(buf != NULL);
    
    if (pos + count <= sizeof(struct vfio_device_migration_info)) {
        ret = handle_region_access_registers(lm_ctx, pvt, migr, buf,
                                                       count, pos, is_write);
    } else {
        pos -= sizeof(struct vfio_device_migration_info);
        if (is_write) {
            ret = migr->callbacks.write_data(pvt, buf, count, pos);
        } else {
            ret = migr->callbacks.read_data(pvt, buf, count, pos);
        }
    }

    if (ret == 0) {
        ret = count;
    }
    return ret;
}

bool
device_is_stopped_and_copying(struct migration *migr)
{
    return migr != NULL && migr->info.device_state == VFIO_DEVICE_STATE_SAVING;
}

bool
device_is_stopped(struct migration *migr)
{
    return migr != NULL && migr->info.device_state == VFIO_DEVICE_STATE_STOP;
}

size_t
migration_get_pgsize(struct migration *migr)
{
    assert(migr != NULL);

    return migr->pgsize;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
