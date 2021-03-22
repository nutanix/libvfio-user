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

/* FIXME no need to use __u32 etc., use uint32_t etc */


bool
vfio_migr_state_transition_is_valid(__u32 from, __u32 to)
{
    return migr_states[from].state & (1 << to);
}

size_t
vfu_get_migr_register_area_size(void)
{
    return ROUND_UP(sizeof(struct vfio_device_migration_info),
                    sysconf(_SC_PAGE_SIZE));
}

/*
 * TODO no need to dynamically allocate memory, we can keep struct migration
 * in vfu_ctx_t.
 */
struct migration *
init_migration(const vfu_migration_callbacks_t * callbacks,
               uint64_t data_offset, int *err)
{
    struct migration *migr;

    if (data_offset < vfu_get_migr_register_area_size()) {
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
     * FIXME must be available even if migration callbacks aren't used
     */
    migr->pgsize = sysconf(_SC_PAGESIZE);

    /* FIXME this should be done in vfu_ctx_realize */
    migr->info.device_state = VFIO_DEVICE_STATE_RUNNING;
    migr->data_offset = data_offset;

    migr->callbacks = *callbacks;
    if (migr->callbacks.transition == NULL ||
        migr->callbacks.get_pending_bytes == NULL ||
        migr->callbacks.prepare_data == NULL ||
        migr->callbacks.read_data == NULL ||
        migr->callbacks.write_data == NULL) {
        free(migr);
        *err = EINVAL;
        return NULL;
    }

    return migr;
}

static void
migr_state_transition(struct migration *migr, enum migr_iter_state state)
{
    assert(migr != NULL);
    /* FIXME validate that state transition */
    migr->iter.state = state;
}

static ssize_t
handle_device_state(vfu_ctx_t *vfu_ctx, struct migration *migr,
                    __u32 *device_state, bool is_write) {

    int ret;

    assert(migr != NULL);
    assert(device_state != NULL);

    if (!is_write) {
        *device_state = migr->info.device_state;
        return 0;
    }

    if (*device_state & ~VFIO_DEVICE_STATE_MASK) {
        vfu_log(vfu_ctx, LOG_ERR, "bad device state %#x", *device_state);
        return -EINVAL;
    }

    if (!vfio_migr_state_transition_is_valid(migr->info.device_state,
                                              *device_state)) {
        vfu_log(vfu_ctx, LOG_ERR, "bad transition from state %s to state %s",
               migr_states[migr->info.device_state].name,
               migr_states[*device_state].name);
        return -EINVAL;
    }

    switch (*device_state) {
        case VFIO_DEVICE_STATE_STOP:
            ret = migr->callbacks.transition(vfu_ctx, VFU_MIGR_STATE_STOP);
            break;
        case VFIO_DEVICE_STATE_RUNNING:
            ret = migr->callbacks.transition(vfu_ctx, VFU_MIGR_STATE_RUNNING);
            break;
        case VFIO_DEVICE_STATE_SAVING:
            /*
             * FIXME How should the device operate during the stop-and-copy
             * phase? Should we only allow the migration data to be read from
             * the migration region? E.g. Access to any other region should be
             * failed? This might be a good question to send to LKML.
             */
            ret = migr->callbacks.transition(vfu_ctx,
                                             VFU_MIGR_STATE_STOP_AND_COPY);
            break;
        case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
            ret = migr->callbacks.transition(vfu_ctx, VFU_MIGR_STATE_PRE_COPY);
            break;
        case VFIO_DEVICE_STATE_RESUMING:
            ret = migr->callbacks.transition(vfu_ctx, VFU_MIGR_STATE_RESUME);
            break;
        default:
            assert(false);
    }

    if (ret == 0) {
        migr->info.device_state = *device_state;
        migr_state_transition(migr, VFIO_USER_MIGR_ITER_STATE_INITIAL);
    } else if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to transition to state %d: %s",
                *device_state, strerror(-ret));
    }

    return ret;
}

// FIXME: no need to use __u* type variants

static ssize_t
handle_pending_bytes(vfu_ctx_t *vfu_ctx, struct migration *migr,
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

    switch (migr->iter.state) {
        case VFIO_USER_MIGR_ITER_STATE_INITIAL:
        case VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED:
            /*
             * FIXME what happens if data haven't been consumed in the previous
             * iteration? Check https://www.spinics.net/lists/kvm/msg228608.html.
             */
            *pending_bytes = migr->iter.pending_bytes = migr->callbacks.get_pending_bytes(vfu_ctx);

            if (*pending_bytes == 0) {
                migr_state_transition(migr, VFIO_USER_MIGR_ITER_STATE_FINISHED);
            } else {
                migr_state_transition(migr, VFIO_USER_MIGR_ITER_STATE_STARTED);
            }
            break;
        case VFIO_USER_MIGR_ITER_STATE_STARTED:
            /*
             * FIXME We might be wrong returning a cached value, check
             * https://www.spinics.net/lists/kvm/msg228608.html
             *
             */
            *pending_bytes = migr->iter.pending_bytes;
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
handle_data_offset_when_saving(vfu_ctx_t *vfu_ctx, struct migration *migr,
                               bool is_write)
{
    int ret = 0;

    assert(migr != NULL);

    if (is_write) {
        vfu_log(vfu_ctx, LOG_ERR, "data_offset is RO when saving");
        return -EINVAL;
    }

    switch (migr->iter.state) {
    case VFIO_USER_MIGR_ITER_STATE_STARTED:
        ret = migr->callbacks.prepare_data(vfu_ctx, &migr->iter.offset,
                                           &migr->iter.size);
        if (ret < 0) {
            return ret;
        }
        /*
         * FIXME must first read data_offset and then data_size. They way we've
         * implemented it now, if data_size is read before data_offset we
         * transition to state VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED without
         * calling callbacks.prepare_data, which is wrong. Maybe we need
         * separate states for data_offset and data_size.
         */
        migr_state_transition(migr, VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED);
        break;
    case VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED:
        /*
         * data_offset is invariant during a save iteration.
         */
        break;
    default:
        vfu_log(vfu_ctx, LOG_ERR,
                "reading data_offset out of sequence is undefined");
        return -EINVAL;
    }

    return 0;
}

static ssize_t
handle_data_offset(vfu_ctx_t *vfu_ctx, struct migration *migr,
                   __u64 *offset, bool is_write)
{
    int ret;

    assert(migr != NULL);
    assert(offset != NULL);

    switch (migr->info.device_state) {
    case VFIO_DEVICE_STATE_SAVING:
    case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
        ret = handle_data_offset_when_saving(vfu_ctx, migr, is_write);
        if (ret == 0 && !is_write) {
            *offset = migr->iter.offset + migr->data_offset;
        }
        return ret;
    case VFIO_DEVICE_STATE_RESUMING:
        if (is_write) {
            /* TODO writing to read-only registers should be simply ignored */
            vfu_log(vfu_ctx, LOG_ERR, "bad write to migration data_offset");
            return -EINVAL;
        }
        ret = migr->callbacks.prepare_data(vfu_ctx, offset, NULL);
        if (ret < 0) {
            return ret;
        }
        *offset += migr->data_offset;
        return 0;
    }
    /* TODO improve error message */
    vfu_log(vfu_ctx, LOG_ERR,
            "bad access to migration data_offset in state %s",
            migr_states[migr->info.device_state].name);
    return -EINVAL;
}

static ssize_t
handle_data_size_when_saving(vfu_ctx_t *vfu_ctx, struct migration *migr,
                             bool is_write)
{
    assert(migr != NULL);

    if (is_write) {
        /* TODO improve error message */
        vfu_log(vfu_ctx, LOG_ERR, "data_size is RO when saving");
        return -EINVAL;
    }

    if (migr->iter.state != VFIO_USER_MIGR_ITER_STATE_STARTED &&
        migr->iter.state != VFIO_USER_MIGR_ITER_STATE_DATA_PREPARED) {
        vfu_log(vfu_ctx, LOG_ERR,
                "reading data_size ouf of sequence is undefined");
        return -EINVAL;
    }
    return 0;
}

static ssize_t
handle_data_size_when_resuming(vfu_ctx_t *vfu_ctx, struct migration *migr,
                               __u64 size, bool is_write)
{
    assert(migr != NULL);

    if (is_write) {
        return  migr->callbacks.data_written(vfu_ctx, size);
    }
    return 0;
}

static ssize_t
handle_data_size(vfu_ctx_t *vfu_ctx, struct migration *migr,
                 __u64 *size, bool is_write)
{
    int ret;

    assert(vfu_ctx != NULL);
    assert(size != NULL);

    switch (migr->info.device_state){
    case VFIO_DEVICE_STATE_SAVING:
    case VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING:
        ret = handle_data_size_when_saving(vfu_ctx, migr, is_write);
        if (ret == 0 && !is_write) {
            *size = migr->iter.size;
        }
        return ret;
    case VFIO_DEVICE_STATE_RESUMING:
        return handle_data_size_when_resuming(vfu_ctx, migr, *size, is_write);
    }
    /* TODO improve error message */
    vfu_log(vfu_ctx, LOG_ERR, "bad access to data_size");
    return -EINVAL;
}

static ssize_t
migration_region_access_registers(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                                  loff_t pos, bool is_write)
{
    struct migration *migr = vfu_ctx->migration;
    int ret;

    assert(migr != NULL);

    switch (pos) {
    case offsetof(struct vfio_device_migration_info, device_state):
        if (count != sizeof(migr->info.device_state)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "bad device_state access size %ld", count);
            return -EINVAL;
        }
        ret = handle_device_state(vfu_ctx, migr, (__u32*)buf, is_write);
        break;
    case offsetof(struct vfio_device_migration_info, pending_bytes):
        if (count != sizeof(migr->info.pending_bytes)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "bad pending_bytes access size %ld", count);
            return -EINVAL;
        }
        ret = handle_pending_bytes(vfu_ctx, migr, (__u64*)buf, is_write);
        break;
    case offsetof(struct vfio_device_migration_info, data_offset):
        if (count != sizeof(migr->info.data_offset)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "bad data_offset access size %ld", count);
            return -EINVAL;
        }
        ret = handle_data_offset(vfu_ctx, migr, (__u64*)buf, is_write);
        break;
    case offsetof(struct vfio_device_migration_info, data_size):
        if (count != sizeof(migr->info.data_size)) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "bad data_size access size %ld", count);
            return -EINVAL;
        }
        ret = handle_data_size(vfu_ctx, migr, (__u64*)buf, is_write);
        break;
    default:
        vfu_log(vfu_ctx, LOG_ERR, "bad migration region register offset %#lx",
               pos);
        return -EINVAL;
    }
    return ret;
}

ssize_t
migration_region_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
                        loff_t pos, bool is_write)
{
    struct migration *migr = vfu_ctx->migration;
    ssize_t ret = -EINVAL;

    assert(migr != NULL);
    assert(buf != NULL);

    /*
     * FIXME don't call the device callback if the migration state is in not in
     * pre-copy/stop-and-copy/resuming state, since the behavior is undefined
     * in that case.
     */

    if (pos + count <= sizeof(struct vfio_device_migration_info)) {
        ret = migration_region_access_registers(vfu_ctx, buf, count,
                                                pos, is_write);
    } else {

        if (pos < (loff_t)migr->data_offset) {
            /*
             * TODO we can simply ignore the access to that part and handle
             * any access to the data region properly.
             */
            vfu_log(vfu_ctx, LOG_WARNING,
                    "bad access to dead space %#lx-%#lx in migration region",
                    pos, pos + count - 1);
            return -EINVAL;
        }

        pos -= migr->data_offset;
        if (is_write) {
            ret = migr->callbacks.write_data(vfu_ctx, buf, count, pos);
            if (ret == -1) {
                ret = -errno;
            }
        } else {
            /*
             * FIXME <linux/vfio.h> says:
             *
             *  d. Read data_size bytes of data from (region + data_offset) from the
             *     migration region.
             *
             * Does this mean that partial reads are not allowed?
             */
            ret = migr->callbacks.read_data(vfu_ctx, buf, count, pos);
            if (ret == -1) {
                ret = -errno;
            }
        }
    }

    if (ret == 0) {
        ret = count;
    }
    return ret;
}

bool
MOCK_DEFINE(device_is_stopped_and_copying)(struct migration *migr)
{
    return migr != NULL && migr->info.device_state == VFIO_DEVICE_STATE_SAVING;
}

bool
MOCK_DEFINE(device_is_stopped)(struct migration *migr)
{
    return migr != NULL && migr->info.device_state == VFIO_DEVICE_STATE_STOP;
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
        return -EINVAL;
    }

    migr->pgsize = pgsize;
    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
