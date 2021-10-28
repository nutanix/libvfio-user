#
# Copyright (c) 2021 Nutanix Inc. All rights reserved.
#
# Authors: Thanos Makatos <thanos@nutanix.com>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of Nutanix nor the names of its contributors may be
#        used to endorse or promote products derived from this software without
#        specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
#  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#

from libvfio_user import *
import ctypes as c
import errno
from unittest.mock import patch

ctx = None
sock = 0


def trans_cb(ctx, state):
    return 0


# TODO use mock
@transition_cb_t
def __trans_cb(ctx, state):
    return trans_cb(ctx, state)


def setup_function(function):
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_MIGR_REGION_IDX, size=0x2000,
                           flags=VFU_REGION_FLAG_RW)
    assert ret == 0

    @c.CFUNCTYPE(c.c_int)
    def stub():
        return 0

    cbs = vfu_migration_callbacks_t()
    cbs.version = VFU_MIGR_CALLBACKS_VERS
    cbs.transition = __trans_cb
    cbs.get_pending_bytes = c.cast(stub, get_pending_bytes_cb_t)
    cbs.prepare_data = c.cast(stub, prepare_data_cb_t)
    cbs.read_data = c.cast(stub, read_data_cb_t)
    cbs.write_data = c.cast(stub, write_data_cb_t)
    cbs.data_written = c.cast(stub, data_written_cb_t)

    ret = vfu_setup_device_migration_callbacks(ctx, cbs, offset=0x4000)
    assert ret == 0

    ret = vfu_setup_device_quiesce_cb(ctx)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)


def teardown_function(function):
    global ctx
    vfu_destroy_ctx(ctx)


def test_migration_trans_sync():

    global ctx, sock

    data = VFIO_DEVICE_STATE_SAVING.to_bytes(c.sizeof(c.c_int), 'little')
    write_region(ctx, sock, VFU_PCI_DEV_MIGR_REGION_IDX, offset=0,
                 count=len(data), data=data)

    ret = vfu_run_ctx(ctx)
    assert ret == 0


@patch(__name__ + '.trans_cb', side_effect=fail_with_errno(errno.EPERM))
def test_migration_trans_sync_err(mock_trans):
    """Tests the device returning an error when the migration state is written
    to."""

    global ctx, sock

    data = VFIO_DEVICE_STATE_SAVING.to_bytes(c.sizeof(c.c_int), 'little')
    write_region(ctx, sock, VFU_PCI_DEV_MIGR_REGION_IDX, offset=0,
                 count=len(data), data=data, expect=errno.EPERM)

    ret = vfu_run_ctx(ctx)
    assert ret == 0


@patch('libvfio_user.quiesce_cb', side_effect=fail_with_errno(errno.EBUSY))
def test_migration_trans_async(mock_quiesce):

    global ctx, sock
    mock_quiesce

    data = VFIO_DEVICE_STATE_SAVING.to_bytes(c.sizeof(c.c_int), 'little')
    write_region(ctx, sock, VFU_PCI_DEV_MIGR_REGION_IDX, offset=0,
                 count=len(data), data=data, rsp=False)

    ret = vfu_run_ctx(ctx, errno.EBUSY)

    vfu_device_quiesced(ctx, 0)

    get_reply(sock)

    ret = vfu_run_ctx(ctx)
    assert ret == 0


@patch('libvfio_user.quiesce_cb', side_effect=fail_with_errno(errno.EBUSY))
@patch(__name__ + '.trans_cb', side_effect=fail_with_errno(errno.ENOTTY))
def test_migration_trans_async_err(mock_trans, mock_quiesce):
    """Tests writing to the migration state register, the device not being able
    to immediately quiesce, and then finally the device failing to transition
    to the new migration state."""

    global ctx, sock

    data = VFIO_DEVICE_STATE_RUNNING.to_bytes(c.sizeof(c.c_int), 'little')
    write_region(ctx, sock, VFU_PCI_DEV_MIGR_REGION_IDX, offset=0,
                 count=len(data), data=data, rsp=False)

    vfu_run_ctx(ctx, errno.EBUSY)

    vfu_device_quiesced(ctx, 0)

    get_reply(sock, errno.ENOTTY)

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
