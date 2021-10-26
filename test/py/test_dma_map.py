#
# Copyright (c) 2021 Nutanix Inc. All rights reserved.
#
# Authors: John Levon <john.levon@nutanix.com>
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
#  SERVICESLOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#

from unittest import mock
from unittest.mock import patch, Mock, create_autospec

from libvfio_user import *
import errno

#
# NB: this is currently very incomplete
#

ctx = None
quiesce_cb_err = 0
mock_reset_cb = Mock(return_value=0)


@vfu_reset_cb_t
def reset_cb(ctx, reset_type):
    global mock_reset_cb
    return mock_reset_cb(ctx, reset_type)


@vfu_device_quiesce_cb_t
def quiesce_cb(ctx):
    global quiesce_cb_err
    if quiesce_cb_err != 0:
        c.set_errno(quiesce_cb_err)
        return -1
    return 0


def setup_function(function):
    global mock_quiesce_cb, ctx, sock
    mock_reset_cb.reset_mock()
    ctx = prepare_ctx_for_dma(quiesce=quiesce_cb, reset=reset_cb)
    assert ctx is not None
    sock = connect_client(ctx)


def teardown_function(function):
    global mock_quiesce_cb, ctx, sock, quiesce_cb_err
    disconnect_client(ctx, sock)
    quiesce_cb_err = 0
    mock_reset_cb.return_value = 0
    ret = vfu_destroy_ctx(ctx)
    assert ret == 0, "failed to destroy context, ret=%s, errno=%s" % (ret, c.get_errno())


def test_dma_region_too_big():
    global ctx, sock

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=MAX_DMA_SIZE + 4096)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, expect=errno.ENOSPC)




def test_dma_region_too_many():
    global ctx, sock

    for i in range(1, MAX_DMA_REGIONS + 2):
        payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
            flags=(VFIO_USER_F_DMA_REGION_READ |
                   VFIO_USER_F_DMA_REGION_WRITE),
            offset=0, addr=0x1000 * i, size=4096)

        if i == MAX_DMA_REGIONS + 1:
            expect = errno.EINVAL
        else:
            expect = 0

        msg(ctx, sock, VFIO_USER_DMA_MAP, payload, expect=expect)


def test_dma_map_busy():
    global ctx, sock, quiesce_cb_err
    quiesce_cb_err = errno.EBUSY

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, rsp=False)

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.EBUSY

    vfu_device_quiesced(ctx, 0)

    dma_register_cb_err = 0

    get_reply(sock)

    ret = vfu_run_ctx(ctx)
    assert ret == 0


# FIXME need the same test for (1) DMA unmap, (2) device reset, and
# (3) migration, where quiesce returns EBUSY but replying fails.
def test_dma_map_busy_reply_fail():
    """Tests mapping a DMA region where the quiesce callback returns EBUSY and replying fails."""

    global ctx, sock, quiesce_cb_err

    # Send a DMA map command.
    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    # device will be busy quiescing
    quiesce_cb_err = errno.EBUSY

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, rsp=False)

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.EBUSY

    # TODO check that quiesce has been called

    # pretend there's a connection failure while the device is still quiescing
    sock.close()

    # device reset callback should not have been called so far
    assert mock_reset_cb.call_count == 0

    # device quiesces
    vfu_device_quiesced(ctx, 0)

    # device reset callback should be called
    mock_reset_cb.assert_has_calls([mock.call(ctx, True)])

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.ENOTCONN


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
