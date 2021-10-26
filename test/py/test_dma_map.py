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
from unittest.mock import patch

from libvfio_user import *
import errno

#
# NB: this is currently very incomplete
#

ctx = None


def setup_function(function):
    global ctx, sock
    ctx = prepare_ctx_for_dma()
    assert ctx is not None
    sock = connect_client(ctx)


def teardown_function(function):
    global ctx, sock
    disconnect_client(ctx, sock)
    vfu_destroy_ctx(ctx)


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


@patch('libvfio_user.quiesce_cb', return_value=-errno.EBUSY)
def test_dma_map_busy(mock_quiesce):
    global ctx, sock

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, rsp=False)

    vfu_run_ctx(ctx, errno.EBUSY)

    vfu_device_quiesced(ctx, 0)

    get_reply(sock)

    ret = vfu_run_ctx(ctx)
    assert ret == 0


# FIXME need the same test for (1) DMA unmap, (2) device reset, and
# (3) migration, where quiesce returns EBUSY but replying fails.
@patch('libvfio_user.reset_cb')
@patch('libvfio_user.quiesce_cb', return_value=-errno.EBUSY)
def test_dma_map_busy_reply_fail(mock_quiesce, mock_reset):
    """Tests mapping a DMA region where the quiesce callback returns EBUSY and
    replying fails."""

    global ctx, sock

    # Send a DMA map command.
    payload = vfio_user_dma_map(
        argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload,
                     rsp=False)

    vfu_run_ctx(ctx, errno.EBUSY)

    # TODO check that quiesce has been called

    # pretend there's a connection failure while the device is still quiescing
    sock.close()

    # device reset callback should not have been called so far
    assert mock_reset.call_count == 0

    # device quiesces
    vfu_device_quiesced(ctx, 0)

    # device reset callback should be called
    mock_reset.assert_has_calls([mock.call(ctx, True)])

    vfu_run_ctx(ctx, errno.ENOTCONN)


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
