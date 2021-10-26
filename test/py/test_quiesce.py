#
# Copyright (c) 2021 Nutanix Inc. All rights reserved.
#
# Authors: Thanos Makatos <thanos.makatos@nutanix.com>
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

from libvfio_user import *
import errno
from unittest.mock import patch


ctx = None


def setup_function(function):
    global ctx, sock
    ctx = prepare_ctx_for_dma()
    assert ctx is not None
    sock = connect_client(ctx)


def teardown_function(function):
    global ctx
    vfu_destroy_ctx(ctx)


@patch('libvfio_user.quiesce_cb')
def test_device_quiesced_no_quiesce_requested(mock_quiesce):
    """Checks that vfu_device_quiesce returns an error if called when there is
    no pending quiesce operation."""

    global ctx
    ret = vfu_device_quiesced(ctx, 0)
    assert ret == -1
    assert c.get_errno() == errno.EINVAL
    assert mock_quiesce.call_count == 0


@patch('libvfio_user.quiesce_cb')
def test_device_quiesce_error(mock_quiesce):
    """Checks that if the device quiesce callbacks fails then the operation
    that requested it also fails with the same error."""

    global ctx, sock

    mock_quiesce.return_value = -errno.ENOTTY

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, errno.ENOTTY)


@patch('libvfio_user.quiesce_cb')
def test_device_quiesce_error_after_busy(mock_quiesce):

    global ctx, sock

    mock_quiesce.return_value = -errno.EBUSY

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, rsp=False)

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.EBUSY

    ret = vfu_device_quiesced(ctx, errno.ENOTTY)
    assert ret == -1
    assert c.get_errno() == errno.ENOTTY


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
