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
import mmap


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
    """
    Checks that vfu_device_quiesce returns an error if called when there is
    no pending quiesce operation.
    """

    global ctx
    ret = vfu_device_quiesced(ctx, 0)
    assert ret == -1
    assert c.get_errno() == errno.EINVAL
    assert mock_quiesce.call_count == 0


@patch('libvfio_user.quiesce_cb', side_effect=fail_with_errno(errno.ENOTTY))
def test_device_quiesce_error(mock_quiesce):
    """
    Checks that if the device quiesce callback fails then the operation
    that requested it also fails with the same error.
    """

    global ctx, sock

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, errno.ENOTTY)


@patch('libvfio_user.dma_register')
@patch('libvfio_user.quiesce_cb', side_effect=fail_with_errno(errno.EBUSY))
def test_device_quiesce_error_after_busy(mock_quiesce, mock_dma_register):
    """
    Checks that the device fails to quiesce after it was busy quiescing.
    """

    global ctx, sock

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, rsp=False,
        expect_run_ctx_errno=errno.EBUSY)

    ret = vfu_device_quiesced(ctx, errno.ENOTTY)
    assert ret == 0

    mock_dma_register.assert_not_called()

    # check that the DMA region was NOT added
    count, sgs = vfu_addr_to_sg(ctx, 0x10000, 0x1000)
    assert count == -1
    assert c.get_errno() == errno.ENOENT


@patch('libvfio_user.dma_register')
@patch('libvfio_user.quiesce_cb', side_effect=fail_with_errno(errno.EBUSY))
def test_allowed_funcs_in_quiesce(mock_quiesce, mock_dma_register):
    """
    Tests that vfu_addr_to_sg, vfu_map_sg, and vfu_unmap_sg can be called by
    device callbacks even if the device is quiesced.
    """

    def side_effect(ctx, info):
        count, sgs = vfu_addr_to_sg(ctx, 0x1000, 0x1000)
        assert count == 1
        sg = sgs[0]
        assert sg.dma_addr == 0x10000 and sg.region == 0 \
            and sg.length == 0x1000 and sg.offset == 0 and sg.writeable
        ret = vfu_map_sg(ctx, sg, iovec)
        assert ret == 0
        assert iovec[0].iov_base != 0
        assert iovec[0].iov_len == 0x1000
        assert ret == 0
        vfu_unmap_sg(ctx, sg, iovec)
    mock_dma_register.side_effect = side_effect

    global ctx, sock

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, rsp=False,
        expect_run_ctx_errno=errno.EBUSY)

    ret = vfu_device_quiesced(ctx, 0)
    assert ret == 0

    expected_info = vfu_dma_info_t(iovec_t(0x10000, 0x1000), 0, iovec_t(0, 0),
                                   0x1000, mmap.PROT_READ | mmap.PROT_WRITE)
    mock_dma_register.assert_called_once_with(ctx, expected_info)

    # TODO test DMA map with quiesce returning 0 (1) instead of EBUSY
    # TODO test DMA unmap with quiesce returning 0 (2) and EBUSY (3)
    # TODO test device reset callback with quiesce returning 0 (4) and EBUSY
    # (4)
    # TODO test migration callback

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
