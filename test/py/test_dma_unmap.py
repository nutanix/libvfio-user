#
# Copyright (c) 2021 Nutanix Inc. All rights reserved.
#
# Authors: John Levon <john.levon@nutanix.com>
#          Swapnil Ingle <swapnil.ingle@nutanix.com>
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

import errno
from libvfio_user import *

ctx = None
sock = None


global quiesce_cb_err
quiesce_cb_err = 0


@vfu_device_quiesce_cb_t
def quiesce_cb(ctx):
    global quiesce_cb_err
    if quiesce_cb_err != 0:
        c.set_errno(quiesce_cb_err)
        return -1
    return 0


def test_dma_unmap_setup():
    global ctx, sock

    ctx = prepare_ctx_for_dma(quiesce=quiesce_cb)
    assert ctx is not None
    payload = struct.pack("II", 0, 0)

    sock = connect_client(ctx)

    for i in range(1, 3):
        payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
            flags=(VFIO_USER_F_DMA_REGION_READ |
                   VFIO_USER_F_DMA_REGION_WRITE),
            offset=0, addr=0x1000 * i, size=4096)

        msg(ctx, sock, VFIO_USER_DMA_MAP, payload)


def test_dma_unmap_short_write():

    payload = struct.pack("II", 0, 0)

    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload, expect=errno.EINVAL)


def test_dma_unmap_bad_argsz():

    vfio_user_dma_unmap(argsz=8, flags=0x2323, addr=0x1000, size=4096)


def test_dma_unmap_invalid_flags():

    payload = vfio_user_dma_unmap(argsz=len(vfio_user_dma_unmap()),
                                  flags=0x4, addr=0x1000, size=4096)
    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload, expect=errno.ENOTSUP)


def test_dma_unmap():

    payload = vfio_user_dma_unmap(argsz=len(vfio_user_dma_unmap()),
                                  flags=0, addr=0x1000, size=0x1000)
    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload)


def test_dma_unmap_invalid_addr():

    payload = vfio_user_dma_unmap(argsz=len(vfio_user_dma_unmap()),
                                  addr=0x10000, size=4096)

    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload, expect=errno.ENOENT)


def test_dma_unmap_async():

    global quiesce_cb_err
    quiesce_cb_err = errno.EBUSY

    payload = vfio_user_dma_unmap(argsz=len(vfio_user_dma_unmap()),
                                  flags=0, addr=0x2000, size=0x1000)
    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload, rsp=False)

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.EBUSY

    vfu_device_quiesced(ctx, 0)

    get_reply(sock)

    ret = vfu_run_ctx(ctx)
    assert ret == 0

    quiesce_cb_err = 0


def test_dma_unmap_all():

    for i in range(0, MAX_DMA_REGIONS):
        payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
            flags=(VFIO_USER_F_DMA_REGION_READ |
                   VFIO_USER_F_DMA_REGION_WRITE),
            offset=0, addr=0x1000 * i, size=4096)

        msg(ctx, sock, VFIO_USER_DMA_MAP, payload)

    payload = vfio_user_dma_unmap(argsz=len(vfio_user_dma_unmap()),
        flags=VFIO_DMA_UNMAP_FLAG_ALL, addr=0, size=0)

    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload)


def test_dma_unmap_all_invalid_addr():

    payload = vfio_user_dma_unmap(argsz=len(vfio_user_dma_unmap()),
        flags=VFIO_DMA_UNMAP_FLAG_ALL, addr=0x10000, size=4096)

    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload, expect=errno.EINVAL)


def test_dma_unmap_all_invalid_flags():

    payload = vfio_user_dma_unmap(argsz=len(vfio_user_dma_unmap()),
        flags=(VFIO_DMA_UNMAP_FLAG_ALL | VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP),
               addr=0, size=0)

    msg(ctx, sock, VFIO_USER_DMA_UNMAP, payload, expect=errno.EINVAL)


def test_dma_unmap_cleanup():

    disconnect_client(ctx, sock)
    vfu_destroy_ctx(ctx)

# FIXME need to add unit tests that test errors in get_request_header,
# do_reply, vfu_dma_transfer

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab
