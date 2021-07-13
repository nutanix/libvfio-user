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

from libvfio_user import *
import errno

#
# NB: this is currently very incomplete
#

ctx = None

@vfu_dma_register_cb_t
def dma_register(ctx, info):
    pass

@vfu_dma_unregister_cb_t
def dma_unregister(ctx, info):
    pass
    return 0

def test_dma_map_setup():
    global ctx

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx != None

    ret = vfu_pci_init(ctx)
    assert ret == 0

    ret = vfu_setup_device_dma(ctx, dma_register, dma_unregister)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

def test_dma_region_too_big():
    sock = connect_client(ctx)

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ |
               VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10000, size=MAX_DMA_SIZE + 4096)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, expect=errno.ENOSPC)

    disconnect_client(ctx, sock)

def test_dma_map_dup():
    sock = connect_client(ctx)

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ | VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0xdeadbeef, size=0x1000)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, expect=0)
    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, expect=0)

    disconnect_client(ctx, sock)


def test_dma_region_too_many():
    sock = connect_client(ctx)

    for i in range(1, MAX_DMA_REGIONS + 2):
        payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
            flags=(VFIO_USER_F_DMA_REGION_READ |
                   VFIO_USER_F_DMA_REGION_WRITE),
            offset=0, addr=0x1000 * i, size=4096)

        if i == MAX_DMA_REGIONS + 1:
            expect=errno.EINVAL
        else:
            expect=0

        msg(ctx, sock, VFIO_USER_DMA_MAP, payload, expect=expect)

    disconnect_client(ctx, sock)

def test_dirty_pages_cleanup():
    vfu_destroy_ctx(ctx)


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab:
