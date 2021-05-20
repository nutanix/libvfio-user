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
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#

from libvfio_user import *
import errno
import tempfile
import os

ctx = None
sock = None

def test_device_get_region_info_setup():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx != None

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR1_REGION_IDX, size=4096,
                           flags=(VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM))
    assert ret == 0

    f = tempfile.TemporaryFile()
    f.truncate(65536)

    mmap_areas = [ (0x2000, 0x1000), (0x4000, 0x2000) ]

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR2_REGION_IDX, size=0x8000,
                           flags=(VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM),
                           mmap_areas=mmap_areas, fd=f.fileno(), offset=0x8000)
    assert ret == 0

    f = tempfile.TemporaryFile()
    f.truncate(0x2000)

    mmap_areas = [ (0x1000, 0x1000) ]

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_MIGR_REGION_IDX, size=0x2000,
                           flags=VFU_REGION_FLAG_RW, mmap_areas=mmap_areas,
                           fd=f.fileno())
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)

def test_device_get_region_info_short_write():

    payload = struct.pack("II", 0, 0)

    hdr = vfio_user_header(VFIO_USER_DEVICE_GET_REGION_INFO, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_device_get_region_info_bad_argsz():

    # struct vfio_region_info
    payload = struct.pack("IIIIQQ", 8, 0, VFU_PCI_DEV_BAR1_REGION_IDX, 0, 0, 0)

    hdr = vfio_user_header(VFIO_USER_DEVICE_GET_REGION_INFO, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_device_get_region_info_bad_index():

    payload = struct.pack("IIIIQQ", 32, 0, VFU_PCI_DEV_NUM_REGIONS, 0, 0, 0)

    hdr = vfio_user_header(VFIO_USER_DEVICE_GET_REGION_INFO, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_device_get_region_info_larger_argsz():

    payload = struct.pack("IIIIQQ", 32 + 8, 0, VFU_PCI_DEV_BAR1_REGION_IDX,
                          0, 0, 0)

    hdr = vfio_user_header(VFIO_USER_DEVICE_GET_REGION_INFO, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    result = get_reply(sock)

    assert(len(result) == 32 + 8)

    info, _ = vfio_region_info(result)

    assert info.argsz == 32
    assert info.flags == (VFIO_REGION_INFO_FLAG_READ |
                          VFIO_REGION_INFO_FLAG_WRITE)
    assert info.index == VFU_PCI_DEV_BAR1_REGION_IDX
    assert info.cap_off == 0
    assert info.size == 4096
    assert info.offset == 0

def test_device_get_region_info_small_argsz_caps():
    global sock

    payload = struct.pack("IIIIQQ", 32, 0, VFU_PCI_DEV_BAR2_REGION_IDX, 0, 0, 0)

    hdr = vfio_user_header(VFIO_USER_DEVICE_GET_REGION_INFO, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    result = get_reply(sock)

    info, _ = vfio_region_info(result)

    assert info.argsz == 80
    assert info.flags == (VFIO_REGION_INFO_FLAG_READ |
                          VFIO_REGION_INFO_FLAG_WRITE |
                          VFIO_REGION_INFO_FLAG_MMAP |
                          VFIO_REGION_INFO_FLAG_CAPS)
    assert info.index == VFU_PCI_DEV_BAR2_REGION_IDX
    assert info.cap_off == 0
    assert info.size == 0x8000
    assert info.offset == 0x8000

    # skip reading the SCM_RIGHTS
    disconnect_client(ctx, sock)

def test_device_get_region_info_caps():
    global sock

    sock = connect_client(ctx)

    payload = struct.pack("IIIIQQ", 80, 0, VFU_PCI_DEV_BAR2_REGION_IDX, 0, 0, 0)
    payload += b'\0' * (80 - 32)

    hdr = vfio_user_header(VFIO_USER_DEVICE_GET_REGION_INFO, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    result = get_reply(sock)

    info, result = vfio_region_info(result)
    cap, result = vfio_region_info_cap_sparse_mmap(result)
    area1, result = vfio_region_sparse_mmap_area(result)
    area2, result = vfio_region_sparse_mmap_area(result)

    assert info.argsz == 80
    assert info.cap_off == 32
    assert info.size == 0x8000
    assert info.offset == 0x8000

    assert cap.id == VFIO_REGION_INFO_CAP_SPARSE_MMAP
    assert cap.version == 1
    assert cap.next == 0
    assert cap.nr_areas == 2

    assert area1.offset == 0x2000
    assert area1.size == 0x1000
    assert area2.offset == 0x4000
    assert area2.size == 0x2000

    # skip reading the SCM_RIGHTS
    disconnect_client(ctx, sock)

def test_device_get_region_info_migr():
    global sock

    sock = connect_client(ctx)

    payload = struct.pack("IIIIQQ", 80, 0, VFU_PCI_DEV_MIGR_REGION_IDX,
                          0, 0, 0)
    payload += b'\0' * (80 - 32)

    hdr = vfio_user_header(VFIO_USER_DEVICE_GET_REGION_INFO, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    result = get_reply(sock)

    info, result = vfio_region_info(result)
    mcap, result = vfio_region_info_cap_type(result)
    cap, result = vfio_region_info_cap_sparse_mmap(result)
    area, result = vfio_region_sparse_mmap_area(result)

    assert info.argsz == 80
    assert info.cap_off == 32

    assert mcap.id == VFIO_REGION_INFO_CAP_TYPE
    assert mcap.version == 1
    assert mcap.next == 48
    assert mcap.type == VFIO_REGION_TYPE_MIGRATION
    assert mcap.subtype == VFIO_REGION_SUBTYPE_MIGRATION

    assert cap.id == VFIO_REGION_INFO_CAP_SPARSE_MMAP
    assert cap.version == 1
    assert cap.next == 0
    assert cap.nr_areas == 1

    assert area.offset == 0x1000
    assert area.size == 0x1000

    # skip reading the SCM_RIGHTS
    disconnect_client(ctx, sock)

def test_device_get_region_info_cleanup():
    vfu_destroy_ctx(ctx)
