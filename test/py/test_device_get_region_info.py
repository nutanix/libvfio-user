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

ctx = None
sock = None

argsz = len(vfio_region_info())
migr_region_size = 2 << PAGE_SHIFT
migr_mmap_areas = [(PAGE_SIZE, PAGE_SIZE)]


def test_device_get_region_info_setup():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR1_REGION_IDX, size=4096,
                           flags=(VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM))
    assert ret == 0

    f = tempfile.TemporaryFile()
    f.truncate(65536)

    mmap_areas = [(0x2000, 0x1000), (0x4000, 0x2000)]

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR2_REGION_IDX, size=0x8000,
                           flags=(VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM),
                           mmap_areas=mmap_areas, fd=f.fileno(), offset=0x8000)
    assert ret == 0

    f = tempfile.TemporaryFile()
    f.truncate(65536)

    mmap_areas = [(0x1000, 0x1000),
                  (0x2000, 0x1000),
                  (0x3000, 0x1000),
                  (0x4000, 0x1000),
                  (0x5000, 0x1000),
                  (0x6000, 0x1000),
                  (0x7000, 0x1000),
                  (0x8000, 0x1000),
                  (0x9000, 0x1000)]

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR3_REGION_IDX,
                           size=0x10000,
                           flags=(VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM),
                           mmap_areas=mmap_areas, fd=f.fileno(), offset=0x0)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)


def test_device_get_region_info_short_write():

    payload = struct.pack("II", 0, 0)

    msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload,
        expect=errno.EINVAL)


def test_device_get_region_info_bad_argsz():

    payload = vfio_region_info(argsz=8, flags=0,
                               index=VFU_PCI_DEV_BAR1_REGION_IDX, cap_offset=0,
                               size=0, offset=0)

    msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload,
        expect=errno.EINVAL)


def test_device_get_region_info_bad_index():

    payload = vfio_region_info(argsz=argsz, flags=0,
                               index=VFU_PCI_DEV_NUM_REGIONS, cap_offset=0,
                               size=0, offset=0)

    msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload,
        expect=errno.EINVAL)


def test_device_get_region_info_larger_argsz():

    payload = vfio_region_info(argsz=argsz + 8, flags=0,
                          index=VFU_PCI_DEV_BAR1_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

    assert len(result) == argsz

    info, _ = vfio_region_info.pop_from_buffer(result)

    assert info.argsz == argsz
    assert info.flags == (VFIO_REGION_INFO_FLAG_READ |
                          VFIO_REGION_INFO_FLAG_WRITE)
    assert info.index == VFU_PCI_DEV_BAR1_REGION_IDX
    assert info.cap_offset == 0
    assert info.size == 4096
    assert info.offset == 0


def test_device_get_region_info_small_argsz_caps():
    global sock

    payload = vfio_region_info(argsz=argsz, flags=0,
                          index=VFU_PCI_DEV_BAR2_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

    info, _ = vfio_region_info.pop_from_buffer(result)

    assert info.argsz == 80

    '''
    There are capabilites but we do not expect VFIO_REGION_INFO_FLAG_CAPS
    to be set because they do not fit in reply as argsz is small
    '''
    assert info.flags == (VFIO_REGION_INFO_FLAG_READ |
                          VFIO_REGION_INFO_FLAG_WRITE |
                          VFIO_REGION_INFO_FLAG_MMAP)
    assert info.index == VFU_PCI_DEV_BAR2_REGION_IDX
    assert info.cap_offset == 0
    assert info.size == 0x8000
    assert info.offset == 0x8000

    # skip reading the SCM_RIGHTS
    disconnect_client(ctx, sock)


def test_device_get_region_info_caps():
    global sock

    sock = connect_client(ctx)

    payload = vfio_region_info(argsz=80, flags=0,
                          index=VFU_PCI_DEV_BAR2_REGION_IDX, cap_offset=0,
                          size=0, offset=0)
    payload = bytes(payload) + b'\0' * (80 - 32)

    fds, result = msg_fds(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

    info, result = vfio_region_info.pop_from_buffer(result)
    cap, result = vfio_region_info_cap_sparse_mmap.pop_from_buffer(result)
    area1, result = vfio_region_sparse_mmap_area.pop_from_buffer(result)
    area2, result = vfio_region_sparse_mmap_area.pop_from_buffer(result)

    assert info.argsz == 80
    assert info.cap_offset == 32
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

    assert len(fds) == 1
    disconnect_client(ctx, sock)


def test_device_get_region_info_cleanup():
    vfu_destroy_ctx(ctx)


def test_device_get_pci_config_space_info_implicit_pci_init():
    """Checks that the PCI config space is implicitly configured if
    vfu_pci_init() is called."""

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    vfu_pci_init(ctx)

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)

    payload = vfio_region_info(argsz=argsz + 8, flags=0,
                          index=VFU_PCI_DEV_CFG_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

    assert len(result) == argsz

    info, _ = vfio_region_info.pop_from_buffer(result)

    assert info.argsz == argsz
    assert info.flags == (VFIO_REGION_INFO_FLAG_READ |
                          VFIO_REGION_INFO_FLAG_WRITE)
    assert info.index == VFU_PCI_DEV_CFG_REGION_IDX
    assert info.cap_offset == 0
    # libvfio-user.py default to PCI Express in vfu_pci_init()
    assert info.size == PCI_CFG_SPACE_EXP_SIZE
    assert info.offset == 0

    disconnect_client(ctx, sock)

    vfu_destroy_ctx(ctx)


def test_device_get_pci_config_space_info_implicit_no_pci_init():
    """Checks that the PCI config space is implicitly configured even if
    vfu_pci_init() is not called."""

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)

    payload = vfio_region_info(argsz=argsz + 8, flags=0,
                          index=VFU_PCI_DEV_CFG_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

    assert len(result) == argsz

    info, _ = vfio_region_info.pop_from_buffer(result)

    assert info.argsz == argsz
    assert info.flags == VFU_REGION_FLAG_RW
    assert info.index == VFU_PCI_DEV_CFG_REGION_IDX
    assert info.cap_offset == 0
    assert info.size == PCI_CFG_SPACE_SIZE
    assert info.offset == 0

    disconnect_client(ctx, sock)

    vfu_destroy_ctx(ctx)


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
