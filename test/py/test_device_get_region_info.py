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
import struct

ctx = None
client = None

argsz = len(vfio_region_info())
migr_region_size = 2 << PAGE_SHIFT
migr_mmap_areas = [(PAGE_SIZE, PAGE_SIZE)]

# PCI_BASE_ADDRESS offsets (from linux/pci_regs.h)
PCI_BASE_ADDRESS_0 = 0x10
PCI_BASE_ADDRESS_1 = 0x14
PCI_BASE_ADDRESS_2 = 0x18
PCI_BASE_ADDRESS_3 = 0x1C
PCI_BASE_ADDRESS_4 = 0x20
PCI_BASE_ADDRESS_5 = 0x24

# PCI_BASE_ADDRESS masks (from linux/pci_regs.h)
# Memory space: lower 4 bits are type/prefetch
PCI_BASE_ADDRESS_MEM_MASK = 0xFFFFFFF0
# I/O space: lower 2 bits are type/reserved
PCI_BASE_ADDRESS_IO_MASK = 0xFFFFFFFC


def setup_bar_region(ctx, bar_idx, size, is_io=False, is_64b=False):
    """Helper function to setup a BAR region.

    Args:
        ctx: vfu context
        bar_idx: BAR region index (VFU_PCI_DEV_BAR0_REGION_IDX, etc.)
        size: Size of the BAR region
        is_io: True for I/O space, False for memory space (default)
        is_64b: True for 64-bit BAR, False for 32-bit BAR (default)

    Returns:
        Return value from vfu_setup_region()
    """
    flags = VFU_REGION_FLAG_RW
    if not is_io:
        flags |= VFU_REGION_FLAG_MEM
    if is_64b:
        flags |= VFU_REGION_FLAG_64_BITS

    return vfu_setup_region(ctx, index=bar_idx, size=size, flags=flags)


def test_device_get_region_info_setup():
    global ctx, client

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

    client = connect_client(ctx)


def test_device_get_region_info_short_write():

    payload = struct.pack("II", 0, 0)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload,
        expect=errno.EINVAL)


def test_device_get_region_info_bad_argsz():

    payload = vfio_region_info(argsz=8, flags=0,
                               index=VFU_PCI_DEV_BAR1_REGION_IDX, cap_offset=0,
                               size=0, offset=0)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload,
        expect=errno.EINVAL)


def test_device_get_region_info_bad_index():

    payload = vfio_region_info(argsz=argsz, flags=0,
                               index=VFU_PCI_DEV_NUM_REGIONS, cap_offset=0,
                               size=0, offset=0)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload,
        expect=errno.EINVAL)


def test_device_get_region_info_larger_argsz():

    payload = vfio_region_info(argsz=argsz + 8, flags=0,
                          index=VFU_PCI_DEV_BAR1_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

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
    global client

    payload = vfio_region_info(argsz=argsz, flags=0,
                          index=VFU_PCI_DEV_BAR2_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

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
    client.disconnect(ctx)


def test_device_get_region_info_caps():
    global client

    client = connect_client(ctx)

    payload = vfio_region_info(argsz=80, flags=0,
                          index=VFU_PCI_DEV_BAR2_REGION_IDX, cap_offset=0,
                          size=0, offset=0)
    payload = bytes(payload) + b'\0' * (80 - 32)

    fds, result = msg_fds(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO,
                          payload)

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
    client.disconnect(ctx)


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

    client = connect_client(ctx)

    payload = vfio_region_info(argsz=argsz + 8, flags=0,
                          index=VFU_PCI_DEV_CFG_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

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

    client.disconnect(ctx)

    vfu_destroy_ctx(ctx)


def test_device_get_pci_config_space_info_implicit_no_pci_init():
    """Checks that the PCI config space is implicitly configured even if
    vfu_pci_init() is not called."""

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    client = connect_client(ctx)

    payload = vfio_region_info(argsz=argsz + 8, flags=0,
                          index=VFU_PCI_DEV_CFG_REGION_IDX, cap_offset=0,
                          size=0, offset=0)

    result = msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_INFO, payload)

    assert len(result) == argsz

    info, _ = vfio_region_info.pop_from_buffer(result)

    assert info.argsz == argsz
    assert info.flags == VFU_REGION_FLAG_RW
    assert info.index == VFU_PCI_DEV_CFG_REGION_IDX
    assert info.cap_offset == 0
    assert info.size == PCI_CFG_SPACE_SIZE
    assert info.offset == 0

    client.disconnect(ctx)

    vfu_destroy_ctx(ctx)


def detect_bar_sizes(ctx, client):
    """Mockup version of PCIe probe protocol - references:
    https://github.com/torvalds/linux/blob/master/drivers/pci/probe.c
    1. read config
    2. write 0xFFFFFFFF to BAR and read it back (don't care of rom case)
    3. calculate the size from the number of bits that return 0
       (return 0: size is 0 (not configured))
    """

    # collect sizes: reference Linux kernel probe.c
    # https://github.com/torvalds/linux/blob/8dfce8991b95d8625d0a1d2896e42f93b9d7f68d/drivers/pci/probe.c#L198
    offsets = [PCI_BASE_ADDRESS_0, PCI_BASE_ADDRESS_1,
               PCI_BASE_ADDRESS_2, PCI_BASE_ADDRESS_3,
               PCI_BASE_ADDRESS_4, PCI_BASE_ADDRESS_5]
    detected_szs = []
    sizes = []

    probe_mask = 0xffffffff
    count = 4

    for offset in offsets:
        orig = read_region(ctx, client.sock, VFU_PCI_DEV_CFG_REGION_IDX,
                           offset=offset, count=count)

        write_region(ctx, client.sock, VFU_PCI_DEV_CFG_REGION_IDX,
                     offset=offset, count=count,
                     data=struct.pack("<I", probe_mask))
        data = read_region(ctx, client.sock, VFU_PCI_DEV_CFG_REGION_IDX,
                           offset=offset, count=count)
        value = struct.unpack("<I", data)[0]
        detected_szs.append(value)

        write_region(ctx, client.sock, VFU_PCI_DEV_CFG_REGION_IDX,
                     offset=offset, count=count,
                     data=orig)

    # pci_read_bases & __pci_read_base -> pci_size
    pos = 0
    while pos < len(offsets):
        if detected_szs[pos] == 0:
            sizes.append(0)
            pos += 1
            continue

        is_64b = False
        detected_sz = detected_szs[pos]

        if detected_sz & PCI_BASE_ADDRESS_SPACE_IO:
            detected_sz = detected_sz & PCI_BASE_ADDRESS_IO_MASK
        else:
            if detected_sz & PCI_BASE_ADDRESS_MEM_TYPE_64:
                if pos % 2 == 1:  # error
                    raise ValueError("64-bit BAR is configured as upper bar")
                detected_sz = ((detected_szs[pos+1] << 32) |
                                (detected_sz & PCI_BASE_ADDRESS_MEM_MASK))
                is_64b = True
            else:
                detected_sz = detected_sz & PCI_BASE_ADDRESS_MEM_MASK

        mask = UINT64_MAX if is_64b else UINT32_MAX
        size = (~detected_sz + 1) & mask

        sizes.append(size)
        pos += 1

        if is_64b:
            sizes.append(0)
            pos += 1

    return sizes


def test_device_get_region_info_32bit_bar_size_detection():
    """Test PCI BAR size detection protocol for 32-bit BARs.

    According to PCI spec, software writes 0xFFFFFFFF to BAR and reads it
    back. The number of bits that return 0 indicates the size.
    For 32-bit BARs, this process is performed on a single 32-bit register.
    """
    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    # Setup BARs: BAR1=4KB, BAR2=8KB, BAR3=16KB, others=0
    bar_sizes = [0, 4096, 8192, 16384, 0, 0]

    for bar_idx, size in enumerate(bar_sizes):
        if size > 0:
            ret = setup_bar_region(ctx, bar_idx, size)
            assert ret == 0

    # Initialize PCI device and config space
    vfu_pci_init(ctx)
    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_CFG_REGION_IDX,
                           size=PCI_CFG_SPACE_EXP_SIZE,
                           flags=VFU_REGION_FLAG_RW)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    client = connect_client(ctx)

    sizes = detect_bar_sizes(ctx, client)
    for i, expected_size in enumerate(bar_sizes):
        assert sizes[i] == expected_size

    client.disconnect(ctx)
    vfu_destroy_ctx(ctx)


def test_64bit_bar_size_detection_protocol():
    """Test PCI BAR size detection protocol for 64-bit BARs.

    According to PCI spec, software writes 0xFFFFFFFF to BAR and reads it back.
    The number of bits that return 0 indicates the size (with the correct mask
    applied). For 64-bit BARs, this process is performed on both lower and
    upper 32 bits.
    """
    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    # Setup BARs: BAR0=4GB, BAR2=8GB, BAR4=16GB (all 64-bit), others=0
    bar_sizes = [0x100000000, 0, 0x200000000, 0, 0x400000000, 0]

    for bar_idx, size in enumerate(bar_sizes):
        if size > 0:
            ret = setup_bar_region(ctx, bar_idx, size, is_64b=True)
            assert ret == 0

    # Initialize PCI device and config space
    vfu_pci_init(ctx)
    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_CFG_REGION_IDX,
                           size=PCI_CFG_SPACE_EXP_SIZE,
                           flags=VFU_REGION_FLAG_RW)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    client = connect_client(ctx)

    sizes = detect_bar_sizes(ctx, client)
    success = True
    for i, expected_size in enumerate(bar_sizes):
        if sizes[i] != expected_size:
            success = False
            msg = (f"Expected size {expected_size} for bar {i}, "
                   f"but got {sizes[i]}")
            print(msg)
    assert success

    client.disconnect(ctx)
    vfu_destroy_ctx(ctx)


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
