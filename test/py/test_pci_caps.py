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
import ctypes as c
import errno

ctx = None

def test_pci_cap_setup():
    global ctx

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx != None

    ret = vfu_pci_init(ctx, pci_type=VFU_PCI_TYPE_CONVENTIONAL)
    assert ret == 0

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_CFG_REGION_IDX,
                           size=PCI_CFG_SPACE_SIZE, flags=VFU_REGION_FLAG_RW)
    assert ret == 0

def test_pci_cap_bad_flags():
    pos = vfu_pci_add_capability(ctx, pos=0, flags=999,
              data=struct.pack("ccHH", to_byte(PCI_CAP_ID_PM), b'\0', 0, 0))
    assert pos == -1
    assert c.get_errno() == errno.EINVAL

def test_pci_cap_no_cb():
    pos = vfu_pci_add_capability(ctx, pos=0, flags=VFU_CAP_FLAG_CALLBACK,
              data=struct.pack("ccHH", to_byte(PCI_CAP_ID_PM), b'\0', 0, 0))
    assert pos == -1
    assert c.get_errno() == errno.EINVAL

def test_pci_cap_unknown_cap():
    pos = vfu_pci_add_capability(ctx, pos=0, flags=0,
              data=struct.pack("ccHH", b'\x81', b'\0', 0, 0))
    assert pos == -1
    assert c.get_errno() == errno.ENOTSUP

def test_pci_cap_bad_pos():
    pos = vfu_pci_add_capability(ctx, pos=PCI_CFG_SPACE_SIZE, flags=0,
              data=struct.pack("ccHH", to_byte(PCI_CAP_ID_PM), b'\0', 0, 0))
    assert pos == -1
    assert c.get_errno() == errno.EINVAL

@c.CFUNCTYPE(c.c_int, c.c_void_p, c.POINTER(c.c_char),
             c.c_long, c.c_long, c.c_int)
def pci_region_cb(ctx, buf, count, offset, is_write):
    if not is_write:
        return read_pci_cfg_space(ctx, buf, count, offset)

    return write_pci_cfg_space(ctx, buf, count, offset)

def test_pci_cap_setup_cb():
    global ctx

    vfu_destroy_ctx(ctx)

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx != None

    ret = vfu_pci_init(ctx, pci_type=VFU_PCI_TYPE_CONVENTIONAL)
    assert ret == 0

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_CFG_REGION_IDX,
                           size=PCI_CFG_SPACE_SIZE, cb=pci_region_cb,
                           flags=VFU_REGION_FLAG_RW)
    assert ret == 0

cap_offsets = (
    PCI_STD_HEADER_SIZEOF,
    PCI_STD_HEADER_SIZEOF + PCI_PM_SIZEOF,
    # NB: note 4-byte alignment of vsc2
    PCI_STD_HEADER_SIZEOF + PCI_PM_SIZEOF + 8,
    0x80,
    0x90
)

def test_add_caps():
    pos = vfu_pci_add_capability(ctx, pos=0, flags=0,
              data=struct.pack("ccHH", to_byte(PCI_CAP_ID_PM), b'\0', 0, 0))
    assert pos == cap_offsets[0]

    data = b"abc"
    cap = struct.pack("ccc%ds" % len(data), to_byte(PCI_CAP_ID_VNDR), b'\0',
                      to_byte(3 + len(data)), data)
    pos = vfu_pci_add_capability(ctx, pos=0, flags=VFU_CAP_FLAG_READONLY,
                                 data=cap)

    assert pos == cap_offsets[1]

    data = b"Hello world."
    cap = struct.pack("ccc%ds" % len(data), to_byte(PCI_CAP_ID_VNDR), b'\0',
                      to_byte(3 + len(data)), data)

    pos = vfu_pci_add_capability(ctx, pos=0, flags=VFU_CAP_FLAG_CALLBACK,
                                 data=cap)
    assert pos == cap_offsets[2]

    pos = vfu_pci_add_capability(ctx, pos=cap_offsets[3], flags=0, data=cap)
    assert pos == cap_offsets[3]

    pos = vfu_pci_add_capability(ctx, pos=cap_offsets[4], flags=0, data=cap)
    assert pos == cap_offsets[4]

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

def test_find_caps():
    offset = vfu_pci_find_capability(ctx, False, PCI_CAP_ID_PM)
    assert offset == cap_offsets[0]

    space = get_pci_cfg_space(ctx)

    assert space[offset] == PCI_CAP_ID_PM
    assert space[offset + PCI_CAP_LIST_NEXT] == cap_offsets[1]

    offset = vfu_pci_find_next_capability(ctx, False, offset, PCI_CAP_ID_PM)
    assert offset == 0

    offset = vfu_pci_find_capability(ctx, False, PCI_CAP_ID_VNDR)
    assert offset == cap_offsets[1]
    assert space[offset] == PCI_CAP_ID_VNDR
    assert space[offset + PCI_CAP_LIST_NEXT] == cap_offsets[2]

    offset = vfu_pci_find_next_capability(ctx, False, offset, PCI_CAP_ID_PM)
    assert offset == 0

    offset = vfu_pci_find_next_capability(ctx, False, 0, PCI_CAP_ID_VNDR)
    assert offset == cap_offsets[1]
    assert space[offset] == PCI_CAP_ID_VNDR
    assert space[offset + PCI_CAP_LIST_NEXT] == cap_offsets[2]

    offset = vfu_pci_find_next_capability(ctx, False, offset, PCI_CAP_ID_VNDR)
    assert offset == cap_offsets[2]
    assert space[offset] == PCI_CAP_ID_VNDR
    assert space[offset + PCI_CAP_LIST_NEXT] == cap_offsets[3]

    offset = vfu_pci_find_next_capability(ctx, False, offset, PCI_CAP_ID_VNDR)
    assert offset == cap_offsets[3]
    offset = vfu_pci_find_next_capability(ctx, False, offset, PCI_CAP_ID_VNDR)
    assert offset == cap_offsets[4]
    offset = vfu_pci_find_next_capability(ctx, False, offset, PCI_CAP_ID_VNDR)
    assert offset == 0

    # check for invalid offsets

    offset = vfu_pci_find_next_capability(ctx, False, 8192, PCI_CAP_ID_PM)
    assert offset == 0
    assert c.get_errno() == errno.EINVAL

    offset = vfu_pci_find_next_capability(ctx, False, 256, PCI_CAP_ID_PM)
    assert offset == 0
    assert c.get_errno() == errno.EINVAL

    offset = vfu_pci_find_next_capability(ctx, False, 255, PCI_CAP_ID_PM)
    assert offset == 0
    assert c.get_errno() == errno.EINVAL

    offset = vfu_pci_find_next_capability(ctx, False,
                                          PCI_STD_HEADER_SIZEOF +
                                          PCI_PM_SIZEOF + 1,
                                          PCI_CAP_ID_VNDR)
    assert offset == 0
    assert c.get_errno() == errno.ENOENT

def test_pci_cap_write_hdr():
    sock = connect_client(ctx)

    # offset of struct cap_hdr
    offset=cap_offsets[0]
    data=b'\x01'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.EPERM)

    disconnect_client(ctx, sock)

def test_pci_cap_readonly():
    sock = connect_client(ctx)

    # start of vendor payload
    offset=cap_offsets[1] + 2
    data=b'\x01'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.EPERM)

    # offsetof(struct vsc, data)
    offset=cap_offsets[1] + 3
    payload = read_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                          count=3)
    assert payload == b'abc'

    disconnect_client(ctx, sock)

def test_pci_cap_callback():
    sock = connect_client(ctx)

    # offsetof(struct vsc, data)
    offset=cap_offsets[2] + 3
    data = b"Hello world."

    payload = read_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                          count=len(data))
    assert payload == data

    data = b"Bye world."
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data)

    payload = read_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                          count=len(data))
    assert payload == data

    disconnect_client(ctx, sock)

def test_pci_cap_write_pmcs():
    sock = connect_client(ctx)

    # struct pc

    offset=cap_offsets[0] + 3
    data=b'\x01\x02'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.EINVAL)

    offset=cap_offsets[0] + 2
    data=b'\x01'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.EINVAL)

    offset=cap_offsets[0] + 2
    data=b'\x01\x02'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.ENOTSUP)

    # struct pmcs

    offset=cap_offsets[0] + 5
    data=b'\x01\x02'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.EINVAL)

    offset=cap_offsets[0] + 4
    data=b'\x01'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.EINVAL)

    offset = cap_offsets[0] + 4
    data=b'\x01\x02'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data)

    assert get_pci_cfg_space(ctx)[offset:offset+2] == data

    # pmcsr_se
    offset=cap_offsets[0] + 6
    data=b'\x01'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.ENOTSUP)

    # data
    offset=cap_offsets[0] + 7
    data=b'\x01'
    write_region(ctx, sock, VFU_PCI_DEV_CFG_REGION_IDX, offset=offset,
                 count=len(data), data=data, expect=errno.ENOTSUP)

    disconnect_client(ctx, sock)

def test_pci_cap_write_px():
    # FIXME
    pass

def test_pci_cap_write_msix():
    # FIXME
    pass

def test_pci_cap_cleanup():
    vfu_destroy_ctx(ctx)
