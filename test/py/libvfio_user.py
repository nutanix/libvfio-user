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

#
# Note that we don't use enum here, as class.value is a little verbose
#

from collections import namedtuple
from types import SimpleNamespace
import ctypes as c
import json
import os
import pathlib
import socket
import struct
import syslog

# from linux/pci_regs.h and linux/pci_defs.h

PCI_HEADER_TYPE_NORMAL = 0

PCI_STD_HEADER_SIZEOF = 64

PCI_BARS_NR = 6

PCI_PM_SIZEOF = 8

PCI_CFG_SPACE_SIZE = 256
PCI_CFG_SPACE_EXP_SIZE = 4096

PCI_CAP_LIST_NEXT = 1

PCI_CAP_ID_PM = 0x1
PCI_CAP_ID_VNDR = 0x9

PCI_EXT_CAP_ID_DSN = 0x03
PCI_EXT_CAP_ID_VNDR = 0x0b

PCI_EXT_CAP_DSN_SIZEOF = 12

PCI_EXT_CAP_VNDR_HDR_SIZEOF = 8

# from linux/vfio.h

VFIO_DEVICE_FLAGS_RESET = (1 << 0)
VFIO_DEVICE_FLAGS_PCI = (1 << 1)

VFIO_REGION_INFO_FLAG_READ = (1 << 0)
VFIO_REGION_INFO_FLAG_WRITE = (1 << 1)
VFIO_REGION_INFO_FLAG_MMAP = (1 << 2)
VFIO_REGION_INFO_FLAG_CAPS = (1 << 3)

VFIO_REGION_TYPE_MIGRATION = 3
VFIO_REGION_SUBTYPE_MIGRATION = 1

VFIO_REGION_INFO_CAP_SPARSE_MMAP = 1
VFIO_REGION_INFO_CAP_TYPE = 2

VFIO_IRQ_SET_DATA_NONE = (1 << 0)
VFIO_IRQ_SET_DATA_BOOL = (1 << 1)
VFIO_IRQ_SET_DATA_EVENTFD = (1 << 2)
VFIO_IRQ_SET_ACTION_MASK = (1 << 3)
VFIO_IRQ_SET_ACTION_UNMASK = (1 << 4)
VFIO_IRQ_SET_ACTION_TRIGGER = (1 << 5)

# libvfio-user defines

VFU_TRANS_SOCK = 0
LIBVFIO_USER_FLAG_ATTACH_NB = (1 << 0)
VFU_DEV_TYPE_PCI = 0

LIBVFIO_USER_MAJOR = 0
LIBVFIO_USER_MINOR = 1

VFIO_USER_CLIENT_MAX_FDS_LIMIT = 1024

SERVER_MAX_FDS = 8

SERVER_MAX_MSG_SIZE = 65536

# enum vfio_user_command
VFIO_USER_VERSION                   = 1
VFIO_USER_DMA_MAP                   = 2
VFIO_USER_DMA_UNMAP                 = 3
VFIO_USER_DEVICE_GET_INFO           = 4
VFIO_USER_DEVICE_GET_REGION_INFO    = 5
VFIO_USER_DEVICE_GET_IRQ_INFO       = 6
VFIO_USER_DEVICE_SET_IRQS           = 7
VFIO_USER_REGION_READ               = 8
VFIO_USER_REGION_WRITE              = 9
VFIO_USER_DMA_READ                  = 10
VFIO_USER_DMA_WRITE                 = 11
VFIO_USER_VM_INTERRUPT              = 12
VFIO_USER_DEVICE_RESET              = 13
VFIO_USER_DIRTY_PAGES               = 14
VFIO_USER_MAX                       = 15

VFIO_USER_F_TYPE_COMMAND = 0
VFIO_USER_F_TYPE_REPLY = 1

SIZEOF_VFIO_USER_HEADER = 16

VFU_PCI_DEV_BAR0_REGION_IDX = 0
VFU_PCI_DEV_BAR1_REGION_IDX = 1
VFU_PCI_DEV_BAR2_REGION_IDX = 2
VFU_PCI_DEV_BAR3_REGION_IDX = 3
VFU_PCI_DEV_BAR4_REGION_IDX = 4
VFU_PCI_DEV_BAR5_REGION_IDX = 5
VFU_PCI_DEV_ROM_REGION_IDX  = 6
VFU_PCI_DEV_CFG_REGION_IDX  = 7
VFU_PCI_DEV_VGA_REGION_IDX  = 8
VFU_PCI_DEV_MIGR_REGION_IDX = 9
VFU_PCI_DEV_NUM_REGIONS     = 10

VFU_REGION_FLAG_READ  = 1
VFU_REGION_FLAG_WRITE = 2
VFU_REGION_FLAG_RW = (VFU_REGION_FLAG_READ | VFU_REGION_FLAG_WRITE)
VFU_REGION_FLAG_MEM   = 4

# enum vfu_dev_irq_type
VFU_DEV_INTX_IRQ = 0
VFU_DEV_MSI_IRQ  = 1
VFU_DEV_MSIX_IRQ = 2
VFU_DEV_ERR_IRQ  = 3
VFU_DEV_REQ_IRQ  = 4
VFU_DEV_NUM_IRQS = 5

# vfu_pci_type_t
VFU_PCI_TYPE_CONVENTIONAL = 0
VFU_PCI_TYPE_PCI_X_1      = 1
VFU_PCI_TYPE_PCI_X_2      = 2
VFU_PCI_TYPE_EXPRESS      = 3

VFU_CAP_FLAG_EXTENDED = (1 << 0)
VFU_CAP_FLAG_CALLBACK = (1 << 1)
VFU_CAP_FLAG_READONLY = (1 << 2)

SOCK_PATH = b"/tmp/vfio-user.sock.%d" % os.getpid()

topdir = os.path.realpath(os.path.dirname(__file__) + "/../..")
build_type = os.getenv("BUILD_TYPE", default="dbg")
libname = "%s/build/%s/lib/libvfio-user.so" % (topdir, build_type)
lib = c.CDLL(libname, use_errno=True)
libc = c.CDLL("libc.so.6", use_errno=True)

#
# Structures
#
class vfu_bar_t(c.Union):
    _pack_ = 1
    _fields_ = [
        ("mem", c.c_int),
        ("io", c.c_int)
    ]

class vfu_pci_hdr_intr_t(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("iline", c.c_byte),
        ("ipin", c.c_byte)
    ]

class vfu_pci_hdr_t(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("id", c.c_int),
        ("cmd", c.c_short),
        ("sts", c.c_short),
        ("rid", c.c_byte),
        ("cc_pi", c.c_byte),
        ("cc_scc", c.c_byte),
        ("cc_bcc", c.c_byte),
        ("cls", c.c_byte),
        ("mlt", c.c_byte),
        ("htype", c.c_byte),
        ("bist", c.c_byte),
        ("bars", vfu_bar_t * PCI_BARS_NR),
        ("ccptr", c.c_int),
        ("ss", c.c_int),
        ("erom", c.c_int),
        ("cap", c.c_byte),
        ("res1", c.c_byte * 7),
        ("intr", vfu_pci_hdr_intr_t),
        ("mgnt", c.c_byte),
        ("mlat", c.c_byte)
    ]

class iovec_t(c.Structure):
    _fields_ = [
        ("iov_base", c.c_void_p),
        ("iov_len", c.c_int)
    ]

#
# Util functions
#

lib.vfu_create_ctx.argtypes = (c.c_int, c.c_char_p, c.c_int,
                               c.c_void_p, c.c_int)
lib.vfu_create_ctx.restype = (c.c_void_p)
lib.vfu_setup_log.argtypes = (c.c_void_p, c.c_void_p, c.c_int)
lib.vfu_realize_ctx.argtypes = (c.c_void_p,)
lib.vfu_attach_ctx.argtypes = (c.c_void_p,)
lib.vfu_run_ctx.argtypes = (c.c_void_p,)
lib.vfu_destroy_ctx.argtypes = (c.c_void_p,)
vfu_region_access_cb_t = c.CFUNCTYPE(c.c_int, c.c_void_p, c.POINTER(c.c_char),
                                     c.c_ulong, c.c_long, c.c_bool)
lib.vfu_setup_region.argtypes = (c.c_void_p, c.c_int, c.c_ulong,
                                 vfu_region_access_cb_t, c.c_int, c.c_void_p,
                                 c.c_uint32, c.c_int, c.c_ulong)
lib.vfu_pci_get_config_space.argtypes = (c.c_void_p,)
lib.vfu_pci_get_config_space.restype = (c.c_void_p)
lib.vfu_setup_device_nr_irqs.argtypes = (c.c_void_p, c.c_int, c.c_uint32)
lib.vfu_pci_init.argtypes = (c.c_void_p, c.c_int, c.c_int, c.c_int)
lib.vfu_pci_add_capability.argtypes = (c.c_void_p, c.c_ulong, c.c_int,
                                       c.POINTER(c.c_byte))
lib.vfu_pci_find_capability.argtypes = (c.c_void_p, c.c_bool, c.c_int)
lib.vfu_pci_find_capability.restype = (c.c_ulong)
lib.vfu_pci_find_next_capability.argtypes = (c.c_void_p, c.c_bool, c.c_ulong,
                                             c.c_int)
lib.vfu_pci_find_next_capability.restype = (c.c_ulong)


def to_byte(val):
    """Cast an int to a byte value."""
    return val.to_bytes(1, 'little')

def skip(fmt, buf):
    """Return the data remaining after skipping the given elements."""
    return buf[struct.calcsize(fmt):]

def unpack_prefix(fmt, fields, buf):
    """Return a namedtuple unpacked from the start of buf, along with the
       remaining buf if any."""
    t = namedtuple('_', fields)
    size = struct.calcsize(fmt)
    return t._make(struct.unpack_from(fmt, buf)), skip(fmt, buf)

def parse_json(json_str):
    """Parse JSON into an object with attributes (instead of using a dict)."""
    return json.loads(json_str, object_hook=lambda d: SimpleNamespace(**d))

def eventfd(initval=0, flags=0):
    libc.eventfd.argtypes = (c.c_uint, c.c_int)
    return libc.eventfd(initval, flags)

def connect_sock():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCK_PATH)
    return sock

def connect_client(ctx):
    sock = connect_sock()

    json = b'{ "capabilities": { "max_msg_fds": 8 } }'
    # struct vfio_user_version
    payload = struct.pack("HH%dsc" % len(json), LIBVFIO_USER_MAJOR,
                          LIBVFIO_USER_MINOR, json, b'\0')
    hdr = vfio_user_header(VFIO_USER_VERSION, size=len(payload))
    sock.send(hdr + payload)
    vfu_attach_ctx(ctx, expect=0)
    payload = get_reply(sock, expect=0)
    return sock

def disconnect_client(ctx, sock):
    sock.close()

    # notice client closed connection
    vfu_run_ctx(ctx)

def get_reply(sock, expect=0):
    buf = sock.recv(4096)
    (msg_id, cmd, msg_size, flags, errno) = struct.unpack("HHIII", buf[0:16])
    assert (flags & VFIO_USER_F_TYPE_REPLY) != 0
    assert errno == expect
    return buf[16:]

def get_pci_header(ctx):
    ptr = lib.vfu_pci_get_config_space(ctx)
    return c.cast(ptr, c.POINTER(vfu_pci_hdr_t)).contents

def get_pci_cfg_space(ctx):
    ptr = lib.vfu_pci_get_config_space(ctx)
    return c.cast(ptr, c.POINTER(c.c_char))[0:PCI_CFG_SPACE_SIZE]

def get_pci_ext_cfg_space(ctx):
    ptr = lib.vfu_pci_get_config_space(ctx)
    return c.cast(ptr, c.POINTER(c.c_char))[0:PCI_CFG_SPACE_EXP_SIZE]

def read_pci_cfg_space(ctx, buf, count, offset, extended=False):
    space = get_pci_ext_cfg_space(ctx) if extended else get_pci_cfg_space(ctx)

    for i in range(count):
        buf[i] = space[offset+i]
    return count

def write_pci_cfg_space(ctx, buf, count, offset, extended=False):
    max_offset = PCI_CFG_SPACE_EXP_SIZE if extended else PCI_CFG_SPACE_SIZE

    assert offset + count <= max_offset

    space = c.cast(lib.vfu_pci_get_config_space(ctx), c.POINTER(c.c_char))

    for i in range(count):
        space[offset+i] = buf[i]
    return count

def access_region(ctx, sock, is_write, region, offset, count,
                  data=None, expect=0):
    # struct vfio_user_region_access
    payload = struct.pack("QII", offset, region, count)
    if is_write:
        payload += data

    cmd = VFIO_USER_REGION_WRITE if is_write else VFIO_USER_REGION_READ
    hdr = vfio_user_header(cmd, size=len(payload))
    sock.send(hdr + payload)
    vfu_run_ctx(ctx)
    result = get_reply(sock, expect=expect)

    if is_write:
        return None

    return skip("QII", result)

def write_region(ctx, sock, region, offset, count, data, expect=0):
    access_region(ctx, sock, True, region, offset, count, data, expect=expect)

def read_region(ctx, sock, region, offset, count, expect=0):
    return access_region(ctx, sock, False, region, offset, count, expect=expect)

def ext_cap_hdr(buf, offset):
    """Read an extended cap header."""

    # struct pcie_ext_cap_hdr
    cap_id, cap_next = struct.unpack_from('HH', buf, offset)
    cap_next >>= 4
    return cap_id, cap_next

def vfio_region_info(buf):
    return unpack_prefix("IIIIQQ", "argsz flags index cap_off size offset", buf)

def vfio_region_info_cap_type(buf):
    return unpack_prefix("HHIII", "id version next type subtype", buf)

def vfio_region_info_cap_sparse_mmap(buf):
    return unpack_prefix("HHIII", "id version next nr_areas reserved", buf)

def vfio_region_sparse_mmap_area(buf):
    return unpack_prefix("QQ", "offset size", buf)

#
# Library wrappers
#

msg_id = 1

@c.CFUNCTYPE(None, c.c_void_p, c.c_int, c.c_char_p)
def log(ctx, level, msg):
    print(msg.decode("utf-8"))

def vfio_user_header(cmd, size, no_reply=False, error=False, error_no=0):
    global msg_id

    buf = struct.pack("HHIII", msg_id, cmd, SIZEOF_VFIO_USER_HEADER + size,
                      0, error_no)

    msg_id += 1

    return buf

def vfu_create_ctx(trans=VFU_TRANS_SOCK, sock_path=SOCK_PATH, flags=0,
                   private=None, dev_type=VFU_DEV_TYPE_PCI):
    if os.path.exists(sock_path):
        os.remove(sock_path)

    ctx = lib.vfu_create_ctx(trans, sock_path, flags, private, dev_type)

    if ctx:
        lib.vfu_setup_log(ctx, log, syslog.LOG_DEBUG)

    return ctx

def vfu_realize_ctx(ctx):
    return lib.vfu_realize_ctx(ctx)

def vfu_attach_ctx(ctx, expect=0):
    ret = lib.vfu_attach_ctx(ctx)
    if expect == 0:
        assert ret == 0
    else:
        assert ret == -1
        assert c.get_errno() == expect
    return ret

def vfu_run_ctx(ctx):
    return lib.vfu_run_ctx(ctx)

def vfu_destroy_ctx(ctx):
    lib.vfu_destroy_ctx(ctx)
    ctx = None
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

def vfu_setup_region(ctx, index, size, cb=None, flags=0,
                     mmap_areas=None, fd=-1, offset=0):
    assert ctx != None

    nr_mmap_areas = 0
    c_mmap_areas = None

    if mmap_areas:
        nr_mmap_areas = len(mmap_areas)
        c_mmap_areas = (iovec_t * nr_mmap_areas)(*mmap_areas)

    # We're sending a file descriptor to ourselves; to pretend the server is
    # separate, we need to dup() here.
    if fd != -1:
        fd = os.dup(fd)

    ret = lib.vfu_setup_region(ctx, index, size,
                               c.cast(cb, vfu_region_access_cb_t),
                               flags, c_mmap_areas, nr_mmap_areas, fd, offset)
    return ret

def vfu_setup_device_nr_irqs(ctx, irqtype, count):
    assert ctx != None
    return lib.vfu_setup_device_nr_irqs(ctx, irqtype, count)

def vfu_pci_init(ctx, pci_type=VFU_PCI_TYPE_EXPRESS,
                 hdr_type=PCI_HEADER_TYPE_NORMAL):
    assert ctx != None
    return lib.vfu_pci_init(ctx, pci_type, hdr_type, 0)

def vfu_pci_add_capability(ctx, pos, flags, data):
    assert ctx != None

    databuf = (c.c_byte * len(data)).from_buffer(bytearray(data))
    return lib.vfu_pci_add_capability(ctx, pos, flags, databuf)

def vfu_pci_find_capability(ctx, extended, cap_id):
    assert ctx != None

    return lib.vfu_pci_find_capability(ctx, extended, cap_id)

def vfu_pci_find_next_capability(ctx, extended, offset, cap_id):
    assert ctx != None

    return lib.vfu_pci_find_next_capability(ctx, extended, offset, cap_id)
