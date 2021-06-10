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
import mmap
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
PCI_CAP_ID_EXP = 0x10

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

VFIO_IRQ_INFO_EVENTFD = (1 << 0)

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

ONE_TB = (1024 * 1024 * 1024 * 1024)

VFIO_USER_DEFAULT_MAX_DATA_XFER_SIZE = (1024 * 1024)
SERVER_MAX_DATA_XFER_SIZE = VFIO_USER_DEFAULT_MAX_DATA_XFER_SIZE
SERVER_MAX_MSG_SIZE = SERVER_MAX_DATA_XFER_SIZE + 16 + 16

MAX_DMA_REGIONS = 16
MAX_DMA_SIZE = (8 * ONE_TB)

# enum vfio_user_command
VFIO_USER_VERSION                   = 1
VFIO_USER_DMA_MAP                   = 2
VFIO_USER_DMA_UNMAP                 = 3
VFIO_USER_DEVICE_GET_INFO           = 4
VFIO_USER_DEVICE_GET_REGION_INFO    = 5
VFIO_USER_DEVICE_GET_REGION_IO_FDS  = 6
VFIO_USER_DEVICE_GET_IRQ_INFO       = 7
VFIO_USER_DEVICE_SET_IRQS           = 8
VFIO_USER_REGION_READ               = 9
VFIO_USER_REGION_WRITE              = 10
VFIO_USER_DMA_READ                  = 11
VFIO_USER_DMA_WRITE                 = 12
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

VFIO_USER_F_DMA_REGION_READ = (1 << 0)
VFIO_USER_F_DMA_REGION_WRITE = (1 << 1)

VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP = (1 << 0)

VFIO_IOMMU_DIRTY_PAGES_FLAG_START = (1 << 0)
VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP = (1 << 1)
VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP = (1 << 2)

# enum vfu_dev_irq_type
VFU_DEV_INTX_IRQ = 0
VFU_DEV_MSI_IRQ  = 1
VFU_DEV_MSIX_IRQ = 2
VFU_DEV_ERR_IRQ  = 3
VFU_DEV_REQ_IRQ  = 4
VFU_DEV_NUM_IRQS = 5

# enum vfu_reset_type
VFU_RESET_DEVICE = 0
VFU_RESET_LOST_CONN = 1
VFU_RESET_PCI_FLR = 2

# vfu_pci_type_t
VFU_PCI_TYPE_CONVENTIONAL = 0
VFU_PCI_TYPE_PCI_X_1      = 1
VFU_PCI_TYPE_PCI_X_2      = 2
VFU_PCI_TYPE_EXPRESS      = 3

VFU_CAP_FLAG_EXTENDED = (1 << 0)
VFU_CAP_FLAG_CALLBACK = (1 << 1)
VFU_CAP_FLAG_READONLY = (1 << 2)

VFU_MIGR_CALLBACKS_VERS = 1

SOCK_PATH = b"/tmp/vfio-user.sock.%d" % os.getpid()

topdir = os.path.realpath(os.path.dirname(__file__) + "/../..")
build_type = os.getenv("BUILD_TYPE", default="dbg")
libname = "%s/build/%s/lib/libvfio-user.so" % (topdir, build_type)
lib = c.CDLL(libname, use_errno=True)
libc = c.CDLL("libc.so.6", use_errno=True)

#
# Structures
#

class Structure(c.Structure):
    def __len__(self):
        """Handy method to return length in bytes."""
        return len(bytes(self))

    @classmethod
    def pop_from_buffer(cls, buf):
        """"Pop a new object from the given bytes buffer."""
        obj = cls.from_buffer_copy(buf)
        return obj, buf[c.sizeof(obj):]

class vfu_bar_t(c.Union):
    _pack_ = 1
    _fields_ = [
        ("mem", c.c_int32),
        ("io", c.c_int32)
    ]

class vfu_pci_hdr_intr_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("iline", c.c_byte),
        ("ipin", c.c_byte)
    ]

class vfu_pci_hdr_t(Structure):
    _pack_ = 1
    _fields_ = [
        ("id", c.c_int32),
        ("cmd", c.c_uint16),
        ("sts", c.c_uint16),
        ("rid", c.c_byte),
        ("cc_pi", c.c_byte),
        ("cc_scc", c.c_byte),
        ("cc_bcc", c.c_byte),
        ("cls", c.c_byte),
        ("mlt", c.c_byte),
        ("htype", c.c_byte),
        ("bist", c.c_byte),
        ("bars", vfu_bar_t * PCI_BARS_NR),
        ("ccptr", c.c_int32),
        ("ss", c.c_int32),
        ("erom", c.c_int32),
        ("cap", c.c_byte),
        ("res1", c.c_byte * 7),
        ("intr", vfu_pci_hdr_intr_t),
        ("mgnt", c.c_byte),
        ("mlat", c.c_byte)
    ]

class iovec_t(Structure):
    _fields_ = [
        ("iov_base", c.c_void_p),
        ("iov_len", c.c_int32)
    ]

class vfio_irq_info(Structure):
    _pack_ = 1
    _fields_ = [
        ("argsz", c.c_uint32),
        ("flags", c.c_uint32),
        ("index", c.c_uint32),
        ("count", c.c_uint32),
    ]

class vfio_irq_set(Structure):
    _pack_ = 1
    _fields_ = [
        ("argsz", c.c_uint32),
        ("flags", c.c_uint32),
        ("index", c.c_uint32),
        ("start", c.c_uint32),
        ("count", c.c_uint32),
    ]

class vfio_user_device_info(Structure):
    _pack_ = 1
    _fields_ = [
        ("argsz", c.c_uint32),
        ("flags", c.c_uint32),
        ("num_regions", c.c_uint32),
        ("num_irqs", c.c_uint32),
    ]

class vfio_region_info(Structure):
    _pack_ = 1
    _fields_ = [
        ("argsz", c.c_uint32),
        ("flags", c.c_uint32),
        ("index", c.c_uint32),
        ("cap_offset", c.c_uint32),
        ("size", c.c_uint64),
        ("offset", c.c_uint64),
    ]

class vfio_region_info_cap_type(Structure):
    _pack_ = 1
    _fields_ = [
        ("id", c.c_uint16),
        ("version", c.c_uint16),
        ("next", c.c_uint32),
        ("type", c.c_uint32),
        ("subtype", c.c_uint32),
    ]

class vfio_region_info_cap_sparse_mmap(Structure):
    _pack_ = 1
    _fields_ = [
        ("id", c.c_uint16),
        ("version", c.c_uint16),
        ("next", c.c_uint32),
        ("nr_areas", c.c_uint32),
        ("reserved", c.c_uint32),
    ]

class vfio_region_sparse_mmap_area(Structure):
    _pack_ = 1
    _fields_ = [
        ("offset", c.c_uint64),
        ("size", c.c_uint64),
    ]

class vfio_user_dma_map(Structure):
    _pack_ = 1
    _fields_ = [
        ("argsz", c.c_uint32),
        ("flags", c.c_uint32),
        ("offset", c.c_uint64),
        ("addr", c.c_uint64),
        ("size", c.c_uint64),
    ]

class vfu_dma_info_t(Structure):
    _fields_ = [
        ("iova", iovec_t),
        ("vaddr", c.c_void_p),
        ("mapping", iovec_t),
        ("page_size", c.c_size_t),
        ("prot", c.c_uint32)
    ]

class vfio_user_dirty_pages(Structure):
    _pack_ = 1
    _fields_ = [
        ("argsz", c.c_uint32),
        ("flags", c.c_uint32)
    ]

class vfio_user_bitmap(Structure):
    _pack_ = 1
    _fields_ = [
        ("pgsize", c.c_uint64),
        ("size", c.c_uint64)
    ]

class vfio_user_bitmap_range(Structure):
    _pack_ = 1
    _fields_ = [
        ("iova", c.c_uint64),
        ("size", c.c_uint64),
        ("bitmap", vfio_user_bitmap)
    ]

transition_cb_t = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_int)
get_pending_bytes_cb_t = c.CFUNCTYPE(c.c_uint64, c.c_void_p)
prepare_data_cb_t = c.CFUNCTYPE(c.c_void_p, c.POINTER(c.c_uint64),
                                c.POINTER(c.c_uint64))
read_data_cb_t = c.CFUNCTYPE(c.c_ssize_t, c.c_void_p, c.c_void_p,
                             c.c_uint64, c.c_uint64)
write_data_cb_t = c.CFUNCTYPE(c.c_ssize_t, c.c_void_p, c.c_uint64)
data_written_cb_t = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_uint64)

class vfu_migration_callbacks_t(Structure):
    _fields_ = [
        ("version", c.c_int),
        ("transition", transition_cb_t),
        ("get_pending_bytes", get_pending_bytes_cb_t),
        ("prepare_data", prepare_data_cb_t),
        ("read_data", read_data_cb_t),
        ("write_data", write_data_cb_t),
        ("data_written", data_written_cb_t),
    ]

class dma_sg_t(Structure):
    _fields_ = [
        ("dma_addr", c.c_void_p),
        ("region", c.c_int),
        ("length", c.c_uint64),
        ("offset", c.c_uint64),
        ("writeable", c.c_bool),
        ("le_next", c.c_void_p), # FIXME add struct for LIST_ENTRY 
        ("le_prev", c.c_void_p),
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
vfu_reset_cb_t = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_int)
lib.vfu_setup_device_reset_cb.argtypes = (c.c_void_p, vfu_reset_cb_t)
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
lib.vfu_irq_trigger.argtypes = (c.c_void_p, c.c_uint)
vfu_dma_register_cb_t = c.CFUNCTYPE(None, c.c_void_p, c.POINTER(vfu_dma_info_t))
vfu_dma_unregister_cb_t = c.CFUNCTYPE(c.c_int, c.c_void_p,
                                      c.POINTER(vfu_dma_info_t))
lib.vfu_setup_device_dma.argtypes = (c.c_void_p, vfu_dma_register_cb_t,
                                     vfu_dma_unregister_cb_t)
lib.vfu_setup_device_migration_callbacks.argtypes = (c.c_void_p,
    c.POINTER(vfu_migration_callbacks_t), c.c_uint64)
lib.vfu_addr_to_sg.argtypes = (c.c_void_p, c.c_void_p, c.c_size_t,
                               c.POINTER(dma_sg_t), c.c_int, c.c_int)
lib.vfu_map_sg.argtypes = (c.c_void_p, c.POINTER(dma_sg_t), c.POINTER(iovec_t),
                           c.c_int, c.c_int)
lib.vfu_unmap_sg.argtypes = (c.c_void_p, c.POINTER(dma_sg_t),
                             c.POINTER(iovec_t), c.c_int)

def to_byte(val):
    """Cast an int to a byte value."""
    return val.to_bytes(1, 'little')

def skip(fmt, buf):
    """Return the data remaining after skipping the given elements."""
    return buf[struct.calcsize(fmt):]

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

def msg(ctx, sock, cmd, payload, expect=0, fds=None):
    """Round trip a request and reply to the server."""
    hdr = vfio_user_header(cmd, size=len(payload))

    if fds:
        sock.sendmsg([hdr + payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                        struct.pack("I" * len(fds), *fds))])
    else:
        sock.send(hdr + payload)

    vfu_run_ctx(ctx)
    return get_reply(sock, expect=expect)

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
                      VFIO_USER_F_TYPE_COMMAND, error_no)

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
                     mmap_areas=None, nr_mmap_areas=None, fd=-1, offset=0):
    assert ctx != None

    c_mmap_areas = None

    if mmap_areas:
        c_mmap_areas = (iovec_t * len(mmap_areas))(*mmap_areas)

    if nr_mmap_areas is None:
        if mmap_areas:
            nr_mmap_areas = len(mmap_areas)
        else:
            nr_mmap_areas = 0

    # We're sending a file descriptor to ourselves; to pretend the server is
    # separate, we need to dup() here.
    if fd != -1:
        fd = os.dup(fd)

    ret = lib.vfu_setup_region(ctx, index, size,
                               c.cast(cb, vfu_region_access_cb_t),
                               flags, c_mmap_areas, nr_mmap_areas, fd, offset)

    if fd != -1 and ret != 0:
        os.close(fd)

    return ret

def vfu_setup_device_reset_cb(ctx, cb):
    assert ctx != None
    return lib.vfu_setup_device_reset_cb(ctx, c.cast(cb, vfu_reset_cb_t))

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

def vfu_irq_trigger(ctx, subindex):
    assert ctx != None

    return lib.vfu_irq_trigger(ctx, subindex)

def vfu_setup_device_dma(ctx, register_cb=None, unregister_cb=None):
    assert ctx != None

    return lib.vfu_setup_device_dma(ctx, c.cast(register_cb,
                                                vfu_dma_register_cb_t),
                                         c.cast(unregister_cb,
                                                vfu_dma_unregister_cb_t))

def vfu_setup_device_migration_callbacks(ctx, cbs=None, offset=0):
    assert ctx != None

    @c.CFUNCTYPE(c.c_int)
    def stub():
        return 0

    if not cbs:
        cbs = vfu_migration_callbacks_t()
        cbs.version = VFU_MIGR_CALLBACKS_VERS
        cbs.transition = c.cast(stub, transition_cb_t)
        cbs.get_pending_bytes = c.cast(stub, get_pending_bytes_cb_t)
        cbs.prepare_data = c.cast(stub, prepare_data_cb_t)
        cbs.read_data = c.cast(stub, read_data_cb_t)
        cbs.write_data = c.cast(stub, write_data_cb_t)
        cbs.data_written = c.cast(stub, data_written_cb_t)

    return lib.vfu_setup_device_migration_callbacks(ctx, cbs, offset)

def vfu_addr_to_sg(ctx, dma_addr, length, max_sg=1,
                   prot=(mmap.PROT_READ | mmap.PROT_WRITE)):
    assert ctx != None

    sg = dma_sg_t()

    return (lib.vfu_addr_to_sg(ctx, dma_addr, length, sg, max_sg, prot), sg)


def vfu_map_sg(ctx, sg, iovec, cnt=1, flags=0):
    # FIXME not sure wheter cnt != 1 will work because iovec is an array
    return lib.vfu_map_sg(ctx, sg, iovec, cnt, flags)

def vfu_unmap_sg(ctx, sg, iovec, cnt=1):
    return lib.vfu_unmap_sg(ctx, sg, iovec, cnt)

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
