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

from types import SimpleNamespace
import ctypes as c
import json
import os
import pathlib
import socket
import struct
import syslog

SOCK_PATH = b"/tmp/vfio-user.sock.%d" % os.getpid()

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

PCI_BARS_NR = 6

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

PCI_HEADER_TYPE_NORMAL = 0

PCI_STD_HEADER_SIZEOF = 64

PCI_CFG_SPACE_SIZE = 256
PCI_CAP_ID_PM = b'\1'


topdir = os.path.realpath(os.path.dirname(__file__) + "/../..")
build_type = os.getenv("BUILD_TYPE", default="dbg")
libname = "%s/build/%s/lib/libvfio-user.so" % (topdir, build_type)
lib = c.CDLL(libname, use_errno=True)
lib.vfu_create_ctx.argtypes = (c.c_int, c.c_char_p, c.c_int,
                               c.c_void_p, c.c_int)
lib.vfu_create_ctx.restype = (c.c_void_p)
lib.vfu_setup_log.argtypes = (c.c_void_p, c.c_void_p, c.c_int)
lib.vfu_realize_ctx.argtypes = (c.c_void_p,)
lib.vfu_attach_ctx.argtypes = (c.c_void_p,)
lib.vfu_run_ctx.argtypes = (c.c_void_p,)
lib.vfu_destroy_ctx.argtypes = (c.c_void_p,)
lib.vfu_setup_region.argtypes = (c.c_void_p, c.c_int, c.c_long, c.c_void_p,
                                 c.c_int, c.c_void_p, c.c_int, c.c_int)
lib.vfu_pci_get_config_space.argtypes = (c.c_void_p,)
lib.vfu_pci_get_config_space.restype = (c.c_void_p)
lib.vfu_setup_device_nr_irqs.argtypes = (c.c_void_p, c.c_int, c.c_int)
lib.vfu_pci_init.argtypes = (c.c_void_p, c.c_int, c.c_int, c.c_int)
lib.vfu_pci_add_capability.argtypes = (c.c_void_p, c.c_long, c.c_int,
                                       c.POINTER(c.c_byte))

msg_id = 1

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

#
# Util functions
#

def connect_sock():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCK_PATH)
    return sock

def get_reply(sock, expect=0):
    buf = sock.recv(4096)
    (msg_id, cmd, msg_size, flags, errno) = struct.unpack("HHIII", buf[0:16])
    assert errno == expect
    msg_size -= 16
    return buf[16:]

def parse_json(json_str):
    """Parse JSON into an object with attributes (instead of using a dict)."""
    return json.loads(json_str, object_hook=lambda d: SimpleNamespace(**d))

def get_pci_header(ctx):
    ptr = lib.vfu_pci_get_config_space(ctx)
    return c.cast(ptr, c.POINTER(vfu_pci_hdr_t)).contents

#
# Library wrappers
#

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

def vfu_setup_region(ctx, index, size, flags=0):
    assert ctx != None
    ret = lib.vfu_setup_region(ctx, index, size, None, flags, None, 0, -1)
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
