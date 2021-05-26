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
import os
import sys

ctx = None
sock = None

argsz = len(vfio_irq_set())

def test_request_errors_setup():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx != None

    ret = vfu_pci_init(ctx)
    assert ret == 0

    ret = vfu_setup_device_nr_irqs(ctx, VFU_DEV_MSIX_IRQ, 2048)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)

def test_too_small():
    # struct vfio_user_header
    hdr = struct.pack("HHIII", 0xbad1, VFIO_USER_DEVICE_SET_IRQS,
                      SIZEOF_VFIO_USER_HEADER - 1, VFIO_USER_F_TYPE_COMMAND, 0)

    sock.send(hdr)
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_too_large():
    # struct vfio_user_header
    hdr = struct.pack("HHIII", 0xbad1, VFIO_USER_DEVICE_SET_IRQS,
                      SERVER_MAX_MSG_SIZE + 1, VFIO_USER_F_TYPE_COMMAND, 0)

    sock.send(hdr)
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_unsolicited_reply():
    # struct vfio_user_header
    hdr = struct.pack("HHIII", 0xbad2, VFIO_USER_DEVICE_SET_IRQS,
                      SIZEOF_VFIO_USER_HEADER, VFIO_USER_F_TYPE_REPLY, 0)

    sock.send(hdr)
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_bad_command():
    hdr = vfio_user_header(VFIO_USER_MAX, size=1)

    sock.send(hdr + b'\0')
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_no_payload():
    hdr = vfio_user_header(VFIO_USER_DEVICE_SET_IRQS, size=0)
    sock.send(hdr)
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

def test_bad_request_closes_fds():
    payload = vfio_irq_set(argsz=argsz, flags=VFIO_IRQ_SET_ACTION_TRIGGER |
                           VFIO_IRQ_SET_DATA_BOOL, index=VFU_DEV_MSIX_IRQ,
                           start=0, count=1)

    fd1 = eventfd()
    fd2 = eventfd()

    hdr = vfio_user_header(VFIO_USER_DEVICE_SET_IRQS, size=len(payload))
    sock.sendmsg([hdr + payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                 struct.pack("II", fd1, fd2))])
    vfu_run_ctx(ctx)
    get_reply(sock, expect=errno.EINVAL)

    #
    # It's a little cheesy, but this is just ensuring no fd's remain open past
    # the one we just allocated; i.e. free_msg() freed the fds it got.
    #
    test_fd = eventfd()
    assert test_fd == fd2 + 1
    os.close(test_fd)

    os.close(fd1)
    os.close(fd2)

def test_request_errors_cleanup():
    vfu_destroy_ctx(ctx)
