#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Authors: Thanos Makatos <thanos.makatos@nutanix.com>
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
import tempfile
import mmap
import errno


def test_shadow_ioeventfd():
    """Configure a shadow ioeventfd, have the client trigger it, confirm that
    the server receives the notification and can see the value."""

    # server setup
    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None
    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR0_REGION_IDX, size=0x1000,
                           flags=VFU_REGION_FLAG_RW)
    assert ret == 0
    fo = tempfile.TemporaryFile(dir="/dev/shm")
    fo.truncate(0x1000)

    # FIXME
    # Use pip install eventfd?
    #   $ grep EFD_NONBLOCK -wr /usr/include/
    #   /usr/include/bits/eventfd.h:    EFD_NONBLOCK = 00004000
    EFD_NONBLOCK = 0o00004000

    efd = eventfd(flags=EFD_NONBLOCK)
    ret = vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, efd, 0x8,
                               0x16, 0, 0, shadow_fd=fo.fileno())
    assert ret == 0
    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    # client queries I/O region FDs
    sock = connect_client(ctx)
    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()) +
                len(vfio_user_sub_region_ioeventfd()), flags=0,
                index=VFU_PCI_DEV_BAR0_REGION_IDX, count=0)
    newfds, ret = msg_fds(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS,
                          payload, expect=0)
    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)
    assert reply.count == 1  # 1 eventfd
    ioevent, _ = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)
    assert ioevent.offset == 0x8
    assert ioevent.size == 0x16
    assert ioevent.fd_index == 0
    assert ioevent.type == VFIO_USER_IO_FD_TYPE_IOEVENTFD_SHADOW
    assert ioevent.flags == 0
    assert ioevent.datamatch == 0

    assert len(newfds) == 2  # 2 FDs: eventfd plus shadow FD
    cefd = newfds[0]
    csfd = newfds[1]
    cmem = mmap.mmap(csfd, 0x1000)

    # vfio-user app reads the eventfd, there should be nothing there
    try:
        os.read(efd, IOEVENT_SIZE)
    except BlockingIOError as e:
        if e.errno != errno.EAGAIN:
            assert False
    else:
        assert False

    # Client writes to the I/O region. The write to the eventfd would be done
    # by KVM and the value would be the same in both cases.
    cmem.seek(0x8)
    cmem.write(c.c_ulonglong(0xdeadbeef))
    os.write(cefd, c.c_ulonglong(0xcafebabe))

    # vfio-user app reads eventfd
    assert os.read(efd, IOEVENT_SIZE) == to_bytes_le(0xcafebabe, 8)
    fo.seek(0x8)
    assert fo.read(0x8) == to_bytes_le(0xdeadbeef, 8)

    vfu_destroy_ctx(ctx)
