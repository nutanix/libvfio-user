#
# Copyright (c) 2021 Nutanix Inc. All rights reserved.
#
# Authors: Jack Kelly <jack.kelly@nutanix.com>
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
import struct

ctx = None
client = None
fds = []


def test_device_get_region_io_fds_setup():
    global ctx, client

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    f = tempfile.TemporaryFile()
    f.truncate(65536)

    mmap_areas = [(0x2000, 0x1000), (0x4000, 0x2000)]

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR1_REGION_IDX, size=0x8000,
                           flags=(VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM),
                           mmap_areas=mmap_areas, fd=f.fileno(), offset=0x8000)
    assert ret == 0

    f = tempfile.TemporaryFile()
    f.truncate(65536)

    mmap_areas = [(0x2000, 0x1000), (0x4000, 0x2000)]

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR2_REGION_IDX, size=0x8000,
                           flags=(VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM),
                           mmap_areas=mmap_areas, fd=f.fileno(), offset=0x8000)
    assert ret == 0

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR5_REGION_IDX, size=0x8000,
                           flags=(VFU_REGION_FLAG_RW), offset=0x8000)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    client = connect_client(ctx)
    for i in range(0, 6):
        tmp = eventfd(0, 0)
        fds.append(tmp)
        assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, tmp,
                                    i * IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1


def test_device_get_region_io_fds_bad_flags():

    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()) +
                len(vfio_user_sub_region_ioeventfd()) * 5, flags=1,
                index=VFU_PCI_DEV_BAR2_REGION_IDX, count=0)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
        expect=errno.EINVAL)


def test_device_get_region_io_fds_bad_count():

    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()) +
                len(vfio_user_sub_region_ioeventfd()) * 5, flags=0,
                index=VFU_PCI_DEV_BAR2_REGION_IDX, count=1)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
        expect=errno.EINVAL)


def test_device_get_region_io_fds_buffer_too_small():

    payload = vfio_user_region_io_fds_request(
            argsz=len(vfio_user_region_io_fds_reply()) - 1, flags=0,
            index=VFU_PCI_DEV_BAR2_REGION_IDX, count=1)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
        expect=errno.EINVAL)


def test_device_get_region_io_fds_buffer_too_large():

    payload = vfio_user_region_io_fds_request(argsz=SERVER_MAX_DATA_XFER_SIZE
                                            + 1, flags=0,
                                            index=VFU_PCI_DEV_BAR2_REGION_IDX,
                                            count=1)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
        expect=errno.EINVAL)


def test_device_get_region_io_fds_no_fds():

    payload = vfio_user_region_io_fds_request(argsz=512, flags=0,
                                index=VFU_PCI_DEV_BAR1_REGION_IDX, count=0)

    ret = msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
              expect=0)

    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    assert reply.argsz == len(vfio_user_region_io_fds_reply())
    assert reply.count == 0
    assert reply.flags == 0
    assert reply.index == VFU_PCI_DEV_BAR1_REGION_IDX


def test_device_get_region_io_fds_no_regions_setup():

    payload = vfio_user_region_io_fds_request(argsz=512, flags=0,
                                index=VFU_PCI_DEV_BAR3_REGION_IDX, count=0)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
        expect=errno.EINVAL)


def test_device_get_region_io_fds_region_no_mmap():

    payload = vfio_user_region_io_fds_request(argsz=512, flags=0,
                                index=VFU_PCI_DEV_BAR5_REGION_IDX, count=0)

    ret = msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
              expect=0)

    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    assert reply.argsz == len(vfio_user_region_io_fds_reply())
    assert reply.count == 0
    assert reply.flags == 0
    assert reply.index == VFU_PCI_DEV_BAR5_REGION_IDX


def test_device_get_region_io_fds_region_out_of_range():

    payload = vfio_user_region_io_fds_request(argsz=512, flags=0,
                                              index=512, count=0)

    msg(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload,
        expect=errno.EINVAL)


def test_device_get_region_io_fds_fds_read_write():

    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()) +
                len(vfio_user_sub_region_ioeventfd()) * 10, flags=0,
                index=VFU_PCI_DEV_BAR2_REGION_IDX, count=0)

    newfds, ret = msg_fds(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS,
                          payload, expect=0)

    assert len(newfds) == 6
    _, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)
    _, ret = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)

    # Simulating a VM triggering an ioeventfd and the server waking up

    # Client
    for i in range(0, len(newfds)):
        os.write(newfds[i], c.c_ulonglong(10))

    # Server
    for i in range(0, len(newfds)):
        out = os.read(newfds[i], IOEVENT_SIZE)
        [out] = struct.unpack("@Q", out)
        assert out == 10

    for i in newfds:
        os.close(i)


def test_device_get_region_io_fds_full():

    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()) +
                len(vfio_user_sub_region_ioeventfd()) * 6, flags=0,
                index=VFU_PCI_DEV_BAR2_REGION_IDX, count=0)

    newfds, ret = msg_fds(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS,
                          payload, expect=0)

    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)
    assert len(newfds) == reply.count
    ioevents = []
    for i in range(0, reply.count):
        ioevent, ret = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)
        ioevents.append(ioevent)
        os.write(newfds[ioevent.fd_index], c.c_ulonglong(1))

    for i in range(0, reply.count):
        out = os.read(newfds[ioevents[i].fd_index], ioevent.size)
        [out] = struct.unpack("@Q", out)
        assert out == 1
        assert ioevents[i].size == IOEVENT_SIZE
        assert ioevents[i].gpa_offset == 40 - (IOEVENT_SIZE * i)
        assert ioevents[i].type == VFIO_USER_IO_FD_TYPE_IOEVENTFD

    for i in newfds:
        os.close(i)


def test_device_get_region_io_fds_fds_read_write_nothing():

    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()), flags=0,
                index=VFU_PCI_DEV_BAR2_REGION_IDX, count=0)

    newfds, ret = msg_fds(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS,
                          payload, expect=0)

    assert len(newfds) == 0
    reply, _ = vfio_user_region_io_fds_request.pop_from_buffer(ret)
    assert reply.argsz == len(vfio_user_region_io_fds_reply()) + \
                          len(vfio_user_sub_region_ioeventfd()) * 6


def test_device_get_region_io_fds_fds_read_write_dupe_fd():
    """ Test here to show that we can return mutliple sub regions with the same
        fd_index. fd_index points to the list of fds returned from the socket
        as returned by msg_fds. """

    t = eventfd(0, 0)
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, t, 6 *
                                IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, t, 7 *
                                IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1

    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()) +
                len(vfio_user_sub_region_ioeventfd()) * 8, flags=0,
                index=VFU_PCI_DEV_BAR2_REGION_IDX, count=0)

    newfds, ret = msg_fds(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS,
                          payload, expect=0)
    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)
    assert len(newfds) == 7
    assert reply.count == 8
    assert reply.argsz == len(vfio_user_region_io_fds_reply()) + \
                          len(vfio_user_sub_region_ioeventfd()) * 8

    ioevents = []
    for i in range(0, reply.count):
        ioevent, ret = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)
        ioevents.append(ioevent)

    for i in range(2, 8):
        os.write(newfds[ioevents[i].fd_index], c.c_ulonglong(1))

    for i in range(2, 8):
        out = os.read(newfds[ioevents[i].fd_index], ioevent.size)
        [out] = struct.unpack("@Q", out)
        assert out == 1
        assert ioevents[i].size == IOEVENT_SIZE
        assert ioevents[i].gpa_offset == 56 - (IOEVENT_SIZE * i)
        assert ioevents[i].type == VFIO_USER_IO_FD_TYPE_IOEVENTFD

    assert ioevents[0].fd_index == ioevents[1].fd_index
    assert ioevents[0].gpa_offset != ioevents[1].gpa_offset

    os.write(newfds[ioevents[0].fd_index], c.c_ulonglong(1))

    out = os.read(newfds[ioevents[1].fd_index], ioevent.size)
    [out] = struct.unpack("@Q", out)
    assert out == 1

    os.write(newfds[ioevents[1].fd_index], c.c_ulonglong(1))

    out = os.read(newfds[ioevents[0].fd_index], ioevent.size)
    [out] = struct.unpack("@Q", out)
    assert out == 1

    os.write(newfds[ioevents[0].fd_index], c.c_ulonglong(1))
    out = os.read(newfds[ioevents[1].fd_index], ioevent.size)
    [out] = struct.unpack("@Q", out)
    assert out == 1

    for i in newfds:
        os.close(i)


def test_device_get_region_io_fds_ioeventfd_invalid_size():

    t = eventfd(0, 0)
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, t,
                                0x8000 - 0x800, 4096, 0, 0) == -1
    os.close(t)


def test_device_get_region_info_cleanup():
    for i in fds:
        os.close(i)
    vfu_destroy_ctx(ctx)


def test_device_get_region_io_fds_invalid_fd():
    """Tests that an ioregionfd where fd is -1 is a legitimate ioregionfd."""
    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_setup_region(ctx, index=VFU_PCI_DEV_BAR0_REGION_IDX, size=0x1000,
                           flags=(VFU_REGION_FLAG_RW))
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    client = connect_client(ctx)

    fds = []

    # use valid fd
    fd = eventfd(0, 0)
    fds.append(fd)
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, fd,
                                0 * IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1

    # use -1 fd
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, -1,
                                1 * IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1

    # use another valid fd
    fd = eventfd(0, 0)
    fds.append(fd)
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, fd,
                                2 * IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1

    # use -1 fd
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, -1,
                                3 * IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1

    # use duplicate valid fd
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, fds[1],
                                4 * IOEVENT_SIZE, IOEVENT_SIZE, 0, 0) != -1

    payload = vfio_user_region_io_fds_request(
                argsz=len(vfio_user_region_io_fds_reply()) +
                len(vfio_user_sub_region_ioeventfd()) * 5, flags=0,
                index=VFU_PCI_DEV_BAR0_REGION_IDX, count=0)

    newfds, ret = msg_fds(ctx, client.sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS,
                          payload, expect=0)

    # two unique fds
    assert len(newfds) == 2
    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    # five ioregionfds
    assert reply.count == 5
    ioevents = []
    for i in range(0, reply.count):
        ioevent, ret = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)
        ioevents.append(ioevent)

    # TODO this assumes that ioregionfds are returned in the reverse order
    # they're created. It should be straightforward to compare based on IOVA.
    assert ioevents[0].fd_index == 0
    assert ioevents[0].gpa_offset == 4 * IOEVENT_SIZE
    assert ioevents[0].size == IOEVENT_SIZE
    assert fds_are_same(newfds[0], fds[0])

    assert ioevents[1].fd_index == UINT32_MAX
    assert ioevents[1].gpa_offset == 3 * IOEVENT_SIZE
    assert ioevents[1].size == IOEVENT_SIZE

    assert ioevents[2].fd_index == 0
    assert ioevents[2].gpa_offset == 2 * IOEVENT_SIZE
    assert ioevents[2].size == IOEVENT_SIZE
    assert fds_are_same(newfds[0], fds[0])

    assert ioevents[3].fd_index == UINT32_MAX
    assert ioevents[3].gpa_offset == 1 * IOEVENT_SIZE
    assert ioevents[3].size == IOEVENT_SIZE

    assert ioevents[4].fd_index == 1
    assert ioevents[4].gpa_offset == 0 * IOEVENT_SIZE
    assert ioevents[4].size == IOEVENT_SIZE
    assert fds_are_same(newfds[1], fds[1])

    # cleanup
    for fd in fds:
        os.close(fd)
    vfu_destroy_ctx(ctx)

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
