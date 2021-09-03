from libvfio_user import *
import ctypes as c
import errno
import tempfile
import os
import struct
import ctypes

ctx = None
sock = None
fds = []

def test_device_get_region_io_fds_setup():
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

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)
    for i in range(0,6):
        tmp = eventfd(0,0)
        fds.append(tmp)
        assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, tmp, \
                                    i * 8, 8, 0, 0) != -1

def test_device_get_region_io_fds_bad_flags():

    payload = vfio_user_region_io_fds_request(argsz = 16+40*5, flags = 1, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 0)

    msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload, \
        expect=errno.EINVAL)

def test_device_get_region_io_fds_bad_count():

    payload = vfio_user_region_io_fds_request(argsz = 16+40*5, flags = 0, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 1)

    msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload, \
        expect=errno.EINVAL)

def test_device_get_region_io_fds_buffer_to_small():

    payload = vfio_user_region_io_fds_request(argsz = 15, flags = 0, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 1)

    msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload, \
        expect=errno.EINVAL)

def test_device_get_region_io_fds_buffer_to_large():

    payload = vfio_user_region_io_fds_request(argsz = SERVER_MAX_DATA_XFER_SIZE\
                                              + 1, flags = 0, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 1)

    msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload, expect=errno.EINVAL)

def test_device_get_region_io_fds_no_regions():

    payload = vfio_user_region_io_fds_request(argsz = 512, flags = 0, \
                                index = VFU_PCI_DEV_BAR1_REGION_IDX, count = 0)

    ret = msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload, expect=0)

    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    assert reply.argsz == ctypes.sizeof(vfio_user_region_io_fds_reply)
    assert reply.count == 0
    assert reply.flags == 0
    assert reply.index == VFU_PCI_DEV_BAR1_REGION_IDX


def test_device_get_region_io_fds_no_regions_setup():

    payload = vfio_user_region_io_fds_request(argsz = 512, flags = 0, \
                                index = VFU_PCI_DEV_BAR3_REGION_IDX, count = 0)

    ret = msg(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, payload, expect=0)

    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    assert reply.argsz == ctypes.sizeof(vfio_user_region_io_fds_reply)
    assert reply.count == 0
    assert reply.flags == 0
    assert reply.index == VFU_PCI_DEV_BAR3_REGION_IDX

def test_device_get_region_io_fds_fds_read_write():

    payload = vfio_user_region_io_fds_request(argsz = 16+40*4, flags = 0, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 0)

    newfds, ret = msg_fd(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, \
                         payload, expect=0)

    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)
    ioevent, ret = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)

    for i in range(0,4):
        os.write(newfds[i], c.c_ulonglong(10))
        out = os.read(newfds[i], 8)
        [out] = struct.unpack("@Q",out)
        assert out == 10

def test_device_get_region_io_fds_full():

    payload = vfio_user_region_io_fds_request(argsz = 16+(40*6), flags = 0, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 0)

    newfds, ret = msg_fd(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, \
                         payload, expect=0)

    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    ioevents = []
    for i in range(0, reply.count):
        ioevent, ret = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)
        ioevents.append(ioevent)
        os.write(newfds[ioevent.fd_index], c.c_ulonglong(1))

    for i in range(0, reply.count):
        out = os.read(newfds[ioevents[i].fd_index], ioevent.size)
        [out] = struct.unpack("@Q",out)
        assert out == 1
        assert ioevents[i].size == 8
        assert ioevents[i].offset == 40 - (8 * i)
        assert ioevents[i].type == VFIO_USER_IO_FD_TYPE_IOEVENTFD

def test_device_get_region_io_fds_fds_read_write_nothing():

    payload = vfio_user_region_io_fds_request(argsz = 16, flags = 0, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 0)

    newfds, ret = msg_fd(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, \
                         payload, expect=0)

    reply, ret = vfio_user_region_io_fds_request.pop_from_buffer(ret)
    assert reply.argsz == 16

def test_device_get_region_io_fds_fds_read_write_dupe_fd():

    t = eventfd(0,0)
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, t, 6 * 8, 8, \
                                 0, 0) != -1
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, t, 7 * 8, 8, \
                                0, 0) != -1

    payload = vfio_user_region_io_fds_request(argsz = 16+(40*8), flags = 0, \
                                index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 0)

    newfds, ret = msg_fd(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, \
                         payload, expect=0)
    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    assert reply.count == 8
    assert reply.argsz == 16+(40*8)

    ioevents = []
    for i in range(0, reply.count):
        ioevent, ret = vfio_user_sub_region_ioeventfd.pop_from_buffer(ret)
        ioevents.append(ioevent)

    for i in range(2, 8):
        os.write(newfds[ioevents[i].fd_index], c.c_ulonglong(1))

    for i in range(2, 8):
        out = os.read(newfds[ioevents[i].fd_index], ioevent.size)
        [out] = struct.unpack("@Q",out)
        assert out == 1
        assert ioevents[i].size == 8
        assert ioevents[i].offset == 56 - (8 * i)
        assert ioevents[i].type == VFIO_USER_IO_FD_TYPE_IOEVENTFD

    assert ioevents[0].fd_index == ioevents[1].fd_index
    assert ioevents[0].offset != ioevents[1].offset

    os.write(newfds[ioevents[0].fd_index], c.c_ulonglong(1))

    out = os.read(newfds[ioevents[1].fd_index], ioevent.size)
    [out] = struct.unpack("@Q",out)
    assert out == 1

    os.write(newfds[ioevents[1].fd_index], c.c_ulonglong(1))

    out = os.read(newfds[ioevents[0].fd_index], ioevent.size)
    [out] = struct.unpack("@Q",out)
    assert out == 1

    os.write(newfds[ioevents[0].fd_index], c.c_ulonglong(1))
    out = os.read(newfds[ioevents[1].fd_index], ioevent.size)
    [out] = struct.unpack("@Q",out)
    assert out == 1

    assert vfu_delete_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, \
                                ioevents[0].offset, ioevents[0].size, \
                                ioevents[0].fd_index, ioevents[0].flags) == 0
    assert vfu_delete_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, \
                                ioevents[1].offset, ioevents[1].size, \
                                ioevents[1].fd_index, ioevents[1].flags) == 0

    payload = vfio_user_region_io_fds_request(argsz = 16+(40*8), flags = 0, \
                                 index = VFU_PCI_DEV_BAR2_REGION_IDX, count = 0)

    newfds, ret = msg_fd(ctx, sock, VFIO_USER_DEVICE_GET_REGION_IO_FDS, \
                         payload, expect=0)
    reply, ret = vfio_user_region_io_fds_reply.pop_from_buffer(ret)

    assert reply.count == 6

def test_device_get_region_io_fds_ioeventfd_invalid_size():

    t = eventfd(0,0)
    assert vfu_create_ioeventfd(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, t, 0x8000 \
                                -2048, 4096, 0, 0) == -1
    os.close(t)

def test_device_get_region_info_cleanup():
    for i in fds:
        os.close(i)
    vfu_destroy_ctx(ctx)
