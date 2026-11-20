#
# Copyright (c) 2026 Advanced Micro Devices, Inc. All rights reserved.
#
# Authors: Brian Kocoloski <bkocolos@amd.com>
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

"""
Peer DMA: one vfio-user server reaching another vfio-user by sending DMA
requests via the client

- 2 servers:
    - Server A: a device that issues DMAs via vfu_sgl_{read,write}
    - Server B: a device being DMA'd to
- Server B has 2 BARs:
    - BAR0 has an access callback and is not mmap-able, so A gets no file
      descriptor to reach it. A's vfu_sgl_write() and vfu_sgl_read() on it
      become DMA_WRITE and DMA_READ messages to the client, which carries
      them out on B as REGION_WRITE and REGION_READ.
    - BAR2 is backed by a file and is mmap-able, so A gets B's file
      descriptor and maps it. A's accesses go straight into the mapping and
      the client sees no DMA message. BAR2 also has an access callback on the
      same file, so a client that does not map it can still use the socket.
- The client asks B how each BAR is accessed (DEVICE_GET_REGION_INFO) and
  DMA_MAPs it into A, so A can name it with vfu_addr_to_sgl().
"""

from libvfio_user import *
import errno
import mmap
import os
import pytest
import select
import tempfile
import threading

# Where B's BARs are in the guest, as announced to A.
BAR_SIZE = PAGE_SIZE
BAR0_ADDR = 0x20000000
BAR2_ADDR = 0x30000000

# B's BARs by region index.
BARS = {
    VFU_PCI_DEV_BAR0_REGION_IDX: BAR0_ADDR,
    VFU_PCI_DEV_BAR2_REGION_IDX: BAR2_ADDR,
}

B_SOCK_PATH = SOCK_PATH + b".b"

ctx_a = None
ctx_b = None
client_a = None
client_b = None

# BAR0's contents, served by its access callback.
bar = bytearray(BAR_SIZE)

# BAR2's backing file, and the test's own view of it.
bar2_file = None
bar2 = None

# How many DMA_READ and DMA_WRITE messages A has sent the client. An access
# through a mapping sends no message, so it is not counted here.
dma_message_count = 0

# What A's library reported for each region it was asked to map.
dma_maps = []


def record_dma_register(ctx, info):
    dma_maps.append(info)


def access_bar(contents, buf, count, offset, is_write):
    if is_write:
        contents[offset:offset + count] = buf[:count]
    else:
        c.memmove(buf, bytes(contents[offset:offset + count]), count)
    return count


@vfu_region_access_cb_t
def bar_cb(ctx, buf, count, offset, is_write):
    return access_bar(bar, buf, count, offset, is_write)


@vfu_region_access_cb_t
def bar2_cb(ctx, buf, count, offset, is_write):
    return access_bar(bar2, buf, count, offset, is_write)


def find_bar(addr):
    """The region index and guest address of the BAR of B that addr is in."""
    for index, base in BARS.items():
        if base <= addr < base + BAR_SIZE:
            return index, base
    raise AssertionError("%#x is not in a BAR of B" % addr)


def forward_dma(sock, pipe, errors):
    """
    Carry out A's DMA accesses on B's BARs, until the pipe is closed. While
    A has an access in flight this thread is the only user of ctx_b and
    client_b; the test thread uses them only before it starts one.
    """
    global dma_message_count

    while True:
        (ready, _, _) = select.select([sock, pipe], [], [])
        if pipe in ready:
            break

        _, msg_id, cmd, payload = get_msg_fds(sock, VFIO_USER_F_TYPE_COMMAND)
        access, data = vfio_user_dma_region_access.pop_from_buffer(payload)
        dma_message_count += 1
        error_no = 0
        try:
            assert cmd in [VFIO_USER_DMA_READ, VFIO_USER_DMA_WRITE]
            index, base = find_bar(access.addr)
            assert access.addr + access.count <= base + BAR_SIZE
            offset = access.addr - base
            if cmd == VFIO_USER_DMA_WRITE:
                write_region(ctx_b, client_b.sock, index, offset,
                             access.count, data)
                data = bytes()
            else:
                data = read_region(ctx_b, client_b.sock, index, offset,
                                   access.count)
        except Exception as e:
            # Fail A's access, rather than leave it waiting for a reply.
            errors.append(e)
            error_no = errno.EIO
            data = bytes()

        send_msg(sock, cmd, VFIO_USER_F_TYPE_REPLY,
                 payload=bytes(access) + data, msg_id=msg_id,
                 error_no=error_no)

    sock.close()


@pytest.fixture(autouse=True)
def peers(monkeypatch, request):
    global ctx_a, ctx_b, client_a, client_b, bar2_file, bar2
    global dma_message_count

    monkeypatch.setattr('libvfio_user.dma_register', record_dma_register)
    bar[:] = bytes(BAR_SIZE)
    dma_message_count = 0
    del dma_maps[:]

    bar2_file = tempfile.TemporaryFile()
    bar2_file.truncate(BAR_SIZE)
    bar2 = mmap.mmap(bar2_file.fileno(), 0)

    # B: a device with two BARs that are DMA'd to by device A: BAR0 with a
    # callback, and BAR2 backed by a file and with a callback on the same file
    ctx_b = vfu_create_ctx(sock_path=B_SOCK_PATH,
                           flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx_b is not None
    assert vfu_pci_init(ctx_b) == 0
    flags = VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM
    assert vfu_setup_region(ctx_b, index=VFU_PCI_DEV_BAR0_REGION_IDX,
                            size=BAR_SIZE, cb=bar_cb, flags=flags) == 0
    assert vfu_setup_region(ctx_b, index=VFU_PCI_DEV_BAR2_REGION_IDX,
                            size=BAR_SIZE, cb=bar2_cb, flags=flags,
                            mmap_areas=[(0, BAR_SIZE)],
                            fd=bar2_file.fileno()) == 0
    assert vfu_realize_ctx(ctx_b) == 0
    client_b = connect_client(ctx_b, sock_path=B_SOCK_PATH)

    # A: a device that does DMA. The twin socket carries its DMA, so that the
    # forwarding thread can answer while the test thread waits in the library.
    ctx_a = prepare_ctx_for_dma()
    caps = {
        "capabilities": {
            "max_data_xfer_size": PAGE_SIZE,
            "twin_socket": {
                "supported": True,
            },
        }
    }
    client_a = connect_client(ctx_a, caps)
    assert client_a.client_cmd_socket is not None

    errors = []
    (pipe_r, pipe_w) = os.pipe()
    # Duplicate the socket so the thread owns it and closes it.
    sock = socket.socket(fileno=os.dup(client_a.client_cmd_socket.fileno()))
    thread = threading.Thread(target=forward_dma, args=[sock, pipe_r, errors])
    thread.start()

    def teardown():
        os.close(pipe_w)
        thread.join()
        os.close(pipe_r)
        client_a.disconnect(ctx_a)
        vfu_destroy_ctx(ctx_a)
        client_b.disconnect(ctx_b)
        vfu_destroy_ctx(ctx_b)
        if os.path.exists(B_SOCK_PATH):
            os.remove(B_SOCK_PATH)
        bar2.close()
        bar2_file.close()
        assert not errors

    request.addfinalizer(teardown)


def announce_bar(index, addr):
    """
    Ask B how the BAR is accessed. If it's mmap'able, get the file descriptor
    for it and advertise it to A. Otherwise advertise it with no fd.
    """
    payload = vfio_region_info(argsz=80, flags=0, index=index, cap_offset=0,
                               size=0, offset=0)
    payload = bytes(payload) + b'\0' * (80 - len(vfio_region_info()))
    fds, result = msg_fds(ctx_b, client_b.sock,
                          VFIO_USER_DEVICE_GET_REGION_INFO, payload)
    info, _ = vfio_region_info.pop_from_buffer(result)

    flags = VFIO_USER_F_DMA_REGION_READ | VFIO_USER_F_DMA_REGION_WRITE
    if info.flags & VFIO_REGION_INFO_FLAG_MMAP:
        assert len(fds) == 1
        flags |= VFIO_USER_F_DMA_REGION_MMAP
    else:
        assert fds == []

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
                                flags=flags,
                                offset=info.offset if fds else 0,
                                addr=addr,
                                size=info.size)
    msg(ctx_a, client_a.sock, VFIO_USER_DMA_MAP, payload, fds=fds or None)

    # Assert that A's library mapped the region if and only if it was given an
    # fd.
    assert len(dma_maps) == 1
    assert dma_maps[0].iova.iov_base == addr
    assert (dma_maps[0].vaddr is not None) == (len(fds) == 1)
    del dma_maps[:]

    for fd in fds:
        os.close(fd)


def test_peer_dma_write():
    announce_bar(VFU_PCI_DEV_BAR0_REGION_IDX, BAR0_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_a, dma_addr=BAR0_ADDR + 0x10, length=8,
                              max_nr_sgs=1, prot=mmap.PROT_WRITE)
    assert ret == 1

    # BAR0 has no file descriptor, so A has nothing to access directly: it
    # sends a DMA message whether or not it asks for direct access.
    data = bytearray(range(1, 9))
    assert vfu_sgl_write(ctx_a, sg, 1, data, 0) == 0
    assert bar[0x10:0x18] == data
    assert dma_message_count == 1

    data = bytearray(range(0x11, 0x19))
    assert vfu_sgl_write(ctx_a, sg, 1, data, VFU_SGL_DIRECT_ACCESS) == 0
    assert bar[0x10:0x18] == data
    assert dma_message_count == 2


def test_peer_dma_read():
    announce_bar(VFU_PCI_DEV_BAR0_REGION_IDX, BAR0_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_a, dma_addr=BAR0_ADDR + 0x20, length=8,
                              max_nr_sgs=1, prot=mmap.PROT_READ)
    assert ret == 1

    # As for writes: a DMA message either way.
    bar[0x20:0x28] = bytes(range(0x80, 0x88))
    assert vfu_sgl_read(ctx_a, sg, 1, 0) == \
        (0, bytearray(range(0x80, 0x88)))
    assert dma_message_count == 1

    bar[0x20:0x28] = bytes(range(0x90, 0x98))
    assert vfu_sgl_read(ctx_a, sg, 1, VFU_SGL_DIRECT_ACCESS) == \
        (0, bytearray(range(0x90, 0x98)))
    assert dma_message_count == 2


def test_peer_dma_mmap_write():
    announce_bar(VFU_PCI_DEV_BAR2_REGION_IDX, BAR2_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_a, dma_addr=BAR2_ADDR + 0x30, length=8,
                              max_nr_sgs=1, prot=mmap.PROT_WRITE)
    assert ret == 1

    # It goes into the shared file, and the client is not involved.
    data = bytearray(range(1, 9))
    assert vfu_sgl_write(ctx_a, sg, 1, data, VFU_SGL_DIRECT_ACCESS) == 0
    assert bar2[0x30:0x38] == data
    assert dma_message_count == 0

    # Without VFU_SGL_DIRECT_ACCESS, A does not use its mapping of BAR2. It
    # sends the access to the client as a DMA message, as it does for BAR0, and
    # the client carries it out on B's BAR2 callback, which writes the same
    # file.
    data = bytearray(range(0x11, 0x19))
    assert vfu_sgl_write(ctx_a, sg, 1, data, 0) == 0
    assert bar2[0x30:0x38] == data
    assert dma_message_count == 1


def test_peer_dma_mmap_read():
    announce_bar(VFU_PCI_DEV_BAR2_REGION_IDX, BAR2_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_a, dma_addr=BAR2_ADDR + 0x40, length=8,
                              max_nr_sgs=1, prot=mmap.PROT_READ)
    assert ret == 1

    # It comes from the shared file, and the client is not involved.
    bar2[0x40:0x48] = bytes(range(0x80, 0x88))
    assert vfu_sgl_read(ctx_a, sg, 1, VFU_SGL_DIRECT_ACCESS) == \
        (0, bytearray(range(0x80, 0x88)))
    assert dma_message_count == 0

    # Without VFU_SGL_DIRECT_ACCESS, A does not use its mapping of BAR2. It
    # sends the access to the client as a DMA message, and the client carries
    # it out on B's BAR2 callback, which reads the same file.
    bar2[0x40:0x48] = bytes(range(0x90, 0x98))
    assert vfu_sgl_read(ctx_a, sg, 1, 0) == \
        (0, bytearray(range(0x90, 0x98)))
    assert dma_message_count == 1


def test_peer_dma_not_announced():
    # Without the DMA_MAP, A has no way to name B's BARs.
    for addr in (BAR0_ADDR, BAR2_ADDR):
        ret, _ = vfu_addr_to_sgl(ctx_a, dma_addr=addr, length=8,
                                 max_nr_sgs=1, prot=mmap.PROT_WRITE)
        assert ret == -1
        assert c.get_errno() == errno.ENOENT
    assert dma_message_count == 0


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
