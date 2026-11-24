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
Peer DMA test: one vfio-user server reaching another vfio-user via DMA.

Components of the test:
- 2 servers:
    - INITIATOR: a device that issues DMAs via vfu_sgl_{read,write}
    - TARGET: a device with 2 BARs that can be DMA'd to
- Client:
    - Acts as an intermediary by "forwarding" DMA requests from the INITIATOR
      to the TARGET. When INITIATOR sends a DMA_READ/DMA_WRITE message, the
      client constructs a REGION_READ/REGION_WRITE message to the TARGET, and
      then sends the result back to the INITIATOR to complete the DMA request.
    - Asks TARGET how each BAR is accessed (DEVICE_GET_REGION_INFO) and
      DMA_MAPs it into INITIATOR, so INITIATOR can access it with
      vfu_addr_to_sgl().
- The TARGET's BARs:
    - BAR0: has an access callback and is not mmap-able, so INITIATOR gets no
      file descriptor to reach it. INITIATOR's vfu_sgl_write() and
      vfu_sgl_read() on it become DMA_WRITE and DMA_READ messages.
    - BAR2: backed by a file and is mmap-able, so INITIATOR gets TARGET's
      file descriptor and maps it. INITIATOR's "direct" accesses go straight
      into the mapping, without a DMA message.
"""

from libvfio_user import *
import errno
import mmap
import os
import pytest
import select
import tempfile
import threading

# Where TARGET's BARs are located
BAR_SIZE = PAGE_SIZE
BAR0_ADDR = (VFU_PCI_DEV_BAR0_REGION_IDX + 1) * BAR_SIZE
BAR2_ADDR = (VFU_PCI_DEV_BAR2_REGION_IDX + 1) * BAR_SIZE

TARGET_SOCK_PATH = SOCK_PATH + b".target"

ctx_initiator = None
ctx_target = None
client_initiator = None
client_target = None

# BAR0's contents
bar0 = bytearray(BAR_SIZE)

# BAR2's contents and backing file
bar2_file = None
bar2 = None

# Carries out the INITIATOR's DMA accesses on TARGET's BARs.
dma_forwarder = None


def access_bar(contents, buf, count, offset, is_write):
    if is_write:
        contents[offset:offset + count] = buf[:count]
    else:
        c.memmove(buf, bytes(contents[offset:offset + count]), count)
    return count


@vfu_region_access_cb_t
def bar0_cb(ctx, buf, count, offset, is_write):
    return access_bar(bar0, buf, count, offset, is_write)


@vfu_region_access_cb_t
def bar2_cb(ctx, buf, count, offset, is_write):
    return access_bar(bar2, buf, count, offset, is_write)


class DMAForwarder:
    """
    Runs the vfio-user client's side of INITIATOR's DMA commands.

    In a real setup the client (e.g. QEMU) and the server (libvfio-user plus
    the device emulation code using it) are separate processes. In these
    tests one Python thread plays all of them. It acts as the client when it
    sends messages and reads replies, and as the device emulation when it
    calls vfu_run_ctx(), as a server's main loop would, or vfu_sgl_*(), as the
    device would to DMA.

    vfu_sgl_read()/vfu_sgl_write() may produce DMA_READ/DMA_WRITE socket
    commands to the client, and *block until the client produces a reply*.
    With a real client in another process that is fine. Here the client runs
    in the same thread, so the fact that vfu_sgl_{read,write} block waiting
    for the reply means that the client code is never able to run to generate
    that reply.

    We address this by spawning a separate thread in this DMAForwarder object,
    whose responsibility it is to process the DMA_READ/DMA_WRITE messages and
    generate replies to the server. Any test where vfu_sgl_{read,write} sends
    a DMA message must do something similar; i.e., on regions with no fd, and
    for accesses without VFU_SGL_DIRECT_ACCESS.

    Note specific to this test: for peer-DMA, the way the client handles
    DMA_READ/DMA_WRITE messages is to forward them to the TARGET server. It
    does so by constructing REGION_READ/REGION_WRITE commands.
    """

    def __handle_requests(self):
        while True:
            (ready, _, _) = select.select([self.initiator_sock, self.pipe_r],
                                          [], [])
            if self.pipe_r in ready:
                break

            # Read a command from the socket and service it.
            _, msg_id, cmd, payload = get_msg_fds(self.initiator_sock,
                                                  VFIO_USER_F_TYPE_COMMAND)
            access, data = vfio_user_dma_region_access.pop_from_buffer(payload)

            self.msg_count += 1
            error_no = 0

            try:
                index = access.addr // BAR_SIZE - 1
                offset = access.addr % BAR_SIZE
                assert offset + access.count <= BAR_SIZE

                assert cmd in [VFIO_USER_DMA_READ, VFIO_USER_DMA_WRITE]
                if cmd == VFIO_USER_DMA_WRITE:
                    write_region(self.target_ctx, self.target_sock, index,
                                 offset, access.count, data)
                    data = bytes()
                else:
                    data = read_region(self.target_ctx, self.target_sock,
                                       index, offset, access.count)
            except Exception as e:
                # Fail INITIATOR's access, rather than leave it waiting for a
                # reply.
                self.errors.append(e)
                error_no = errno.EIO
                data = bytes()

            send_msg(self.initiator_sock, cmd, VFIO_USER_F_TYPE_REPLY,
                     payload=bytes(access) + data, msg_id=msg_id,
                     error_no=error_no)

        self.initiator_sock.close()

    def __init__(self, initiator_sock, target_ctx, target_sock):
        self.target_ctx = target_ctx
        self.target_sock = target_sock

        # How many DMA_READ and DMA_WRITE messages INITIATOR has sent
        self.msg_count = 0

        # Anything that went wrong carrying out an access.
        self.errors = []
        (self.pipe_r, self.pipe_w) = os.pipe()

        # Duplicate the socket file descriptor so the thread can own it and
        # make sure it gets closed only when terminating the thread.
        self.initiator_sock = socket.socket(
            fileno=os.dup(initiator_sock.fileno()))
        self.thread = threading.Thread(target=self.__handle_requests)
        self.thread.start()

    def shutdown(self):
        # Closing the pipe's write end signals the thread to terminate.
        os.close(self.pipe_w)
        self.thread.join()
        os.close(self.pipe_r)


@pytest.fixture(autouse=True)
def setup_peers(request):
    """
    setup_peers() is run for every peer-DMA test in this file. It sets up the
    two servers (INITIATOR and TARGET), creates connections to the client,
    and tears them down after each test.

    For the TARGET, we create 2 BARs. BAR0 has an access callback and no fd,
    so it cannot be mmap'd. BAR2 is backed by a file and is mmap-able. It also
    has a callback, allowing it to handle accesses made without
    VFU_SGL_DIRECT_ACCESS.

    This function also sets up the DMAForwarder thread to process the
    DMA_READ/DMA_WRITE commands issued by the INITIATOR. See the description
    in the DMAForwarder class for details on why this thread is needed.

    Teardown stops the forwarder, disconnects and destroys both contexts, and
    checks that the forwarder hit no errors.
    """

    global ctx_initiator, ctx_target, client_initiator, client_target
    global bar2_file, bar2, dma_forwarder

    bar0[:] = bytes(BAR_SIZE)

    bar2_file = tempfile.TemporaryFile()
    bar2_file.truncate(BAR_SIZE)
    bar2 = mmap.mmap(bar2_file.fileno(), 0)

    ctx_target = vfu_create_ctx(sock_path=TARGET_SOCK_PATH,
                                flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx_target is not None
    assert vfu_pci_init(ctx_target) == 0
    flags = VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM
    assert vfu_setup_region(ctx_target, index=VFU_PCI_DEV_BAR0_REGION_IDX,
                            size=BAR_SIZE, cb=bar0_cb, flags=flags) == 0
    assert vfu_setup_region(ctx_target, index=VFU_PCI_DEV_BAR2_REGION_IDX,
                            size=BAR_SIZE, cb=bar2_cb, flags=flags,
                            mmap_areas=[(0, BAR_SIZE)],
                            fd=bar2_file.fileno()) == 0
    assert vfu_realize_ctx(ctx_target) == 0
    client_target = connect_client(ctx_target, sock_path=TARGET_SOCK_PATH)

    ctx_initiator = prepare_ctx_for_dma()
    caps = {
        "capabilities": {
            "max_data_xfer_size": PAGE_SIZE,
            "twin_socket": {
                "supported": True,
            },
        }
    }
    client_initiator = connect_client(ctx_initiator, caps)
    assert client_initiator.client_cmd_socket is not None

    dma_forwarder = DMAForwarder(client_initiator.client_cmd_socket,
                                 ctx_target, client_target.sock)

    def teardown():
        dma_forwarder.shutdown()
        client_initiator.disconnect(ctx_initiator)
        vfu_destroy_ctx(ctx_initiator)
        client_target.disconnect(ctx_target)
        vfu_destroy_ctx(ctx_target)
        if os.path.exists(TARGET_SOCK_PATH):
            os.remove(TARGET_SOCK_PATH)
        bar2.close()
        bar2_file.close()
        assert not dma_forwarder.errors

    request.addfinalizer(teardown)


def dma_map_target_bar(index, addr):
    """
    DMA_MAP one of the TARGET's BARs as a DMA region in the INITIATOR. This is
    needed so that the INITIATOR can DMA to it, as vfu_addr_to_sgl() cannot
    resolve addresses outside of a DMA_MAP'd region.

    Ask TARGET how the BAR is accessed (DEVICE_GET_REGION_INFO). If it is
    mmap-able (BAR2), TARGET returns an fd, which is passed along in the
    DMA_MAP so INITIATOR can map it and, with VFU_SGL_DIRECT_ACCESS, access it
    directly. Otherwise (BAR0) the DMA_MAP carries no fd, so INITIATOR's
    accesses become DMA_READ/DMA_WRITE messages to the client.
    """
    payload = vfio_region_info(argsz=80, flags=0, index=index, cap_offset=0,
                               size=0, offset=0)
    payload = bytes(payload) + b'\0' * (80 - len(vfio_region_info()))
    fds, result = msg_fds(ctx_target, client_target.sock,
                          VFIO_USER_DEVICE_GET_REGION_INFO, payload)
    info, _ = vfio_region_info.pop_from_buffer(result)

    fd = None
    flags = VFIO_USER_F_DMA_REGION_READ | VFIO_USER_F_DMA_REGION_WRITE
    if info.flags & VFIO_REGION_INFO_FLAG_MMAP:
        assert len(fds) == 1
        fd = fds[0]
        flags |= VFIO_USER_F_DMA_REGION_MMAP
    else:
        assert fds == []

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
                                flags=flags,
                                offset=info.offset if fds else 0,
                                addr=addr,
                                size=info.size)
    msg(ctx_initiator, client_initiator.sock, VFIO_USER_DMA_MAP, payload,
        fds=fds)

    if fd is not None:
        os.close(fd)


def test_peer_dma_write():
    """
    INITIATOR writes to TARGET's BAR0, which has no fd. Every write becomes a
    DMA_WRITE that the client carries out on TARGET's BAR0 callback, with or
    without VFU_SGL_DIRECT_ACCESS.
    """
    dma_map_target_bar(VFU_PCI_DEV_BAR0_REGION_IDX, BAR0_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_initiator, dma_addr=BAR0_ADDR + 0x10,
                              length=8, max_nr_sgs=1, prot=mmap.PROT_WRITE)
    assert ret == 1

    # direct access case - sends a message since BAR is not mmap-able
    data = bytearray(range(1, 9))
    assert vfu_sgl_write(ctx_initiator, sg, 1, data,
                         VFU_SGL_DIRECT_ACCESS) == 0
    assert bar0[0x10:0x18] == data
    assert dma_forwarder.msg_count == 1

    # non direct access case
    data = bytearray(range(0x11, 0x19))
    assert vfu_sgl_write(ctx_initiator, sg, 1, data, 0) == 0
    assert bar0[0x10:0x18] == data
    assert dma_forwarder.msg_count == 2


def test_peer_dma_read():
    """
    As per test_peer_dma_write(), for reads.
    """
    dma_map_target_bar(VFU_PCI_DEV_BAR0_REGION_IDX, BAR0_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_initiator, dma_addr=BAR0_ADDR + 0x20,
                              length=8, max_nr_sgs=1, prot=mmap.PROT_READ)
    assert ret == 1

    # direct access case - sends a message since BAR is not mmap-able
    bar0[0x20:0x28] = bytes(range(0x80, 0x88))
    assert vfu_sgl_read(ctx_initiator, sg, 1, VFU_SGL_DIRECT_ACCESS) == \
        (0, bytearray(range(0x80, 0x88)))
    assert dma_forwarder.msg_count == 1

    # non direct access case
    bar0[0x20:0x28] = bytes(range(0x90, 0x98))
    assert vfu_sgl_read(ctx_initiator, sg, 1, 0) == \
        (0, bytearray(range(0x90, 0x98)))
    assert dma_forwarder.msg_count == 2


def test_peer_dma_mmap_write():
    """
    INITIATOR writes to TARGET's BAR2, which is mmap-able. With
    VFU_SGL_DIRECT_ACCESS, the write goes straight into the shared file.
    Without it, the write is a DMA_WRITE, which the client carries out on
    TARGET's BAR2 callback.
    """
    dma_map_target_bar(VFU_PCI_DEV_BAR2_REGION_IDX, BAR2_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_initiator, dma_addr=BAR2_ADDR + 0x30,
                              length=8, max_nr_sgs=1, prot=mmap.PROT_WRITE)
    assert ret == 1

    # direct access case
    data = bytearray(range(1, 9))
    assert vfu_sgl_write(ctx_initiator, sg, 1, data,
                         VFU_SGL_DIRECT_ACCESS) == 0
    assert bar2[0x30:0x38] == data
    assert dma_forwarder.msg_count == 0

    # non direct access case
    data = bytearray(range(0x11, 0x19))
    assert vfu_sgl_write(ctx_initiator, sg, 1, data, 0) == 0
    assert bar2[0x30:0x38] == data
    assert dma_forwarder.msg_count == 1


def test_peer_dma_mmap_read():
    """
    As per test_peer_dma_mmap_write(), for reads.
    """
    dma_map_target_bar(VFU_PCI_DEV_BAR2_REGION_IDX, BAR2_ADDR)

    ret, sg = vfu_addr_to_sgl(ctx_initiator, dma_addr=BAR2_ADDR + 0x40,
                              length=8, max_nr_sgs=1, prot=mmap.PROT_READ)
    assert ret == 1

    # direct access case
    bar2[0x40:0x48] = bytes(range(0x80, 0x88))
    assert vfu_sgl_read(ctx_initiator, sg, 1, VFU_SGL_DIRECT_ACCESS) == \
        (0, bytearray(range(0x80, 0x88)))
    assert dma_forwarder.msg_count == 0

    # non direct access case
    bar2[0x40:0x48] = bytes(range(0x90, 0x98))
    assert vfu_sgl_read(ctx_initiator, sg, 1, 0) == \
        (0, bytearray(range(0x90, 0x98)))
    assert dma_forwarder.msg_count == 1


def test_peer_dma_not_mapped():
    """
    Without a DMA_MAP, vfu_addr_to_sgl() cannot resolve addresses in TARGET's
    BARs.
    """
    for addr in (BAR0_ADDR, BAR2_ADDR):
        ret, _ = vfu_addr_to_sgl(ctx_initiator, dma_addr=addr, length=8,
                                 max_nr_sgs=1, prot=mmap.PROT_WRITE)
        assert ret == -1
        assert c.get_errno() == errno.ENOENT
    assert dma_forwarder.msg_count == 0


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
