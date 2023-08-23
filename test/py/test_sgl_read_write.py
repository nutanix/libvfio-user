#
# Copyright (c) 2023 Nutanix Inc. All rights reserved.
# Copyright (c) 2023 Rivos Inc. All rights reserved.
#
# Authors: Mattias Nissler <mnissler@rivosinc.com>
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
import select
import threading

MAP_ADDR = 0x10000000
MAP_SIZE = 16 << PAGE_SHIFT

ctx = None
client = None


class DMARegionHandler:
    """
    A helper to service DMA region accesses arriving over a socket. Accesses
    are performed against an internal bytearray buffer. DMA request processing
    takes place on a separate thread so as to not block the test code.
    """

    def handle_requests(sock, pipe, buf, lock, addr, error_no):
        while True:
            (ready, _, _) = select.select([sock, pipe], [], [])
            if pipe in ready:
                break

            # Read a command from the socket and service it.
            _, msg_id, cmd, payload = get_msg_fds(sock,
                                                  VFIO_USER_F_TYPE_COMMAND)
            assert cmd in [VFIO_USER_DMA_READ, VFIO_USER_DMA_WRITE]
            access, data = vfio_user_dma_region_access.pop_from_buffer(payload)

            assert access.addr >= addr
            assert access.addr + access.count <= addr + len(buf)

            offset = access.addr - addr
            with lock:
                if cmd == VFIO_USER_DMA_READ:
                    data = buf[offset:offset + access.count]
                else:
                    buf[offset:offset + access.count] = data
                    data = bytearray()

            send_msg(sock,
                     cmd,
                     VFIO_USER_F_TYPE_REPLY,
                     payload=payload[:c.sizeof(access)] + data,
                     msg_id=msg_id,
                     error_no=error_no)

        os.close(pipe)
        sock.close()

    def __init__(self, sock, addr, size, error_no=0):
        self.data = bytearray(size)
        self.data_lock = threading.Lock()
        self.addr = addr
        (pipe_r, self.pipe_w) = os.pipe()
        # Duplicate the socket file descriptor so the thread can own it and
        # make sure it gets closed only when terminating the thread.
        sock = socket.socket(fileno=os.dup(sock.fileno()))
        thread = threading.Thread(
            target=DMARegionHandler.handle_requests,
            args=[sock, pipe_r, self.data, self.data_lock, addr, error_no])
        thread.start()

    def shutdown(self):
        # Closing the pipe's write end will signal the thread to terminate.
        os.close(self.pipe_w)

    def read(self, addr, size):
        offset = addr - self.addr
        with self.data_lock:
            return self.data[offset:offset + size]


def setup_function(function):
    global ctx, client, dma_handler
    ctx = prepare_ctx_for_dma()
    assert ctx is not None
    client = connect_client(ctx, max_data_xfer_size=PAGE_SIZE,
                            reverse_cmd_socket=True)

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
                                flags=(VFIO_USER_F_DMA_REGION_READ
                                       | VFIO_USER_F_DMA_REGION_WRITE),
                                offset=0,
                                addr=MAP_ADDR,
                                size=MAP_SIZE)

    msg(ctx, client.sock, VFIO_USER_DMA_MAP, payload)

    dma_handler = DMARegionHandler(client.reverse_cmd_sock, payload.addr,
                                   payload.size)


def teardown_function(function):
    dma_handler.shutdown()
    client.disconnect(ctx)
    vfu_destroy_ctx(ctx)


def test_dma_read_write():
    ret, sg = vfu_addr_to_sgl(ctx,
                              dma_addr=MAP_ADDR + 0x1000,
                              length=64,
                              max_nr_sgs=1,
                              prot=mmap.PROT_READ | mmap.PROT_WRITE)
    assert ret == 1

    data = bytearray([x & 0xff for x in range(0, sg[0].length)])
    assert vfu_sgl_write(ctx, sg, 1, data) == 0

    assert vfu_sgl_read(ctx, sg, 1) == (0, data)

    assert dma_handler.read(sg[0].dma_addr + sg[0].offset,
                            sg[0].length) == data


def test_dma_read_write_large():
    ret, sg = vfu_addr_to_sgl(ctx,
                              dma_addr=MAP_ADDR + 0x1000,
                              length=2 * PAGE_SIZE,
                              max_nr_sgs=1,
                              prot=mmap.PROT_READ | mmap.PROT_WRITE)
    assert ret == 1

    data = bytearray([x & 0xff for x in range(0, sg[0].length)])
    assert vfu_sgl_write(ctx, sg, 1, data) == 0

    assert vfu_sgl_read(ctx, sg, 1) == (0, data)

    assert dma_handler.read(sg[0].dma_addr + sg[0].offset,
                            sg[0].length) == data


def test_dma_read_write_error():
    # Reinitialize the handler to return EIO.
    global dma_handler
    dma_handler.shutdown()
    dma_handler = DMARegionHandler(client.reverse_cmd_sock, MAP_ADDR, MAP_SIZE,
                                   error_no=errno.EIO)

    ret, sg = vfu_addr_to_sgl(ctx,
                              dma_addr=MAP_ADDR + 0x1000,
                              length=64,
                              max_nr_sgs=1,
                              prot=mmap.PROT_READ | mmap.PROT_WRITE)
    assert ret == 1

    ret, _ = vfu_sgl_read(ctx, sg, 1)
    assert ret == -1
    assert c.get_errno() == errno.EIO


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
