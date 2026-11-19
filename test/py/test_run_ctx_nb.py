#
# Copyright (c) 2026 Red Hat LLC. All rights reserved.
#
# Authors: Jesse Taube <jtaubepe@redhat.com>
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
import signal


def test_run_ctx_nb():
    """
    LIBVFIO_USER_FLAG_RUN_CTX_NB makes vfu_run_ctx() non-blocking while
    leaving vfu_attach_ctx() blocking.
    """
    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_RUN_CTX_NB)
    assert ctx is not None
    assert vfu_realize_ctx(ctx) == 0

    # SIGALRM is used to detect blocking calls. The handler does nothing; it
    # only needs to be installed so the signal interrupts a blocked syscall
    # (making it fail with EINTR) instead of killing the process.
    #
    # signal.alarm(1) asks the kernel to deliver SIGALRM to this process one
    # second from now; it returns immediately, so the call that follows starts
    # with a one-second deadline. signal.alarm(0) cancels the pending alarm
    # once that call has returned, so it can't fire later in the test.
    old_handler = signal.signal(signal.SIGALRM, lambda signum, frame: None)

    # Check that vfu_attach_ctx() still blocks. No client has connected, so a
    # blocking accept() waits until the alarm interrupts it, and
    # vfu_attach_ctx() fails with EINTR. If the listening socket were
    # non-blocking (as with LIBVFIO_USER_FLAG_ATTACH_NB), accept() would fail
    # at once with EAGAIN and the test would fail.
    signal.alarm(1)
    vfu_attach_ctx(ctx, expect=errno.EINTR)
    signal.alarm(0)

    # The failed attach left the ctx unconnected, so attach properly.
    # connect_client() sends the version message before calling
    # vfu_attach_ctx(), so the blocking attach completes.
    client = connect_client(ctx)

    # Check that vfu_run_ctx() does not block. No message is pending, so it
    # must return 0 (no requests processed) immediately. If it blocked waiting
    # for the client, the alarm would interrupt it, vfu_run_ctx() would fail
    # with EINTR, and the test would fail instead of hanging.
    signal.alarm(1)
    vfu_run_ctx(ctx, expect=0)
    signal.alarm(0)

    # Check that a pending message is still processed. msg() sends the request,
    # calls vfu_run_ctx() once, and returns the reply; the alarm makes sure
    # vfu_run_ctx() returns after handling it rather than waiting for more.
    payload = vfio_user_device_info(argsz=16, flags=0,
                                    num_regions=0, num_irqs=0)

    signal.alarm(1)
    result = msg(ctx, client.sock, VFIO_USER_DEVICE_GET_INFO, payload)
    signal.alarm(0)

    (argsz, flags, num_regions, num_irqs) = struct.unpack("IIII", result)
    assert argsz == 16
    assert flags == VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET
    assert num_regions == VFU_PCI_DEV_NUM_REGIONS
    assert num_irqs == VFU_DEV_NUM_IRQS

    signal.signal(signal.SIGALRM, old_handler)

    client.disconnect(ctx)
    vfu_destroy_ctx(ctx)
