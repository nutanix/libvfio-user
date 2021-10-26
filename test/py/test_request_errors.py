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

from unittest import mock
from unittest.mock import patch, Mock, create_autospec

from libvfio_user import *
import errno
import os

ctx = None
sock = None

# Passing an Mock object to vfu_setup_device_quiesce doesn't work at all, not
# sure what's wrong, using a Mock object in an actual function is the only way
# I managed to make it work.
mock_quiesce_cb = Mock()

@vfu_device_quiesce_cb_t
def quiesce_cb(ctx):
    global mock_quiesce_cb
    return mock_quiesce_cb(ctx)

global mock_reset_cb
mock_reset_cb = Mock()

@vfu_reset_cb_t
def reset_cb(ctx, reset_type):
    global mock_reset_cb
    return mock_reset_cb(ctx, reset_type)


argsz = len(vfio_irq_set())


def test_request_errors_setup():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_pci_init(ctx)
    assert ret == 0

    ret = vfu_setup_device_nr_irqs(ctx, VFU_DEV_MSIX_IRQ, 2048)
    assert ret == 0

    ret = vfu_setup_device_quiesce_cb(ctx, quiesce_cb)
    assert ret == 0

    ret = vfu_setup_device_reset_cb(ctx, reset_cb)
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


def test_disconnected_socket():
    """Tests that calling vfu_run_ctx on a disconnected socket results in resetting the context and returning ENOTCONN."""

    global mock_quiesce_cb
    mock_quiesce_cb.return_value = 0

    global sock
    sock.close()

    global mock_reset_cb
    mock_reset_cb.return_value = 0

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.ENOTCONN

    # quiece callback gets called during reset
    # FIXME how can we ensure that quiesce is called before reset?
    mock_quiesce_cb.assert_called_with(ctx)
    mock_reset_cb.assert_called_with(ctx, VFU_RESET_LOST_CONN)


def test_disconnected_socket_quiesce_busy():
    """Tests that calling vfu_run_ctx on a disconnected socket results in resetting the context which returns EBUSY."""

    global ctx
    ret = vfu_destroy_ctx(ctx)
    assert ret == 0

    # FIXME this should be done in setup
    test_request_errors_setup()

    global mock_quiesce_cb
    mock_quiesce_cb.reset_mock()
    def side_effect(ctx):
        c.set_errno(errno.EBUSY)
        return -1
    mock_quiesce_cb.side_effect = side_effect

    global sock
    sock.close()

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.ENOTCONN

    # quiesce callback must be called during reset
    mock_quiesce_cb.assert_called_once_with(ctx)

    # device hasn't finished quiescing
    for _ in range(0, 3):
        ret = vfu_run_ctx(ctx)
        assert ret == -1
        assert c.get_errno() == errno.EBUSY

    # device quiesced
    vfu_device_quiesced(ctx, 0)

    ret = vfu_run_ctx(ctx)
    assert ret == -1
    assert c.get_errno() == errno.ENOTCONN

    # no further calls to the quiesce callback should have been made
    mock_quiesce_cb.assert_called_once_with(ctx)


def test_request_errors_cleanup():
    global mock_quiesce_cb
    mock_quiesce_cb.side_effect = None
    mock_quiesce_cb.return_value = 0
    ret = vfu_destroy_ctx(ctx)
    assert ret == 0, "ret=%s errno=%s" % (ret, c.get_errno())

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
