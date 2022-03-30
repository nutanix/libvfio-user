#
# Copyright (c) 2021 Nutanix Inc. All rights reserved.
#
# Authors: Thanos Makatos <thanos@nutanix.com>
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
from unittest.mock import patch

ctx = None
sock = 0


def setup_function(function):
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)


def teardown_function(function):
    global ctx
    vfu_destroy_ctx(ctx)


def test_probe_migration_unsupported():
    """
    Checks that probing migration when the device does not support it fails
    with ENOTTY.
    """

    global ctx, sock
    vfu_realize_ctx(ctx)
    payload = vfio_user_device_feature(c.sizeof(vfio_user_device_feature),
                                       flags=VFIO_DEVICE_FEATURE_MIGRATION | VFIO_DEVICE_FEATURE_PROBE)
    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, bytearray(payload), errno.ENOTTY)


def test_probe_migration():

    global ctx, sock
    vfu_setup_device_migration(ctx, flags=0)
    vfu_realize_ctx(ctx)
    payload = vfio_user_device_feature(c.sizeof(vfio_user_device_feature),
                                       flags=VFIO_DEVICE_FEATURE_MIGRATION | VFIO_DEVICE_FEATURE_PROBE)
    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, bytearray(payload))


# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
