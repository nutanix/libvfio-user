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
import struct

ctx = None


def setup_function(function):
    global ctx

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_setup_device_reset_cb(ctx)
    assert ret == 0

    vfu_setup_device_quiesce_cb(ctx)


def teardown_function(function):
    vfu_destroy_ctx(ctx)


def read_status(sock):
    payload = read_region(
        ctx,
        sock,
        VFU_PCI_DEV_CFG_REGION_IDX,
        offset=PCI_STATUS,
        count=2
    )

    return struct.unpack("<H", payload)[0]


def test_pci_status_rw1c():
    """
    Verify RW1C handling of the PCI status register.

    Checks that all six write-1-to-clear bits (dpd, sta, rta, rma, sse, dpe):
      - are cleared when the guest writes a 1;
      - are left unchanged when the guest writes a 0.

    Also checks that writing to a read-only bit (Capabilities List) has no
    effect.
    """
    ret = vfu_pci_init(ctx, pci_type=VFU_PCI_TYPE_CONVENTIONAL)
    assert ret == 0

    ret = vfu_setup_region(
        ctx,
        index=VFU_PCI_DEV_CFG_REGION_IDX,
        size=PCI_CFG_SPACE_SIZE,
        flags=VFU_REGION_FLAG_RW
    )
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    client = connect_client(ctx)
    rw1c_bits = [
        PCI_STATUS_PARITY,
        PCI_STATUS_SIG_TARGET_ABORT,
        PCI_STATUS_REC_TARGET_ABORT,
        PCI_STATUS_REC_MASTER_ABORT,
        PCI_STATUS_SIG_SYSTEM_ERROR,
        PCI_STATUS_DETECTED_PARITY,
    ]
    all_rw1c = 0
    for bit in rw1c_bits:
        all_rw1c |= bit

    # Seed every RW1C bit plus a read-only bit (CAP_LIST) directly.
    write_pci_cfg_space(ctx, struct.pack("<H", all_rw1c | PCI_STATUS_CAP_LIST),
                        2, PCI_STATUS)
    assert read_status(client.sock) == all_rw1c | PCI_STATUS_CAP_LIST

    # Writing 0 must clear nothing.
    write_region(ctx, client.sock, VFU_PCI_DEV_CFG_REGION_IDX,
                 offset=PCI_STATUS, count=2, data=struct.pack("<H", 0))
    assert read_status(client.sock) == all_rw1c | PCI_STATUS_CAP_LIST

    # Writing 1 clears that bit only; the RO CAP_LIST bit must survive.
    remaining = all_rw1c
    for bit in rw1c_bits:
        write_region(ctx, client.sock, VFU_PCI_DEV_CFG_REGION_IDX,
                     offset=PCI_STATUS, count=2, data=struct.pack("<H", bit))
        remaining &= ~bit
        assert read_status(client.sock) == remaining | PCI_STATUS_CAP_LIST

    # Writing 1 to a read-only bit must have no effect.
    write_region(
        ctx,
        client.sock,
        VFU_PCI_DEV_CFG_REGION_IDX,
        offset=PCI_STATUS,
        count=2,
        data=struct.pack(
            "<H",
            PCI_STATUS_CAP_LIST))
    assert read_status(client.sock) == PCI_STATUS_CAP_LIST
