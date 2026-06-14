#
# Copyright (c) 2026 Nutanix Inc.
#

from libvfio_user import *
import struct

ctx = None

PCI_STATUS = 0x06
PCI_STATUS_CAP_LIST = 0x0010
PCI_STATUS_DETECTED_PARITY = 0x8000


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

    initial = (
        PCI_STATUS_DETECTED_PARITY |
        PCI_STATUS_CAP_LIST
    )

    write_pci_cfg_space(
        ctx,
        struct.pack("<H", initial),
        2,
        PCI_STATUS
    )

    assert read_status(client.sock) == initial

    write_region(
        ctx,
        client.sock,
        VFU_PCI_DEV_CFG_REGION_IDX,
        offset=PCI_STATUS,
        count=2,
        data=struct.pack(
            "<H",
            PCI_STATUS_DETECTED_PARITY
        )
    )

    assert read_status(client.sock) == PCI_STATUS_CAP_LIST

    write_pci_cfg_space(
        ctx,
        struct.pack(
            "<H",
            PCI_STATUS_DETECTED_PARITY
        ),
        2,
        PCI_STATUS
    )

    write_region(
        ctx,
        client.sock,
        VFU_PCI_DEV_CFG_REGION_IDX,
        offset=PCI_STATUS,
        count=2,
        data=struct.pack("<H", 0)
    )

    assert (
        read_status(client.sock)
        ==
        PCI_STATUS_DETECTED_PARITY
    )
