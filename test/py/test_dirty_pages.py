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
#  SERVICESLOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#

from libvfio_user import *
import ctypes as c
import errno
import mmap
import tempfile

ctx = None
quiesce_errno = 0


@vfu_dma_register_cb_t
def dma_register(ctx, info):
    return 0


@vfu_dma_unregister_cb_t
def dma_unregister(ctx, info):
    return 0


@vfu_device_quiesce_cb_t
def quiesce_cb(ctx):
    if quiesce_errno:
        c.set_errno(errno.EBUSY)
        return -1
    return 0


def test_dirty_pages_setup():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_pci_init(ctx)
    assert ret == 0

    vfu_setup_device_quiesce_cb(ctx, quiesce_cb=quiesce_cb)

    ret = vfu_setup_device_dma(ctx, dma_register, dma_unregister)
    assert ret == 0

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)

    f = tempfile.TemporaryFile()
    f.truncate(0x10 << PAGE_SHIFT)

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ | VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x10 << PAGE_SHIFT, size=0x20 << PAGE_SHIFT)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload, fds=[f.fileno()])

    payload = vfio_user_dma_map(argsz=len(vfio_user_dma_map()),
        flags=(VFIO_USER_F_DMA_REGION_READ | VFIO_USER_F_DMA_REGION_WRITE),
        offset=0, addr=0x40 << PAGE_SHIFT, size=0x10 << PAGE_SHIFT)

    msg(ctx, sock, VFIO_USER_DMA_MAP, payload)


def test_setup_migration():
    ret = vfu_setup_device_migration_callbacks(ctx)
    assert ret == 0


def start_logging(addr=None, length=None, page_size=PAGE_SIZE, expect=0):
    """
    Start logging dirty writes.

    If a region and page size are specified, they will be sent to the server to
    start logging. Otherwise, all regions will be logged and the default page
    size will be used.

    Note: in the current implementation, all regions are logged whether or not
    you specify a region, as the additional constraint of only logging a
    certain region is considered an optimisation and is not yet implemented.
    """

    if addr is not None:
        ranges = vfio_user_device_feature_dma_logging_range(
            iova=addr,
            length=length
        )
        num_ranges = 1
    else:
        ranges = bytearray()
        num_ranges = 0

    feature = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()) +
              len(vfio_user_device_feature_dma_logging_control()) +
              len(ranges),
        flags=VFIO_DEVICE_FEATURE_DMA_LOGGING_START | VFIO_DEVICE_FEATURE_SET)

    payload = vfio_user_device_feature_dma_logging_control(
        page_size=page_size,
        num_ranges=num_ranges,
        reserved=0)

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE,
        bytes(feature) + bytes(payload) + bytes(ranges), expect=expect)


def test_dirty_pages_start_zero_pgsize():
    start_logging(page_size=0, expect=errno.EINVAL)


def test_dirty_pages_start():
    start_logging()
    # should be idempotent
    start_logging()


def test_dirty_pages_start_different_pgsize():
    """
    Once we've started logging with page size PAGE_SIZE, any request to start
    logging at a different page size should be rejected.
    """

    start_logging(page_size=PAGE_SIZE >> 1, expect=errno.EINVAL)
    start_logging(page_size=PAGE_SIZE << 1, expect=errno.EINVAL)


def get_dirty_page_bitmap(addr=0x10 << PAGE_SHIFT, length=0x10 << PAGE_SHIFT,
                          page_size=PAGE_SIZE, expect=0):
    """
    Get the dirty page bitmap from the server for the given region and page
    size as a 64-bit integer. This only works for bitmaps that fit within a
    64-bit integer.
    """

    bitmap_size = get_bitmap_size(length, page_size)

    assert bitmap_size == 8

    argsz = len(vfio_user_device_feature()) + \
            len(vfio_user_device_feature_dma_logging_report()) + \
            bitmap_size

    feature = vfio_user_device_feature(
        argsz=argsz,
        flags=VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT | VFIO_DEVICE_FEATURE_GET
    )

    report = vfio_user_device_feature_dma_logging_report(
        iova=addr,
        length=length,
        page_size=page_size
    )

    payload = bytes(feature) + bytes(report)

    result = msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload, expect=expect)

    if expect != 0:
        return

    assert len(result) == argsz

    _, result = vfio_user_device_feature.pop_from_buffer(result)
    _, result = \
        vfio_user_device_feature_dma_logging_report.pop_from_buffer(result)

    assert len(result) == bitmap_size

    return struct.unpack("Q", result)[0]


def test_dirty_pages_get_unmodified():
    bitmap = get_dirty_page_bitmap()
    assert bitmap == 0


sg3 = None
iovec3 = None


def write_to_page(ctx, page, nr_pages, get_bitmap=True):
    """Simulate a write to the given address and size."""
    ret, sg = vfu_addr_to_sgl(ctx, dma_addr=page << PAGE_SHIFT,
                              length=nr_pages << PAGE_SHIFT)
    assert ret == 1
    iovec = iovec_t()
    ret = vfu_sgl_get(ctx, sg, iovec)
    assert ret == 0
    vfu_sgl_put(ctx, sg, iovec)
    if get_bitmap:
        return get_dirty_page_bitmap()
    return None


def test_dirty_pages_get_modified():
    ret, sg1 = vfu_addr_to_sgl(ctx, dma_addr=0x10 << PAGE_SHIFT,
                               length=PAGE_SIZE)
    assert ret == 1
    iovec1 = iovec_t()
    ret = vfu_sgl_get(ctx, sg1, iovec1)
    assert ret == 0

    # read only
    ret, sg2 = vfu_addr_to_sgl(ctx, dma_addr=0x11 << PAGE_SHIFT,
                               length=PAGE_SIZE, prot=mmap.PROT_READ)
    assert ret == 1
    iovec2 = iovec_t()
    ret = vfu_sgl_get(ctx, sg2, iovec2)
    assert ret == 0

    # simple single bitmap entry map
    ret, sg3 = vfu_addr_to_sgl(ctx, dma_addr=0x12 << PAGE_SHIFT,
                               length=PAGE_SIZE)
    assert ret == 1
    iovec3 = iovec_t()
    ret = vfu_sgl_get(ctx, sg3, iovec3)
    assert ret == 0

    # write that spans bytes in bitmap
    ret, sg4 = vfu_addr_to_sgl(ctx, dma_addr=0x16 << PAGE_SHIFT,
                               length=0x4 << PAGE_SHIFT)
    assert ret == 1
    iovec4 = iovec_t()
    ret = vfu_sgl_get(ctx, sg4, iovec4)
    assert ret == 0

    # not put yet, dirty bitmap should be zero
    bitmap = get_dirty_page_bitmap()
    assert bitmap == 0b0000000000000000

    # put SGLs, dirty bitmap should be updated
    vfu_sgl_put(ctx, sg1, iovec1)
    vfu_sgl_put(ctx, sg4, iovec4)
    bitmap = get_dirty_page_bitmap()
    assert bitmap == 0b0000001111000001

    # check dirty bitmap is correctly extended when we give a smaller page size
    vfu_sgl_put(ctx, sg1, iovec1)
    vfu_sgl_put(ctx, sg4, iovec4)
    bitmap = get_dirty_page_bitmap(page_size=PAGE_SIZE >> 1)
    assert bitmap == 0b00000000000011111111000000000011

    # check dirty bitmap is correctly shortened when we give a larger page size
    vfu_sgl_put(ctx, sg1, iovec1)
    vfu_sgl_put(ctx, sg4, iovec4)
    bitmap = get_dirty_page_bitmap(page_size=PAGE_SIZE << 1)
    assert bitmap == 0b00011001

    # check dirty bitmap is correctly shortened when we give a page size that
    # is so large that one bit corresponds to multiple bytes in the raw bitmap
    vfu_sgl_put(ctx, sg1, iovec1)
    vfu_sgl_put(ctx, sg4, iovec4)
    bitmap = get_dirty_page_bitmap(page_size=PAGE_SIZE << 4)
    assert bitmap == 0b1
    bitmap = get_dirty_page_bitmap(page_size=PAGE_SIZE << 4)
    assert bitmap == 0b0

    # after another two puts, should just be one dirty page
    vfu_sgl_put(ctx, sg2, iovec2)
    vfu_sgl_put(ctx, sg3, iovec3)
    bitmap = get_dirty_page_bitmap()
    assert bitmap == 0b0000000000000100

    # and should now be clear
    bitmap = get_dirty_page_bitmap()
    assert bitmap == 0b0000000000000000

    #
    # check various edge cases of bitmap values.
    #

    # very first bit
    bitmap = write_to_page(ctx, 0x10, 1)
    assert bitmap == 0b0000000000000001

    # top bit of first byte
    bitmap = write_to_page(ctx, 0x17, 1)
    assert bitmap == 0b0000000010000000

    # all bits except top one of first byte
    bitmap = write_to_page(ctx, 0x10, 7)
    assert bitmap == 0b0000000001111111

    # all bits of first byte
    bitmap = write_to_page(ctx, 0x10, 8)
    assert bitmap == 0b0000000011111111

    # all bits of first byte plus bottom bit of next
    bitmap = write_to_page(ctx, 0x10, 9)
    assert bitmap == 0b0000000111111111

    # straddle top/bottom bit
    bitmap = write_to_page(ctx, 0x17, 2)
    assert bitmap == 0b0000000110000000

    # top bit of second byte
    bitmap = write_to_page(ctx, 0x1f, 1)
    assert bitmap == 0b1000000000000000

    # top bit of third byte
    bitmap = write_to_page(ctx, 0x27, 1)
    assert bitmap == 0b100000000000000000000000

    # bits in third and first byte
    write_to_page(ctx, 0x26, 1, get_bitmap=False)
    write_to_page(ctx, 0x12, 2, get_bitmap=False)
    bitmap = get_dirty_page_bitmap()
    assert bitmap == 0b010000000000000000001100


def test_dirty_pages_invalid_arguments():
    # Failed to translate
    get_dirty_page_bitmap(addr=0xdeadbeef, expect=errno.ENOENT)

    # Does not exactly match a region (libvfio-user limitation)
    get_dirty_page_bitmap(addr=(0x10 << PAGE_SHIFT) + 1,
                          length=(0x20 << PAGE_SHIFT) - 1,
                          expect=errno.ENOTSUP)

    # Invalid requested bitmap size
    get_dirty_page_bitmap(page_size=1 << 24, expect=errno.EINVAL)

    # Region not mapped
    get_dirty_page_bitmap(addr=0x40 << PAGE_SHIFT, expect=errno.EINVAL)


def stop_logging(addr=None, length=None):
    if addr is not None:
        ranges = vfio_user_device_feature_dma_logging_range(
            iova=addr,
            length=length
        )
    else:
        ranges = []

    feature = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()) +
              len(vfio_user_device_feature_dma_logging_control()) +
              len(ranges),
        flags=VFIO_DEVICE_FEATURE_DMA_LOGGING_STOP | VFIO_DEVICE_FEATURE_SET)

    payload = vfio_user_device_feature_dma_logging_control(
        page_size=PAGE_SIZE,
        num_ranges=(1 if addr is not None else 0),
        reserved=0)

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE,
        bytes(feature) + bytes(payload) + bytes(ranges))


def test_dirty_pages_stop():
    stop_logging()


def test_dirty_pages_cleanup():
    disconnect_client(ctx, sock)
    vfu_destroy_ctx(ctx)


def test_dirty_pages_uninitialised_dma():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    ret = vfu_pci_init(ctx)
    assert ret == 0

    vfu_setup_device_quiesce_cb(ctx, quiesce_cb=quiesce_cb)

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx)

    start_logging(expect=errno.EINVAL)
    get_dirty_page_bitmap(expect=errno.EINVAL)

    disconnect_client(ctx, sock)

    vfu_destroy_ctx(ctx)

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab:
