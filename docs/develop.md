Developing with libvfio-user
============================

The API is currently documented via the [libvfio-user header file](../include/libvfio-user.h),
along with some additional [documentation](./).

The library is actively under development, and should not yet be considered a
stable API/ABI.

The protocol itself can be considered stable and will not break backwards
compatibility. See the QEMU repository for the [canonical protocol
definition](https://www.qemu.org/docs/master/interop/vfio-user.html).

The API is not thread safe, but individual `vfu_ctx_t` handles can be
used separately by each thread: that is, there is no global library state.

See [Accessing memory with libvfio-user](memory-mapping.md) for more details on
how to manage memory.

See [Examples](examples.md) for some simple examples of using the library.

Supported features
------------------

With the client support found in
[cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor/) or
[qemu](https://gitlab.com/qemu-project/qemu), most guest VM use cases will work.

However, guests with an IOMMU (vIOMMU) will not currently work: the number of
DMA regions is strictly limited, and there are also issues with some server
implementations such as SPDK's virtual NVMe controller.

Currently, `libvfio-user` has explicit support for PCI devices only. In
addition, only PCI endpoints are supported (no bridges etc.).

Live migration
--------------

The `master` branch of `libvfio-user` implements live migration with a protocol
based on vfio's v2 protocol. Currently, there is no support for this in any qemu
client. Contributions are welcome!
