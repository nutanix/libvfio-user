libvfio-user
============

vfio-user is a framework that allows implementing PCI devices in userspace.
Clients (such as [qemu](https://qemu.org)) talk the [vfio-user
protocol](https://www.qemu.org/docs/master/interop/vfio-user.html)
over a UNIX socket to a server. This library, `libvfio-user`, provides an API
for implementing such servers.

![vfio-user example block diagram](docs/libvfio-user.png)

[VFIO](https://www.kernel.org/doc/Documentation/vfio.txt) is a kernel facility
for providing secure access to PCI devices in userspace (including pass-through
to a VM). With `vfio-user`, instead of talking to the kernel, all interactions
are done in userspace, without requiring any kernel component; the kernel `VFIO`
implementation is not used at all for a `vfio-user` device.

Put another way, `vfio-user` is to VFIO as
[vhost-user](https://www.qemu.org/docs/master/interop/vhost-user.html) is to
`vhost`.

The `vfio-user` protocol is intentionally modelled after the VFIO `ioctl()`
interface, and shares many of its definitions.  However, there is not an exact
equivalence: for example, IOMMU groups are not represented in `vfio-user`.

There many different purposes you might put this library to, such as prototyping
novel devices, testing frameworks, implementing alternatives to qemu's device
emulation, adapting a device class to work over a network, etc.

The library abstracts most of the complexity around representing the device.
Applications using libvfio-user provide a description of the device (eg. region and
IRQ information) and as set of callbacks which are invoked by `libvfio-user` when
those regions are accessed.

Memory Mapping the Device
-------------------------

The device driver can allow parts of the virtual device to be memory mapped by
the virtual machine (e.g. the PCI BARs). The business logic needs to implement
the mmap callback and reply to the request passing the memory address whose
backing pages are then used to satisfy the original mmap call; [more details
here](./docs/memory-mapping.md).

Interrupts
----------

Interrupts are implemented via eventfd's passed from the client and registered
with the library. `libvfio-user` consumers can then trigger interrupts by
writing to the eventfd.

Building libvfio-user
=====================

Build requirements:

 * `meson` (v0.53.0 or above)
 * `apt install libjson-c-dev libcmocka-dev` or
 * `yum install json-c-devel libcmocka-devel`

The kernel headers are necessary because VFIO structs and defines are reused.

To build:

```
meson build
ninja -C build
```

Finally build your program and link with `libvfio-user.so`.

Using the library
=================

qemu
----

Step-by-step instructions for using `libvfio-user` with `qemu` can be [found
here](docs/qemu.md).

See also [libvirt](docs/libvirt.md).

SPDK
----

SPDK uses `libvfio-user` to implement a virtual NVMe controller: see
[SPDK and libvfio-user](docs/spdk.md) for more details.

Developing with the library
===========================

See [Developing with libvfio-user](./docs/develop.md).

Mailing List & Chat
===================

libvfio-user development is discussed in libvfio-user-devel@nongnu.org.
Subscribe here: https://lists.gnu.org/mailman/listinfo/libvfio-user-devel.

We are on Slack at [libvfio-user.slack.com](https://libvfio-user.slack.com)
([invite link](https://join.slack.com/t/libvfio-user/shared_invite/zt-193oqc8jl-a2nKYFZESQMMlsiYHSsAMw));
or IRC at [#qemu on OFTC](https://oftc.net/).

Contributing
============

Contributions are welcome; please file an
[issue](https://github.com/nutanix/libvfio-user/issues/) or
[open a PR](https://github.com/nutanix/libvfio-user/pulls). Anything substantial
is worth discussing with us first.

Please make sure to mark any commits with `Signed-off-by` (`git commit -s`),
which signals agreement with the [Developer Certificate of Origin
v1.1](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin).

Running `make pre-push` will do the same checks as done in github CI. After
merging, a Coverity scan is also done.

See [Testing](docs/testing.md) for details on how the library is tested.

History
=======

This project was formerly known as "muser", short for "Mediated Userspace
Device". It implemented a proof-of-concept [VFIO mediated
device](https://www.kernel.org/doc/Documentation/vfio-mediated-device.txt) in
userspace.  Normally, VFIO mdev devices require a kernel module; `muser`
implemented a small kernel module that forwarded onto userspace. The old
kernel-module-based implementation can be found in the [kmod
branch](https://github.com/nutanix/muser/tree/kmod).
