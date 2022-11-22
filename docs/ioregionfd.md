# ioregionfd

ioregionfd is a mechanism that speeds up ioeventfds:
https://lore.kernel.org/kvm/cover.1613828726.git.eafanasova@gmail.com/. In the
author's original words: "ioregionfd is a KVM dispatch mechanism which can be
used for handling MMIO/PIO accesses over file descriptors without returning
from ioctl(KVM_RUN).".

libvfio-user currently supports an experimental variant of this mechanism
called shadow ioeventfd. A shadow ioeventfd is a normal ioeventfd where the
vfio-user server passes another piece of memory (called the _shadow_ memory)
via an additional file descriptor when configuring the ioregionfd, which then
QEMU memory maps and passes this address to KVM. This shadow memory is never
exposed to the guest. When the guest writes to the trapped memory, KVM writes
the value to the shadow memory instread of discarding it, and then proceeds
kicking the eventfd as normal.

To use shadow ioeventfd, the kernel and QEMU need to be patched. The QEMU patch
is designed specifically for SPDK's doorbells (one ioregionfd of 4K in BAR0);
it should be trivial to extend.

The list of patches:
* kernel: https://gist.github.com/tmakatos/532afd092a8df2175120d3dbfcd719ef
* QEMU: https://gist.github.com/tmakatos/57755d2a37a6d53c9ff392e7c34470f6
* SPDK: https://gist.github.com/tmakatos/f6c10fdaff59c9d629f94bd8e44a53bc

shadow ioeventfd sample
-----------------------

samples/shadow_ioeventfd_server.c implements a vfio-user server that allows a
part of its BAR0 to be accessed via a shadow ioeventfd.
shadow_ioeventfd_speed_test.c is run in the guest. It compares peformance of
shadow ioeventfd vs. vfio-user messages by repeatedly writing to the part of
the BAR0 that is handled by shadow ioeventfd and to the part not handled by
shadow ioeventfd.

To run the sample:
* Patch and build the kernel and QEMU using above patches.
* Enable support for shadow ioeventfd in libvfio-user (set `shadow-ieoventfd`
  to `true` in meson_options.txt and then build libvfio-user.
* Run samples/shadow_ioeventfd_server, e.g.
  ```
  build/samples/shadow_ioeventfd_server /var/run/cntrl
  ```
* Start the guest with `intel_iommu=off` in the kernel command line.
* Bind the device to VFIO:
  ```
  modprobe vfio-iommu-type1 allow_unsafe_interrupts=1
  modprobe vfio-pci ids=4e58:0
  ```
  Build and run the test app in the guest (it needs to be copied there first),
  the BDF needs to be substituted accordingly:
  ```
  gcc shadow_ioeventfd_speed_test.c
  ./a.out 3 0000:00:03.0
  ```
