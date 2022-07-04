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
