# Shadow ioeventfd

Shadow ioeventfd is mechanism that reduces the cost of MMIO writes in
vfio-user. In a nutshell, it eliminates the involvement of the VMM by allowing
KVM to write the MMIO value in a piece of memory provided by the device
emulation task and then notifying it by kicking the ioeventfd. The device
emulation task can then find the value in a known location.

This mechanism is especially important for cases where the MMIO value is
required by the device protocol, which is the case for NVMe.

This functionality requires patching the kernel (KVM) and QEMU:
- kernel patches: https://github.com/tmakatos/linux/tree/shadow-ioeventfd
- QEMU patches: https://github.com/tmakatos/qemu/tree/shadow-ioeventfd

