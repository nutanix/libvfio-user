Mediated Userspace Device
=========================

Overview
--------

MUSER is a framework that allows PCI devices to be implemented in userspace. It
leverages the Linux kernel VFIO/MDEV infrastructure, allowing such devices to
be easily accessed via standard VFIO interfaces and subsequently virtual
machines. These can be completely virtual and not backed by any real hardware.
This provides interesting benefits, including:

* Simplification of the initial development of kernel drivers for new devices
* Easy plumbing to hypervisors that support VFIO device pass-through
* Performance benefits as a single process can poll multiple drivers

MUSER is implemented by two components: a loadable kernel module (muser.ko) and
a userspace library (libmuser). The LKM registers itself with MDEV and relay
VFIO requests to libmuser via a custom ioctl-based interface. The library, in
turn, abstracts most of the complexity around representing the device.
Applications using libmuser provide a description of the device (eg. region and
irq information) and as set of callbacks which are invoked by libmuser when
those regions are accessed. See src/samples on how to build such an
application.

Currently there is a one, single-threaded application instance per device,
however the application can employ any form of concurrency needed. In the
future we plan to make libmuser multi-threaded. The application can be
implemented in whatever way is convenient, e.g. as a Python script using
bindings, on the cloud, etc.


Memory Mapping the Device
-------------------------

The device driver can allow parts of the virtual device to be memory mapped by
the virtual machine (e.g. the PCI BARs). The business logic needs to implement
the mmap callback and reply to the request passing the memory address whose
backing pages are then used to satisfy the original mmap call. Currently
reading and writing of the memory mapped memory by the client goes undetected
by libmuser, the business logic needs to poll. In the future we plan to
implement a mechanism in order to provide notifications to libmuser whenever a
page is written to.


Interrupts
----------

Interrupts are implemented by installing the event file descriptor in libmuser
and then notifying it about it. libmuser can then trigger interrupts simply by
writing to it. This can be much more expensive compared to triggering interrupts
from the kernel, however this performance penalty is perfectly acceptable when
prototyping the functional aspect of a device driver.


System Architecture
-------------------

muser.ko and libmuser communicate via ioctl on a control device. This control
device is create when the mediated device is created and appears as
/dev/muser/<UUID>. libmuser opens this device and then executes a "wait
command" ioctl. Whenever a callback of muser.ko is executed, it fills a struct
with the command details and then completes the ioctl, unblocking libmuser. It
then waits to receive another ioctl from libmuser with the result. Currently
there can be only one command pending, we plan to allow multiple commands to be
executed in parallel.


Building muser
==============

vfio/mdev needs to be patched:

	patch -p1 < muser/patches/vfio.diff

Apply the patch and rebuild the vfio/mdev modules:

	make SUBDIRS=drivers/vfio/ modules

Reload the relevant kernel modules:

	drivers/vfio/vfio_iommu_type1.ko
	drivers/vfio/vfio.ko
	drivers/vfio/mdev/mdev.ko
	drivers/vfio/mdev/vfio_mdev.ko

To build and install the library run:

	make && make install

To specify an alternative kernel directory set the KDIR environment variable
accordingly.
To enable Python bindings set the PYTHON_BINDINGS environment variable to a
non-empty string.

Finally build your program and link it to libmuser.so.

Running QEMU
============

To pass the device to QEMU add the following options:

		-device vfio-pci,sysfsdev=/sys/bus/mdev/devices/<UUID>
		-object memory-backend-file,id=ram-node0,prealloc=yes,mem-path=mem,share=yes,size=1073741824 -numa node,nodeid=0,cpus=0,memdev=ram-node0

Guest RAM must be shared (share=yes) otherwise libmuser won't be able to do DMA
transfers from/to it. If you're not using QEMU then any memory that must be
accessed by libmuser must be allocate MAP_SHARED. Registering memory for DMA
that has not been allocated with MAP_SHARED is ignored and any attempts to
access that memory will result in an error.

Example
=======

samples/gpio-pci-idio-16.c implements a tiny part of the PCI-IDIO-16 GPIO
(https://www.accesio.com/?p=/pci/pci_idio_16.html). In this sample it's a simple
device that toggles the input every 3 times it's read.

Running gpio-pci-idio-16
------------------------

1. First, follow the instructions to build and load muser.
2. Then, start the gpio-pci-idio-16 device emulation:
```
# echo 00000000-0000-0000-0000-000000000000 > /sys/class/muser/muser/mdev_supported_types/muser-1/create
# build/dbg/samples/gpio-pci-idio-16 00000000-0000-0000-0000-000000000000
```
3. Finally, start the VM adding the command line explained earlier and then
execute:
```
# insmod gpio-pci-idio-16.ko
# cat /sys/class/gpio/gpiochip480/base > /sys/class/gpio/export
# for ((i=0;i<12;i++)); do cat /sys/class/gpio/OUT0/value; done
0
0
0
1
1
1
0
0
0
1
1
1
```

Future Work
===========

Making libmuser Restartable
----------------------------

muser can be made restartable so that (a) it can recover from failures, and
(b) upgrades are less disrupting. This is something we plan to implement in the
future. To make it restarable muser needs to reconfigure eventfds and DMA
region mmaps first thing when the device is re-opened by libmuser. After muser
has finished reconfiguring it will send a "ready" command, after which normal
operation will be resumed. This "ready" command will always be sent when the
device is opened, even if this is the first time, as this way we don't need to
differentiate between normal operation and restarted operation. libmuser will
store the PCI BAR on /dev/shm (named after e.g. the device UUID) so that it can
easily find them on restart.


Making libmuser Multi-threaded
-------------------------------

libmuser can be made multi-threaded in order to improve performance. To
implement this we'll have to maintain a private context in struct file.

Troubleshooting
---------------

If you get the following error when starting QEMU:

    qemu-system-x86_64: -device vfio-pci,sysfsdev=/sys/bus/mdev/devices/00000000-0000-0000-0000-000000000000: vfio 00000000-0000-0000-0000-000000000000: failed to read device config space: Bad address

it might mean that you haven't properly patched your kernel.

To debug accesses to your PCI device from QEMU add the following to the QEMU
command line:

    -trace enable=vfio*,file=qemu-vfio.trace
