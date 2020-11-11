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
 
In this fork we focus on making QEMU and MUSER work without the need of the
MUSER kernel module. This has been demonstrated as a PoC in
https://lists.gnu.org/archive/html/qemu-devel/2020-03/msg07900.html. In the PoC
we use a library to intercept QEMU's syscalls to VFIO (libpathtrap) and convert
theme into messages that we send to the process where device emulation is
implemented (libvfio). Any QEMU version can be used, unpatched.

The PoC is merely a step towards defining a device offloading protocol that
will hopefully be officially suported by QEMU so we won't need to do tricks with
intercepting syscalls etc. This protocol will be called VFIO-over-socket (or
vfio-user) and is based on the existing VFIO framework (it reuses structs,
defines, concepts, etc). Hopefully the protocol won't be too different from the
one in the PoC. You can follow/participate in the discussion here:
https://www.mail-archive.com/qemu-devel@nongnu.org/msg723773.html 

The library abstracts most of the complexity around representing the device.
Applications using libmuser provide a description of the device (eg. region and
irq information) and as set of callbacks which are invoked by libmuser when
those regions are accessed. See src/samples on how to build such an
application.

Currently there is one, single-threaded application instance per device,
however the application can employ any form of concurrency needed. In the
future we plan to make libmuser multi-threaded. The application can be
implemented in whatever way is convenient, e.g. as a Python script using
bindings, on the cloud, etc. There's also experimental support for polling.

There is also an ongoing effort to define a protocol based on VFIO that will be
officially supported by QEMU so the kernel module won't be necessary.  This
protocol (tentatively named VFIO-over-socket and soon to be renamed to
vfio-user) has been discussed as an RFC in qemu-devel:
https://lists.gnu.org/archive/html/qemu-devel/2020-03/msg07900.html,
and is now in the process of being reviewed:
https://www.mail-archive.com/qemu-devel@nongnu.org/msg723773.html.
In the RFC email thread it is explained how to run the GPIO sample without the
MUSER kernel module, where to get sources etc. Please refer to the RFC email
thread for more information.


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

Interrupts are implemented by passing the event file descriptor to libmuser
and then notifying it about it. libmuser can then trigger interrupts simply by
writing to it. This can be much more expensive compared to triggering interrupts
from the kernel, however this performance penalty is perfectly acceptable when
prototyping the functional aspect of a device driver.


System Architecture
-------------------

QEMU (with the "help" of libpathtrap and livfio) and libmuser communicate via a
UNIX domain socket (in the future it can be anything, e.g. UDP).  Whenever QEMU
executes an ioctl to the VFIO device, libpathtrap/libvfio convert the operation
into a message and send it to libmuser, unblocking it. libmuser executed the
request and sends back the response.  Currently there can be only one command
pending, we plan to allow multiple commands to be executed in parallel.


Building muser
==============

Just do:

	git submodule update --init
	make && make install

The kernel headers are necessary because VFIO structs and defines are resused.
To specify an alternative kernel directory set the KDIR environment variable
accordingly.
To enable Python bindings set the PYTHON_BINDINGS environment variable to a
non-empty string.

Finally build your program and link it to libmuser.so.

Running QEMU
============

Use the following snippet to create the directory structure, this is required
because QEMU still thinks it's talking to VFIO. "muser" can really by anything
or even omitted. "foo" is typically the guest name/UUID. "0" is the IOMMU
group, this must be an integer and must not exist under /dev/vfio. SELinux and
cgroups can be tricky to set up correctly, so try and keep it simple for now
(e.g. disable SELinux, use world-accessible paths such as /var/run etc.).

	mkdir -p /var/run/muser/iommu_group /var/run/muser/foo/0
	cd /var/run/muser/foo/0 && ln -sf ../0 iommu_group
	ln -s /var/run/muser/foo/0 /var/run/muser/iommu_group/0

Create your libmuser context setting /var/run/muser/foo/0 as the UUID.

Run QEMU as follows:

    LD_PRELOAD=muser/build/dbg/libvfio/libvfio.so qemu-system-x86_64 \
	... \
	-device vfio-pci,sysfsdev=/var/run/muser/foo/0
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

	# build/dbg/samples/gpio-pci-idio-16 -s /var/run/muser/foo/0

3. Finally, start the VM adding the command line explained earlier and then
execute:

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

Future Work
===========

See official fork for more details.

Troubleshooting
---------------

It's easy to mess things up as this is a PoC. libvfio stores logs under
`/tmp/libvfio`. When things fail it's usually because the directory hasn't been
correctly set up or cleaned up from the previous run, use `strace` and check
which syscalls fail and why.

To debug accesses to your PCI device from QEMU add the following to the QEMU
command line:

    -trace enable=vfio*,file=qemu-vfio.trace
