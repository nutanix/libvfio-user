Mediated Userspace Device
=========================

Overview
--------

MUSER is a framework that allows implementing PCI devices under the [vfio-user
protocol](https://lists.gnu.org/archive/html/qemu-devel/2020-11/msg02458.html).
MUSER is the _backend_ part of the vfio-user protocol, the frontend part is
implemented by Oracle in https://github.com/oracle/qemu/tree/vfio-user-v0.1.

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


Building muser
==============

Just do:

	make && make install

The kernel headers are necessary because VFIO structs and defines are reused.
To enable Python bindings set the PYTHON_BINDINGS environment variable to a
non-empty string.

Finally build your program and link it to libmuser.so.
