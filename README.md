libvfio-user
============

vfio-user is a framework that allows implementing PCI devices in userspace.
Clients (such as [qemu](https://qemu.org) talk the [vfio-user
protocol](https://lists.gnu.org/archive/html/qemu-devel/2020-11/msg02458.html)
over a UNIX socket to a server. This library, `libvfio-user`, provides an API
for implementing such servers.

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

Currently there is one, single-threaded, application instance per device,
however the application can employ any form of concurrency needed. In the future
we plan to make libvfio-user multi-threaded. The application can be implemented
in whatever way is convenient, e.g. as a Python script using the bindings, on
the cloud, etc. There's also experimental support for polling.

The library (and the protocol) are actively under development, and should not be
considered a stable API or interface. Work is underway to integrate the protocol
with `qemu` (as a client) and [SPDK](https://spdk.io) (on the server side,
implementing a virtual NVMe controller).

Memory Mapping the Device
-------------------------

The device driver can allow parts of the virtual device to be memory mapped by
the virtual machine (e.g. the PCI BARs). The business logic needs to implement
the mmap callback and reply to the request passing the memory address whose
backing pages are then used to satisfy the original mmap call. Currently reading
and writing of the memory mapped memory by the client goes undetected by
`libvfio-user`, the business logic needs to poll. In the future we plan to
implement a mechanism in order to provide notifications to `libvfio-user`
whenever a page is written to.


Interrupts
----------

Interrupts are implemented by passing the event file descriptor to
`libvfio-user` and then notifying it about it. `libvfio-user` can then trigger
interrupts simply by writing to it. This can be much more expensive compared to
triggering interrupts from the kernel, however this performance penalty is
perfectly acceptable when prototyping the functional aspect of a device driver.


Building muser
==============

Build requirements:

 * `cmake` (v2 or above)
 * `libjson-c-dev` / `libjson-c-devel`
 * `libcmocka-dev` / `libcmocka-devel`

To build:

    make && make install
    # optional
    make test

By default a debug build is created. To create a release build do:

    make BUILD_TYPE=rel

The kernel headers are necessary because VFIO structs and defines are reused.
To enable Python bindings set the `PYTHON_BINDINGS` environment variable to a
non-empty string.

Finally build your program and link with `libvfio-user.so`.

Example
=======

The [samples directory](./samples/) contains various libvfio-user samples.


lspci
-----

[lspci](./samples/lspci.c) implements an example of how to dump the PCI header
of a libvfio-user device and examine it with lspci(8):

    # lspci -vv -F <(build/dbg/samples/lspci)
    00:00.0 Non-VGA unclassified device: Device 0000:0000
            Control: I/O- Mem- BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx-
            Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
            Region 0: I/O ports at <unassigned> [disabled]
            Region 1: I/O ports at <unassigned> [disabled]
            Region 2: I/O ports at <unassigned> [disabled]
            Region 3: I/O ports at <unassigned> [disabled]
            Region 4: I/O ports at <unassigned> [disabled]
            Region 5: I/O ports at <unassigned> [disabled]
            Capabilities: [40] Power Management version 0
                    Flags: PMEClk- DSI- D1- D2- AuxCurrent=0mA PME(D0-,D1-,D2-,D3hot-,D3cold-)
                    Status: D0 NoSoftRst+ PME-Enable- DSel=0 DScale=0 PME-

The above sample implements a very simple PCI device that supports the Power
Management PCI capability. The sample can be trivially modified to change the
PCI configuration space header and add more PCI capabilities.


Client/Server Implementation
----------------------------

[Client](./samples/client.c)/[server](./samples/server.c) implements a basic
client/server model were basic tasks are performed.

The server implements a device that can be programmed to trigger interrupts
(INTx) to the client. This is done by writing the desired time in seconds since
Epoch.  The server then trigger an eventfd-based IRQ and then a message-based
one (in order to demonstrate how it's done when passing of file descriptors
isn't possible/desirable).

The client excercises all commands in the vfio-user protocol, and then proceeds
to perform live migration. The client spawns the destination server (this would
be normally done by `libvirt`) and then migrates the device state, before
switching entirely to the destination server. We re-use the source client
instead of spawning a destination one as this is something libvirt/QEMU would
normally do. To spice things up, the client programmes the source server to
trigger an interrupt and then quickly migrates to the destination server; the
programmed interrupt is delivered by the destination server.

Start the source server as follows (pick whatever you like for `/tmp/mysock`):

    rm -f /tmp/mysock* ; build/dbg/samples/server -v /tmp/mysock

And then the client:

    build/dbg/samples/client /tmp/mysock

After a couple of seconds the client will start live migration. The source
server will exit and the destination server will start, watch the client
terminal for destination server messages.

History
=======

This project was formerly known as "muser", short for "Mediated Userspace
Device". It implemented a proof-of-concept [VFIO mediated
device](https://www.kernel.org/doc/Documentation/vfio-mediated-device.txt) in
userspace.  Normally, VFIO mdev devices require a kernel module; `muser`
implemented a small kernel module that forwarded onto userspace. The old
kernel-module-based implementation can be found in the [kmod
branch](https://github.com/nutanix/muser/tree/kmod).

License
=======

Copyright © 2019-2020  Nutanix Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

 * Neither the name of Nutanix nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

