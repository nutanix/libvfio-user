.. include:: <isonum.txt>

********************************
vfio-user Protocol Specification
********************************

------------
Version_ 0.1
------------

.. contents:: Table of Contents

Introduction
============
vfio-user is a protocol that allows a device to be emulated in a separate
process outside of a Virtual Machine Monitor (VMM). vfio-user devices consist
of a generic VFIO device type, living inside the VMM, which we call the client,
and the core device implementation, living outside the VMM, which we call the
server.

The `Linux VFIO ioctl interface <https://www.kernel.org/doc/html/latest/driver-api/vfio.html>`_
been chosen as the base for this protocol for the following reasons:

1) It is a mature and stable API, backed by an extensively used framework.
2) The existing VFIO client implementation in QEMU (qemu/hw/vfio/) can be
   largely reused.

.. Note::
   In a proof of concept implementation it has been demonstrated that using VFIO
   over a UNIX domain socket is a viable option. vfio-user is designed with
   QEMU in mind, however it could be used by other client applications. The
   vfio-user protocol does not require that QEMU's VFIO client  implementation
   is used in QEMU.

None of the VFIO kernel modules are required for supporting the protocol,
neither in the client nor the server, only the source header files are used.

The main idea is to allow a virtual device to function in a separate process in
the same host over a UNIX domain socket. A UNIX domain socket (AF_UNIX) is
chosen because file descriptors can be trivially sent over it, which in turn
allows:

* Sharing of client memory for DMA with the server.
* Sharing of server memory with the client for fast MMIO.
* Efficient sharing of eventfd's for triggering interrupts.

Other socket types could be used which allow the server to run in a separate
guest in the same host (AF_VSOCK) or remotely (AF_INET). Theoretically the
underlying transport does not necessarily have to be a socket, however we do
not examine such alternatives. In this protocol version we focus on using a
UNIX domain socket and introduce basic support for the other two types of
sockets without considering performance implications.

While passing of file descriptors is desirable for performance reasons, it is
not necessary neither for the client nor for the server to support it in order
to implement the protocol. There is always an in-band, message-passing fall
back mechanism.

VFIO
====
VFIO is a framework that allows a physical device to be securely passed through
to a user space process; the device-specific kernel driver does not drive the
device at all.  Typically, the user space process is a VMM and the device is
passed through to it in order to achieve high performance. VFIO provides an API
and the required functionality in the kernel. QEMU has adopted VFIO to allow a
guest to directly access physical devices, instead of emulating them in
software.

vfio-user reuses the core VFIO concepts defined in its API, but implements them
as messages to be sent over a socket. It does not change the kernel-based VFIO
in any way, in fact none of the VFIO kernel modules need to be loaded to use
vfio-user. It is also possible for the client to concurrently use the current
kernel-based VFIO for one device, and vfio-user for another device.

VFIO Device Model
-----------------
A device under VFIO presents a standard interface to the user process. Many of
the VFIO operations in the existing interface use the ioctl() system call, and
references to the existing interface are called the ioctl() implementation in
this document.

The following sections describe the set of messages that implement the VFIO
interface over a socket. In many cases, the messages are direct translations of
data structures used in the ioctl() implementation. Messages derived from
ioctl()s will have a name derived from the ioctl() command name.  E.g., the
VFIO_GET_INFO ioctl() command becomes a VFIO_USER_GET_INFO message.  The
purpose of this reuse is to share as much code as feasible with the ioctl()
implementation.

Connection Initiation
^^^^^^^^^^^^^^^^^^^^^
After the client connects to the server, the initial client message is
VFIO_USER_VERSION to propose a protocol version and set of capabilities to
apply to the session. The server replies with a compatible version and set of
capabilities it supports, or closes the connection if it cannot support the
advertised version.

DMA Memory Configuration
^^^^^^^^^^^^^^^^^^^^^^^^
The client uses VFIO_USER_DMA_MAP and VFIO_USER_DMA_UNMAP messages to inform
the server of the valid DMA ranges that the server can access on behalf
of a device. DMA memory may be accessed by the server via VFIO_USER_DMA_READ
and VFIO_USER_DMA_WRITE messages over the socket.

An optimization for server access to client memory is for the client to provide
file descriptors the server can mmap() to directly access client memory. Note
that mmap() privileges cannot be revoked by the client, therefore file
descriptors should only be exported in environments where the client trusts the
server not to corrupt guest memory.

Device Information
^^^^^^^^^^^^^^^^^^
The client uses a VFIO_USER_DEVICE_GET_INFO message to query the server for
information about the device. This information includes:

* The device type and whether it supports reset (``VFIO_DEVICE_FLAGS_``),
* the number of device regions, and
* the device presents to the client the number of interrupt types the device
  supports.

Region Information
^^^^^^^^^^^^^^^^^^
The client uses VFIO_USER_DEVICE_GET_REGION_INFO messages to query the server
for information about the device's memory regions. This information describes:

* Read and write permissions, whether it can be memory mapped, and whether it
  supports additional capabilities (``VFIO_REGION_INFO_CAP_``).
* Region index, size, and offset.

When a region can be mapped by the client, the server provides a file
descriptor which the client can mmap(). The server is responsible for polling
for client updates to memory mapped regions.

Region Capabilities
"""""""""""""""""""
Some regions have additional capabilities that cannot be described adequately
by the region info data structure. These capabilities are returned in the
region info reply in a list similar to PCI capabilities in a PCI device's
configuration space.

Sparse Regions
""""""""""""""
A region can be memory-mappable in whole or in part. When only a subset of a
region can be mapped by the client, a VFIO_REGION_INFO_CAP_SPARSE_MMAP
capability is included in the region info reply. This capability describes
which portions can be mapped by the client.

.. Note::
   For example, in a virtual NVMe controller, sparse regions can be used so
   that accesses to the NVMe registers (found in the beginning of BAR0) are
   trapped (an infrequent event), while allowing direct access to the doorbells
   (an extremely frequent event as every I/O submission requires a write to
   BAR0), found right after the NVMe registers in BAR0.

Device-Specific Regions
"""""""""""""""""""""""

A device can define regions additional to the standard ones (e.g. PCI indexes
0-8). This is achieved by including a VFIO_REGION_INFO_CAP_TYPE capability
in the region info reply of a device-specific region. Such regions are reflected
in ``struct vfio_device_info.num_regions``. Thus, for PCI devices this value can
be equal to, or higher than, VFIO_PCI_NUM_REGIONS.

Region I/O via file descriptors
-------------------------------

For unmapped regions, region I/O from the client is done via
VFIO_USER_REGION_READ/WRITE.  As an optimization, ioeventfds or ioregionfds may
be configured for sub-regions of some regions. A client may request information
on these sub-regions via VFIO_USER_DEVICE_GET_REGION_IO_FDS; by configuring the
returned file descriptors as ioeventfds or ioregionfds, the server can be
directly notified of I/O (for example, by KVM) without taking a trip through the
client.

Interrupts
^^^^^^^^^^
The client uses VFIO_USER_DEVICE_GET_IRQ_INFO messages to query the server for
the device's interrupt types. The interrupt types are specific to the bus the
device is attached to, and the client is expected to know the capabilities of
each interrupt type. The server can signal an interrupt either with
VFIO_USER_VM_INTERRUPT messages over the socket, or can directly inject
interrupts into the guest via an event file descriptor. The client configures
how the server signals an interrupt with VFIO_USER_SET_IRQS messages.

Device Read and Write
^^^^^^^^^^^^^^^^^^^^^
When the guest executes load or store operations to device memory, the client
forwards these operations to the server with VFIO_USER_REGION_READ or
VFIO_USER_REGION_WRITE messages. The server will reply with data from the
device on read operations or an acknowledgement on write operations.

DMA
^^^
When a device performs DMA accesses to guest memory, the server will forward
them to the client with VFIO_USER_DMA_READ and VFIO_USER_DMA_WRITE messages.
These messages can only be used to access guest memory the client has
configured into the server.

Protocol Specification
======================
To distinguish from the base VFIO symbols, all vfio-user symbols are prefixed
with vfio_user or VFIO_USER. In revision 0.1, all data is in the little-endian
format, although this may be relaxed in future revision in cases where the
client and server are both big-endian. The messages are formatted for seamless
reuse of the native VFIO structs.

Socket
------

A server can serve:

1) one or more clients, and/or
2) one or more virtual devices, belonging to one or more clients.

The current protocol specification requires a dedicated socket per
client/server connection. It is a server-side implementation detail whether a
single server handles multiple virtual devices from the same or multiple
clients. The location of the socket is implementation-specific. Multiplexing
clients, devices, and servers over the same socket is not supported in this
version of the protocol.

Authentication
--------------
For AF_UNIX, we rely on OS mandatory access controls on the socket files,
therefore it is up to the management layer to set up the socket as required.
Socket types than span guests or hosts will require a proper authentication
mechanism. Defining that mechanism is deferred to a future version of the
protocol.

Command Concurrency
-------------------
A client may pipeline multiple commands without waiting for previous command
replies.  The server will process commands in the order they are received.  A
consequence of this is if a client issues a command with the *No_reply* bit,
then subseqently issues a command without *No_reply*, the older command will
have been processed before the reply to the younger command is sent by the
server.  The client must be aware of the device's capability to process
concurrent commands if pipelining is used.  For example, pipelining allows
multiple client threads to concurently access device memory; the client must
ensure these acceses obey device semantics.

An example is a frame buffer device, where the device may allow concurrent
access to different areas of video memory, but may have indeterminate behavior
if concurrent acceses are performed to command or status registers.

Note that unrelated messages sent from the sevrer to the client can appear in
between a client to server request/reply and vice versa.

Socket Disconnection Behavior
-----------------------------
The server and the client can disconnect from each other, either intentionally
or unexpectedly. Both the client and the server need to know how to handle such
events.

Server Disconnection
^^^^^^^^^^^^^^^^^^^^
A server disconnecting from the client may indicate that:

1) A virtual device has been restarted, either intentionally (e.g. because of a
   device update) or unintentionally (e.g. because of a crash).
2) A virtual device has been shut down with no intention to be restarted.

It is impossible for the client to know whether or not a failure is
intermittent or innocuous and should be retried, therefore the client should
reset the VFIO device when it detects the socket has been disconnected.
Error recovery will be driven by the guest's device error handling
behavior.

Client Disconnection
^^^^^^^^^^^^^^^^^^^^
The client disconnecting from the server primarily means that the client
has exited. Currently, this means that the guest is shut down so the device is
no longer needed therefore the server can automatically exit. However, there
can be cases where a client disconnection should not result in a server exit:

1) A single server serving multiple clients.
2) A multi-process QEMU upgrading itself step by step, which is not yet
   implemented.

Therefore in order for the protocol to be forward compatible the server should
take no action when the client disconnects. If anything happens to the client
the control stack will know about it and can clean up resources
accordingly.

Request Retry and Response Timeout
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
A failed command is a command that has been successfully sent and has been
responded to with an error code. Failure to send the command in the first place
(e.g. because the socket is disconnected) is a different type of error examined
earlier in the disconnect section.

.. Note::
   QEMU's VFIO retries certain operations if they fail. While this makes sense
   for real HW, we don't know for sure whether it makes sense for virtual
   devices.

Defining a retry and timeout scheme is deferred to a future version of the
protocol.

.. _Commands:

Commands
--------
The following table lists the VFIO message command IDs, and whether the
message command is sent from the client or the server.

+------------------------------------+---------+-------------------+
| Name                               | Command | Request Direction |
+====================================+=========+===================+
| VFIO_USER_VERSION                  | 1       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DMA_MAP                  | 2       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DMA_UNMAP                | 3       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DEVICE_GET_INFO          | 4       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DEVICE_GET_REGION_INFO   | 5       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DEVICE_GET_REGION_IO_FDS | 6       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DEVICE_GET_IRQ_INFO      | 7       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DEVICE_SET_IRQS          | 8       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_REGION_READ              | 9       | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_REGION_WRITE             | 10      | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DMA_READ                 | 11      | server -> client  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DMA_WRITE                | 12      | server -> client  |
+------------------------------------+---------+-------------------+
| VFIO_USER_VM_INTERRUPT             | 13      | server -> client  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DEVICE_RESET             | 14      | client -> server  |
+------------------------------------+---------+-------------------+
| VFIO_USER_DIRTY_PAGES              | 15      | client -> server  |
+------------------------------------+---------+-------------------+


.. Note:: Some VFIO defines cannot be reused since their values are
   architecture-specific (e.g. VFIO_IOMMU_MAP_DMA).

Header
------
All messages, both command messages and reply messages, are preceded by a
header that contains basic information about the message. The header is
followed by message-specific data described in the sections below.

+----------------+--------+-------------+
| Name           | Offset | Size        |
+================+========+=============+
| Message ID     | 0      | 2           |
+----------------+--------+-------------+
| Command        | 2      | 2           |
+----------------+--------+-------------+
| Message size   | 4      | 4           |
+----------------+--------+-------------+
| Flags          | 8      | 4           |
+----------------+--------+-------------+
|                | +-----+------------+ |
|                | | Bit | Definition | |
|                | +=====+============+ |
|                | | 0-3 | Type       | |
|                | +-----+------------+ |
|                | | 4   | No_reply   | |
|                | +-----+------------+ |
|                | | 5   | Error      | |
|                | +-----+------------+ |
+----------------+--------+-------------+
| Error          | 12     | 4           |
+----------------+--------+-------------+
| <message data> | 16     | variable    |
+----------------+--------+-------------+

* *Message ID* identifies the message, and is echoed in the command's reply
  message. Message IDs belong entirely to the sender, can be re-used (even
  concurrently) and the receiver must not make any assumptions about their
  uniqueness.
* *Command* specifies the command to be executed, listed in Commands_.
* *Message size* contains the size of the entire message, including the header.
* *Flags* contains attributes of the message:

  * The *Type* bits indicate the message type.

    *  *Command* (value 0x0) indicates a command message.
    *  *Reply* (value 0x1) indicates a reply message acknowledging a previous
       command with the same message ID.
  * *No_reply* in a command message indicates that no reply is needed for this command.
    This is commonly used when multiple commands are sent, and only the last needs
    acknowledgement.
  * *Error* in a reply message indicates the command being acknowledged had
    an error. In this case, the *Error* field will be valid.

* *Error* in a reply message is an optional UNIX errno value. It may be zero
  even if the Error bit is set in Flags. It is reserved in a command message.

Each command message in Commands_ must be replied to with a reply message, unless the
message sets the *No_Reply* bit.  The reply consists of the header with the *Reply*
bit set, plus any additional data.

If an error occurs, the reply message must only include the reply header.

VFIO_USER_VERSION
-----------------

This is the initial message sent by the client after the socket connection is
established:

Message format
^^^^^^^^^^^^^^

+--------------+-------------------------------------------+
| Name         | Value                                     |
+==============+===========================================+
| Message ID   | <ID>                                      |
+--------------+-------------------------------------------+
| Command      | 1                                         |
+--------------+-------------------------------------------+
| Message size | 16 + version header + version data length |
+--------------+-------------------------------------------+
| Flags        | Reply bit set in reply                    |
+--------------+-------------------------------------------+
| Error        | 0/errno                                   |
+--------------+-------------------------------------------+
| Version      | version header                            |
+--------------+-------------------------------------------+

Version Header Format
^^^^^^^^^^^^^^^^^^^^^

+---------------+--------+------------------------------------------------+
| Name          | Offset | Size                                           |
+===============+========+================================================+
| version major | 16     | 2                                              |
+---------------+--------+------------------------------------------------+
| version minor | 18     | 2                                              |
+---------------+--------+------------------------------------------------+
| version data  | 22     | variable (including terminating NUL            |
|               |        | character). Optional.                          |
+---------------+--------+------------------------------------------------+

Version Data Format
^^^^^^^^^^^^^^^^^^^

The version data is an optional JSON byte array with the following format:

+--------------------+------------------+-----------------------------------+
| Name               | Type             | Description                       |
+====================+==================+===================================+
| ``"capabilities"`` | collection of    | Contains common capabilities that |
|                    | name/value pairs | the sender supports. Optional.    |
+--------------------+------------------+-----------------------------------+

Capabilities:

+--------------------+------------------+-------------------------------------+
| Name               | Type             | Description                         |
+====================+==================+=====================================+
| ``"max_fds"``      | number           | Maximum number of file descriptors  |
|                    |                  | the can be received by the sender.  |
|                    |                  | Optional. If not specified then the |
|                    |                  | receiver must assume                |
|                    |                  | ``"max_fds"=1``.                    |
+--------------------+------------------+-------------------------------------+
| ``"max_msg_size"`` | number           | Maximum message size in bytes that  |
|                    |                  | the receiver can handle, including  |
|                    |                  | the header. Optional. If not        |
|                    |                  | specified then the receiver must    |
|                    |                  | assume ``"max_msg_size"=4096``.     |
+--------------------+------------------+-------------------------------------+
| ``"migration"``    | collection of    | Migration capability parameters. If |
|                    | name/value pairs | missing then migration is not       |
|                    |                  | supported by the sender.            |
+--------------------+------------------+-------------------------------------+

The migration capability contains the following name/value pairs:

+--------------+--------+-----------------------------------------------+
| Name         | Type   | Description                                   |
+==============+========+===============================================+
| ``"pgsize"`` | number | Page size of dirty pages bitmap. The smallest |
|              |        | between the client and the server is used.    |
+--------------+--------+-----------------------------------------------+


.. _Version:

Versioning and Feature Support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Upon establishing a connection, the client must send a VFIO_USER_VERSION message
proposing a protocol version and a set of capabilities. The server compares
these with the versions and capabilities it supports and sends a
VFIO_USER_VERSION reply according to the following rules.

* The major version in the reply must be the same as proposed. If the client
  does not support the proposed major, it closes the connection.
* The minor version in the reply must be equal to or less than the minor
  version proposed.
* The capability list must be a subset of those proposed. If the server
  requires a capability the client did not include, it closes the connection.

The protocol major version will only change when incompatible protocol changes
are made, such as changing the message format. The minor version may change
when compatible changes are made, such as adding new messages or capabilities,
Both the client and server must support all minor versions less than the
maximum minor version it supports. E.g., an implementation that supports
version 1.3 must also support 1.0 through 1.2.

When making a change to this specification, the protocol version number must
be included in the form "added in version X.Y"


VFIO_USER_DMA_MAP
-----------------

Message Format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 2                      |
+--------------+------------------------+
| Message size | 16 + table size        |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| Table        | array of table entries |
+--------------+------------------------+

This command message is sent by the client to the server to inform it of the
memory regions the server can access. It must be sent before the server can
perform any DMA to the client. It is normally sent directly after the version
handshake is completed, but may also occur when memory is added to the client,
or if the client uses a vIOMMU. If the client does not expect the server to
perform DMA then it does not need to send to the server VFIO_USER_DMA_MAP
commands. If the server does not need to perform DMA then it can ignore such
commands but it must still reply to them. The table is an array of the
following structure:

Table entry format
^^^^^^^^^^^^^^^^^^

+-------------+--------+-------------+
| Name        | Offset | Size        |
+=============+========+=============+
| Address     | 0      | 8           |
+-------------+--------+-------------+
| Size        | 8      | 8           |
+-------------+--------+-------------+
| Offset      | 16     | 8           |
+-------------+--------+-------------+
| Protections | 24     | 4           |
+-------------+--------+-------------+
| Flags       | 28     | 4           |
+-------------+--------+-------------+
|             | +-----+------------+ |
|             | | Bit | Definition | |
|             | +=====+============+ |
|             | | 0   | Mappable   | |
|             | +-----+------------+ |
+-------------+--------+-------------+

* *Address* is the base DMA address of the region.
* *Size* is the size of the region.
* *Offset* is the file offset of the region with respect to the associated file
  descriptor.
* *Protections* are the region's protection attributes as encoded in
  ``<sys/mman.h>``.
* *Flags* contains the following region attributes:

  * *Mappable* indicates that the region can be mapped via the mmap() system
    call using the file descriptor provided in the message meta-data.

This structure is 32 bytes in size, so the message size is:
16 + (# of table entries * 32).

If a DMA region being added can be directly mapped by the server, an array of
file descriptors must be sent as part of the message meta-data. Each mappable
region entry must have a corresponding file descriptor. On AF_UNIX sockets, the
file descriptors must be passed as SCM_RIGHTS type ancillary data. Otherwise,
if a DMA region cannot be directly mapped by the server, it can be accessed by
the server using VFIO_USER_DMA_READ and VFIO_USER_DMA_WRITE messages, explained
in `Read and Write Operations`_. A command to map over an existing region must
be failed by the server with ``EEXIST`` set in error field in the reply.

Adding multiple DMA regions can partially fail. The response does not indicate
which regions were added and which were not, therefore it is a client
implementation detail how to recover from the failure.

.. Note::
   The server can optionally remove succesfully added DMA regions making this
   operation atomic.
   The client can recover by attempting to unmap one by one all the DMA regions
   in the VFIO_USER_DMA_MAP command, ignoring failures for regions that do not
   exist.


VFIO_USER_DMA_UNMAP
-------------------

Message Format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 3                      |
+--------------+------------------------+
| Message size | 16 + table size        |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| Table        | array of table entries |
+--------------+------------------------+

This command message is sent by the client to the server to inform it that a
DMA region, previously made available via a VFIO_USER_DMA_MAP command message,
is no longer available for DMA. It typically occurs when memory is subtracted
from the client or if the client uses a vIOMMU. If the client does not expect
the server to perform DMA then it does not need to send to the server
VFIO_USER_DMA_UNMAP commands. If the server does not need to perform DMA then
it can ignore such commands but it must still reply to them. The table is an
array of the following structure:

Table entry format
^^^^^^^^^^^^^^^^^^

+--------------+--------+---------------------------------------+
| Name         | Offset | Size                                  |
+==============+========+=======================================+
| Address      | 0      | 8                                     |
+--------------+--------+---------------------------------------+
| Size         | 8      | 8                                     |
+--------------+--------+---------------------------------------+
| Offset       | 16     | 8                                     |
+--------------+--------+---------------------------------------+
| Protections  | 24     | 4                                     |
+--------------+--------+---------------------------------------+
| Flags        | 28     | 4                                     |
+--------------+--------+---------------------------------------+
|              | +-----+--------------------------------------+ |
|              | | Bit | Definition                           | |
|              | +=====+======================================+ |
|              | | 0   | VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP | |
|              | +-----+--------------------------------------+ |
+--------------+--------+---------------------------------------+
| VFIO Bitmaps | 32     | variable                              |
+--------------+--------+---------------------------------------+

* *Address* is the base DMA address of the region.
* *Size* is the size of the region.
* *Offset* is the file offset of the region with respect to the associated file
  descriptor.
* *Protections* are the region's protection attributes as encoded in
  ``<sys/mman.h>``.
* *Flags* contains the following region attributes:

  * *VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP* indicates that a dirty page bitmap
    must be populated before unmapping the DMA region. The client must provide
    a ``struct vfio_bitmap`` in the VFIO bitmaps field for each region, with
    the ``vfio_bitmap.pgsize`` and ``vfio_bitmap.size`` fields initialized.

* *VFIO Bitmaps* contains one ``struct vfio_bitmap`` per region (explained
  below) if ``VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP`` is set in Flags.

.. _VFIO bitmap format:

VFIO bitmap format
^^^^^^^^^^^^^^^^^^

If the VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP bit is set in the request, the
server must append to the header the ``struct vfio_bitmap`` received in the
command followed by the bitmap, for each region. ``struct vfio_bitmap`` has the
following format:

+--------+--------+------+
| Name   | Offset | Size |
+========+========+======+
| pgsize | 0      | 8    |
+--------+--------+------+
| size   | 8      | 8    |
+--------+--------+------+
| data   | 16     | 8    |
+--------+--------+------+

* *pgsize* is the page size for the bitmap, in bytes.
* *size* is the size for the bitmap, in bytes, excluding the VFIO bitmap header.
* *data* This field is unused in vfio-user.

The VFIO bitmap structure is defined in ``<linux/vfio.h>``
(``struct vfio_bitmap``).

Each ``struct vfio_bitmap`` entry is followed by the region's bitmap. Each bit
in the bitmap represents one page of size ``struct vfio_bitmap.pgsize``.

If ``VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP`` is not set in Flags then the size
of the message is: 16 + (# of table entries * 32).
If ``VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP`` is set in Flags then the size of
the message is: 16 + (# of table entries * 56) + size of all bitmaps.

Upon receiving a VFIO_USER_DMA_UNMAP command, if the file descriptor is mapped
then the server must release all references to that DMA region before replying,
which includes potentially in flight DMA transactions. Removing a portion of a
DMA region is possible.

VFIO_USER_DEVICE_GET_INFO
-------------------------

Message format
^^^^^^^^^^^^^^

+--------------+----------------------------+
| Name         | Value                      |
+==============+============================+
| Message ID   | <ID>                       |
+--------------+----------------------------+
| Command      | 4                          |
+--------------+----------------------------+
| Message size | 32                         |
+--------------+----------------------------+
| Flags        | Reply bit set in reply     |
+--------------+----------------------------+
| Error        | 0/errno                    |
+--------------+----------------------------+
| Device info  | VFIO device info           |
+--------------+----------------------------+

This command message is sent by the client to the server to query for basic
information about the device. The VFIO device info structure is defined in
``<linux/vfio.h>`` (``struct vfio_device_info``).

VFIO device info format
^^^^^^^^^^^^^^^^^^^^^^^

+-------------+--------+--------------------------+
| Name        | Offset | Size                     |
+=============+========+==========================+
| argsz       | 16     | 4                        |
+-------------+--------+--------------------------+
| flags       | 20     | 4                        |
+-------------+--------+--------------------------+
|             | +-----+-------------------------+ |
|             | | Bit | Definition              | |
|             | +=====+=========================+ |
|             | | 0   | VFIO_DEVICE_FLAGS_RESET | |
|             | +-----+-------------------------+ |
|             | | 1   | VFIO_DEVICE_FLAGS_PCI   | |
|             | +-----+-------------------------+ |
+-------------+--------+--------------------------+
| num_regions | 24     | 4                        |
+-------------+--------+--------------------------+
| num_irqs    | 28     | 4                        |
+-------------+--------+--------------------------+

* *argsz* is the size of the VFIO device info structure. This is the only field
that should be set to non-zero in the request, identifying the client's expected
size. Currently this is a fixed value.
* *flags* contains the following device attributes.

  * VFIO_DEVICE_FLAGS_RESET indicates that the device supports the
    VFIO_USER_DEVICE_RESET message.
  * VFIO_DEVICE_FLAGS_PCI indicates that the device is a PCI device.

* *num_regions* is the number of memory regions that the device exposes.
* *num_irqs* is the number of distinct interrupt types that the device supports.

This version of the protocol only supports PCI devices. Additional devices may
be supported in future versions.

VFIO_USER_DEVICE_GET_REGION_INFO
--------------------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 5                      |
+--------------+------------------------+
| Message size | 48 + any caps          |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| Region info  | VFIO region info       |
+--------------+------------------------+

This command message is sent by the client to the server to query for
information about device memory regions. The VFIO region info structure is
defined in ``<linux/vfio.h>`` (``struct vfio_region_info``).

VFIO region info format
^^^^^^^^^^^^^^^^^^^^^^^

+------------+--------+------------------------------+
| Name       | Offset | Size                         |
+============+========+==============================+
| argsz      | 16     | 4                            |
+------------+--------+------------------------------+
| flags      | 20     | 4                            |
+------------+--------+------------------------------+
|            | +-----+-----------------------------+ |
|            | | Bit | Definition                  | |
|            | +=====+=============================+ |
|            | | 0   | VFIO_REGION_INFO_FLAG_READ  | |
|            | +-----+-----------------------------+ |
|            | | 1   | VFIO_REGION_INFO_FLAG_WRITE | |
|            | +-----+-----------------------------+ |
|            | | 2   | VFIO_REGION_INFO_FLAG_MMAP  | |
|            | +-----+-----------------------------+ |
|            | | 3   | VFIO_REGION_INFO_FLAG_CAPS  | |
|            | +-----+-----------------------------+ |
+------------+--------+------------------------------+
| index      | 24     | 4                            |
+------------+--------+------------------------------+
| cap_offset | 28     | 4                            |
+------------+--------+------------------------------+
| size       | 32     | 8                            |
+------------+--------+------------------------------+
| offset     | 40     | 8                            |
+------------+--------+------------------------------+

* *argsz* is the size of the VFIO region info structure plus the
  size of any region capabilities returned.
* *flags* are attributes of the region:

  * *VFIO_REGION_INFO_FLAG_READ* allows client read access to the region.
  * *VFIO_REGION_INFO_FLAG_WRITE* allows client write access to the region.
  * *VFIO_REGION_INFO_FLAG_MMAP* specifies the client can mmap() the region.
    When this flag is set, the reply will include a file descriptor in its
    meta-data. On AF_UNIX sockets, the file descriptors will be passed as
    SCM_RIGHTS type ancillary data.
  * *VFIO_REGION_INFO_FLAG_CAPS* indicates additional capabilities found in the
    reply.

* *index* is the index of memory region being queried, it is the only field
  that is required to be set in the command message.
* *cap_offset* describes where additional region capabilities can be found.
  cap_offset is relative to the beginning of the VFIO region info structure.
  The data structure it points is a VFIO cap header defined in
  ``<linux/vfio.h>``.
* *size* is the size of the region.
* *offset* is the offset given to the mmap() system call for regions with the
  MMAP attribute. It is also used as the base offset when mapping a VFIO
  sparse mmap area, described below.

The client sets the ``argsz`` field to indicate the maximum size of the
response that the server can send, which must be at least the size of the
response header plus the size of VFIO region info. If the region contains
capabilities whose size exceeds ``argsz``, then the server must respond only with
the response header and VFIO region info, omitting the region capabilities, and
setting in ``argsz`` the buffer size required to store the initial response
*plus* the region capabilities. The client then retries the operation with a
larger receive buffer.

VFIO Region capabilities
^^^^^^^^^^^^^^^^^^^^^^^^
The VFIO region information can also include a capabilities list. This list is
similar to a PCI capability list - each entry has a common header that
identifies a capability and where the next capability in the list can be found.
The VFIO capability header format is defined in ``<linux/vfio.h>`` (``struct
vfio_info_cap_header``).

VFIO cap header format
^^^^^^^^^^^^^^^^^^^^^^

+---------+--------+------+
| Name    | Offset | Size |
+=========+========+======+
| id      | 0      | 2    |
+---------+--------+------+
| version | 2      | 2    |
+---------+--------+------+
| next    | 4      | 4    |
+---------+--------+------+

* *id* is the capability identity.
* *version* is a capability-specific version number.
* *next* specifies the offset of the next capability in the capability list. It
  is relative to the beginning of the VFIO region info structure.

VFIO sparse mmap
^^^^^^^^^^^^^^^^

+------------------+----------------------------------+
| Name             | Value                            |
+==================+==================================+
| id               | VFIO_REGION_INFO_CAP_SPARSE_MMAP |
+------------------+----------------------------------+
| version          | 0x1                              |
+------------------+----------------------------------+
| next             | <next>                           |
+------------------+----------------------------------+
| sparse mmap info | VFIO region info sparse mmap     |
+------------------+----------------------------------+

This capability is defined when only a subrange of the region supports
direct access by the client via mmap(). The VFIO sparse mmap area is defined in
``<linux/vfio.h>`` (``struct vfio_region_sparse_mmap_area``).

VFIO region info cap sparse mmap
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
+----------+--------+------+
| Name     | Offset | Size |
+==========+========+======+
| nr_areas | 0      | 4    |
+----------+--------+------+
| reserved | 4      | 4    |
+----------+--------+------+
| offset   | 8      | 8    |
+----------+--------+------+
| size     | 16     | 9    |
+----------+--------+------+
| ...      |        |      |
+----------+--------+------+

* *nr_areas* is the number of sparse mmap areas in the region.
* *offset* and size describe a single area that can be mapped by the client.
  There will be nr_areas pairs of offset and size. The offset will be added to
  the base offset given in the VFIO_USER_DEVICE_GET_REGION_INFO to form the
  offset argument of the subsequent mmap() call.

The VFIO sparse mmap area is defined in ``<linux/vfio.h>`` (``struct
vfio_region_info_cap_sparse_mmap``).

VFIO Region Type
^^^^^^^^^^^^^^^^

+------------------+---------------------------+
| Name             | Value                     |
+==================+===========================+
| id               | VFIO_REGION_INFO_CAP_TYPE |
+------------------+---------------------------+
| version          | 0x1                       |
+------------------+---------------------------+
| next             | <next>                    |
+------------------+---------------------------+
| region info type | VFIO region info type     |
+------------------+---------------------------+

This capability is defined when a region is specific to the device.

VFIO region info type
^^^^^^^^^^^^^^^^^^^^^

The VFIO region info type is defined in ``<linux/vfio.h>``
(``struct vfio_region_info_cap_type``).

+---------+--------+------+
| Name    | Offset | Size |
+=========+========+======+
| type    | 0      | 4    |
+---------+--------+------+
| subtype | 4      | 4    |
+---------+--------+------+

The only device-specific region type and subtype supported by vfio-user is
VFIO_REGION_TYPE_MIGRATION (3) and VFIO_REGION_SUBTYPE_MIGRATION (1).

VFIO Device Migration Info
^^^^^^^^^^^^^^^^^^^^^^^^^^

The beginning of the subregion must contain
``struct vfio_device_migration_info``, defined in ``<linux/vfio.h>``. This
subregion is accessed like any other part of a standard vfio-user PCI region
using VFIO_USER_REGION_READ/VFIO_USER_REGION_WRITE.

+---------------+--------+-----------------------------+
| Name          | Offset | Size                        |
+===============+========+=============================+
| device_state  | 0      | 4                           |
+---------------+--------+-----------------------------+
|               | +-----+----------------------------+ |
|               | | Bit | Definition                 | |
|               | +=====+============================+ |
|               | | 0   | VFIO_DEVICE_STATE_RUNNING  | |
|               | +-----+----------------------------+ |
|               | | 1   | VFIO_DEVICE_STATE_SAVING   | |
|               | +-----+----------------------------+ |
|               | | 2   | VFIO_DEVICE_STATE_RESUMING | |
|               | +-----+----------------------------+ |
+---------------+--------+-----------------------------+
| reserved      | 4      | 4                           |
+---------------+--------+-----------------------------+
| pending_bytes | 8      | 8                           |
+---------------+--------+-----------------------------+
| data_offset   | 16     | 8                           |
+---------------+--------+-----------------------------+
| data_size     | 24     | 8                           |
+---------------+--------+-----------------------------+

* *device_state* defines the state of the device:

  The client initiates device state transition by writing the intended state.
  The server must respond only after it has succesfully transitioned to the new
  state. If an error occurs then the server must respond to the
  VFIO_USER_REGION_WRITE operation with the Error field set accordingly and
  must remain at the previous state, or in case of internal error it must
  transtition to the error state, defined as
  VFIO_DEVICE_STATE_RESUMING | VFIO_DEVICE_STATE_SAVING. The client must
  re-read the device state in order to determine it afresh.

  The following device states are defined:

  +-----------+---------+----------+-----------------------------------+
  | _RESUMING | _SAVING | _RUNNING | Description                       |
  +===========+=========+==========+===================================+
  | 0         | 0       | 0        | Device is stopped.                |
  +-----------+---------+----------+-----------------------------------+
  | 0         | 0       | 1        | Device is running, default state. |
  +-----------+---------+----------+-----------------------------------+
  | 0         | 1       | 0        | Stop-and-copy state               |
  +-----------+---------+----------+-----------------------------------+
  | 0         | 1       | 1        | Pre-copy state                    |
  +-----------+---------+----------+-----------------------------------+
  | 1         | 0       | 0        | Resuming                          |
  +-----------+---------+----------+-----------------------------------+
  | 1         | 0       | 1        | Invalid state                     |
  +-----------+---------+----------+-----------------------------------+
  | 1         | 1       | 0        | Error state                       |
  +-----------+---------+----------+-----------------------------------+
  | 1         | 1       | 1        | Invalid state                     |
  +-----------+---------+----------+-----------------------------------+

  Valid state transitions are shown in the following table:

  +-------------------------+---------+---------+---------------+----------+----------+
  | |darr| From / To |rarr| | Stopped | Running | Stop-and-copy | Pre-copy | Resuming |
  +=========================+=========+=========+===============+==========+==========+
  | Stopped                 |    \-   |    0    |       0       |    0     |     0    |
  +-------------------------+---------+---------+---------------+----------+----------+
  | Running                 |    1    |    \-   |       1       |    1     |     1    |
  +-------------------------+---------+---------+---------------+----------+----------+
  | Stop-and-copy           |    1    |    0    |       \-      |    0     |     0    |
  +-------------------------+---------+---------+---------------+----------+----------+
  | Pre-copy                |    0    |    0    |       1       |    \-    |     0    |
  +-------------------------+---------+---------+---------------+----------+----------+
  | Resuming                |    0    |    1    |       0       |    0     |     \-   |
  +-------------------------+---------+---------+---------------+----------+----------+

  A device is migrated to the destination as follows:

  * The source client transitions the device state from the running state to
    the pre-copy state. This transition is optional for the client but must be
    supported by the server. The souce server starts sending device state data
    to the source client through the migration region while the device is
    running.

  * The source client transitions the device state from the running state or the
    pre-copy state to the stop-and-copy state. The source server stops the
    device, saves device state and sends it to the source client through the
    migration region.

  The source client is responsible for sending the migration data to the
  destination client.

  A device is resumed on the destination as follows:

  * The destination client transitions the device state from the running state
    to the resuming state. The destination server uses the device state data
    received through the migration region to resume the device.

  * The destination client provides saved device state to the destination
    server and then transitions the device to back to the running state.

* *reserved* This field is reserved and any access to it must be ignored by the
  server.

* *pending_bytes* Remaining bytes to be migrated by the server. This field is
  read only.

* *data_offset* Offset in the migration region where the client must:

  * read from, during the pre-copy or stop-and-copy state, or

  * write to, during the resuming state.

  This field is read only.

* *data_size* Contains the size, in bytes, of the amount of data copied to:

  * the source migration region by the source server during the pre-copy or
    stop-and copy state, or

  * the destination migration region by the destination client during the
    resuming state.

Device-specific data must be stored at any position after
`struct vfio_device_migration_info`. Note that the migration region can be
memory mappable, even partially. In practise, only the migration data portion
can be memory mapped.

The client processes device state data during the pre-copy and the
stop-and-copy state in the following iterative manner:

  1. The client reads `pending_bytes` to mark a new iteration. Repeated reads
     of this field is an idempotent operation. If there are no migration data
     to be consumed then the next step depends on the current device state:

     * pre-copy: the client must try again.

     * stop-and-copy: this procedure can end and the device can now start
       resuming on the destination.

  2. The client reads `data_offset`; at thich point the server must make
     available a portion of migration data at this offset to be read by the
     client, which must happen *before* completing the read operation. The
     amount of data to be read must be stored in the `data_size` field, which
     the client reads next.

  3. The client reads `data_size` to determine the amount of migration data
     available.

  4. The client reads and processes the migration data.

  5. Go to step 1.

Note that the client can transition the device from the pre-copy state to the
stop-and-copy state at any time; `pending_bytes` does not need to become zero.

The client initializes the device state on the destination by setting the
device state in the resuming state and writing the migration data to the
destination migration region at `data_offset` offset. The client can write the
source migration data in an iterative manner and the server must consume this
data before completing each write operation, updating the `data_offset` field.
The server must apply the source migration data on the device resume state. The
client must write data on the same order and transction size as read.

If an error occurs then the server must fail the read or write operation. It is
an implementation detail of the client how to handle errors.

VFIO_USER_DEVICE_GET_REGION_IO_FDS
----------------------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 6                      |
+--------------+------------------------+
| Message size | 32 + subregion info    |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| Region info  | Region IO FD info      |
+--------------+------------------------+

Clients can access regions via VFIO_USER_REGION_READ/WRITE or, if provided, by
mmap()ing a file descriptor provided by the server.

VFIO_USER_DEVICE_GET_REGION_IO_FDS provides an alternative access mechanism via
file descriptors. This is an optional feature intended for performance
improvements where an underlying sub-system (such as KVM) supports communication
across such file descriptors to the vfio-user server, without needing to
round-trip through the client.

The server returns an array of sub-regions for the requested region. Each
sub-region describes a span (offset and size) of a region, along with the
requested file descriptor notification mechanism to use.  Each sub-region in the
response message may choose to use a different method, as defined below.  The
two mechanisms supported in this specification are ioeventfds and ioregionfds.

The server in addition returns a file descriptor in the ancillary data; clients
are expected to configure each sub-region's file descriptor with the requested
notification method. For example, a client could configure KVM with the
requested ioeventfd via a KVM_IOEVENTFD ioctl().

Region IO FD info format
^^^^^^^^^^^^^^^^^^^^^^^^

+-------------+--------+------+
| Name        | Offset | Size |
+=============+========+======+
| argsz       | 16     | 4    |
+-------------+--------+------+
| flags       | 20     | 4    |
+-------------+--------+------+
| index       | 24     | 4    |
+-------------+--------+------+
| count       | 28     | 4    |
+-------------+--------+------+
| sub-regions | 32     | ...  |
+-------------+--------+------+

* *argsz* is the size of the region IO FD info structure plus the
  total size of the sub-region array. Thus, each array entry "i" is at offset
  i * ((argsz - 32) / count). Note that currently this is 40 bytes for both IO
  FD types, but this is not to be relied on.
* *flags* must be zero
* *index* is the index of memory region being queried
* *count* is the number of sub-regions in the array
* *sub-regions* is the array of Sub-Region IO FD info structures

The client must set ``flags`` to zero and specify the region being queried in
the ``index``.

The client sets the ``argsz`` field to indicate the maximum size of the response
that the server can send, which must be at least the size of the response header
plus space for the sub-region array. If the full response size exceeds ``argsz``,
then the server must respond only with the response header and the Region IO FD
info structure, setting in ``argsz`` the buffer size required to store the full
response. In this case, no file descriptors are passed back.  The client then
retries the operation with a larger receive buffer.

The reply message will additionally include at least one file descriptor in the
ancillary data. Note that more than one sub-region may share the same file
descriptor.

Each sub-region given in the response has one of two possible structures,
depending whether *type* is `VFIO_USER_IO_FD_TYPE_IOEVENTFD` or
`VFIO_USER_IO_FD_TYPE_IOREGIONFD`:

Sub-Region IO FD info format (ioeventfd)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+-----------+--------+------+
| Name      | Offset | Size |
+===========+========+======+
| offset    | 0      | 8    |
+-----------+--------+------+
| size      | 8      | 8    |
+-----------+--------+------+
| fd_index  | 16     | 4    |
+-----------+--------+------+
| type      | 20     | 4    |
+-----------+--------+------+
| flags     | 24     | 4    |
+-----------+--------+------+
| padding   | 28     | 4    |
+-----------+--------+------+
| datamatch | 32     | 8    |
+-----------+--------+------+

* *offset* is the offset of the start of the sub-region within the region
  requested ("physical address offset" for the region)
* *size* is the length of the sub-region. This may be zero if the access size is
  not relevant, which may allow for optimizations
* *fd_index* is the index in the ancillary data of the FD to use for ioeventfd
  notification; it may be shared.
* *type* is `VFIO_USER_IO_FD_TYPE_IOEVENTFD`
* *flags* is any of:
  * `KVM_IOEVENTFD_FLAG_DATAMATCH`
  * `KVM_IOEVENTFD_FLAG_PIO`
  * `KVM_IOEVENTFD_FLAG_VIRTIO_CCW_NOTIFY` (FIXME: makes sense?)
* *datamatch* is the datamatch value if needed

See https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt 4.59
KVM_IOEVENTFD for further context on the ioeventfd-specific fields.

Sub-Region IO FD info format (ioregionfd)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+-----------+--------+------+
| Name      | Offset | Size |
+===========+========+======+
| offset    | 0      | 8    |
+-----------+--------+------+
| size      | 8      | 8    |
+-----------+--------+------+
| fd_index  | 16     | 4    |
+-----------+--------+------+
| type      | 20     | 4    |
+-----------+--------+------+
| flags     | 24     | 4    |
+-----------+--------+------+
| padding   | 28     | 4    |
+-----------+--------+------+
| user_data | 32     | 8    |
+-----------+--------+------+

* *offset* is the offset of the start of the sub-region within the region
  requested ("physical address offset" for the region)
* *size* is the length of the sub-region. This may be zero if the access size is
  not relevant, which may allow for optimizations; `KVM_IOREGION_POSTED_WRITES`
  must be set in *flags* in this case
* *fd_index* is the index in the ancillary data of the FD to use for ioregionfd
  messages; it may be shared
* *type* is `VFIO_USER_IO_FD_TYPE_IOREGIONFD`
* *flags* is any of:
  * `KVM_IOREGION_PIO`
  * `KVM_IOREGION_POSTED_WRITES`
* *user_data* is an opaque value passed back to the server via a message on the
  file descriptor

For further information on the ioregionfd-specific fields, see:
https://lore.kernel.org/kvm/cover.1613828726.git.eafanasova@gmail.com/

(FIXME: update with final API docs.)

VFIO_USER_DEVICE_GET_IRQ_INFO
-----------------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 7                      |
+--------------+------------------------+
| Message size | 32                     |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| IRQ info     | VFIO IRQ info          |
+--------------+------------------------+

This command message is sent by the client to the server to query for
information about device interrupt types. The VFIO IRQ info structure is
defined in ``<linux/vfio.h>`` (``struct vfio_irq_info``).

VFIO IRQ info format
^^^^^^^^^^^^^^^^^^^^

+-------+--------+---------------------------+
| Name  | Offset | Size                      |
+=======+========+===========================+
| argsz | 16     | 4                         |
+-------+--------+---------------------------+
| flags | 20     | 4                         |
+-------+--------+---------------------------+
|       | +-----+--------------------------+ |
|       | | Bit | Definition               | |
|       | +=====+==========================+ |
|       | | 0   | VFIO_IRQ_INFO_EVENTFD    | |
|       | +-----+--------------------------+ |
|       | | 1   | VFIO_IRQ_INFO_MASKABLE   | |
|       | +-----+--------------------------+ |
|       | | 2   | VFIO_IRQ_INFO_AUTOMASKED | |
|       | +-----+--------------------------+ |
|       | | 3   | VFIO_IRQ_INFO_NORESIZE   | |
|       | +-----+--------------------------+ |
+-------+--------+---------------------------+
| index | 24     | 4                         |
+-------+--------+---------------------------+
| count | 28     | 4                         |
+-------+--------+---------------------------+

* *argsz* is the size of the VFIO IRQ info structure.
* *flags* defines IRQ attributes:

  * *VFIO_IRQ_INFO_EVENTFD* indicates the IRQ type can support server eventfd
    signalling.
  * *VFIO_IRQ_INFO_MASKABLE* indicates that the IRQ type supports the MASK and
    UNMASK actions in a VFIO_USER_DEVICE_SET_IRQS message.
  * *VFIO_IRQ_INFO_AUTOMASKED* indicates the IRQ type masks itself after being
    triggered, and the client must send an UNMASK action to receive new
    interrupts.
  * *VFIO_IRQ_INFO_NORESIZE* indicates VFIO_USER_SET_IRQS operations setup
    interrupts as a set, and new sub-indexes cannot be enabled without disabling
    the entire type.

* index is the index of IRQ type being queried, it is the only field that is
  required to be set in the command message.
* count describes the number of interrupts of the queried type.

VFIO_USER_DEVICE_SET_IRQS
-------------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 8                      |
+--------------+------------------------+
| Message size | 36 + any data          |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| IRQ set      | VFIO IRQ set           |
+--------------+------------------------+

This command message is sent by the client to the server to set actions for
device interrupt types. The VFIO IRQ set structure is defined in
``<linux/vfio.h>`` (``struct vfio_irq_set``).

VFIO IRQ set format
^^^^^^^^^^^^^^^^^^^

+-------+--------+------------------------------+
| Name  | Offset | Size                         |
+=======+========+==============================+
| argsz | 16     | 4                            |
+-------+--------+------------------------------+
| flags | 20     | 4                            |
+-------+--------+------------------------------+
|       | +-----+-----------------------------+ |
|       | | Bit | Definition                  | |
|       | +=====+=============================+ |
|       | | 0   | VFIO_IRQ_SET_DATA_NONE      | |
|       | +-----+-----------------------------+ |
|       | | 1   | VFIO_IRQ_SET_DATA_BOOL      | |
|       | +-----+-----------------------------+ |
|       | | 2   | VFIO_IRQ_SET_DATA_EVENTFD   | |
|       | +-----+-----------------------------+ |
|       | | 3   | VFIO_IRQ_SET_ACTION_MASK    | |
|       | +-----+-----------------------------+ |
|       | | 4   | VFIO_IRQ_SET_ACTION_UNMASK  | |
|       | +-----+-----------------------------+ |
|       | | 5   | VFIO_IRQ_SET_ACTION_TRIGGER | |
|       | +-----+-----------------------------+ |
+-------+--------+------------------------------+
| index | 24     | 4                            |
+-------+--------+------------------------------+
| start | 28     | 4                            |
+-------+--------+------------------------------+
| count | 32     | 4                            |
+-------+--------+------------------------------+
| data  | 36     | variable                     |
+-------+--------+------------------------------+

* *argsz* is the size of the VFIO IRQ set structure, including any *data* field.
* *flags* defines the action performed on the interrupt range. The DATA flags
  describe the data field sent in the message; the ACTION flags describe the
  action to be performed. The flags are mutually exclusive for both sets.

  * *VFIO_IRQ_SET_DATA_NONE* indicates there is no data field in the command.
    The action is performed unconditionally.
  * *VFIO_IRQ_SET_DATA_BOOL* indicates the data field is an array of boolean
    bytes. The action is performed if the corresponding boolean is true.
  * *VFIO_IRQ_SET_DATA_EVENTFD* indicates an array of event file descriptors
    was sent in the message meta-data. These descriptors will be signalled when
    the action defined by the action flags occurs. In AF_UNIX sockets, the
    descriptors are sent as SCM_RIGHTS type ancillary data.
    If no file descriptors are provided, this de-assigns the specified
    previously configured interrupts.
  * *VFIO_IRQ_SET_ACTION_MASK* indicates a masking event. It can be used with
    VFIO_IRQ_SET_DATA_BOOL or VFIO_IRQ_SET_DATA_NONE to mask an interrupt, or
    with VFIO_IRQ_SET_DATA_EVENTFD to generate an event when the guest masks
    the interrupt.
  * *VFIO_IRQ_SET_ACTION_UNMASK* indicates an unmasking event. It can be used
    with VFIO_IRQ_SET_DATA_BOOL or VFIO_IRQ_SET_DATA_NONE to unmask an
    interrupt, or with VFIO_IRQ_SET_DATA_EVENTFD to generate an event when the
    guest unmasks the interrupt.
  * *VFIO_IRQ_SET_ACTION_TRIGGER* indicates a triggering event. It can be used
    with VFIO_IRQ_SET_DATA_BOOL or VFIO_IRQ_SET_DATA_NONE to trigger an
    interrupt, or with VFIO_IRQ_SET_DATA_EVENTFD to generate an event when the
    server triggers the interrupt.

* *index* is the index of IRQ type being setup.
* *start* is the start of the sub-index being set.
* *count* describes the number of sub-indexes being set. As a special case, a
  count (and start) of 0, with data flags of VFIO_IRQ_SET_DATA_NONE disables
  all interrupts of the index.
* *data* is an optional field included when the
  VFIO_IRQ_SET_DATA_BOOL flag is present. It contains an array of booleans
  that specify whether the action is to be performed on the corresponding
  index. It's used when the action is only performed on a subset of the range
  specified.

Not all interrupt types support every combination of data and action flags.
The client must know the capabilities of the device and IRQ index before it
sends a VFIO_USER_DEVICE_SET_IRQ message.

.. _Read and Write Operations:

Read and Write Operations
-------------------------

Not all I/O operations between the client and server can be done via direct
access of memory mapped with an mmap() call. In these cases, the client and
server use messages sent over the socket. It is expected that these operations
will have lower performance than direct access.

The client can access server memory with VFIO_USER_REGION_READ and
VFIO_USER_REGION_WRITE commands. These share a common data structure that
appears after the message header.

REGION Read/Write Data
^^^^^^^^^^^^^^^^^^^^^^

+--------+--------+----------+
| Name   | Offset | Size     |
+========+========+==========+
| Offset | 16     | 8        |
+--------+--------+----------+
| Region | 24     | 4        |
+--------+--------+----------+
| Count  | 28     | 4        |
+--------+--------+----------+
| Data   | 32     | variable |
+--------+--------+----------+

* *Offset* into the region being accessed.
* *Region* is the index of the region being accessed.
* *Count* is the size of the data to be transferred.
* *Data* is the data to be read or written.

The server can access client memory with VFIO_USER_DMA_READ and
VFIO_USER_DMA_WRITE messages. These also share a common data structure that
appears after the message header.

DMA Read/Write Data
^^^^^^^^^^^^^^^^^^^

+---------+--------+----------+
| Name    | Offset | Size     |
+=========+========+==========+
| Address | 16     | 8        |
+---------+--------+----------+
| Count   | 24     | 4        |
+---------+--------+----------+
| Data    | 28     | variable |
+---------+--------+----------+

* *Address* is the area of client memory being accessed. This address must have
  been previously exported to the server with a VFIO_USER_DMA_MAP message.
* *Count* is the size of the data to be transferred.
* *Data* is the data to be read or written.

VFIO_USER_REGION_READ
---------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 9                      |
+--------------+------------------------+
| Message size | 32 + data size         |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| Read info    | REGION read/write data |
+--------------+------------------------+

This command message is sent from the client to the server to read from server
memory.  In the command messages, there is no data, and the count is the amount
of data to be read. The reply message must include the data read, and its count
field is the amount of data read.

VFIO_USER_REGION_WRITE
----------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 10                     |
+--------------+------------------------+
| Message size | 32 + data size         |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| Write info   | REGION read/write data |
+--------------+------------------------+

This command message is sent from the client to the server to write to server
memory.  The command message must contain the data to be written, and its count
field must contain the amount of write data. The count field in the reply
message must be zero.

VFIO_USER_DMA_READ
------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 11                     |
+--------------+------------------------+
| Message size | 28 + data size         |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| DMA info     | DMA read/write data    |
+--------------+------------------------+

This command message is sent from the server to the client to read from client
memory.  In the command message, there is no data, and the count must will be
the amount of data to be read. The reply message must include the data read,
and its count field must be the amount of data read.

VFIO_USER_DMA_WRITE
-------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 12                     |
+--------------+------------------------+
| Message size | 28 + data size         |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+
| DMA info     | DMA read/write data    |
+--------------+------------------------+

This command message is sent from the server to the client to write to client
memory.  The command message must contain the data to be written, and its count
field must contain the amount of write data. The count field in the reply
message must be zero.

VFIO_USER_VM_INTERRUPT
----------------------

Message format
^^^^^^^^^^^^^^

+----------------+------------------------+
| Name           | Value                  |
+================+========================+
| Message ID     | <ID>                   |
+----------------+------------------------+
| Command        | 13                     |
+----------------+------------------------+
| Message size   | 20                     |
+----------------+------------------------+
| Flags          | Reply bit set in reply |
+----------------+------------------------+
| Error          | 0/errno                |
+----------------+------------------------+
| Interrupt info | <interrupt>            |
+----------------+------------------------+

This command message is sent from the server to the client to signal the device
has raised an interrupt.

Interrupt info format
^^^^^^^^^^^^^^^^^^^^^

+-----------+--------+------+
| Name      | Offset | Size |
+===========+========+======+
| Sub-index | 16     | 4    |
+-----------+--------+------+

* *Sub-index* is relative to the IRQ index, e.g., the vector number used in PCI
  MSI/X type interrupts.

VFIO_USER_DEVICE_RESET
----------------------

Message format
^^^^^^^^^^^^^^

+--------------+------------------------+
| Name         | Value                  |
+==============+========================+
| Message ID   | <ID>                   |
+--------------+------------------------+
| Command      | 14                     |
+--------------+------------------------+
| Message size | 16                     |
+--------------+------------------------+
| Flags        | Reply bit set in reply |
+--------------+------------------------+
| Error        | 0/errno                |
+--------------+------------------------+

This command message is sent from the client to the server to reset the device.

VFIO_USER_DIRTY_PAGES
---------------------

Message format
^^^^^^^^^^^^^^

+--------------------+------------------------+
| Name               | Value                  |
+====================+========================+
| Message ID         | <ID>                   |
+--------------------+------------------------+
| Command            | 15                     |
+--------------------+------------------------+
| Message size       | 16                     |
+--------------------+------------------------+
| Flags              | Reply bit set in reply |
+--------------------+------------------------+
| Error              | 0/errno                |
+--------------------+------------------------+
| VFIO Dirty bitmap  | <dirty bitmap>         |
+--------------------+------------------------+

This command is analogous to VFIO_IOMMU_DIRTY_PAGES. It is sent by the client
to the server in order to control logging of dirty pages, usually during a live
migration. The VFIO dirty bitmap structure is defined in ``<linux/vfio.h>``
(``struct vfio_iommu_type1_dirty_bitmap``).

VFIO Dirty Bitmap Format
^^^^^^^^^^^^^^^^^^^^^^^^

+-------+--------+-----------------------------------------+
| Name  | Offset | Size                                    |
+=======+========+=========================================+
| argsz | 0      | 4                                       |
+-------+--------+-----------------------------------------+
| flags | 4      | 4                                       |
+-------+--------+-----------------------------------------+
|       | +-----+----------------------------------------+ |
|       | | Bit | Definition                             | |
|       | +=====+========================================+ |
|       | | 0   | VFIO_IOMMU_DIRTY_PAGES_FLAG_START      | |
|       | +-----+----------------------------------------+ |
|       | | 1   | VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP       | |
|       | +-----+----------------------------------------+ |
|       | | 2   | VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP | |
|       | +-----+----------------------------------------+ |
+-------+--------+-----------------------------------------+
| data  | 8      | 4                                       |
+-------+--------+-----------------------------------------+

* *argsz* is the size of the VFIO dirty bitmap info structure.

* *flags* defines the action to be performed by the server:

  * *VFIO_IOMMU_DIRTY_PAGES_FLAG_START* instructs the server to start logging
    pages it dirties. Logging continues until explicitly disabled by
    VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP.

  * *VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP* instructs the server to stop logging
    dirty pages.

  * *VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP* requests from the server to return
    the dirty bitmap for a specific IOVA range. The IOVA range is specified by
    "VFIO dirty bitmap get" structure, which must immediatelly follow the
    "VFIO dirty bitmap" structure, explained next. This operation is only valid
    if logging of dirty pages has been previously started. The server must
    respond the same way it does for ``VFIO_USER_DMA_UNMAP`` if
    ``VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP`` is set in the flags field of the
    table entry (``struct vfio_bitmap`` plus the bitmap must follow the
    response header).

  These flags are mutually exclusive with each other.

* *data* This field is unused in vfio-user.

VFIO Dirty Bitmap Get Format
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+--------+--------+------+
| Name   | Offset | Size |
+========+========+======+
| iova   | 0      | 8    |
+--------+--------+------+
| size   | 8      | 8    |
+--------+--------+------+
| bitmap | 16     | 24   |
+--------+--------+------+

* *iova* is the IOVA offset

* *size* is the size of the IOVA region

* *bitmap* is the VFIO bitmap (``struct vfio_bitmap``). This field is explained
  in `VFIO bitmap format`_.

Appendices
==========

Unused VFIO ioctl() commands
----------------------------

The following VFIO commands do not have an equivalent vfio-user command:

* VFIO_GET_API_VERSION
* VFIO_CHECK_EXTENSION
* VFIO_SET_IOMMU
* VFIO_GROUP_GET_STATUS
* VFIO_GROUP_SET_CONTAINER
* VFIO_GROUP_UNSET_CONTAINER
* VFIO_GROUP_GET_DEVICE_FD
* VFIO_IOMMU_GET_INFO

However, once support for live migration for VFIO devices is finalized some
of the above commands may have to be handled by the client in their
corresponding vfio-user form. This will be addressed in a future protocol
version.

VFIO groups and containers
^^^^^^^^^^^^^^^^^^^^^^^^^^

The current VFIO implementation includes group and container idioms that
describe how a device relates to the host IOMMU. In the vfio-user
implementation, the IOMMU is implemented in SW by the client, and is not
visible to the server. The simplest idea would be that the client put each
device into its own group and container.

Backend Program Conventions
---------------------------

vfio-user backend program conventions are based on the vhost-user ones.

* The backend program must not daemonize itself.
* No assumptions must be made as to what access the backend program has on the
  system.
* File descriptors 0, 1 and 2 must exist, must have regular
  stdin/stdout/stderr semantics, and can be redirected.
* The backend program must honor the SIGTERM signal.
* The backend program must accept the following commands line options:

  * ``--socket-path=PATH``: path to UNIX domain socket,
  * ``--fd=FDNUM``: file descriptor for UNIX domain socket, incompatible with
    ``--socket-path``
* The backend program must be accompanied with a JSON file stored under
  ``/usr/share/vfio-user``.

TODO add schema similar to docs/interop/vhost-user.json.
