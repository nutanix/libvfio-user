Examples
========

The [samples directory](../samples/) contains various libvfio-user examples.

lspci
-----

[lspci](../samples/lspci.c) implements an example of how to dump the PCI header
of a libvfio-user device and examine it with lspci(8):

```
# lspci -vv -F <(build/samples/lspci)
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
```

The above sample implements a very simple PCI device that supports the Power
Management PCI capability. The sample can be trivially modified to change the
PCI configuration space header and add more PCI capabilities.


Client/Server Implementation
----------------------------

[Client](../samples/client.c)/[server](../samples/server.c) implements a basic
client/server model where basic tasks are performed.

The server implements a device that can be programmed to trigger interrupts
(INTx) to the client. This is done by writing the desired time in seconds since
Epoch to BAR0. The server then triggers an eventfd-based IRQ and then a message-based
one (in order to demonstrate how it's done when passing of file descriptors
isn't possible/desirable). The device also works as memory storage: BAR1 can
be freely written to/read from by the host.

Since this is a completely made up device, there's no kernel driver (yet).
[Client](../samples/client.c) implements a client that knows how to drive this
particular device (that would normally be QEMU + guest VM + kernel driver).

The client exercises all commands in the vfio-user protocol, and then proceeds
to perform live migration. The client spawns the destination server (this would
be normally done by libvirt) and then migrates the device state, before
switching entirely to the destination server. We re-use the source client
instead of spawning a destination one as this is something libvirt/QEMU would
normally do.

To spice things up, the client programs the source server to trigger an
interrupt and then migrates to the destination server; the programmed interrupt
is delivered by the destination server. Also, while the device is being live
migrated, the client spawns a thread that constantly writes to BAR1 in a tight
loop. This thread emulates the guest VM accessing the device while the main
 thread (what would normally be QEMU) is driving the migration.

Start the source server as follows (pick whatever you like for
`/tmp/vfio-user.sock`):

```
rm -f /tmp/vfio-user.sock* ; build/samples/server -v /tmp/vfio-user.sock
```

And then the client:

```
build/samples/client /tmp/vfio-user.sock
```

After a couple of seconds the client will start live migration. The source
server will exit and the destination server will start, watch the client
terminal for destination server messages.

shadow_ioeventfd_server
-----------------------

shadow_ioeventfd_server.c and shadow_ioeventfd_speed_test.c are used to
demonstrate the benefits of shadow ioeventfd, see
[ioregionfd](./ioregionfd.md) for more information.


