libvirt
=======

You can configure `vfio-user` devices in a `libvirt` domain configuration:

1. Add `xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'` to the `domain`
   element.

2. Enable sharing of the guest's RAM:

```xml
<memoryBacking>
  <source type='file'/>
  <access mode='shared'/>
</memoryBacking>
```

3. Pass the vfio-user device:

```xml
<qemu:commandline>
  <qemu:arg value='-device'/>
  <qemu:arg value='{"driver":"vfio-user-pci","socket":{"path": "/tmp/vfio-user.sock", "type": "unix"}'/>
</qemu:commandline>
```
