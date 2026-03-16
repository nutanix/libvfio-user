SPDK and libvfio-user
=====================

[SPDK](https://github.com/spdk/) has support for a virtual NVMe controller
called nvmf/vfio-user. These are instructions on how to use it with the QEMU
`vfio-user` client.

Build QEMU
----------

You will need QEMU 10.1.1 or later. Let's build it:

```
cd ~/src/
curl -L https://download.qemu.org/qemu-10.1.1.tar.xz | tar xJf -
cd ~/src/qemu-10.1.1

./configure --enable-kvm --enable-vnc --target-list=x86_64-softmmu --enable-trace-backends=log --enable-debug
make -j
```

Build SPDK
----------

Here we'll use SPDK v25.09:

```
git clone https://github.com/spdk/spdk --recursive  --branch v25.09 spdk-v25.09
cd spdk-v25.09
./configure --with-vfio-user
make -j
```

NB: SPDK includes `libvfio-user` as a submodule: some older versions of SPDK
require a particular branch of libvfio-user.

Start SPDK
----------

```
./build/bin/nvmf_tgt --no-huge -s 1024 &
```

Now let's create an NVMe controller with a 512MB RAM-based namespace:

```
mkdir /tmp/spdk
scripts/rpc.py bdev_malloc_create 512 512 -b Malloc0
scripts/rpc.py nvmf_create_subsystem nqn.2019-07.io.spdk:cnode0 -a -s SPDK0
scripts/rpc.py nvmf_subsystem_add_ns nqn.2019-07.io.spdk:cnode0 Malloc0
scripts/rpc.py nvmf_create_transport -t VFIOUSER
scripts/rpc.py nvmf_subsystem_add_listener nqn.2019-07.io.spdk:cnode0 -t VFIOUSER -a /tmp/spdk -s 0
```

Start the VM
------------

Now let's start our guest VM. We'll create a 2GB VM booting from an Ubuntu cloud
image, with a NIC so we can ssh in, and our virtual NVMe PCI device:

```
cd ~/src/qemu-10.1.1
./build/qemu-system-x86_64 \
  -monitor stdio \
  -machine accel=kvm,type=q35 \
  -m 2G \
  -object memory-backend-file,id=mem,size=2G,mem-path=/dev/shm/qemu-mem,share=on \
  -numa node,memdev=mem \
  -drive if=virtio,format=qcow2,file=/home/jlevon/bionic-server-cloudimg-amd64.img \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22
  -device '{"driver":"vfio-user-pci","socket":{"path": "/tmp/spdk/cntrl", "type": "unix"}}'
```

And in the VM we should be able to see our NVMe device:

```
ssh -p 2222 ubuntu@localhost

ubuntu@cloudimg:~$ sudo nvme list
Node             SN                   Model                                    Namespace Usage                      Format           FW Rev  
---------------- -------------------- ---------------------------------------- --------- -------------------------- ---------------- --------
/dev/nvme0n1     SPDK0                SPDK bdev Controller                     1         536.87  MB / 536.87  MB    512   B +  0 B   25.05   
```

For generating a cloud image, see below.

Using libvirt
-------------

To use the nvmf/vfio-user target with a libvirt quest, in addition to the
libvirtd configuration documented in the [README](../README.md) the guest RAM must
be backed by hugepages:

    <memoryBacking>
      <hugepages>
        <page size='2048' unit='KiB'/>
      </hugepages>
      <source type='memfd'/>
      <access mode='shared'/>
    </memoryBacking>

Because SPDK must be run as root, either fix the vfio-user socket permissions
or configure libvirt to run QEMU as root.

Live Migration
--------------

Live migration with SPDK is currently non-functional, although code exists in
`libvfio-user`. If you are interested in helping, please let us know!

Generating an Ubuntu cloud image
--------------------------------

Set up the necessary metadata files:

```
sudo apt install cloud-image-utils

$ cat metadata.yaml
instance-id: iid-local01
local-hostname: cloudimg

$ cat user-data.yaml
#cloud-config
ssh_import_id:
  - gh:jlevon

cloud-localds seed.img user-data.yaml metadata.yaml
```

Replace `jlevon` with *your* github username; this will pull your public key
from github, so you can subsequently ssh into the VM.
