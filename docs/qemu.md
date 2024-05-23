qemu usage walkthrough
======================

In this walk-through, we'll use an Ubuntu cloudimg along with the
[gpio sample server](../samples/gpio-pci-idio-16.c) to emulate a very simple GPIO
device.

Building qemu
-------------

`vfio-user` client support is not yet merged into `qemu`. Instead, download and
build [jlevon's master.vfio-user branch of
qemu](https://github.com/jlevon/qemu/tree/master.vfio-user); for example:

```
git clone -b master.vfio-user git@github.com:jlevon/qemu.git
cd qemu

./configure --prefix=/usr --enable-kvm --enable-vnc --target-list=x86_64-softmmu --enable-debug  --enable-vfio-user-client
make -j
```

Configuring the cloudimg
------------------------

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

don't forget to replace `jlevon` with *your* github user name.

Starting the server
-------------------

Start the `gpio` server process:

```
rm -f /tmp/vfio-user.sock
./build/samples/gpio-pci-idio-16 -v /tmp/vfio-user.sock &
```

Booting the guest OS
--------------------

Make sure your system has hugepages available:

```
$ cat /proc/sys/vm/nr_hugepages
1024
```

Now you should be able to start qemu:

```
$ imgpath=/path/to/bionic-server-cloudimg-amd64.img
$ sudo ~/src/build/qemu-system-x86_64 \
   -machine accel=kvm,type=q35 -cpu host -m 2G \
   -mem-prealloc -object memory-backend-file,id=ram-node0,prealloc=yes,mem-path=/dev/hugepages/gpio,share=yes,size=2G \
   -numa node,memdev=ram-node0 \
   -nographic \
   -device virtio-net-pci,netdev=net0 \
   -netdev user,id=net0,hostfwd=tcp::2222-:22 \
   -drive if=virtio,format=qcow2,file=$imgpath \
   -drive if=virtio,format=raw,file=seed.img \
   -device vfio-user-pci,socket=/tmp/vfio-user.sock
```

Log in to your VM and load the kernel driver:

```
$ ssh -p 2222 ubuntu@localhost
...
$ sudo apt install linux-modules-extra-$(uname -r)
$ sudo modprobe gpio-pci-idio-16
```

Now we should be able to observe the emulated GPIO device's pins:

```
$ sudo su -
# cat /sys/class/gpio/gpiochip480/base > /sys/class/gpio/export
# for ((i=0;i<12;i++)); do cat /sys/class/gpio/OUT0/value; done
```

and the server should output something like:

```
gpio: region2: read 0 from (0:1)
gpio: region2: read 0 from (0:1)
gpio: region2: read 0 from (0:1)
gpio: region2: read 0x1 from (0:1)
gpio: region2: read 0x1 from (0:1)
gpio: region2: read 0x1 from (0:1)
gpio: region2: read 0x2 from (0:1)
gpio: region2: read 0x2 from (0:1)
gpio: region2: read 0x2 from (0:1)
gpio: region2: read 0x3 from (0:1)
gpio: region2: read 0x3 from (0:1)
gpio: region2: read 0x3 from (0:1)
```
