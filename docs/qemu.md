qemu usage walkthrough
======================

In this walk-through, we'll use a buildroot image VM along with the
[gpio sample server](../samples/gpio-pci-idio-16.c) to emulate a very simple GPIO
device.

Building qemu
-------------

You will need QEMU 10.1 plus a small fix. Let's build it:

```
cd ~/src/qemu
git clone https://github.com/jlevon/qemu.git -b fix-class-code .
./configure --enable-kvm --enable-vnc --target-list=x86_64-softmmu --enable-trace-backends=log --enable-debug
make -j
```


Starting the server
-------------------

Start the `gpio` server process:

```
rm -f /tmp/vfio-user.sock
./build/samples/gpio-pci-idio-16 -v /tmp/vfio-user.sock &
```

Starting the client
-------------------

Our client in this case will be a Linux image with the pci-idio-16 kernel
driver. Let's grab the images:

```
curl https://github.com/mcayland-ntx/libvfio-user-test/raw/refs/heads/main/images/bzImage
curl https://github.com/mcayland-ntx/libvfio-user-test/raw/refs/heads/main/images/rootfs.ext2
```

Now use the qemu you've built to start the VM as follows:

```
~/src/qemu/build/qemu-system-x86_64 \
    -accel kvm \
    -nographic \
    -display none \
    -m 1G \
    -net none \
    -kernel ./bzImage \
    -hda ./rootfs.ext2 \
    -append "console=ttyS0 root=/dev/sda" \
    -device vfio-user-pci,socket=/tmp/vfio-user.sock
```

Log in to this VM as root (no password). We should be able to interact with the
device:

```
lspci -k # confirm the pci-idio-16 driver is loaded
gpioinfo
gpioset -c gpiochip0 -t 0 OUT0=1
gpioget -c gpiochip0 --numeric OUT0
```

and the server should output something like:

```
gpio: region2: read 0 from (0:1)
gpio: region2: wrote 0x1 to (0:1)
gpio: region2: read 0 from (0:1)
```
