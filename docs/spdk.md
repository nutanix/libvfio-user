SPDK and libvfio-user
=====================

SPDK can provide a virtual NVMe controller as a vfio-user device which can be
consumed by a QEMU guest.

Use Oracle's QEMU d377d483f9 from https://github.com/oracle/qemu:

	git clone https://github.com/oracle/qemu qemu-orcl
	cd qemu-ocrl
	git submodule update --init --recursive
	./configure --enable-multiprocess
	make

Use SPDK 72a5fa139:

	git clone https://github.com/spdk/spdk
	cd spdk
	git submodule update --init --recursive
	./configure --with-vfio-user
	make

Start SPDK:

	LD_LIBRARY_PATH=build/lib:dpdk/build/lib build/bin/nvmf_tgt &

Create an NVMe controller with a 512MB RAM-based namespace:

	rm -f /var/run/{cntrl,bar0}
	scripts/rpc.py nvmf_create_transport -t VFIOUSER && \
		scripts/rpc.py bdev_malloc_create 512 512 -b Malloc0 && \
		scripts/rpc.py nvmf_create_subsystem nqn.2019-07.io.spdk:cnode0 -a -s SPDK0 && \
		scripts/rpc.py nvmf_subsystem_add_ns nqn.2019-07.io.spdk:cnode0 Malloc0 && \
		scripts/rpc.py nvmf_subsystem_add_listener nqn.2019-07.io.spdk:cnode0 -t VFIOUSER -a /var/run -s 0

Start the guest with e.g. 4 GB of RAM:

	qemu-orcl/build/qemu-system-x86_64 ... \
		-m 4G -object memory-backend-file,id=mem0,size=4G,mem-path=/dev/hugepages,share=on,prealloc=yes -numa node,memdev=mem0 \
		-device vfio-user-pci,socket=/var/run/cntrl
