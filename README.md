# i10 I/O scheduler for the upstream Linux kernel.

## Prerequisites
Download the recent 'linux-block' source tree that includes [Ming's patch-set](https://www.spinics.net/lists/linux-block/msg55860.html) and NVMe-TCP optimizations[[1](http://git.infradead.org/nvme.git/commit/122e5b9f3d370ae11e1502d14ff5c7ea9b144a76)][[2](http://git.infradead.org/nvme.git/commit/86f0348ace1510d7ac25124b096fb88a6ab45270)][[3](http://git.infradead.org/nvme.git/commit/15ec928a65e0528ef4999e2947b4802b772f0891)].

```
git clone -b for-5.9/drivers https://git.kernel.org/pub/scm/linux/kernel/git/axboe/linux-block.git
```

## Setup instructions (with root)

1. Download our i10 I/O scheduler kernel module and copy to the kernel source tree:

```
git clone https://github.com/i10-kernel/upstream-linux.git
cd upstream-linux
cp i10-iosched.patch /usr/src/linux-block/
cd /usr/src/linux-block/
```

2. Apply the patch to the 'linux-block' kernel source tree.

```
patch -p1 < i10-iosched.patch
```

3. Make sure the i10 module is included in the kernel configuration:

```
make menuconfig

IO Schedulers ---> <M> i10 I/O scheduler
```
  
Please refer to the [i10-implementation](https://github.com/i10-kernel/i10-implementation) repository for the remaining parts.

## Running i10
We assume that a target device (e.g., nvme0n1) is already initialized via NVMe-over-TCP.

1. Load i10 I/O scherduler:
```
modprobe i10-iosched
```

2. Use i10 I/O scheduler for the target device:
```
echo i10 > /sys/block/nvme0c0n1/queue/scheduler
```

3. The default batch size (in #requests, bytes, or timeout) can be changed:
```
echo 16 > /sys/block/nvme0c0n1/queue/scheduler/iosched/batch_nr
echo 65536 > /sys/block/nvme0c0n1/queue/scheduler/iosched/batch_bytes
echo 50 > /sys/block/nvme0c0n1/queue/scheduler/iosched/batch_timeout
```
