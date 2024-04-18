# mcu-sdio

A simple Linux SDIO device driver which would export device node and communicate with ROM SDIO slave interface.

## Build the driver from source

Simply use the following command to build the driver, where
* KDIR : where the Linux kernel source is
* ARCH : Linux kernel CPU architecture used
* CROSS_COMPILE : name of the cross compiler

### Native build

Here is an example to demostrate how to build for x86 Linux uBuntu machine.

```
make KDIR=/lib/modules/$(uname -r)/build/
```

### Cross build

Here is an example to demostrate how to build with cross compiler for i.MX8 platform.

```
make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- KDIR=/home/kshi/linux-imx/
```

## How to use

Simply use the following command to insert kernel module,

```
insmod mcu-sdio.ko
```

The following messages would appear when SDIO slave device has been correctly connected.

```
[17758.267426] vendor=0x0471 device=0x0209 class=0 function=1
[17758.273300] SDIO FUNC1 IO port: 0x10000
[17758.277624] MCU SDIO simple driver v0.1
```