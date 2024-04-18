EXTRA_CFLAGS+= -Werror -Wno-implicit-fallthrough
EXTRA_CFLAGS+= -O2
EXTRA_CFLAGS+= -g

#PWD   := $(shell pwd)

obj-m := mcu-sdio.o
mcu-sdio-objs := mcu_sdio_drv.o

all:
ifeq ($(CROSS_COMPILE),)
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
else
	$(MAKE) -C $(KDIR) M=$(shell pwd) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
endif

clean:
	rm -f *.o *.a *.ko *.ko.cmd *.o.cmd *.mod.* *.mod $(mcu-sdio-objs)
	rm -f modules.order
	rm -f Module.symvers