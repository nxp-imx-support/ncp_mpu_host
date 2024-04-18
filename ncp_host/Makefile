# /*
# * Copyright 2022-2024 NXP
# * All rights reserved.
# *
# * SPDX-License-Identifier: BSD-3-Clause
# */

#$(shell . /opt/fsl-imx-xwayland/5.10-hardknott/environment-setup-cortexa53-crypto-poky-linux)

# How to compile for specific interface:
# You need to provide each interface as an argument to make command,

# USB interface -> "make interface=USB"
# UART interface -> "make interface=UART"
# SDIO interface -> "make interface=SDIO"
# SPI interface -> "make interface=SPI"

CC := gcc
BIN = MPU_BRIDGE
CFLAGS = -Wall
CFLAGS += -std=gnu99

SRC_DIR 	= ./src
INC_DIR		= $(shell find $(SRC_DIR) -type d)
OBJ_DIR		= ./obj
BIN_NAME 	= MPU_BRIDGE
BIN_DIR 	= ./bin

SRC_FILES	= $(shell find src -name *.c)
OBJ_FILES 	= $(SRC_FILES:.c=.o)

_INC_DIR 	= $(foreach dir,$(INC_DIR),$(addprefix -I, $(dir)))

CFLAGS		+= -DCONFIG_NCP_$(interface)
#CFLAGS		+= -DCONFIG_NCP_DEBUG
LDFLAGS 	= -lpthread -lc -lrt

#When use USB interface
#******For NCP MPU Host side(i.mx8mini)*****
#1.Need install libusb in imx8 mini to support host app compile
#2.Use "make interface=USB" to build app support usb interface

#******For NCP device side(rw61x)*****
#Enable compile macro 'CONFIG_USB_BRIDGE'

#Note
#Path of '-I/usr/local/include/libusb-1.0 -L/usr/local/lib' is corresponding to your libusb install path.
LDFLAGS += -I/usr/local/include/libusb-1.0 -L/usr/local/lib -lusb-1.0
CFLAGS += -g
#endif


#When use SDIO interface
#******For NCP MPU Host side(i.mx8mini)*****
#Use "make interface=SDIO"  to build app support sdio interface

#******For NCP device side(rw61x)*****
#Enable compile macro 'CONFIG_SDIO_BRIDGE'

ifeq ($(CONFIG_NCP_SDIO), y)
CFLAGS += -g -DCONFIG_SDIO_BRIDGE
ifeq ($(CONFIG_NCP_SDIO_TEST_LOOPBACK), y)
CFLAGS += -g -DCONFIG_SDIO_TEST_LOOPBACK
endif
endif



.PHONY : $(BIN_DIR)/$(BIN_NAME)

$(BIN_DIR)/$(BIN_NAME): $(OBJ_FILES)
	@echo "start compiling ......"
	$(CC) -o $@ $^ $(_INC_DIR) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $< $(_INC_DIR) $(LDFLAGS)

.PHONY : clean

clean :
	$(shell find . -name *.o | xargs rm -rf)
	rm -rf $(BIN_DIR)/$(BIN_NAME)