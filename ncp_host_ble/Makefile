# /*
# * Copyright 2022-2024 NXP
# * All rights reserved.
# *
# * SPDX-License-Identifier: BSD-3-Clause
# */

#$(shell . /opt/fsl-imx-xwayland/5.10-hardknott/environment-setup-cortexa53-crypto-poky-linux)

# How to compile for specific interface:
# You need to provide each interface as an argument to make command,
# for example, to compile for USB interface
# use this command -> "make interface=USB"
# to compile for UART -> "make interface=UART"

CC := gcc
BIN = MPU_BRIDGE_BLE
#SOURCE = mpu_bridge_app.c mpu_bridge_command.c
#LDFLAGS = -lpthread  -Iservice
CFLAGS = -Wall
CFLAGS += -std=gnu99

SRC_DIR 	= ./src
INC_DIR		= $(shell find $(SRC_DIR) -type d)
OBJ_DIR		= ./obj
BIN_NAME 	= MPU_BRIDGE_BLE
BIN_DIR 	= ./bin

SRC_FILES	= $(shell find src -name *.c)
OBJ_FILES 	= $(SRC_FILES:.c=.o)

_INC_DIR 	= $(foreach dir,$(INC_DIR),$(addprefix -I, $(dir)))

CFLAGS		+= -DCONFIG_NCP_$(interface)
#CFLAGS		+= -DCONFIG_NCP_DEBUG
LDFLAGS 	= -lpthread -lc -lrt

#When use USB interface
#******For NCP MPU Host side(i.mx8mini)*****
#1.Need install libusb in host compile environment to support host app compile
#2.Use "make CONFIG_NCP_USB=y" to enable usb interface

#******For NCP device side(rw61x)*****
#Enable compile macro 'CONFIG_USB_BRIDGE'

#ifeq ($(CONFIG_NCP_USB), y)
#Path of '-I/usr/local/include/libusb-1.0 -L/usr/local/lib' is corresponding to your libusb install path.
LDFLAGS += -I/usr/local/include/libusb-1.0 -L/usr/local/lib -lusb-1.0
CFLAGS += -g
#endif

#When use SDIO interface
#******For NCP MPU Host side(i.mx8mini)*****
#Use "make CONFIG_NCP_SDIO=y" to enable sdio interface

#******For NCP device side(rw61x)*****
#Enable compile macro 'CONFIG_SDIO_BRIDGE'

ifeq ($(CONFIG_NCP_SDIO), y)
CFLAGS += -g -DCONFIG_SDIO_BRIDGE
ifeq ($(CONFIG_NCP_SDIO_TEST_LOOPBACK), y)
CFLAGS += -g -DCONFIG_SDIO_TEST_LOOPBACK
endif
endif

#When use SPI interface
#******For NCP MPU Host side(i.mx8mini)*****
#Use "make CONFIG_NCP_SPI=y" to enable sdio interface

#******For NCP device side(rw61x)*****
#Enable compile macro 'CONFIG_NCP_SPI'


# Use "make HTS=y" to compile with HTS profile
ifeq ($(HTS), y)
#SOURCE += service/hts.c
CFLAGS += -DCONFIG_NCP_HTS
endif

# Use "make HTC=y" to compile with HTC profile
ifeq ($(HTC), y)
#SOURCE += service/htc.c
CFLAGS += -DCONFIG_NCP_HTC
endif

# Use "make HRS=y" to compile with HRS profile
ifeq ($(HRS), y)
#SOURCE += service/hrs.c
CFLAGS += -DCONFIG_NCP_HRS
endif

# Use "make HRC=y" to compile with HRC profile
ifeq ($(HRC), y)
#SOURCE += service/hrc.c
CFLAGS += -DCONFIG_NCP_HRC
endif

# Use "make BAS=y" to compile with BAS profile
ifeq ($(BAS), y)
#SOURCE += service/bas.c
CFLAGS += -DCONFIG_NCP_BAS
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