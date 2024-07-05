# /*
# * Copyright 2022-2024 NXP
# * All rights reserved.
# *
# * SPDX-License-Identifier: BSD-3-Clause
# */

#$(shell . /opt/fsl-imx-xwayland/5.10-hardknott/environment-setup-cortexa53-crypto-poky-linux)

# How to compile for specific function:
# You need to provide function as an argument to make command:
# WIFI function        -> "make func=WIFI"
# BLE function         -> "make func=BLE"
# WIFI + BLE function  -> "make func=WIFI_BLE"

# How to compile for specific interface:
# You need to provide each interface as an argument to make command:
# USB interface  -> "make interface=USB"
# UART interface -> "make interface=UART"
# SDIO interface -> "make interface=SDIO"
# SPI interface  -> "make interface=SPI"

# How to compile for specific ble profile:
# You need to provide HTS/HTC/HRS/HRC/BAS profile as argument to make command,
# HTS profile -> "make HTS=y"
# HTC profile -> "make HTC=y"
# HRS profile -> "make HRS=y"
# HRC profile -> "make HRC=y"
# BAS profile -> "make BAS=y"

# for example:
# WIFI function + USB interface                  -> "make func=WIFI interface=USB"
# BLE function + UART interface                  -> "make func=BLE interface=UART"
# BLE function + UART interface + HTS profile    -> "make func=BLE interface=UART HTS=y"
# WIFI + BLE function + SPI interface -> "make func=WIFI_BLE interface=UART"


CC := gcc
BIN = MPU_NCP_HOST
CFLAGS = -Wall
CFLAGS += -std=gnu99
CFLAGS += -g

SRC_DIR 	= ./src
INC_DIR		= $(shell find $(SRC_DIR) -type d)
OBJ_DIR		= ./obj
BIN_NAME 	= MPU_NCP_HOST
BIN_DIR 	= ./bin

SRC_FILES	= $(shell find src -name *.c)
OBJ_FILES 	= $(SRC_FILES:.c=.o)

_INC_DIR 	= $(foreach dir,$(INC_DIR),$(addprefix -I, $(dir)))

CFLAGS		+= -DCONFIG_NCP_$(func)
CFLAGS		+= -DCONFIG_NCP_$(interface)
#CFLAGS		+= -DCONFIG_NCP_DEBUG
LDFLAGS 	= -lpthread -lc -lrt

ifeq ($(func), WIFI_BLE)
CFLAGS += -DCONFIG_NCP_WIFI
CFLAGS += -DCONFIG_NCP_BLE
endif

ifeq ($(func), WIFI_BLE_OT)
CFLAGS += -DCONFIG_NCP_WIFI
CFLAGS += -DCONFIG_NCP_BLE
CFLAGS += -DCONFIG_NCP_OT
endif

ifeq ($(func), WIFI_OT)
CFLAGS += -DCONFIG_NCP_WIFI
CFLAGS += -DCONFIG_NCP_OT
endif

ifeq ($(func), BLE_OT)
CFLAGS += -DCONFIG_NCP_BLE
CFLAGS += -DCONFIG_NCP_OT
endif

ifeq ($(func), OT)
CFLAGS += -DCONFIG_NCP_OT
endif



#When use USB interface
#******For NCP MPU Host side(i.mx8mini)*****
#1.Need install libusb in imx8 mini to support host app compile
#2.Use "make interface=USB" to build app support usb interface

#******For NCP device side(rw61x)*****
#Enable compile macro 'CONFIG_NCP_USB'

#Note
#Path of '-I/usr/local/include/libusb-1.0 -L/usr/local/lib' is corresponding to your libusb install path.
LDFLAGS += -I/usr/local/include/libusb-1.0 -L/usr/local/lib -lusb-1.0
#endif



ifeq ($(CONFIG_NCP_SDIO), y)
ifeq ($(CONFIG_NCP_SDIO_TEST_LOOPBACK), y)
CFLAGS += -g -DCONFIG_SDIO_TEST_LOOPBACK
endif
endif

ifeq ($(func), BLE)
# Use "make HTS=y" to compile with HTS profile
ifeq ($(HTS), y)
CFLAGS += -DCONFIG_NCP_HTS
endif

# Use "make HTC=y" to compile with HTC profile
ifeq ($(HTC), y)
CFLAGS += -DCONFIG_NCP_HTC
endif

# Use "make HRS=y" to compile with HRS profile
ifeq ($(HRS), y)
CFLAGS += -DCONFIG_NCP_HRS
endif

# Use "make HRC=y" to compile with HRC profile
ifeq ($(HRC), y)
CFLAGS += -DCONFIG_NCP_HRC
endif

# Use "make BAS=y" to compile with BAS profile
ifeq ($(BAS), y)
CFLAGS += -DCONFIG_NCP_BAS
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