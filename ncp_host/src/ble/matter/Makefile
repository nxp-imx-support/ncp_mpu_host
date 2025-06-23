# /*
# * Copyright 2024 NXP
# * All rights reserved.
# *
# * SPDX-License-Identifier: BSD-3-Clause
# */

COM_INTERFACE	= $(shell echo $(interface) | tr  '[:lower:]' '[:upper:]')
SRC_DIR 	= ../../
INC_DIR		= $(shell find $(SRC_DIR) -type d)
OBJ_DIR		= ./obj
BIN_NAME 	= ncp-ble
BIN_DIR 	= ./bin

SRC_FILES	= $(shell find $(SRC_DIR) -name *.c)
OBJ_FILES 	= $(SRC_FILES:.c=.o)

_INC_DIR 	= $(foreach dir,$(INC_DIR),$(addprefix -I, $(dir)))

CFLAGS 		= -DCONFIG_NCP_${COM_INTERFACE}
LDFLAGS 	= -lpthread -lc -lrt -lusb-1.0

$(BIN_DIR)/$(BIN_NAME): $(OBJ_FILES)
	$(CC) -o $@ $^ $(_INC_DIR) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $< $(_INC_DIR) $(LDFLAGS)

.PHONY: clean

clean:
	$(shell find $(SRC_DIR) -name *.o | xargs rm -rf)
	rm -rf $(BIN_DIR)/$(BIN_NAME)