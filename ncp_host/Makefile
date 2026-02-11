# /*
# * Copyright 2022-2024 NXP
# * All rights reserved.
# *
# * SPDX-License-Identifier: BSD-3-Clause
# */

# ==================== Configuration ====================
# Parallel build configuration
NPROC := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
JOBS ?= $(NPROC)

# Enable parallel builds with output synchronization
ifeq ($(findstring j,$(MAKEFLAGS)),)
    MAKEFLAGS += -j$(JOBS)
endif
MAKEFLAGS += --output-sync=target

# Show parallel build info
$(info [INFO] Parallel build enabled with $(JOBS) jobs)

# Default values
func ?= WIFI
interface ?= UART
DEBUG ?= 1
NCP_DEBUG ?= 0
NCP_ENCRYPT ?= 1

# ==================== Build Output Control ====================
# Better output formatting for parallel builds
ifeq ($(VERBOSE),1)
    Q :=
    QUIET :=
else
    Q := @
    QUIET := --quiet
endif

# Toolchain
CC := gcc
AR := ar
STRIP := strip

# Project structure
SRC_DIR := src
DRV_DIR := drivers/gpio
OBJ_DIR := build
BIN_DIR := bin
DEP_DIR := $(OBJ_DIR)/.deps

# Binary name
BIN_NAME := MPU_NCP_HOST
TARGET := $(BIN_DIR)/$(BIN_NAME)

# ==================== Feature Configuration ====================
# Define feature sets for different functions
FEATURES := 

ifeq ($(func), WIFI)
    FEATURES += WIFI
else ifeq ($(func), BLE)
    FEATURES += BLE
else ifeq ($(func), OT)
    FEATURES += OT
else ifeq ($(func), WIFI_BLE)
    FEATURES += WIFI BLE
else ifeq ($(func), WIFI_OT)
    FEATURES += WIFI OT
else ifeq ($(func), BLE_OT)
    FEATURES += BLE OT
else ifeq ($(func), WIFI_BLE_OT)
    FEATURES += WIFI BLE OT
endif

# BLE Profiles
BLE_PROFILES := HTS HTC HRS HRC BAS

# ==================== Compiler Flags ====================
CFLAGS := -Wall -std=gnu99 -g
CFLAGS += -MMD -MP  # Auto dependency generation
CFLAGS += -DCONFIG_NCP_$(func)=1
CFLAGS += -DCONFIG_NCP_$(interface)
CFLAGS += -DCONFIG_NCP_DEBUG=$(NCP_DEBUG)
CFLAGS += -DCONFIG_NCP_USE_ENCRYPT=$(NCP_ENCRYPT)

# Add feature flags
$(foreach feature,$(FEATURES),$(eval CFLAGS += -DCONFIG_NCP_$(feature)))

# Add BLE profile flags if enabled
ifeq ($(findstring BLE,$(FEATURES)),BLE)
    $(foreach profile,$(BLE_PROFILES),\
        $(if $($(profile)),$(eval CFLAGS += -DCONFIG_NCP_$(profile))))
endif

# Optimization flags based on DEBUG
ifeq ($(DEBUG), 0)
    CFLAGS += -O2 -DNDEBUG
else
    CFLAGS += -O0 -g3 -DDEBUG
endif

# ==================== Libraries and Includes ====================
LDFLAGS := -lpthread -lc -lrt

# USB support
ifeq ($(interface), USB)
    LDFLAGS += -I/usr/local/include/libusb-1.0 -L/usr/local/lib -lusb-1.0
endif

# Include directories
INC_DIRS := $(shell find $(SRC_DIR) -type d) \
            $(shell find $(DRV_DIR) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

# ==================== Source Files ====================
# Find all source files
SRC_FILES := $(shell find $(SRC_DIR) -name '*.c') \
             $(shell find $(DRV_DIR) -name '*.c')

# Generate object file names
OBJ_FILES := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES))
DEP_FILES := $(patsubst %.c,$(DEP_DIR)/%.d,$(SRC_FILES))

# ==================== Build Rules ====================
.PHONY: all clean install debug release help

# Default target
all: $(TARGET)

# Main target
$(TARGET): $(OBJ_FILES) | $(BIN_DIR)
	$(Q)echo "[LD] Linking $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	$(Q)echo "[OK] Build complete: $(notdir $@)"
	$(Q)size $@

# Pattern rule for object files
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR) $(DEP_DIR)
	@mkdir -p $(dir $@)
	@mkdir -p $(dir $(DEP_DIR)/$*.d)
	$(Q)echo "[CC] $(notdir $<)"
	$(Q)$(CC) $(CFLAGS) $(INC_FLAGS) -MF $(DEP_DIR)/$*.d -c $< -o $@


# Create directories
$(BIN_DIR) $(OBJ_DIR) $(DEP_DIR):
	@mkdir -p $@

# ==================== Utility Targets ====================
# Clean build artifacts
clean:
	@echo "[CLEAN] Removing build artifacts..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

# Deep clean (includes dependency files)
distclean: clean
	@echo "[DISTCLEAN] Removing all generated files..."
	@find . -name "*.o" -delete
	@find . -name "*.d" -delete

# Install target
install: $(TARGET)
	@echo "[INSTALL] Installing to /usr/local/bin..."
	@install -D -m 755 $(TARGET) /usr/local/bin/$(BIN_NAME)

# Debug build
debug:
	@$(MAKE) DEBUG=1

# Release build (with optimization and stripping)
release: CFLAGS += -O3
release: $(TARGET)
	@echo "[STRIP] Stripping debug symbols..."
	@$(STRIP) $(TARGET)

# Print configuration
info:
	@echo "=== Build Configuration ==="
	@echo "Function:  $(func)"
	@echo "Interface: $(interface)"
	@echo "Features:  $(FEATURES)"
	@echo "Debug build:   $(DEBUG)"
	@echo "NCP debug:     $(NCP_DEBUG)"
	@echo "NCP encrypt:   $(NCP_ENCRYPT)"
	@echo "Target:    $(TARGET)"
	@echo "=========================="

# Help target
help:
	@echo "NCP Host Application Build System"
	@echo "================================="
	@echo ""
	@echo "Usage: make [target] [options]"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the application (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  distclean - Remove all generated files"
	@echo "  install   - Install the application"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build optimized release version"
	@echo "  info      - Show build configuration"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  func=<FUNCTION>      - WIFI, BLE, OT, WIFI_BLE, WIFI_OT, BLE_OT, WIFI_BLE_OT"
	@echo "  interface=<IFACE>    - USB, UART, SDIO, SPI"
	@echo "  DEBUG=<0|1>          - Enable debug mode (default: 0)"
	@echo "  NCP_DEBUG=<0|1>      - Enable NCP debug logs (default: 0)"
	@echo "  NCP_ENCRYPT=<0|1>    - Enable NCP encryption (default: 1)"
	@echo ""
	@echo "BLE Profile Options (when func includes BLE):"
	@echo "  HTS=y     - Enable HTS profile"
	@echo "  HTC=y     - Enable HTC profile"
	@echo "  HRS=y     - Enable HRS profile"
	@echo "  HRC=y     - Enable HRC profile"
	@echo "  BAS=y     - Enable BAS profile"
	@echo ""
	@echo "Examples:"
	@echo "  make func=WIFI interface=USB"
	@echo "  make func=BLE interface=UART HTS=y"
	@echo "  make func=WIFI_BLE interface=SDIO DEBUG=1"

# Include dependency files
-include $(DEP_FILES)

# Enable parallel build by default
.PHONY: parallel
parallel:
	@$(MAKE) -j$(shell nproc) all
