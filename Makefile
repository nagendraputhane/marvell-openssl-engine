#*******************************************************************************
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.
#
#******************************************************************************/

# Provide DPDK and OPENSSL INSTALL paths
ifeq ($(DPDK_INSTALL),)
$(error "Please define DPDK_INSTALL path")
endif
ifeq ($(OPENSSL_INSTALL),)
$(error "Please define OPENSSL_INSTALL path")
endif

BUILD_TYPE ?= cross
PAL ?= dpdk

ifeq ($(PAL),lc)
ifeq ($(DAO_LC_INSTALL),)
$(error "Please define DAO_LC_INSTALL path")
endif
endif

ifneq ($(PAL),lc)
DPDK_PC?=$(DPDK_INSTALL)/usr/local/lib/pkgconfig/
else
DPDK_PC?=$(firstword $(wildcard $(DPDK_INSTALL)/lib64/pkgconfig) \
		 $(wildcard $(DPDK_INSTALL)/lib/x86_64-linux-gnu/pkgconfig))
endif

ifeq ($(BUILD_TYPE),native)
PKG_CONFIG_CMD=PKG_CONFIG_PATH=$(DPDK_PC) pkg-config
else
PKG_CONFIG_CMD=PKG_CONFIG_PATH=$(DPDK_PC) PKG_CONFIG_SYSROOT_DIR=$(DPDK_INSTALL) pkg-config
endif
PC_FILE := $(DPDK_PC)/libdpdk.pc

CFLAGS = $(shell $(PKG_CONFIG_CMD) --cflags libdpdk)
CFLAGS += -I$(DPDK_INSTALL)/include
CFLAGS += -I$(DPDK_INSTALL)/$(shell $(PKG_CONFIG_CMD) --variable=includedir libdpdk)
CFLAGS += -I$(DAO_LC_INSTALL)/../lib/liquid_crypto
CFLAGS += -DOSSL_CONF_INIT

LDFLAGS_SHARED = -L$(DPDK_INSTALL)/$(shell $(PKG_CONFIG_CMD) --variable=libdir libdpdk)
LDFLAGS_SHARED += $(shell $(PKG_CONFIG_CMD) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKG_CONFIG_CMD) --static --libs libdpdk)
LDFLAGS = -L$(OPENSSL_INSTALL)/ -lcrypto
ifeq ($(PAL),lc)
LDFLAGS += -L$(DAO_LC_INSTALL)/lib/  -ldao_liquid_crypto
endif


CFLAGS += -g -O2  -I./openssl_provider -I./pal/common
ifeq ($(PAL),lc)
CFLAGS +=  -I./pal/liquid_crypto
else
CFLAGS +=  -I./pal/dpdk
endif
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(OPENSSL_INSTALL)/include -I$(OPENSSL_INSTALL)/crypto/modes/ -I$(OPENSSL_INSTALL)/crypto/ -I$(OPENSSL_INSTALL)/crypto/evp/
CFLAGS += -I$(OPENSSL_INSTALL)/include -I$(OPENSSL_INSTALL)/providers/common/include -I$(OPENSSL_INSTALL)/providers/implementations/include

OTX2 ?= y
ifeq ($(OTX2),y)
CFLAGS += -DCRYPTO_OCTEONTX2
else ifeq ($(A80X0),y)
CFLAGS += -DCRYPTO_A80X0
else
CFLAGS += -DOSSL_PMD
endif

CFLAGS += -D_FORTIFY_SOURCE=1
LIBABIVER=1

# Library names
LIB_OPENSSL_PROVIDER = dpdk_provider.a
LIB_PAL = pal_dpdk_crypto.a

# All source files are stored in SRCS
SRCS_OPENSSL_PROVIDER = $(wildcard openssl_provider/*.c)
SRCS_OPENSSL_ENGINE = $(wildcard openssl_engine/*.c)
SRCS_PAL_LC = $(wildcard pal/liquid_crypto/*.c)
SRCS_PAL_DPDK = $(wildcard pal/dpdk/*.c)

CROSS ?=
CC=$(CROSS)gcc
OBJS_PAL_LC = $(patsubst %.c,%.o,$(SRCS_PAL_LC))
OBJS_PAL_DPDK = $(patsubst %.c,%.o,$(SRCS_PAL_DPDK))
OBJS_OPENSSL_PROVIDER = $(patsubst %.c,%.o,$(SRCS_OPENSSL_PROVIDER))
OBJS_OPENSSL_ENGINE = $(patsubst %.c,%.o,$(SRCS_OPENSSL_ENGINE))

# Needed to call TLS related functions for pad/unpad
# These are moved from libssl into libcommon as default provider also needs them.
OBJS_OPENSSL_PROVIDER += $(OPENSSL_INSTALL)/providers/libcommon.a


%.o: %.c $(wildcard *.h) $(wildcard pal/common/*.h) $(wildcard pal/liquid_crypto/*.h) $(wildcard pal/dpdk/*.h)
	$(CC) $(CFLAGS) $(DEBUG) -fPIC -c $< -o $@

all: build_targets

VERSION_FILE := $(OPENSSL_INSTALL)/VERSION.dat
ifeq ($(wildcard $(VERSION_FILE)),)
	MAJOR := 1
else
	MAJOR := $(shell grep '^MAJOR=' $(VERSION_FILE) | cut -d= -f2)
endif
BUILD_TYPE ?= cross
PAL ?= dpdk
BUILD_ENGINE ?=
BUILD_PROVIDER ?=

build_targets:
ifeq ($(shell [ $(MAJOR) -ge 3 ] && echo yes),yes)

ifeq ($(BUILD_TYPE),native)

ifeq ($(PAL),lc)
ifeq ($(BUILD_ENGINE)$(BUILD_PROVIDER),)
	@echo "Building lc_engine.so and lc_provider.so"
	$(MAKE) lc_engine.so lc_provider.so
else
ifeq ($(BUILD_ENGINE),y)
	$(MAKE) lc_engine.so
endif
ifeq ($(BUILD_PROVIDER),y)
	$(MAKE) lc_provider.so
endif
endif

else ifeq ($(PAL),dpdk)
ifeq ($(BUILD_ENGINE)$(BUILD_PROVIDER),)
	@echo "Building dpdk_engine.so and dpdk_provider.so"
	$(MAKE) dpdk_engine.so dpdk_provider.so
else
ifeq ($(BUILD_ENGINE),y)
	$(MAKE) dpdk_engine.so
endif
ifeq ($(BUILD_PROVIDER),y)
	$(MAKE) dpdk_provider.so
endif
endif

else
	@echo "PAL not specified; building dpdk engine"
	$(MAKE) dpdk_engine.so
endif

else ifeq ($(BUILD_TYPE),cross)

ifeq ($(PAL),lc)
	$(error Cross-compiling not supported for lc)

else ifeq ($(PAL),dpdk)
ifeq ($(BUILD_ENGINE)$(BUILD_PROVIDER),)
	@echo "Cross-compiling dpdk_engine.so and dpdk_provider.so"
	$(MAKE) dpdk_engine.so dpdk_provider.so
else
ifeq ($(BUILD_ENGINE),y)
	$(MAKE) dpdk_engine.so
endif
ifeq ($(BUILD_PROVIDER),y)
	$(MAKE) dpdk_provider.so
endif
endif

else
	@echo "Unknown or missing PAL during cross-compilation"
endif

else
	$(error Unknown build type: $(BUILD_TYPE))
endif

else  # OpenSSL version < 3
ifeq ($(BUILD_TYPE),native)
ifeq ($(PAL),lc)
ifeq ($(BUILD_PROVIDER),y)
	$(error Provider not supported for OpenSSL < 3)
else
	$(MAKE) lc_engine.so
endif
else ifeq ($(PAL),dpdk)
ifeq ($(BUILD_PROVIDER),y)
	$(error Provider not supported for OpenSSL < 3)
else
	$(MAKE) dpdk_engine.so
endif

endif
else ifeq ($(BUILD_TYPE),cross)
ifeq ($(PAL),lc)
	$(error Cross-compiling not supported for lc)
else ifeq ($(PAL),dpdk)
ifeq ($(BUILD_PROVIDER),y)
	$(error Provider not supported for OpenSSL < 3)
else
	$(MAKE) dpdk_engine.so
endif
else
	$(error Unknown or missing PAL during cross-compilation)
endif
else
	$(error Unknown build type: $(BUILD_TYPE))
endif
endif

lc_provider.so: $(OBJS_OPENSSL_PROVIDER) $(OBJS_PAL_LC) Makefile $(PC_FILE)
	$(CC) $(CFLAGS) -shared $(OBJS_OPENSSL_PROVIDER) $(OBJS_PAL_LC) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

dpdk_provider.so: $(OBJS_OPENSSL_PROVIDER) $(OBJS_PAL_DPDK) Makefile $(PC_FILE)
	$(CC) $(CFLAGS) -shared $(OBJS_OPENSSL_PROVIDER) $(OBJS_PAL_DPDK) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

dpdk_engine.so: $(OBJS_OPENSSL_ENGINE) $(OBJS_PAL_DPDK) Makefile $(PC_FILE)
# chacha-armv8-sve.S file is present in openssl versions >= 3.1, not in 1.1.x
ifeq ($(shell [ $(MAJOR) -ge 3 ] && echo yes),yes)
	$(CC) $(CFLAGS) -shared $(OBJS_OPENSSL_ENGINE) $(OBJS_PAL_DPDK) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) $(OPENSSL_INSTALL)/crypto/aes/aesv8-armx.S $(OPENSSL_INSTALL)/crypto/chacha/chacha-armv8.S $(OPENSSL_INSTALL)/crypto/chacha/chacha-armv8-sve.S $(OPENSSL_INSTALL)/crypto/poly1305/poly1305.c $(OPENSSL_INSTALL)/crypto/poly1305/poly1305-armv8.S $(OPENSSL_INSTALL)/crypto/armcap.c $(OPENSSL_INSTALL)/crypto/arm64cpuid.S
else
	$(CC) $(CFLAGS) -shared $(OBJS_OPENSSL_ENGINE) $(OBJS_PAL_DPDK) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) $(OPENSSL_INSTALL)/crypto/aes/aesv8-armx.S $(OPENSSL_INSTALL)/crypto/chacha/chacha-armv8.S $(OPENSSL_INSTALL)/crypto/poly1305/poly1305.c $(OPENSSL_INSTALL)/crypto/poly1305/poly1305-armv8.S $(OPENSSL_INSTALL)/crypto/armcap.c $(OPENSSL_INSTALL)/crypto/arm64cpuid.S
endif

clean:
	rm -fr *.a pal/dpdk/*.o pal/liquid_crypto/*.o  openssl_provider/*.o  openssl_engine/*.o  lc_provider.so dpdk_provider.so dpdk_engine.so

