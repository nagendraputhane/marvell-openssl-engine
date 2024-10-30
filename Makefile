#*******************************************************************************
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.
# 
#******************************************************************************/
#

# provide DPDK and OPENSSL INSTALL paths
ifeq ($(DPDK_INSTALL),)
$(error "Please define DPDK_INSTALL path")
endif
ifeq ($(OPENSSL_INSTALL),)
$(error "Please define OPENSSL_INSTALL path")
endif
DPDK_PC?=$(DPDK_INSTALL)/usr/local/lib/pkgconfig/

PKG_CONFIG_CMD=PKG_CONFIG_PATH=$(DPDK_PC) PKG_CONFIG_SYSROOT_DIR=$(DPDK_INSTALL) pkg-config
PC_FILE := $(DPDK_PC)/libdpdk.pc
CFLAGS = $(shell $(PKG_CONFIG_CMD) --cflags libdpdk)
CFLAGS += -I$(DPDK_INSTALL)/$(shell $(PKG_CONFIG_CMD) --variable=includedir libdpdk)
LDFLAGS_SHARED = -L$(DPDK_INSTALL)/$(shell $(PKG_CONFIG_CMD) --variable=libdir libdpdk)
LDFLAGS_SHARED += $(shell $(PKG_CONFIG_CMD) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKG_CONFIG_CMD) --static --libs libdpdk)
LDFLAGS = -L$(OPENSSL_INSTALL)/ -lcrypto

CFLAGS += -O3 -I./
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(OPENSSL_INSTALL)/include -I$(OPENSSL_INSTALL)/crypto/modes/ -I$(OPENSSL_INSTALL)/crypto/ -I$(OPENSSL_INSTALL)/crypto/evp/
CFLAGS += -DALLOW_EXPERIMENTAL_API -DPOLY1305_ASM

ifeq ($(OTX2),y)
CFLAGS += -DCRYPTO_OCTEONTX2
else ifeq ($(A80X0),y)
CFLAGS += -DCRYPTO_A80X0
else
CFLAGS += -DOSSL_PMD
endif

ifeq ($(OSSL_CONF),y)
CFLAGS += -DOSSL_CONF_INIT
endif

LIBABIVER=1

# Library names
LIB_OPENSSL_ENGINE = openssl_engine.a
LIB_PAL = pal_dpdk_crypto.a
LIB_DPDK_ENGINE = dpdk_engine.a

# All source files are stored in SRCS
SRCS_OPENSSL_ENGINE = $(wildcard openssl_engine/*.c)
SRCS_PAL = $(wildcard pal/*.c)

CC=$(CROSS)gcc
OBJS_OPENSSL_ENGINE = $(patsubst %.c,%.o,$(SRCS_OPENSSL_ENGINE))
OBJS_PAL = $(patsubst %.c,%.o,$(SRCS_PAL))

%.o: %.c $(wildcard *.h) $(wildcard pal/*.h)
	$(CC) $(CFLAGS) $(DEBUG) -fPIC -c $< -o $@

all: $(LIB_OPENSSL_ENGINE) $(LIB_PAL) dpdk_engine.so

$(LIB_OPENSSL_ENGINE): $(OBJS_OPENSSL_ENGINE)
	ar rcs $@ $^

$(LIB_PAL): $(OBJS_PAL)
	ar rcs $@ $^

dpdk_engine.so: $(LIB_OPENSSL_ENGINE) $(LIB_PAL) Makefile $(PC_FILE)
# chacha-armv8-sve.S file is present in openssl versions >= 3.1, not in 1.1.x
ifneq ("$(wildcard $(OPENSSL_INSTALL)/crypto/chacha/chacha-armv8-sve.S)","")
	$(CC) $(CFLAGS) -shared $(OBJS_OPENSSL_ENGINE) $(OBJS_PAL) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) $(OPENSSL_INSTALL)/crypto/aes/aesv8-armx.S $(OPENSSL_INSTALL)/crypto/chacha/chacha-armv8.S $(OPENSSL_INSTALL)/crypto/chacha/chacha-armv8-sve.S $(OPENSSL_INSTALL)/crypto/poly1305/poly1305.c $(OPENSSL_INSTALL)/crypto/poly1305/poly1305-armv8.S $(OPENSSL_INSTALL)/crypto/armcap.c $(OPENSSL_INSTALL)/crypto/arm64cpuid.S
else
	$(CC) $(CFLAGS) -shared $(OBJS_OPENSSL_ENGINE) $(OBJS_PAL) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) $(OPENSSL_INSTALL)/crypto/aes/aesv8-armx.S $(OPENSSL_INSTALL)/crypto/chacha/chacha-armv8.S $(OPENSSL_INSTALL)/crypto/poly1305/poly1305.c $(OPENSSL_INSTALL)/crypto/poly1305/poly1305-armv8.S $(OPENSSL_INSTALL)/crypto/armcap.c $(OPENSSL_INSTALL)/crypto/arm64cpuid.S
endif

clean:
	rm -fr $(OBJS_OPENSSL_ENGINE) $(OBJS_PAL) $(LIB_OPENSSL_ENGINE) $(LIB_PAL) dpdk_engine.so
