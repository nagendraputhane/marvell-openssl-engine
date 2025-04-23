/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal.h"
#ifndef _E_PAL_RSA_H
#define _E_PAL_RSA_H
#define MBUF_TEST_SIZE 1024
#define PAL_RSA_PKCS1_PADDING 1
#define PAL_RSA_NO_PADDING 3

int pal_rsa_pub_enc(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_rsa_pub_dec(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_rsa_priv_enc(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_rsa_priv_dec(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_rsa_capability_check_modlen(int16_t modlen);
#endif //_E_PAL_DPDK_RSA_H
