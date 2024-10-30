/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __CPT_ENGINE_CBC_H__
#define __CPT_ENGINE_CBC_H__
#include "cpt_engine.h"
#include "pal/pal_cbc.h"
#define ARMv8_AES_cbc_encrypt aes_v8_cbc_encrypt

typedef struct ossl_cbc_ctx {
	union {
		double align;
		AES_KEY ks;
	} ks;
	block128_f block;
	union {
		cbc128_f cbc;
		ctr128_f ctr;
	} stream;
  pal_cbc_ctx_t pal_ctx;
}ossl_cbc_ctx_t;

void ARMv8_AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
			   size_t length, const AES_KEY *key,
			   unsigned char *ivec, const int enc);
#endif //__CPT_ENGINE_CBC_H__
