/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#ifndef _CPT_ENGINE_GCM_H_
#define _CPT_ENGINE_GCM_H_
#include "pal/pal_gcm.h"
#include "cpt_engine.h"

typedef struct ossl_gcm_ctx
{
	union {
		double align;
		AES_KEY ks;
	} ks;
	GCM128_CONTEXT gcm;
	ctr128_f ctr;
	uint8_t key_set:1;
	uint8_t iv_set:1;
	uint8_t iv_gen:1;
	int taglen;
  pal_gcm_ctx_t pal_ctx;
} ossl_gcm_ctx_t;

void ARMv8_AES_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
		size_t len, const AES_KEY *key, const unsigned char ivec[16]);

#endif //_CPT_ENGINE_GCM_H_
