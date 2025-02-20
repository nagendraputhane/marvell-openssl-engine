/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#ifndef _CPT_ENGINE_CPOLY_H
#define _CPT_ENGINE_CPOLY_H

#include "pal/pal_cpoly.h"

typedef struct {
	union {
		double align;   /* this ensures even sizeof(EVP_CHACHA_KEY)%8==0 */
		unsigned int d[CHACHA_KEY_SIZE / 4];
	} key;
	unsigned int  counter[CHACHA_CTR_SIZE / 4];
	unsigned char buf[CHACHA_BLK_SIZE];
	unsigned int  partial_len;
} EVP_CHACHA_KEY;

typedef struct {
	EVP_CHACHA_KEY key;
	unsigned int nonce[12/4];
	unsigned char tag[POLY1305_BLOCK_SIZE];
	unsigned char tls_aad[POLY1305_BLOCK_SIZE];
	struct { uint64_t aad, text; } len;
	int aad, mac_inited, tag_len, nonce_len;
	size_t tls_payload_length;
} EVP_CHACHA_AEAD_CTX;

typedef struct ossl_cpoly_ctx {
	EVP_CHACHA_AEAD_CTX *actx;
  pal_cpoly_ctx_t pal_ctx;
  uint8_t is_tlsv_1_3;
}ossl_cpoly_ctx_t;

#endif /* _CPT_ENGINE_CPOLY_H */
