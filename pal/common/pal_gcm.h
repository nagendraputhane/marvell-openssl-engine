/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PAL_COMMON_PAL_GCM_H__
#define __PAL_COMMON_PAL_GCM_H__

#include "pal.h"
#include "defs.h"

#define PAL_AEAD_DIGEST_LENGTH	  16
#define PAL_AES128_GCM_KEY_LENGTH	16
#define PAL_AES256_GCM_KEY_LENGTH	32
#define PAL_AES_CTR_IV_LENGTH	    16


#define ARMv8_AES_ctr32_encrypt_blocks aes_v8_ctr32_encrypt_blocks
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define CRYPTO_OP(c)                                                           \
	((c) ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT)

int pal_crypto_gcm_tls_1_3_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
                                        const unsigned char *in, size_t len,
                                  unsigned char *buf, void *wctx);
int pal_crypto_gcm_non_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
			     const unsigned char *in, size_t len, unsigned char *buf);
int pal_aes_gcm_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *buf,
                            void *usr_ctx, void *wctx);
int pal_create_aead_session(pal_crypto_aead_algorithm_t algo,
			       pal_gcm_ctx_t *pal_ctx, int aad_len, uint8_t reconfigure);
int pal_create_cipher_session(pal_crypto_cipher_algorithm_t algo,
				pal_gcm_ctx_t *pal_ctx, uint8_t reconfigure);
int pal_sym_session_gcm_cleanup(pal_gcm_ctx_t *pal_ctx);
#endif /* _PAL_GCM_H_ */
