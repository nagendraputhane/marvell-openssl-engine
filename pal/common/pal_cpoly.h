/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#ifndef __PAL_COMMON_CPOLY_H__
#define __PAL_COMMON_CPOLY_H__

#include "pal.h"
#include "defs.h"
#include <crypto/poly1305.h>
#include <crypto/chacha.h>

#define CPOLY_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
					| EVP_CIPH_FLAG_CUSTOM_CIPHER \
					| EVP_CIPH_ALWAYS_CALL_INIT \
					| EVP_CIPH_CTRL_INIT \
					| EVP_CIPH_CUSTOM_COPY \
					| EVP_CIPH_FLAG_AEAD_CIPHER \
					| EVP_CIPH_FLAG_PIPELINE)



int pal_create_cpoly_aead_session(pal_cpoly_ctx_t *pal_ctx,
        int aad_len, uint8_t reconfigure);
int pal_chacha20_poly1305_tls_cipher(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
        const unsigned char *in, size_t len, int sym_queue, void *wctx);
int pal_chacha20_poly1305_non_tls_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
        const unsigned char *in, size_t len, int sym_queue, unsigned char *buf);
int pal_chacha20_poly1305_tls_1_3_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
        const unsigned char *in, size_t len, int sym_queue, unsigned char *buf, void *wctx);
int pal_sym_session_cpoly_cleanup(pal_cpoly_ctx_t *pal_ctx);
#endif
