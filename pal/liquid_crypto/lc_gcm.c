/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <pal_gcm.h>

extern int cpt_num_cipher_pipeline_requests_in_flight;

/*
 * Create AEAD Session
 */
int pal_create_aead_session(pal_crypto_aead_algorithm_t algo,
					pal_gcm_ctx_t *pal_ctx, int aad_len,
					uint8_t reconfigure)
{
 return 0;
}

/*
 * Create CIPHER Session for Crypto operation only
 */
int pal_create_cipher_session( pal_crypto_cipher_algorithm_t algo,
								pal_gcm_ctx_t *pal_ctx)
{
	return 0;
}

static int create_crypto_operation_pl(pal_gcm_ctx_t *pal_ctx,
		const uint8_t *in, int len, uint8_t pipe_index)
{

	return 0;
}

/* Below API added for TLS1_2 protocol
 *
 * AAD data is alway set via control function in case of TLS1_2
 * IV is updating by XOR'ing with sequence number
 * Here, len value is comming from SSL layer is equal to
 * (PT/CT length + AUTH tag len) for both encryption/decryption.
 *
 * Return: correct outlen on success, <0 on failure
 */
int pal_aes_gcm_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *buf,
							void *usr_ctx, void *wctx)
{
return 0;
}

/*
 * Common crypto operation for both TLS and Crypto case
 */
static int create_crypto_operation(pal_gcm_ctx_t *pal_ctx,
					const uint8_t *in, int len, unsigned char *buf)
{
	return 0;
}

/*
 *Pure crypto application (Cipher case only)
 */
static int crypto_ctr_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
				const unsigned char *in, size_t len, unsigned char *buf)
{
	return 0;
}

/*
 * Normal crypto application
 */
int pal_crypto_gcm_non_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
					const unsigned char *in, size_t len,
					unsigned char *buf)
{
return 0;
}

int pal_crypto_gcm_tls_1_3_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
								const unsigned char *in, size_t len,
								unsigned char *buf, void *wctx)
{
	return 0;
}

int pal_sym_session_gcm_cleanup(pal_gcm_ctx_t *pal_ctx)
{
	return 1;
}
