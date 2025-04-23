/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal_cpoly.h"

extern int cpt_num_cipher_pipeline_requests_in_flight;
extern dpdk_pools_t *pools;

/*
 * Create AEAD Session
 */
int pal_create_cpoly_aead_session(pal_cpoly_ctx_t *pal_ctx,
					int aad_len, uint8_t reconfigure)
{
	return 1;
}

static int create_crypto_operation_pl(pal_cpoly_ctx_t *pal_ctx,
		const uint8_t *in, int len, int enc, uint8_t pipe_index)
{
	return 0;
}

/* Below API added for TLS1_2 protocol
 *
 * AAD data is alway set via control function in case of TLS1_2
 * IV is updating by XOR'ing with sequence number
 * Here, len value is comming from SSL layer is equal to
 * (PT/CT length + AUTH tag len) for both encryption/decryption.
 * @returns correct outlen on success, <0 on failure
*/

int pal_chacha20_poly1305_tls_cipher(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
		const unsigned char *in, size_t len, int sym_queue, void *wctx)
{
	return 0;
}

static int
create_crypto_operation(pal_cpoly_ctx_t *pal_ctx, const uint8_t *in, int len,
	unsigned char *buf)
{
	return 0;
}

int pal_chacha20_poly1305_non_tls_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, unsigned char *buf)
{
	return 0;
}

int pal_chacha20_poly1305_tls_1_3_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, unsigned char *buf, void *wctx)
{
	return 0;
}
