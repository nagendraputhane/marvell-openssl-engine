/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

/**
 * @file pal_cbc.c
 * @brief PAL CBC implementation
 */

#include "pal_cbc.h"


extern int cpt_num_cipher_pipeline_requests_in_flight;
extern  dpdk_pools_t *pools;

/**
 * Function: pal_aes_cbc_cipher
 */
int pal_aes_cbc_cipher(pal_cbc_ctx_t *pal_ctx, unsigned char *out,
		const unsigned char *in, size_t inl, unsigned char *iv, int enc,
		int sym_queue, void *wctx)
{
	return 0;
}

int pal_aes_cbc_cleanup(pal_cbc_ctx_t *pal_ctx)
{
	return 1;
}

/**
 * Function: pal_aes_cbc_create_session
 * ------------------------------------
 *  Create AES CBC session
 *  ctx: pointer to the context
 *  key: pointer to the key
 *  iv: pointer to the iv
 *  enc: encrypt or decrypt
 *  key_len: length of the key
 *  returns: 1 on success, 0 on failure
 */

int pal_aes_cbc_create_session(pal_cbc_ctx_t *pal_ctx, const unsigned char *key,
				const unsigned char *iv, int enc, int key_len)
{
	return 1;
}
