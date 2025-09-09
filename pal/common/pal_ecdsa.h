/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PAL_COMMON_ECDSA_H__
#define __PAL_COMMON_ECDSA_H__

#include "pal.h"
#include "defs.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

#define PCURVES_MAX_PRIME_LEN		72 /* P521 curve */
#define PCURVES_MAX_DER_SIG_LEN		141

int pal_ecdsa_verify(pal_ecdsa_ctx_t *pal_ctx);
int pal_ecdsa_sign(pal_ecdsa_ctx_t *pal_ctx);

int pal_ecdh_keygen(EC_KEY *key, int devid, int queue);

int pal_ecdsa_ec_point_multiplication( pal_ecdsa_ctx_t *pal_ctx);

static inline uint8_t *
bn_to_crypto_param(const BIGNUM *bn)
{
	uint8_t *data;

  data = malloc(PCURVES_MAX_PRIME_LEN);
	if (!data)
		return 0;

	memset(data, 0, PCURVES_MAX_PRIME_LEN);
	if (BN_bn2bin(bn, data) <= 0) {
		free(data);
		return NULL;
	}

	return data;
}
#endif//__PAL_ECDSA_H_
