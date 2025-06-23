/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PAL_ECDSA_H_
#define __PAL_ECDSA_H_

#include "pal.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

#define PCURVES_MAX_PRIME_LEN		72 /* P521 curve */
#define PCURVES_MAX_DER_SIG_LEN		141

typedef enum pal_crypto_curve_id{
  PAL_CRYPTO_EC_GROUP_SECP192R1 = RTE_CRYPTO_EC_GROUP_SECP192R1,
  PAL_CRYPTO_EC_GROUP_SECP224R1 = RTE_CRYPTO_EC_GROUP_SECP224R1,
  PAL_CRYPTO_EC_GROUP_SECP256R1 = RTE_CRYPTO_EC_GROUP_SECP256R1,
  PAL_CRYPTO_EC_GROUP_SECP384R1 = RTE_CRYPTO_EC_GROUP_SECP384R1,
  PAL_CRYPTO_EC_GROUP_SECP521R1 = RTE_CRYPTO_EC_GROUP_SECP521R1,
}pal_crypto_curve_id_t;

typedef enum pal_crypto_asym_xform_type {
  PAL_CRYPTO_ASYM_XFORM_ECDSA = RTE_CRYPTO_ASYM_XFORM_ECDSA,
  PAL_CRYPTO_ASYM_XFORM_ECPM = RTE_CRYPTO_ASYM_XFORM_ECPM
} pal_crypto_asym_xform_type_t;

typedef struct pal_ecdsa_ctx {
  int devid;
  int queue;
  uint8_t *x_data;
  int x_data_len;
  uint8_t *y_data;
  int y_data_len;
  uint8_t *scalar_data;
  int scalar_data_len;
  void *rxbuf;
  void *rybuf;
  uint8_t *rdata;
  int rlen;
  uint8_t *sdata;
  int slen;
  char *dgst;
  int dlen;
  uint8_t *pkey;
  int pkey_len;
  uint8_t *secret;
  int secret_len;
  pal_crypto_asym_xform_type_t xform_type;
  pal_crypto_curve_id_t curve_id;
  async_job async_cb;
  uint8_t *wctx_p;
} pal_ecdsa_ctx_t;

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
