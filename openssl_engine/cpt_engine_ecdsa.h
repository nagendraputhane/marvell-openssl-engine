/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _CPT_ENGINE_ECDSA_H_
#define _CPT_ENGINE_ECDSA_H_

#include <openssl/bn.h>
#include <openssl/ec.h>

#define PCURVES_MAX_PRIME_LEN		72 /* P521 curve */
#define PCURVES_MAX_DER_SIG_LEN		141

int ecdsa_sign(int type, const unsigned char *dgst, int dlen,
	       unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
	       const BIGNUM *r, EC_KEY *eckey);

int ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
		 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

int ecdh_keygen(EC_KEY *key);

int ecdh_compute_key(unsigned char **psec, size_t *pseclen,
		      const EC_POINT *pub_key, const EC_KEY *ecdh);
#endif //_CPT_ENGINE_ECDSA_H_
