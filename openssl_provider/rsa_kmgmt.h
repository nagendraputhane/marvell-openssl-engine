/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __RSA_KMGMT_H__
#define __RSA_KMGMT_H__
#include <openssl/bn.h> // For BIGNUM(bn)
#include <openssl/rsa.h> // For RSA
#include "pal_rsa.h"

#define PROV_RSA_PSS_MAX_NAME 50

typedef struct {
    int hash_algorithm_nid;
    struct {
        int algorithm_nid;       /* Currently always NID_mgf1 */
        int hash_algorithm_nid;
    } mask_gen;
    int salt_len;
    int trailer_field;
} prov_rsa_pss_params;

/*  Our provider side key object data type */
typedef struct {
    uint8_t *n_data;
    int n_len;
    uint8_t *d_data;
    int d_len;
    uint8_t *e_data;
    int e_len;
    uint8_t *qt_p_data;
    int qt_p_len;
    uint8_t *qt_q_data;
    int qt_q_len;
    uint8_t *qt_dP_data;
    int qt_dP_len;
    uint8_t *qt_dQ_data;
    int qt_dQ_len;
    uint8_t *qt_qInv_data;
    int qt_qInv_len;
    void *base_ptr; // Base pointer to free the memory allocated for xform members
    void *provctx;
    int use_crt;
    int refcnt;
    prov_rsa_pss_params pss;
    RSA *rsa; /* For HW-unsupported keys, store as RSA struct for SW fallback */
} prov_rsa_key_data;

void __prov_rsa_freedata(void *keydata);

/* Get modulus length in bytes from either RSA struct or raw data */
static inline int
prov_rsa_key_len(prov_rsa_key_data *keydata)
{
	if (unlikely(keydata->rsa != NULL)) {
		const BIGNUM *n = NULL;
		RSA_get0_key(keydata->rsa, &n, NULL, NULL);
		return n ? BN_num_bytes(n) : 0;
	}
	return keydata->n_len;
}

/* Check if hardware supports the key's modulus length (returns non-zero if HW unsupported) */
static inline int
prov_rsa_check_modlen(prov_rsa_key_data *key)
{
	int16_t modlen = prov_rsa_key_len(key);
	return pal_rsa_capability_check_modlen(modlen);
}
#endif
