/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/params.h>

#include "prov.h"
#include "rsa_kmgmt.h"

static OSSL_FUNC_keymgmt_new_fn prov_rsa_newdata;
static OSSL_FUNC_keymgmt_free_fn prov_rsa_freedata;
static OSSL_FUNC_keymgmt_get_params_fn prov_rsa_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn prov_rsa_gettable_params;
static OSSL_FUNC_keymgmt_has_fn prov_rsa_has;
static OSSL_FUNC_keymgmt_import_fn prov_rsa_import;
static OSSL_FUNC_keymgmt_import_types_fn prov_rsa_import_types;
static OSSL_FUNC_keymgmt_export_fn prov_rsa_export;
static OSSL_FUNC_keymgmt_export_types_fn prov_rsa_export_types;

/* Parametaers that OpenSSL core can retrieve from our provider */
static OSSL_PARAM prov_rsa_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_END
};

/* Key parts that can be improted and exported from/to different providers */
static OSSL_PARAM prov_rsa_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
};

/**
 * Create new provider side key object to be used with other KEYMGMT and SIGNATURE functions
 *
 * @param provctx Provider context
 * @return New provider side key object or NULL on failure
 */

static void *prov_rsa_newdata(void *provctx)
{
    prov_rsa_key_data *kd;

    if (!prov_is_running())
	return NULL;

    kd = pal_malloc(sizeof(*kd));

    if (kd == NULL) {
	fprintf(stderr, "%s:%d:%s(): Memory allocation failed: "
		"rte_zmalloc returned NULL\n", __FILE__,
		__LINE__, __func__);
	return NULL;
    }

    memset(kd, 0, sizeof(*kd));

    kd->provctx = provctx;
    PROV_ATOMIC_INC(kd->refcnt);
    return kd;
}

void __prov_rsa_freedata(void *keydata)
{
    prov_rsa_key_data *kd = (prov_rsa_key_data *) keydata;

    if ((kd == NULL) || PROV_ATOMIC_DEC(kd->refcnt) > 0)
	return;

    pal_free(kd->base_ptr);
    pal_free(kd);
    return;
}

static void prov_rsa_freedata(void *keydata)
{
    /* This function can be called from other compilation units such as rsa_sig.c */
    __prov_rsa_freedata(keydata);
}

static const OSSL_PARAM *prov_rsa_gettable_params(void *provctx)
{
    return prov_rsa_params;
}

static int prov_rsa_modsz_to_security_bits(int rsa_modulus_bits)
{
    int security_bits = 0;

    if (rsa_modulus_bits > 1024)
	security_bits = 80;
    if (rsa_modulus_bits > 2048)
	security_bits = 112;
    if (rsa_modulus_bits > 3072)
	security_bits = 128;
    if (rsa_modulus_bits > 7680)
	security_bits = 192;
    if (rsa_modulus_bits > 15360)
	security_bits = 256;

    return security_bits;
}

static int prov_rsa_get_params(void *key, OSSL_PARAM params[])
{
    prov_rsa_key_data *kd = (prov_rsa_key_data *) key;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, kd->n_len * 8))
	return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
	int mod_sz = kd->n_len * 8;
	int sec_bits = prov_rsa_modsz_to_security_bits(mod_sz);

	if (!OSSL_PARAM_set_int(p, sec_bits))
	    return 0;

	fprintf(stderr,
		"%s:%d:%s(): Failed to set security bits value %d\n",
		__FILE__, __LINE__, __func__, sec_bits);
	return 1;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, kd->n_len))
	return 0;

    fprintf(stderr, "%s:%d:%s(): Unknown OSSL_PARAM key\n", __FILE__,
	    __LINE__, __func__);
    return 1;
}

static int prov_rsa_has(const void *keydata, int selection)
{
    const prov_rsa_key_data *kd = (prov_rsa_key_data *) keydata;
    int ok = 1;

    if (kd == NULL || !prov_is_running())
	return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
	ok = ok && (kd->n_data != NULL);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
	ok = ok && (kd->e_data != NULL);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
	ok = ok && (kd->d_data != NULL || kd->use_crt);

    return ok;
}

static const OSSL_PARAM *prov_rsa_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
	return prov_rsa_key_types;

    return NULL;
}

static const OSSL_PARAM *prov_rsa_import_types(int selection)
{
    return prov_rsa_imexport_types(selection);
}

static const OSSL_PARAM *prov_rsa_export_types(int selection)
{
    return prov_rsa_imexport_types(selection);
}

static int prov_rsa_fromdata(void *keydata, const OSSL_PARAM params[],
			     int include_private)
{
    const OSSL_PARAM *param_p, *param_q, *param_r, *param_dP, *param_dQ, *param_qInv;
    BIGNUM *p = NULL, *q = NULL, *dP = NULL, *dQ = NULL, *qInv = NULL;
    const OSSL_PARAM *param_n, *param_e, *param_d = NULL;
    prov_rsa_key_data *kd = (prov_rsa_key_data *) keydata;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    uint8_t *base;
    int alloc_sz;
    int ret = 0;

    param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);

    if ((param_n != NULL && !OSSL_PARAM_get_BN(param_n, &n))
	|| (param_e != NULL && !OSSL_PARAM_get_BN(param_e, &e))) {
	fprintf(stderr, "%s:%d:%s(): Failed to get RSA key parameters 'n' or 'e'\n",
		__FILE__, __LINE__, __func__);
	goto err;
    }

    alloc_sz = BN_num_bytes(n) + BN_num_bytes(e);

    if (include_private) {
	param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
	param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
	param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
	param_r = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR3);
	param_dP = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT1);
	param_dQ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT2);
	param_qInv = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);

	/* param_r is used to identify if this is a multi prime RSA */
	if (!param_r &&
	    param_p && OSSL_PARAM_get_BN(param_p, &p) &&
	    param_q && OSSL_PARAM_get_BN(param_q, &q) &&
	    param_dP && OSSL_PARAM_get_BN(param_dP, &dP) &&
	    param_dQ && OSSL_PARAM_get_BN(param_dQ, &dQ) &&
	    param_qInv && OSSL_PARAM_get_BN(param_qInv, &qInv)) {
		alloc_sz += BN_num_bytes(p) + BN_num_bytes(q) + BN_num_bytes(dP) +
			    BN_num_bytes(dQ) + BN_num_bytes(qInv);
	} else if (param_d && OSSL_PARAM_get_BN(param_d, &d)) {
		alloc_sz += BN_num_bytes(d);
	} else {
		fprintf(stderr, "%s:%d:%s(): Failed to import RSA key "
				"parameters 'd' or 'p', 'q', 'dP', 'dQ',"
				" 'qInv'\n",__FILE__, __LINE__, __func__);
		goto err;
	}

    }

    base = (uint8_t *)pal_malloc(alloc_sz);
    if (unlikely(!base)) {
	fprintf(stderr, "%s:%d:%s(): Failed to allocate memory for RSA key data\n",
		__FILE__, __LINE__, __func__);
	goto err;
    }

    kd->n_data = base;
    kd->n_len = BN_bn2bin(n, kd->n_data);

    kd->e_data = base + kd->n_len;
    kd->e_len = BN_bn2bin(e, kd->e_data);

    if (p && q && dP && dQ && qInv) {
	kd->use_crt = 1;
	kd->qt_p_data = kd->e_data + kd->e_len;
	kd->qt_p_len = BN_bn2bin(p, kd->qt_p_data);

	kd->qt_q_data = kd->qt_p_data + kd->qt_p_len;
	kd->qt_q_len = BN_bn2bin(q, kd->qt_q_data);

	kd->qt_dP_data = kd->qt_q_data + kd->qt_q_len;
	kd->qt_dP_len = BN_bn2bin(dP, kd->qt_dP_data);

	kd->qt_dQ_data = kd->qt_dP_data + kd->qt_dP_len;
	kd->qt_dQ_len = BN_bn2bin(dQ, kd->qt_dQ_data);

	kd->qt_qInv_data = kd->qt_dQ_data + kd->qt_dQ_len;
	kd->qt_qInv_len = BN_bn2bin(qInv, kd->qt_qInv_data);
    } else if (d) {
	kd->use_crt = 0;
	kd->d_data = kd->e_data + kd->e_len;
	kd->d_len = BN_bn2bin(d, kd->d_data);
    }

    kd->base_ptr = base;
    ret = 1;

  err:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dP);
    BN_free(dQ);
    BN_free(qInv);
    return ret;
}

static int prov_rsa_import(void *keydata, int selection,
			   const OSSL_PARAM params[])
{
    int ok = 1;

    if (!prov_is_running() || keydata == NULL)
	return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
	int include_private =
	    selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

	ok = ok && prov_rsa_fromdata(keydata, params, include_private);
    }

    return ok;
}

static int prov_rsa_export(void *keydata, int selection,
			   OSSL_CALLBACK * param_callback, void *cbarg)
{
    (void) keydata;
    (void) selection;
    (void) param_callback;
    (void) cbarg;

    fprintf(stderr,
	    "%s:%d:%s(): Key data export function not implemented\n",
	    __FILE__, __LINE__, __func__);
    return 0;
}

const OSSL_DISPATCH prov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) prov_rsa_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) prov_rsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) prov_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
     (void (*)(void)) prov_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) prov_rsa_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) prov_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
     (void (*)(void)) prov_rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) prov_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
     (void (*)(void)) prov_rsa_export_types },
    { 0, NULL }
};
