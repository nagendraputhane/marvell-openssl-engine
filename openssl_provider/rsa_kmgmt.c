/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <string.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/rsa.h> // for software key gen

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
static OSSL_FUNC_keymgmt_gen_init_fn rsa_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn rsa_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn rsa_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn rsapss_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn rsa_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn rsa_gen_cleanup;

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

#define PROV_RSA_DEFAULT_PRIME_NUM    2
#define PROV_RSA_DEFAULT_KEY_BITS     2048
#define PROV_PUB_EXP_DEFAULT    0x10001
#define PROV_FLAG_TYPE_RSA   0x0000
#define PROV_RSA_MIN_MODULUS_BITS    512
#define PROV_FLAG_TYPE_MASK    0xF000

/* Key gen */
struct rsa_gen_ctx {
    OSSL_LIB_CTX *libctx;
    const char *propq;

    int rsa_type;

    size_t nbits;
    BIGNUM *pub_exp;
    size_t primes;
    /* For generation callback */
    OSSL_CALLBACK *cb;
    void *cbarg;
};

static inline RSA *prov_rsa_new_intern(OSSL_LIB_CTX *libctx)
{
    RSA *ret = RSA_new();
    if (ret == NULL)
        return NULL;
    return ret;
}

static int rsa_gencb(int p, int n, BN_GENCB *cb)
{
    struct rsa_gen_ctx *gctx = BN_GENCB_get_arg(cb);
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);
    return gctx->cb(params, gctx->cbarg);
}

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

    /* Refcount reached 0, free resources */
    if (unlikely(kd->rsa != NULL)) {
        /* Free RSA struct (owned by keydata) */
        RSA_free(kd->rsa);
    } else {
        /* Free raw data if no RSA struct */
        pal_free(kd->base_ptr);
    }

    /* Free the keydata structure itself */
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
    if (p != NULL && !OSSL_PARAM_set_int(p, prov_rsa_key_len(kd) * 8))
	return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
	int mod_sz = prov_rsa_key_len(kd) * 8;
	int sec_bits = prov_rsa_modsz_to_security_bits(mod_sz);

	if (!OSSL_PARAM_set_int(p, sec_bits))
	    return 0;

	engine_log(ENG_LOG_INFO,
		"%s:%d:%s(): Failed to set security bits value %d\n",
		__FILE__, __LINE__, __func__, sec_bits);
	return 1;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, prov_rsa_key_len(kd)))
	return 0;

    engine_log(ENG_LOG_INFO, "%s:%d:%s(): Unknown OSSL_PARAM key\n", __FILE__,
	    __LINE__, __func__);
    return 1;
}

static int prov_rsa_has(const void *keydata, int selection)
{
    const prov_rsa_key_data *kd = (prov_rsa_key_data *) keydata;
    int ok = 1;

    if (kd == NULL || !prov_is_running())
	return 0;

    if (unlikely(kd->rsa != NULL)) {
        const BIGNUM *n = NULL, *e = NULL, *d = NULL;
        RSA_get0_key(kd->rsa, &n, &e, &d);

        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
            ok = ok && (n != NULL);

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (e != NULL);

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (d != NULL);
    } else {
        /* Key stored as raw data */
        if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
            ok = ok && (kd->n_data != NULL);

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (kd->e_data != NULL);

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (kd->d_data != NULL || kd->use_crt);
    }

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
    uint8_t *base = NULL;
    int alloc_sz;
    int ret = 0;
    int modulus_bytes = 0;
    RSA *rsa = NULL;

    param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);

    if ((param_n != NULL && !OSSL_PARAM_get_BN(param_n, &n))
	|| (param_e != NULL && !OSSL_PARAM_get_BN(param_e, &e))) {
	fprintf(stderr, "%s:%d:%s(): Failed to get RSA key parameters 'n' or 'e'\n",
		__FILE__, __LINE__, __func__);
	goto err;
    }

    modulus_bytes = BN_num_bytes(n);

    /* Locate private key parameters once if needed */
    if (include_private) {
	param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
	param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
	param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
	param_r = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR3);
	param_dP = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT1);
	param_dQ = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT2);
	param_qInv = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
    }

    /* Check if hardware supports this modulus length */
    if (pal_rsa_capability_check_modlen(modulus_bytes)) {
        /* Hardware doesn't support this key size, store as RSA struct for SW fallback */
        rsa = RSA_new();
        if (!rsa)
            goto err;

        /* Set public key components */
        if (!RSA_set0_key(rsa, n, e, NULL)) {
            RSA_free(rsa);
            goto err;
        }
        /* Ownership transferred, set to NULL */
        n = NULL;
        e = NULL;

        if (include_private) {
            if (param_d && OSSL_PARAM_get_BN(param_d, &d)) {
                if (!RSA_set0_key(rsa, NULL, NULL, d)) {
                    RSA_free(rsa);
                    goto err;
                }
                d = NULL;
            }

            if (param_p && OSSL_PARAM_get_BN(param_p, &p) &&
                param_q && OSSL_PARAM_get_BN(param_q, &q)) {
                if (!RSA_set0_factors(rsa, p, q)) {
                    RSA_free(rsa);
                    goto err;
                }
                p = NULL;
                q = NULL;
            }

            if (param_dP && OSSL_PARAM_get_BN(param_dP, &dP) &&
                param_dQ && OSSL_PARAM_get_BN(param_dQ, &dQ) &&
                param_qInv && OSSL_PARAM_get_BN(param_qInv, &qInv)) {
                if (!RSA_set0_crt_params(rsa, dP, dQ, qInv)) {
                    RSA_free(rsa);
                    goto err;
                }
                dP = NULL;
                dQ = NULL;
                qInv = NULL;
            }
        }

        /* Store only the RSA struct, no raw data fields */
        kd->rsa = rsa;
        ret = 1;
        goto cleanup;
    }

    /* Normal path for hardware-supported keys: convert to raw data format */
    alloc_sz = BN_num_bytes(n) + BN_num_bytes(e);

    if (include_private) {
	/* param_r is used to identify if this is a multi prime RSA */
	if (!param_r &&
	    param_p && OSSL_PARAM_get_BN(param_p, &p) &&
	    param_q && OSSL_PARAM_get_BN(param_q, &q) &&
	    param_dP && OSSL_PARAM_get_BN(param_dP, &dP) &&
	    param_dQ && OSSL_PARAM_get_BN(param_dQ, &dQ) &&
	    param_qInv && OSSL_PARAM_get_BN(param_qInv, &qInv)) {
		alloc_sz += BN_num_bytes(p) + BN_num_bytes(q) + BN_num_bytes(dP) +
			    BN_num_bytes(dQ) + BN_num_bytes(qInv);
	} else {
        if (param_d && OSSL_PARAM_get_BN(param_d, &d)) {
		    alloc_sz += BN_num_bytes(d);
	        }
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
    goto cleanup;

  err:
    if (base)
        pal_free(base);
    /* Free RSA struct if allocated but not stored in keydata */
    if (unlikely(rsa != NULL && kd->rsa != rsa))
        RSA_free(rsa);
    ret = 0;

  cleanup:
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
    prov_rsa_key_data *kd = (prov_rsa_key_data *)keydata;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL;
    BIGNUM *bn_p = NULL, *bn_q = NULL;
    BIGNUM *bn_dP = NULL, *bn_dQ = NULL, *bn_qInv = NULL;
    const BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
    const BIGNUM *rsa_p = NULL, *rsa_q = NULL;
    const BIGNUM *rsa_dP = NULL, *rsa_dQ = NULL, *rsa_qInv = NULL;
    int ok = 0;

    if (kd == NULL || !prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    /* Handle keys stored as RSA struct (for unsupported key sizes) */
    if (unlikely(kd->rsa != NULL)) {
        RSA_get0_key(kd->rsa, &rsa_n, &rsa_e, &rsa_d);

        /* Export public key */
        if (rsa_n && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, rsa_n))
            goto err;
        if (rsa_e && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, rsa_e))
            goto err;

        /* Export private key if requested */
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (rsa_d && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, rsa_d))
                goto err;

            RSA_get0_factors(kd->rsa, &rsa_p, &rsa_q);
            RSA_get0_crt_params(kd->rsa, &rsa_dP, &rsa_dQ, &rsa_qInv);

            if (rsa_p && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR1, rsa_p))
                goto err;
            if (rsa_q && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR2, rsa_q))
                goto err;
            if (rsa_dP && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT1, rsa_dP))
                goto err;
            if (rsa_dQ && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT2, rsa_dQ))
                goto err;
            if (rsa_qInv && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, rsa_qInv))
                goto err;
        }
    } else {
        /* Handle keys stored as raw data (normal hardware-supported keys) */
        if (kd->n_data && kd->n_len > 0) {
            bn_n = BN_bin2bn(kd->n_data, kd->n_len, NULL);
            if (bn_n == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, bn_n))
                goto err;
        }

        if (kd->e_data && kd->e_len > 0) {
            bn_e = BN_bin2bn(kd->e_data, kd->e_len, NULL);
            if (bn_e == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, bn_e))
                goto err;
        }

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (kd->d_data && kd->d_len > 0) {
                bn_d = BN_bin2bn(kd->d_data, kd->d_len, NULL);
                if (bn_d == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, bn_d))
                    goto err;
            }

            if (kd->use_crt) {
                if (kd->qt_p_data && kd->qt_p_len > 0) {
                    bn_p = BN_bin2bn(kd->qt_p_data, kd->qt_p_len, NULL);
                    if (bn_p == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR1, bn_p))
                        goto err;
                }

                if (kd->qt_q_data && kd->qt_q_len > 0) {
                    bn_q = BN_bin2bn(kd->qt_q_data, kd->qt_q_len, NULL);
                    if (bn_q == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR2, bn_q))
                        goto err;
                }

                if (kd->qt_dP_data && kd->qt_dP_len > 0) {
                    bn_dP = BN_bin2bn(kd->qt_dP_data, kd->qt_dP_len, NULL);
                    if (bn_dP == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT1, bn_dP))
                        goto err;
                }

                if (kd->qt_dQ_data && kd->qt_dQ_len > 0) {
                    bn_dQ = BN_bin2bn(kd->qt_dQ_data, kd->qt_dQ_len, NULL);
                    if (bn_dQ == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT2, bn_dQ))
                        goto err;
                }

                if (kd->qt_qInv_data && kd->qt_qInv_len > 0) {
                    bn_qInv = BN_bin2bn(kd->qt_qInv_data, kd->qt_qInv_len, NULL);
                    if (bn_qInv == NULL || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, bn_qInv))
                        goto err;
                }
            }
        }
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ok = param_callback(params, cbarg);

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(bn_n);
    BN_free(bn_e);
    BN_free(bn_d);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_dP);
    BN_free(bn_dQ);
    BN_free(bn_qInv);

    return ok;
}

static void *gen_init(void *provctx, int selection, int rsa_type,
                      const OSSL_PARAM params[])
{
    struct rsa_gen_ctx *gctx = NULL;

    if (!prov_is_running())
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    if ((gctx = OPENSSL_malloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = PROV_LIBCTX_OF(provctx);
        if ((gctx->pub_exp = BN_new()) == NULL
            || !BN_set_word(gctx->pub_exp, PROV_PUB_EXP_DEFAULT)) {
            goto err;
        }
        gctx->nbits = PROV_RSA_DEFAULT_KEY_BITS;
        gctx->primes = PROV_RSA_DEFAULT_PRIME_NUM;
        gctx->rsa_type = rsa_type;
    } else {
        goto err;
    }

    if (!rsa_gen_set_params(gctx, params))
        goto err;
    return gctx;

err:
    if (gctx != NULL)
        BN_free(gctx->pub_exp);
    OPENSSL_free(gctx);
    return NULL;
}

static void *rsa_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    return gen_init(provctx, selection, PROV_FLAG_TYPE_RSA, params);
}

/*
 * This function is common for all RSA sub-types, to detect possible
 * misuse, such as PSS parameters being passed when a plain RSA key
 * is generated.
 */
static int rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct rsa_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &gctx->nbits))
            return 0;
        if (gctx->nbits < PROV_RSA_MIN_MODULUS_BITS) {
            fprintf(stderr,
                "%s:%d:%s(): Key size is too small %zu\n",
                __FILE__, __LINE__, __func__, gctx->nbits);
            return 0;
        }
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES)) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->primes))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL
        && !OSSL_PARAM_get_BN(p, &gctx->pub_exp))
        return 0;
    return 1;
}

#define rsa_gen_basic                                           \
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),          \
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),        \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0)

static const OSSL_PARAM *rsa_gen_settable_params(ossl_unused void *genctx,
                                                 ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        rsa_gen_basic,
        OSSL_PARAM_END
    };

    return settable;
}

/**
 * Convert RSA struct to provider keydata format
 *
 * @param rsa Input RSA key structure
 * @param keydata Output keydata pointer
 * @return -1 on error, 0 if RSA stored, 1 if converted to keydata
 */
static int prov_rsa_to_keydata(RSA *rsa, void **keydata)
{
    const BIGNUM *p = NULL, *q = NULL, *dP = NULL, *dQ = NULL, *qInv = NULL, *n = NULL, *e = NULL, *d = NULL;
    prov_rsa_key_data *kd = NULL;
    uint8_t *base = NULL;
    int alloc_sz = 0;
    int ret = -1;
    int modulus_bytes = 0;

    if (!rsa)
        return -1;

    kd = pal_malloc(sizeof(prov_rsa_key_data));
    if (!kd)
        return -1;
    memset(kd, 0, sizeof(prov_rsa_key_data));
    PROV_ATOMIC_INC(kd->refcnt);

    RSA_get0_key(rsa, &n, &e, &d);

    if (!n || !e)
        goto err;

    modulus_bytes = BN_num_bytes(n);

    /* Check if hardware supports this modulus length */
    if (pal_rsa_capability_check_modlen(modulus_bytes)) {
        /* Hardware doesn't support this key size, store as RSA struct for SW fallback */
        kd->rsa = rsa;
        *keydata = (void *)kd;
        return 0;
    }

    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dP, &dQ, &qInv);

    /* Normal path for hardware-supported keys: convert to raw data format */
    alloc_sz = BN_num_bytes(n) + BN_num_bytes(e);

    if (p && q && dP && dQ && qInv && d) {
        alloc_sz += BN_num_bytes(d);
        alloc_sz += (modulus_bytes / 2) * 5;
    } else if (d) {
        alloc_sz += BN_num_bytes(d);
    } else
        goto err;

    base = (uint8_t *)pal_malloc(alloc_sz);
    if (!base) {
       fprintf(stderr, "%s:%d:%s(): Failed to allocate memory for RSA key data\n",
               __FILE__, __LINE__, __func__);
       goto err;
    }

    kd->n_data = base;
    kd->n_len = BN_bn2bin(n, kd->n_data);

    kd->e_data = base + kd->n_len;
    kd->e_len = BN_bn2bin(e, kd->e_data);

    if (p && q && dP && dQ && qInv && d) {
       kd->use_crt = 1;
       /* Store d first (needed for export and software fallback) */
       kd->d_data = kd->e_data + kd->e_len;
       kd->d_len = BN_bn2bin(d, kd->d_data);

        /* Microcode requires CRT parameters be prepadded with zeroes if length
         * is lesser than modlength/2
        */
       kd->qt_p_data = kd->d_data + kd->d_len;
       kd->qt_p_len = BN_bn2binpad(p, kd->qt_p_data, modulus_bytes / 2);

       kd->qt_q_data = kd->qt_p_data + kd->qt_p_len;
       kd->qt_q_len = BN_bn2binpad(q, kd->qt_q_data, modulus_bytes / 2);

       kd->qt_dP_data = kd->qt_q_data + kd->qt_q_len;
       kd->qt_dP_len = BN_bn2binpad(dP, kd->qt_dP_data, modulus_bytes / 2);

       kd->qt_dQ_data = kd->qt_dP_data + kd->qt_dP_len;
       kd->qt_dQ_len = BN_bn2binpad(dQ, kd->qt_dQ_data, modulus_bytes / 2);

       kd->qt_qInv_data = kd->qt_dQ_data + kd->qt_dQ_len;
       kd->qt_qInv_len = BN_bn2binpad(qInv, kd->qt_qInv_data, modulus_bytes / 2);
    }
    else {
      kd->use_crt = 0;
      kd->d_data = kd->e_data + kd->e_len;
      kd->d_len = BN_bn2bin(d, kd->d_data);
    }

    kd->base_ptr = base;
    *keydata = (void *)kd;
    ret = 1;
    return ret;

err:
    if (base)
        pal_free(base);
    if (kd)
        pal_free(kd);
    return -1;
}

static void *rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct rsa_gen_ctx *gctx = genctx;
    RSA *rsa_tmp = NULL;
    void *keydata = NULL;
    BN_GENCB *gencb = NULL;
    int ret;

    if (!prov_is_running() || gctx == NULL)
        return NULL;

    switch (gctx->rsa_type) {
    case PROV_FLAG_TYPE_RSA:
        break;
    default:
        fprintf(stderr,
            "%s:%d:%s():  Unsupported RSA key sub-type %d\n",
            __FILE__, __LINE__, __func__, gctx->rsa_type);
        return NULL;
    }

    if ((rsa_tmp = prov_rsa_new_intern(gctx->libctx)) == NULL)
        return NULL;

    gctx->cb = osslcb;
    gctx->cbarg = cbarg;
    gencb = BN_GENCB_new();
    if (gencb != NULL)
        BN_GENCB_set(gencb, rsa_gencb, genctx);

    if (!RSA_generate_multi_prime_key(rsa_tmp,
                                      (int)gctx->nbits, (int)gctx->primes,
                                      gctx->pub_exp, gencb))
        goto err;

    RSA_clear_flags(rsa_tmp, PROV_FLAG_TYPE_MASK);
    RSA_set_flags(rsa_tmp, gctx->rsa_type);

    ret = prov_rsa_to_keydata(rsa_tmp, &keydata);
    if (ret < 0)
        goto err;

    if (ret == 1)
        RSA_free(rsa_tmp);
    rsa_tmp = NULL;

    BN_GENCB_free(gencb);
    return keydata;

 err:
    BN_GENCB_free(gencb);
    if (rsa_tmp != NULL)
        RSA_free(rsa_tmp);
    return NULL;
}

static void rsa_gen_cleanup(void *genctx)
{
    struct rsa_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;
    BN_clear_free(gctx->pub_exp);
    OPENSSL_free(gctx);
}

const OSSL_DISPATCH prov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) prov_rsa_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))rsa_gen_cleanup },
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

