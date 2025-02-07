/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include "internal/deprecated.h"

#include <string.h> /* memcpy */
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "internal/cryptlib.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "crypto/ec.h"
#include "prov/der_ec.h"
#include "prov.h"
#include "ec_common.h"
#include "pal/pal_ecdsa.h"

#define PCURVES_MAX_PRIME_LEN		72 /* P521 curve */
#define PCURVES_MAX_DER_SIG_LEN		141
#define PROV_MAX_NAME_SIZE 	50
#define OSSL_MAX_ALGORITHM_ID_SIZE   256

static OSSL_FUNC_signature_newctx_fn ecdsa_newctx;
static OSSL_FUNC_signature_sign_init_fn ecdsa_sign_init;
static OSSL_FUNC_signature_verify_init_fn ecdsa_verify_init;
static OSSL_FUNC_signature_sign_fn prov_ecdsa_sign;
static OSSL_FUNC_signature_verify_fn prov_ecdsa_verify;
static OSSL_FUNC_signature_freectx_fn ecdsa_freectx;
static OSSL_FUNC_signature_set_ctx_params_fn ecdsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn ecdsa_settable_ctx_params;

static OSSL_FUNC_signature_dupctx_fn ecdsa_dupctx;
static OSSL_FUNC_signature_digest_sign_init_fn ecdsa_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn ecdsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn ecdsa_digest_sign_final;
static OSSL_FUNC_signature_digest_sign_fn ecdsa_digest_sign;
static OSSL_FUNC_signature_digest_verify_init_fn ecdsa_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn ecdsa_digest_verify_final;
static OSSL_FUNC_signature_digest_verify_final_fn ecdsa_digest_verify_final;
static OSSL_FUNC_signature_digest_verify_fn ecdsa_digest_verify;
/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DSA structures, so
 * we use that here too.
 */

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EC_KEY *ec;
    char mdname[PROV_MAX_NAME_SIZE];

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    size_t mdsize;
    int operation;

    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    /*
     * Internally used to cache the results of calling the EC group
     * sign_setup() methods which are then passed to the sign operation.
     * This is used by CAVS failure tests to terminate a loop if the signature
     * is not valid.
     * This could of also been done with a simple flag.
     */
    BIGNUM *kinv;
    BIGNUM *r;

#if !defined(OPENSSL_NO_ACVP_TESTS)
    /*
     * This indicates that KAT (CAVS) test is running. Externally an app will
     * override the random callback such that the generated private key and k
     * are known.
     * Normal operation will loop to choose a new k if the signature is not
     * valid - but for this mode of operation it forces a failure instead.
     */
    unsigned int kattest;
#endif
} PROV_ECDSA_CTX;

static void *ecdsa_newctx(void *provctx, const char *propq)
{
    PROV_ECDSA_CTX *ctx;

    if (!prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_ECDSA_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->flag_allow_md = 1;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        ctx = NULL;
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    }
    return ctx;
}

static inline int ecdsa_signverify_init(void *vctx, void *ec,
        const OSSL_PARAM params[], int operation)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (!prov_is_running()
            || ctx == NULL
            || ec == NULL
            || !EC_KEY_up_ref(ec))
        return 0;
    EC_KEY_free(ctx->ec);
    ctx->ec = ec;
    ctx->operation = operation;
    if (!ecdsa_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int ecdsa_sign_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
    return ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_SIGN);
}

static int ecdsa_verify_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
    return ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_VERIFY);
}


static inline int ecdsa_sign(int type, const unsigned char *dgst, int dlen,
        unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
        const BIGNUM *r, EC_KEY *eckey)
{
    int ret = -1;
    pal_crypto_curve_id_t curve_id;
    BIGNUM *rbn = NULL;
    BIGNUM *sbn = NULL;
    BIGNUM *px = BN_new();
    BIGNUM *py = BN_new();
    BIGNUM *k = BN_new();
    ECDSA_SIG *sig_st = NULL;
    unsigned char *buf = NULL;
    int redo, rlen, slen, derlen;
    pal_ecdsa_ctx_t pal_ctx = {0};
    unsigned char *dup_buf = NULL;
    const int max_rslen = PCURVES_MAX_PRIME_LEN;
    const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
    uint8_t rdata[PCURVES_MAX_DER_SIG_LEN] = {0};
    uint8_t sdata[PCURVES_MAX_DER_SIG_LEN] = {0};


    if(!prov_asym_get_valid_devid_qid(&pal_ctx.devid, &pal_ctx.queue))
        goto err;

    curve_id = get_curve_id(ecgroup);
    if (!curve_id) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
        goto err;
    }

    EC_POINT_get_affine_coordinates_GFp(ecgroup, EC_KEY_get0_public_key(eckey), px, py, NULL);

    pal_ctx.x_data = bn_to_crypto_param(px);
    pal_ctx.x_data_len  = BN_num_bytes(px);
    pal_ctx.y_data = bn_to_crypto_param(py);;
    pal_ctx.y_data_len  = BN_num_bytes(py);
    pal_ctx.pkey = bn_to_crypto_param(EC_KEY_get0_private_key(eckey));
    pal_ctx.pkey_len = BN_num_bytes(EC_KEY_get0_private_key(eckey));
    pal_ctx.dgst = dgst;
    pal_ctx.dlen = dlen;
    pal_ctx.curve_id = curve_id;
    pal_ctx.xform_type = PAL_CRYPTO_ASYM_XFORM_ECDSA;
    pal_ctx.rdata = rdata;
    pal_ctx.sdata = sdata;
    pal_ctx.rlen = max_rslen;
    pal_ctx.slen = max_rslen;
    pal_ctx.async_cb = provider_ossl_handle_async_job;

    do {
        redo = false;

        do {
            BN_rand_range(k, EC_GROUP_get0_order(ecgroup));
        } while (BN_is_zero(k));

        pal_ctx.secret = bn_to_crypto_param(k);
        pal_ctx.secret_len = BN_num_bytes(k);
        if (!pal_ctx.secret)
            goto err;

        if(!pal_ecdsa_sign(&pal_ctx))
            goto err;

        rbn = BN_bin2bn(rdata, pal_ctx.rlen, NULL);
        sbn = BN_bin2bn(sdata, pal_ctx.slen, NULL);

        if (rbn == NULL || sbn == NULL) {
            BN_free(rbn);
            BN_free(sbn);
            goto err;
        }

        if (BN_is_zero(rbn) || BN_is_zero(sbn)) {
            redo = true;
            BN_free(rbn);
            BN_free(sbn);
            sbn = NULL;
            rbn = NULL;
            pal_ctx.rlen = max_rslen;
            pal_ctx.slen = max_rslen;
        }
    } while (redo);

    sig_st = ECDSA_SIG_new();
    if (!ECDSA_SIG_set0(sig_st, rbn, sbn)) {
        BN_free(rbn);
        BN_free(sbn);
        goto err;
    }

    buf = malloc(PCURVES_MAX_DER_SIG_LEN);
    if (buf == NULL)
        goto err;

    dup_buf = buf;
    derlen = i2d_ECDSA_SIG(sig_st, &dup_buf);

    memcpy(sig, buf, derlen);
    *siglen = derlen;
    ret = 1;
err:
    if(sig_st)
        ECDSA_SIG_free(sig_st);
    BN_free(px);
    BN_free(py);
    BN_free(k);
    if(buf)
        free(buf);

    return ret;
}

/**
 * @returns 1 on successful verification, 0 on verification failure, -1 on error
 */
static inline int ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
        const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    pal_crypto_curve_id_t curve_id;
    pal_ecdsa_ctx_t pal_ctx = {0};
    const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
    const BIGNUM *rbn = NULL;
    const BIGNUM *sbn = NULL;
    ECDSA_SIG *sig_st = NULL;
    int rlen;
    int slen;
    BIGNUM *px = BN_new();
    BIGNUM *py = BN_new();
    int ret = 0;
    (void)type;

    if(!prov_asym_get_valid_devid_qid(&pal_ctx.devid, &pal_ctx.queue))
        goto err;

    curve_id = get_curve_id(ecgroup);
    if (!curve_id) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
        goto err;
    }

    EC_POINT_get_affine_coordinates_GFp(ecgroup, EC_KEY_get0_public_key(eckey), px, py, NULL);

    if (d2i_ECDSA_SIG(&sig_st, &sigbuf, sig_len) == NULL)
        goto err;

    ECDSA_SIG_get0(sig_st, &rbn, &sbn);

    rlen = BN_num_bytes(rbn);
    slen = BN_num_bytes(sbn);

    pal_ctx.x_data = bn_to_crypto_param(px);
    pal_ctx.x_data_len  = BN_num_bytes(px);
    pal_ctx.y_data = bn_to_crypto_param(py);;
    pal_ctx.y_data_len  = BN_num_bytes(py);
    pal_ctx.rdata = malloc(rlen);
    pal_ctx.sdata = malloc(slen);
    pal_ctx.rlen = rlen;
    pal_ctx.slen = slen;
    pal_ctx.dgst = dgst;
    pal_ctx.dlen = dgst_len;
    pal_ctx.curve_id = curve_id;
    pal_ctx.xform_type = PAL_CRYPTO_ASYM_XFORM_ECDSA;
    pal_ctx.async_cb = provider_ossl_handle_async_job;

    BN_bn2bin(rbn, pal_ctx.rdata);
    BN_bn2bin(sbn, pal_ctx.sdata);

    ret = pal_ecdsa_verify(&pal_ctx);
err:
    ECDSA_SIG_free(sig_st);
    if (pal_ctx.rdata)
        free(pal_ctx.rdata);
    if (pal_ctx.sdata)
        free(pal_ctx.sdata);

    return ret;
}

static int prov_ecdsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
        size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    int ret;
    unsigned int sltmp;
    size_t ecsize = ECDSA_size(ctx->ec);

    if (!prov_is_running())
        return 0;

    if (sig == NULL) {
        *siglen = ecsize;
        return 1;
    }

#if !defined(OPENSSL_NO_ACVP_TESTS)
    if (ctx->kattest && !ECDSA_sign_setup(ctx->ec, NULL, &ctx->kinv, &ctx->r))
        return 0;
#endif

    if (sigsize < (size_t)ecsize)
        return 0;

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    ret =  ecdsa_sign(0, tbs, tbslen, sig, &sltmp, ctx->kinv, ctx->r, ctx->ec);

    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

static int prov_ecdsa_verify(void *vctx, const unsigned char *sig, size_t siglen,
        const unsigned char *tbs, size_t tbslen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (!prov_is_running() || (ctx->mdsize != 0 && tbslen != ctx->mdsize))
        return 0;

    return ecdsa_verify(0, tbs, tbslen, sig, siglen, ctx->ec);
}

static void ecdsa_freectx(void *vctx)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    OPENSSL_free(ctx->propq);
    ctx->propq = NULL;
    ctx->mdsize = 0;
    EC_KEY_free(ctx->ec);
    BN_clear_free(ctx->kinv);
    BN_clear_free(ctx->r);
    OPENSSL_free(ctx);
}

static int ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t mdsize = 0;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

#if !defined(OPENSSL_NO_ACVP_TESTS)
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_KAT);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &ctx->kattest))
        return 0;
#endif

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
                && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &mdsize)
                || (!ctx->flag_allow_md && mdsize != ctx->mdsize))
            return 0;
        ctx->mdsize = mdsize;
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ecdsa_settable_ctx_params(void *vctx,
        ossl_unused void *provctx)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (ctx != NULL && !ctx->flag_allow_md)
        return settable_ctx_params_no_digest;
    return settable_ctx_params;
}

static void *ecdsa_dupctx(void *vctx)
{
    PROV_ECDSA_CTX *srcctx = (PROV_ECDSA_CTX *)vctx;
    PROV_ECDSA_CTX *dstctx;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->ec = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->propq = NULL;

    if (srcctx->ec != NULL && !EC_KEY_up_ref(srcctx->ec))
        goto err;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            fprintf(stderr, "Error in duplicating\n");
        goto err;
    }

    if (srcctx->propq != NULL) {
        dstctx->propq = OPENSSL_strdup(srcctx->propq);
        if (dstctx->propq == NULL)
            goto err;
    }

    return dstctx;
err:
    ecdsa_freectx(dstctx);
    return NULL;
}

int ecdsa_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
        size_t sigsize)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!prov_is_running())
        return 0;

    if(unlikely ( ctx == NULL || ctx->mdctx == NULL))
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to ecdsa_sign.
     */
    if (sig != NULL
            && !EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    ctx->flag_allow_md = 1;
    return prov_ecdsa_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

int ecdsa_digest_verify_final(void *vctx, const unsigned char *sig,
        size_t siglen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!prov_is_running())
         return 0;

    if(unlikely ( ctx == NULL || ctx->mdctx == NULL))
        return 0;

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    ctx->flag_allow_md = 1;
    return prov_ecdsa_verify(ctx, sig, siglen, digest, (size_t)dlen);
}

int ecdsa_digest_signverify_update(void *vctx, const unsigned char *data,
        size_t datalen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}
static int ecdsa_digest_sign(void *vprsactx, unsigned char *sig,
        size_t *siglen, size_t sigsize,
        const unsigned char *data, size_t datalen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vprsactx;
    size_t ecsize = ECDSA_size(ctx->ec);

    if (sig == NULL) {
        *siglen = ecsize;
        return 1;
    }
    return ecdsa_digest_signverify_update(vprsactx, data, datalen)
        && ecdsa_digest_sign_final(vprsactx, sig, siglen, sigsize);
}

static int ecdsa_digest_verify(void *vprsactx, const unsigned char *sig,
        size_t siglen, const unsigned char *data,
        size_t datalen)
{
    return ecdsa_digest_signverify_update(vprsactx, data, datalen)
        && ecdsa_digest_verify_final(vprsactx, sig, siglen);
}

static int ecdsa_setup_md(PROV_ECDSA_CTX *ctx, const char *mdname, const char *mdprops)
{
    EVP_MD *md = NULL;
    size_t mdname_len;

    if (mdname == NULL)
        return 1;

    mdname_len = strlen(mdname);
    if (mdname_len >= sizeof(ctx->mdname)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST, "%s exceeds name buffer length", mdname);
        return 0;
    }
    if (mdprops == NULL)
        mdprops = ctx->propq;
    md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
    if (md == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST, "%s could not be fetched", mdname);
        return 0;
    }

    if (!ctx->flag_allow_md) {
        if (ctx->mdname[0] != '\0' && !EVP_MD_is_a(md, ctx->mdname)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED, "digest %s != %s", mdname, ctx->mdname);
            EVP_MD_free(md);
            return 0;
        }
        EVP_MD_free(md);
        return 1;
    }

    if (ctx->mdctx != NULL)
        EVP_MD_CTX_reset(ctx->mdctx);
    else
        ctx->mdctx = EVP_MD_CTX_new();

    if (ctx->mdctx == NULL) {
        EVP_MD_free(md);
        return 0;
    }

    EVP_MD_free(ctx->md);

    ctx->md = md;
    ctx->mdsize = EVP_MD_get_size(ctx->md);
    OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));

    return 1;
}
static int ecdsa_digest_signverify_init(void *vctx, const char *mdname,
        void *ec, const OSSL_PARAM params[],
        int operation)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    const char *properties = "provider=default";

    if (!ecdsa_signverify_init(vctx, ec, params, operation))
        return 0;

    if (mdname != NULL
            && (mdname[0] == '\0'
                || OPENSSL_strcasecmp(ctx->mdname, mdname) != 0)
            && !ecdsa_setup_md(ctx, mdname, properties))
        return 0;

    ctx->flag_allow_md = 0;

    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
        goto error;

    return 1;

error:
    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = NULL;
    return 0;
}

static int ecdsa_digest_sign_init(void *vprsactx, const char *mdname,
        void *vrsa, const OSSL_PARAM params[])
{
    return ecdsa_digest_signverify_init(vprsactx, mdname, vrsa,
            params, EVP_PKEY_OP_SIGN);
}

static int ecdsa_digest_verify_init(void *vprsactx, const char *mdname,
        void *vrsa, const OSSL_PARAM params[])
{
    return ecdsa_digest_signverify_init(vprsactx, mdname, vrsa,
            params, EVP_PKEY_OP_VERIFY);
}

const OSSL_DISPATCH prov_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))ecdsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))prov_ecdsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))ecdsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))prov_ecdsa_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))ecdsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))ecdsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ecdsa_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void)) ecdsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void)) ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,  (void (*)(void)) ecdsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void)) ecdsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void)) ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void)) ecdsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))ecdsa_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))ecdsa_digest_verify },
    { 0, NULL }
};
