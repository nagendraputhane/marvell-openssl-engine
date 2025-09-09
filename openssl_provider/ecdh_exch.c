/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "crypto/ec.h" /* ossl_ecdh_kdf_X9_63() */

#include "prov.h"
#include "ec_common.h"
#include "pal_ecdsa.h"

#define PCURVES_MAX_PRIME_LEN	72 /* P521 curve */

static OSSL_FUNC_keyexch_newctx_fn prov_ecdh_newctx;
static OSSL_FUNC_keyexch_init_fn prov_ecdh_init;
static OSSL_FUNC_keyexch_set_peer_fn prov_ecdh_set_peer;
static OSSL_FUNC_keyexch_derive_fn prov_ecdh_derive;
static OSSL_FUNC_keyexch_freectx_fn prov_ecdh_freectx;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes EC_KEY structures, so
 * we use that here too.
 */

typedef struct {
    OSSL_LIB_CTX *libctx;

    EC_KEY *k;
    EC_KEY *peerk;

} PROV_ECDH_CTX;

static
void *prov_ecdh_newctx(void *provctx)
{
    PROV_ECDH_CTX *ctx;

    if (!prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);

    return (void *)ctx;
}

static
int prov_ecdh_init(void *vctx, void *vecdh, const OSSL_PARAM params[])
{
    PROV_ECDH_CTX *ctx = (PROV_ECDH_CTX *)vctx;

    if (!prov_is_running()
            || ctx == NULL
            || vecdh == NULL
            || !EC_KEY_up_ref(vecdh))
        return 0;
    EC_KEY_free(ctx->k);
    ctx->k = vecdh;
    return 1;
}

static
int prov_ecdh_set_peer(void *vctx, void *vecdh)
{
    PROV_ECDH_CTX *ctx = (PROV_ECDH_CTX *)vctx;

    if (!prov_is_running()
            || ctx == NULL
            || vecdh == NULL
            || !EC_KEY_up_ref(vecdh))
        return 0;

    EC_KEY_free(ctx->peerk);
    ctx->peerk = vecdh;
    return 1;
}

static
void prov_ecdh_freectx(void *vctx)
{
    PROV_ECDH_CTX *ctx = (PROV_ECDH_CTX *)vctx;

    EC_KEY_free(ctx->k);
    EC_KEY_free(ctx->peerk);


    OPENSSL_free(ctx);
}

static ossl_inline
size_t ecdh_size(const EC_KEY *k)
{
    size_t degree = 0;
    const EC_GROUP *group;

    if (k == NULL
            || (group = EC_KEY_get0_group(k)) == NULL)
        return 0;

    degree = EC_GROUP_get_degree(group);

    return (degree + 7) / 8;
}


static inline int ecdh_compute_key(unsigned char **pout, size_t *poutlen,
        const EC_POINT *pub_key, const EC_KEY *ecdh)
{

    BN_CTX *ctx;
    BIGNUM *x = NULL, *y = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int ret = 0;
    size_t buflen;
    void *rxbuf = NULL;
    void *rybuf = NULL;
    BIGNUM *px = BN_new();
    BIGNUM *py = BN_new();
    pal_ecdsa_ctx_t pal_ctx = {0};
    pal_crypto_curve_id_t curve_id;

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (x == NULL || y == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(ecdh);
    if (priv_key == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_NO_PRIVATE_VALUE);
        goto err;
    }

    group = EC_KEY_get0_group(ecdh);
    if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
        if (!EC_GROUP_get_cofactor(group, x, NULL) ||
                !BN_mul(x, x, priv_key, ctx)) {
            ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        priv_key = x;
    }

    rxbuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
    rybuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
    if (rxbuf == NULL || rybuf == NULL)
        goto err;

    memset(rxbuf, 0, PCURVES_MAX_PRIME_LEN);
    memset(rybuf, 0, PCURVES_MAX_PRIME_LEN);

    curve_id = get_curve_id(group);
    if (!curve_id) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
        goto err;
    }

    EC_POINT_get_affine_coordinates_GFp(group, pub_key, px, py, NULL);

    pal_ctx.x_data = bn_to_crypto_param(px);
    pal_ctx.x_data_len  = BN_num_bytes(px);
    pal_ctx.y_data = bn_to_crypto_param(py);;
    pal_ctx.y_data_len  = BN_num_bytes(py);
    pal_ctx.scalar_data = bn_to_crypto_param(priv_key);
    pal_ctx.scalar_data_len  = BN_num_bytes(priv_key);
    pal_ctx.rxbuf = rxbuf;
    pal_ctx.rybuf = rybuf;
    pal_ctx.curve_id = curve_id;
    pal_ecdh_init(&pal_ctx);
    pal_ctx.rxbuf = rxbuf;
    pal_ctx.rybuf = rybuf;
    pal_ctx.async_cb = provider_ossl_handle_async_job;

    if ((buflen = pal_ecdsa_ec_point_multiplication(&pal_ctx)) == 0) {
        ECerr(EC_F_ECDH_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    *pout = rxbuf;
    *poutlen = buflen;
    rxbuf = NULL;
    ret = 1;
err:
    if (rybuf)
        OPENSSL_free(rybuf);
    if (rxbuf)
        OPENSSL_free(rxbuf);
    if (ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(py);
    BN_free(px);

    return ret;
}

static inline int
ecdh_compute_key_internal(void *out, size_t outlen, const EC_POINT *pub_key,
        const EC_KEY *eckey)
{
    unsigned char *sec = NULL;
    size_t seclen;

    if (!ecdh_compute_key(&sec, &seclen, pub_key, eckey))
        return 0;
    if (outlen > seclen)
        outlen = seclen;
    memcpy(out, sec, outlen);

    OPENSSL_clear_free(sec, seclen);
    return outlen;
}

static int prov_ecdh_derive(void *vctx, unsigned char *secret,
        size_t *psecretlen, size_t outlen)
{
    PROV_ECDH_CTX *ctx = (PROV_ECDH_CTX *)vctx;
    int retlen, ret = 0;
    size_t ecdhsize, size;
    const EC_POINT *ppubkey = NULL;
    EC_KEY *privk = NULL;
    const EC_GROUP *group;
    unsigned char *sec = NULL;

    if (ctx->k == NULL || ctx->peerk == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    ecdhsize = ecdh_size(ctx->k);
    if (secret == NULL) {
        *psecretlen = ecdhsize;
        return 1;
    }

    if ((group = EC_KEY_get0_group(ctx->k)) == NULL)
        return 0;

    /*
     * NB: unlike PKCS#3 DH, if outlen is less than maximum size this is not
     * an error, the result is truncated.
     */
    size = outlen < ecdhsize ? outlen : ecdhsize;

    privk = ctx->k;

    ppubkey = EC_KEY_get0_public_key(ctx->peerk);

    retlen = ecdh_compute_key_internal(secret, size, ppubkey, privk);//, NULL);

    if (retlen <= 0)
        goto end;

    *psecretlen = retlen;
    ret = 1;

end:
    if (privk != ctx->k)
        EC_KEY_free(privk);
    return ret;
}

const OSSL_DISPATCH prov_ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))prov_ecdh_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))prov_ecdh_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))prov_ecdh_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))prov_ecdh_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))prov_ecdh_freectx },
    { 0, NULL }
};
