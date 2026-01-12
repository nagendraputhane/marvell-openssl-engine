/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

/*
 * RSA KEM (Key Encapsulation Mechanism) implementation
 * Reference: NIST SP 800-56B Rev 2 - RSASVE
 */

#include "rsa_kem.h"
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "prov.h"
#include "rsa_kmgmt.h"
#include "pal_rsa.h"
#include "rsa_sig.h"

static OSSL_FUNC_kem_newctx_fn rsa_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn rsa_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn rsa_generate_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn rsa_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn rsa_decapsulate;
static OSSL_FUNC_kem_freectx_fn rsa_freectx;
static OSSL_FUNC_kem_dupctx_fn rsa_dupctx;
static OSSL_FUNC_kem_get_ctx_params_fn rsa_get_ctx_params;
static OSSL_FUNC_kem_gettable_ctx_params_fn rsa_gettable_ctx_params;
static OSSL_FUNC_kem_set_ctx_params_fn rsa_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn rsa_settable_ctx_params;

/*
 * Only the KEM for RSASVE as defined in SP800-56b r2 is implemented
 * currently.
 */
#define KEM_OP_UNDEFINED   -1
#define KEM_OP_RSASVE       0

/*
 * RSA KEM context
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    prov_rsa_key_data *key;
    int op;
} PROV_RSA_KEM_CTX;

static const OSSL_ITEM rsakem_opname_id_map[] = {
    { KEM_OP_RSASVE, OSSL_KEM_PARAM_OPERATION_RSASVE },
};

static int name2id(const char *name, const OSSL_ITEM *map, size_t sz)
{
    size_t i;

    if (name == NULL)
        return -1;

    for (i = 0; i < sz; ++i) {
        if (strcasecmp(map[i].ptr, name) == 0)
            return map[i].id;
    }
    return -1;
}

static int rsakem_opname2id(const char *name)
{
    return name2id(name, rsakem_opname_id_map, sizeof(rsakem_opname_id_map)/sizeof(rsakem_opname_id_map[0]));
}

static void *rsa_newctx(void *provctx)
{
    PROV_RSA_KEM_CTX *ctx;

    if (!prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_RSA_KEM_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->op = KEM_OP_UNDEFINED;
    return ctx;
}

static void rsa_freectx(void *vctx)
{
    PROV_RSA_KEM_CTX *ctx = (PROV_RSA_KEM_CTX *)vctx;

    if (ctx == NULL)
        return;

    /* Release key reference */
    if (ctx->key != NULL)
        __prov_rsa_freedata(ctx->key);

    OPENSSL_free(ctx);
}

static void *rsa_dupctx(void *vctx)
{
    PROV_RSA_KEM_CTX *srcctx = (PROV_RSA_KEM_CTX *)vctx;
    PROV_RSA_KEM_CTX *dstctx;

    if (!prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->key != NULL)
        PROV_ATOMIC_INC(dstctx->key->refcnt);

    return dstctx;
}

/*
 * NIST.SP.800-56Br2
 * 7.2.1.2 RSASVE Generate Operation (RSASVE.GENERATE).
 *
 * Generate a random in the range 1 < z < (n – 1)
 */
static int rsasve_gen_rand_bytes(prov_rsa_key_data *key,
                                 unsigned char *out, int outlen)
{
    int ret = 0;
    BN_CTX *bnctx;
    const BIGNUM *rsa_n = NULL;
    BIGNUM *z, *nminus3, *n;

    bnctx = BN_CTX_secure_new();
    if (bnctx == NULL)
        return 0;

    /*
     * Generate a random in the range 1 < z < (n – 1).
     * Since BN_priv_rand_range() returns a value in range 0 <= r < max
     * We can achieve this by adding 2.. but then we need to subtract 3 from
     * the upper bound i.e: 2 + (0 <= r < (n - 3))
     */
    BN_CTX_start(bnctx);
    n = BN_CTX_get(bnctx);
    nminus3 = BN_CTX_get(bnctx);
    z = BN_CTX_get(bnctx);

    /* Get n from either RSA struct or keydata, then compute random */
    if (unlikely(key->rsa != NULL)) {
        RSA_get0_key(key->rsa, &rsa_n, NULL, NULL);
        ret = (z != NULL && n != NULL && BN_copy(n, rsa_n) != NULL);
    } else {
        ret = (z != NULL && n != NULL &&
               BN_bin2bn(key->n_data, prov_rsa_key_len(key), n) != NULL);
    }
    if (ret) {
        ret = (BN_sub_word(n, 3)
               && BN_copy(nminus3, n)
               && BN_priv_rand_range(z, nminus3)
               && BN_add_word(z, 2)
               && (BN_bn2binpad(z, out, outlen) == outlen));
    }

    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ret;
}

static int rsa_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_RSA_KEM_CTX *ctx = (PROV_RSA_KEM_CTX *)vctx;
    prov_rsa_key_data *key = (prov_rsa_key_data *)vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    if (!prov_is_running())
        return 0;

    /* Basic key validation - check if we have public key components */
    if (likely(key->rsa == NULL)) {
        /* For HW-supported keys, check raw data */
        if (key->n_data == NULL || key->e_data == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }
    }

    if (ctx->key != NULL)
        __prov_rsa_freedata(ctx->key);

    ctx->key = key;
    PROV_ATOMIC_INC(ctx->key->refcnt);

    return rsa_set_ctx_params(ctx, params);
}

static int rsa_encapsulate_init(void *vctx, void *vkey,
                                  const OSSL_PARAM params[])
{
    return rsa_init(vctx, vkey, params);
}

/*
 * NIST.SP.800-56Br2
 * 7.2.1.2 RSASVE Generate Operation (RSASVE.GENERATE).
 */
static int rsa_generate_encapsulate(void *vctx, unsigned char *out,
                                      size_t *outlen, unsigned char *secret,
                                      size_t *secretlen)
{
    PROV_RSA_KEM_CTX *ctx = (PROV_RSA_KEM_CTX *)vctx;
    prov_rsa_key_data *key = ctx->key;
    int ret = 0;
    pal_rsa_ctx_t pal_ctx = {0};
    size_t nlen;

    if (ctx == NULL || key == NULL)
        return 0;

    if (!prov_is_running())
        return 0;

    /* Step (1): nlen = Ceil(len(n)/8) - use helper function */
    nlen = prov_rsa_key_len(key);

    if (nlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    /* Query mode: return required sizes */
    if (out == NULL) {
        if (outlen == NULL && secretlen == NULL)
            return 0;
        if (outlen != NULL)
            *outlen = nlen;
        if (secretlen != NULL)
            *secretlen = nlen;
        return 1;
    }

    /*
     * Verify output buffers are large enough
     * Both secret and ciphertext are nlen bytes
     */
    if (outlen != NULL && *outlen < nlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH);
        return 0;
    }

    /*
     * Step (2): Generate a random byte string z of nlen bytes where
     *            1 < z < n - 1
     */
    if (!rsasve_gen_rand_bytes(key, secret, nlen))
        return 0;

    /* Use software fallback if key has RSA struct (HW-unsupported) */
    if (unlikely(key->rsa != NULL)) {
        ret = RSA_public_encrypt(nlen, secret, out, key->rsa, RSA_NO_PADDING);
        if (ret < 0) {
            fprintf(stderr, "%s:%d:%s(): RSA_public_encrypt failed\n",
                    __FILE__, __LINE__, __func__);
            ERR_print_errors_fp(stderr);
            OPENSSL_cleanse(secret, nlen);
            return 0;
        }
        if (outlen != NULL)
            *outlen = ret;
        if (secretlen != NULL)
            *secretlen = nlen;
        return 1;
    }

    /* Step(3): out = RSAEP((n,e), z) - raw RSA encryption with NO_PADDING */
    rsa_xform_pub_setup(key, &pal_ctx);
    pal_ctx.padding = PAL_RSA_NO_PADDING;
    pal_ctx.async_cb = provider_ossl_handle_async_job;

    /* Encrypt the secret using RSA public key */
    ret = pal_rsa_pub_enc(&pal_ctx, nlen, secret, out);
    if (ret > 0) {
        ret = 1;
        if (outlen != NULL)
            *outlen = nlen;
        if (secretlen != NULL)
            *secretlen = nlen;
    } else {
        OPENSSL_cleanse(secret, nlen);
        ret = 0;
    }
    return ret;
}

static int rsa_decapsulate_init(void *vctx, void *vkey,
                                  const OSSL_PARAM params[])
{
    PROV_RSA_KEM_CTX *ctx = (PROV_RSA_KEM_CTX *)vctx;
    prov_rsa_key_data *key = (prov_rsa_key_data *)vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    if (!prov_is_running())
        return 0;

    /* Check if we have private key components */
    if (likely(key->rsa == NULL)) {
        /* For HW-supported keys, check raw data */
        if (key->n_data == NULL || key->e_data == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }

        /* Verify we have private key (either CRT or non-CRT) */
        if (!key->use_crt && key->d_data == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }

        if (key->use_crt && (key->qt_p_data == NULL || key->qt_q_data == NULL)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }
    }
    /* HW-unsupported keys stored as RSA struct are always valid */

    if (ctx->key != NULL)
        __prov_rsa_freedata(ctx->key);

    ctx->key = key;
    PROV_ATOMIC_INC(ctx->key->refcnt);

    return rsa_set_ctx_params(ctx, params);
}

/*
 * NIST.SP.800-56Br2
 * 7.2.1.3 RSASVE Recovery Operation (RSASVE.RECOVER).
 *
 * This function performs RSA decryption using the private key.
 * It takes the input ciphertext, decrypts it using NO_PADDING,
 * and writes the decrypted secret to the output buffer.
 */
static int rsa_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen)
{
    PROV_RSA_KEM_CTX *ctx = (PROV_RSA_KEM_CTX *)vctx;
    prov_rsa_key_data *key = ctx->key;
    int ret = 0;
    pal_rsa_ctx_t pal_ctx = {0};
    size_t nlen;

    if (ctx == NULL || key == NULL)
        return 0;

    if (!prov_is_running())
        return 0;

    /* Step (1): get the byte length of n - use helper function */
    nlen = prov_rsa_key_len(key);

    if (nlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    /* Query mode: return required size */
    if (out == NULL) {
        *outlen = nlen;
        return 1;
    }

    /*
     * Step (2): check the input ciphertext 'inlen' matches the nlen
     * and that outlen is at least nlen bytes
     */
    if (inlen != nlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return 0;
    }

    /*
     * Verify output buffer is large enough
     */
    if (outlen != NULL && *outlen < nlen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH);
        return 0;
    }

    /* Use software fallback if key has RSA struct (HW-unsupported) */
    if (unlikely(key->rsa != NULL)) {
        /* Decrypt using software RSA private key with NO_PADDING */
        ret = RSA_private_decrypt(inlen, in, out, key->rsa, RSA_NO_PADDING);
        if (ret < 0) {
            fprintf(stderr, "%s:%d:%s(): RSA_private_decrypt failed\n",
                    __FILE__, __LINE__, __func__);
            ERR_print_errors_fp(stderr);
            return 0;
        }
        if (outlen != NULL)
            *outlen = ret;
        return 1;
    }

    /* Step (3): out = RSADP((n,d), in) - raw RSA decryption with NO_PADDING */
    if (likely((pal_ctx.use_crt_method = key->use_crt) == 1))
        rsa_xform_crt_setup(key, &pal_ctx);
    else
        rsa_xform_non_crt_setup(key, &pal_ctx);

    pal_ctx.padding = PAL_RSA_NO_PADDING;
    pal_ctx.async_cb = provider_ossl_handle_async_job;
    /* Decrypt the encapsulated secret */
    ret = pal_rsa_priv_dec(&pal_ctx, inlen, in, out);

    if (ret > 0 && outlen != NULL)
        *outlen = ret;

    return ret > 0;
}

static int rsa_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_RSA_KEM_CTX *ctx = (PROV_RSA_KEM_CTX *)vctx;

    if (ctx == NULL)
        return 0;

    return 1;
}

static const OSSL_PARAM *rsa_gettable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int rsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_RSA_KEM_CTX *ctx = (PROV_RSA_KEM_CTX *)vctx;
    const OSSL_PARAM *p;
    int op;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_OPERATION);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        op = rsakem_opname2id(p->data);
        if (op < 0)
            return 0;
        ctx->op = op;
    }

    return 1;
}

static const OSSL_PARAM *rsa_settable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

const OSSL_DISPATCH prov_rsa_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))rsa_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))rsa_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))rsa_generate_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))rsa_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))rsa_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))rsa_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))rsa_dupctx },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))rsa_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))rsa_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))rsa_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))rsa_settable_ctx_params },
    { 0, NULL }
};

