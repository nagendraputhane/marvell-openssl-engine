/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>	// RSA_*_PADDING macro declarations
#include <openssl/rand.h>
#include "pal.h"
#include "pal_rsa.h"
#include "defs.h"
#include "prov.h"
#include "rsa_kmgmt.h"
#include "rsa_sig.h"

#define PROV_RSA_OP_SIGN                1
#define PROV_RSA_OP_VERIFY              2
#define PROV_MAX_NAME_SIZE	50
#define PROV_MAX_MD_SIZE 64	// SHA-512

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH  36

/* Application can set the RSA PAD mode either using the standard RSA_*_PADDING
 * macros or using strings like "none", "pkcs1", "oeap", "x931" in default
 * provider. Align to same convention in dpdk provider, so that application can
 * stick to standart openssl interface i.e openssl/rsa.h.
 */

static OSSL_ITEM padding_item[] = {
    { RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS },
    { 0, NULL }
};

static const unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

static OSSL_FUNC_signature_newctx_fn rsa_newctx;
static OSSL_FUNC_signature_freectx_fn rsa_freectx;
static OSSL_FUNC_signature_dupctx_fn rsa_dupctx;
static OSSL_FUNC_signature_sign_init_fn rsa_sign_init;
static OSSL_FUNC_signature_sign_fn prov_rsa_sign;
static OSSL_FUNC_signature_verify_init_fn rsa_verify_init;
static OSSL_FUNC_signature_verify_fn prov_rsa_verify;
static OSSL_FUNC_signature_set_ctx_params_fn rsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn rsa_settable_ctx_params;

static OSSL_FUNC_signature_digest_sign_init_fn rsa_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn rsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn rsa_digest_sign_final;
static OSSL_FUNC_signature_digest_sign_fn rsa_digest_sign;
static OSSL_FUNC_signature_digest_verify_init_fn rsa_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn rsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn rsa_digest_verify_final;
static OSSL_FUNC_signature_digest_verify_fn rsa_digest_verify;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    prov_rsa_key_data *key;
    int operation;
    int pad_type;
    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    char mdname[PROV_MAX_NAME_SIZE];

    EVP_MD *mgf1_md;
    int mgf1_mdnid;
    char mgf1_mdname[PROV_MAX_NAME_SIZE];
    /* PSS salt length */
    int saltlen;
    /* Minimum salt length or -1 if no PSS parameter restriction */
    int min_saltlen;
    unsigned char *tbuf;
} PROV_RSA_CTX;

static inline int prov_rsa_check_modlen(prov_rsa_key_data * key)
{
    int16_t modlen = key->n_len;

    return pal_rsa_capability_check_modlen(modlen);
}

#define prov_rsa_pss_restricted(prsactx) ((prsactx)->min_saltlen != -1)

static int setup_tbuf(PROV_RSA_CTX *ctx)
{
    if (ctx->tbuf != NULL)
        return 1;
    if ((ctx->tbuf = OPENSSL_malloc(ctx->key->n_len)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static void clean_tbuf(PROV_RSA_CTX *ctx)
{
    if (ctx->tbuf != NULL)
        OPENSSL_cleanse(ctx->tbuf, ctx->key->n_len);
}

static void free_tbuf(PROV_RSA_CTX *ctx)
{
    clean_tbuf(ctx);
    OPENSSL_free(ctx->tbuf);
    ctx->tbuf = NULL;
}

static void *rsa_newctx(void *provctx, const char *propq)
{
    PROV_RSA_CTX *prsactx;

    if (!prov_is_running())
        return NULL;

    prsactx = OPENSSL_zalloc(sizeof(PROV_RSA_CTX));
    if (prsactx == NULL)
        return NULL;

    prsactx->libctx = PROV_LIBCTX_OF(provctx);
    if (propq != NULL && (prsactx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(prsactx);
        prsactx = NULL;
        fprintf(stderr, "%s:%d:%s(): OPENSSL_zalloc failure\n",
                __FILE__, __LINE__, __func__);
    }
    /* Maximum up to digest length for sign, auto for verify */
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
    prsactx->min_saltlen = -1;
    return prsactx;
}

static void *rsa_dupctx(void *vprsactx)
{
    PROV_RSA_CTX *srcctx = (PROV_RSA_CTX *) vprsactx;
    PROV_RSA_CTX *dstctx;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL) {
        fprintf(stderr, "%s:%d:%s(): OPENSSL_zalloc failure\n",
                __FILE__, __LINE__, __func__);
    }

    *dstctx = *srcctx;
    /* reset pointers so that any goto err case can't lead to double free */
    dstctx->key = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->mgf1_md = NULL;
    dstctx->propq = NULL;
    dstctx->tbuf = NULL;

    if (srcctx->key != NULL) {
        (void) PROV_ATOMIC_INC(srcctx->key->refcnt);
        dstctx->key = srcctx->key;
    }

    if (srcctx->md != NULL) {
        EVP_MD_up_ref(srcctx->md);
        dstctx->md = srcctx->md;
    }

    if (srcctx->mgf1_md) {
        EVP_MD_up_ref(srcctx->mgf1_md);
        dstctx->mgf1_md = srcctx->mgf1_md;
    }

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx)) {
            fprintf(stderr, "%s:%d:%s(): Error in duplicating mdctx\n",__FILE__, __LINE__, __func__);
            goto err;
        }
    }

    if (srcctx->propq != NULL) {
        dstctx->propq = OPENSSL_strdup(srcctx->propq);
        if (dstctx->propq == NULL)
            goto err;
    }

    return dstctx;
err:
    rsa_freectx(dstctx);
    return NULL;
}

int prov_padding_add_PKCS1_PSS_mgf1(prov_rsa_key_data *rsa, unsigned char *EM,
                                   const unsigned char *mHash,
                                   const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                                   int sLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    unsigned char *H, *salt = NULL, *p;
    EVP_MD_CTX *ctx = NULL;
    int sLenMax = -1;

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_get_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is maximized
     *      -3      same as above (on signing)
     *      -4      salt length is min(hLen, maximum salt length)
     *      -N      reserved
     */
    /* FIPS 186-4 section 5 "The RSA Digital Signature Algorithm", subsection
     * 5.5 "PKCS #1" says: "For RSASSA-PSS […] the length (in bytes) of the
     * salt (sLen) shall satisfy 0 <= sLen <= hLen, where hLen is the length of
     * the hash function output block (in bytes)."
     *
     * Provide a way to use at most the digest length, so that the default does
     * not violate FIPS 186-4. */
    if (sLen == RSA_PSS_SALTLEN_DIGEST) {
        sLen = hLen;
    } else if (sLen == RSA_PSS_SALTLEN_MAX_SIGN
            || sLen == RSA_PSS_SALTLEN_AUTO) {
        sLen = RSA_PSS_SALTLEN_MAX;
    } else if (sLen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        sLen = RSA_PSS_SALTLEN_MAX;
        sLenMax = hLen;
    } else if (sLen < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        ERR_raise(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (rsa->n_len - 1) & 0x7;
    emLen = rsa->n_len;
    if (MSBits == 0) {
        *EM++ = 0;
        emLen--;
    }
    if (emLen < hLen + 2) {
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen == RSA_PSS_SALTLEN_MAX) {
        sLen = emLen - hLen - 2;
        if (sLenMax >= 0 && sLen > sLenMax)
            sLen = sLenMax;
    } else if (sLen > emLen - hLen - 2) {
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto err;
    }
    if (sLen > 0) {
        salt = OPENSSL_malloc(sLen);
        if (salt == NULL)
            goto err;
        if (RAND_bytes_ex(NULL, salt, sLen, 0) <= 0)
            goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;
    if (!EVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVP_DigestUpdate(ctx, zeroes, sizeof(zeroes))
        || !EVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (sLen && !EVP_DigestUpdate(ctx, salt, sLen))
        goto err;
    if (!EVP_DigestFinal_ex(ctx, H, NULL))
        goto err;

    /* Generate dbMask in place then perform XOR on it */
    if (PKCS1_MGF1(EM, maskedDBLen, H, hLen, mgf1Hash))
        goto err;

    p = EM;

    /*
     * Initial PS XORs with all zeroes which is a NOP so just update pointer.
     * Note from a test above this value is guaranteed to be non-negative.
     */
    p += emLen - sLen - hLen - 2;
    *p++ ^= 0x1;
    if (sLen > 0) {
        for (i = 0; i < sLen; i++)
            *p++ ^= salt[i];
    }
    if (MSBits)
        EM[0] &= 0xFF >> (8 - MSBits);

    /* H is already in place so just set final 0xbc */

    EM[emLen - 1] = 0xbc;

    ret = 1;

 err:
    EVP_MD_CTX_free(ctx);
    OPENSSL_clear_free(salt, (size_t)sLen); /* salt != NULL implies sLen > 0 */

    return ret;

}

static inline int
rsa_signverify_init(void *vctx, void *provkey,
        const OSSL_PARAM params[], int operation)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;

    if (!prov_is_running() || prsactx == NULL)
        return 0;

    if (provkey == NULL && prsactx->key == NULL) {
        fprintf(stderr, "%s:%d:%s(): RSA key is not set\n",__FILE__, __LINE__, __func__);
        return 0;
    }

    if (provkey != NULL) {
        PROV_ATOMIC_INC(((prov_rsa_key_data *) provkey)->refcnt);
        __prov_rsa_freedata(prsactx->key);
        prsactx->key = provkey;
    }

    if (unlikely(prov_rsa_check_modlen(prsactx->key) != 0)) {
        fprintf(stderr, "Mod length %u not in supported range\n", prsactx->key->n_len);
        return -1;
    }

    prsactx->operation = operation;
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
    prsactx->min_saltlen = -1;
    /* Default provider sets pad mode to RSA_PKCS1_PADDING as the default padding mode. */
    prsactx->pad_type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;

    if (!rsa_set_ctx_params(vctx, params))
        return 0;

    return 1;
}

static int rsa_sign_init(void *vctx, void *vrsa, const OSSL_PARAM params[])
{
    return rsa_signverify_init(vctx, vrsa, params, PROV_RSA_OP_SIGN);
}

static int rsa_verify_init(void *vctx, void *vrsa,
        const OSSL_PARAM params[])
{
    return rsa_signverify_init(vctx, vrsa, params,
            PROV_RSA_OP_VERIFY);
}


static inline void
rsa_xform_crt_setup(const prov_rsa_key_data * key, pal_rsa_ctx_t *pal_ctx)
{

    pal_ctx->rsa_n_data = key->n_data;
    pal_ctx->rsa_n_len = key->n_len;

    pal_ctx->rsa_e_data = key->e_data;
    pal_ctx->rsa_e_len = key->e_len;

    pal_ctx->rsa_qt_p_data = key->qt_p_data;
    pal_ctx->rsa_qt_p_len = key->qt_p_len;

    pal_ctx->rsa_qt_q_data = key->qt_q_data;
    pal_ctx->rsa_qt_q_len = key->qt_q_len;

    pal_ctx->rsa_qt_dP_data = key->qt_dP_data;
    pal_ctx->rsa_qt_dP_len = key->qt_dP_len;

    pal_ctx->rsa_qt_dQ_data = key->qt_dQ_data;
    pal_ctx->rsa_qt_dQ_len = key->qt_dQ_len;

    pal_ctx->rsa_qt_qInv_data = key->qt_qInv_data;
    pal_ctx->rsa_qt_qInv_len = key->qt_qInv_len;

    pal_ctx->rsa_key_type = PAL_RSA_KEY_TYPE_QT;

    return;
}

static inline void
rsa_xform_non_crt_setup(const prov_rsa_key_data * key, pal_rsa_ctx_t *pal_ctx)
{

    pal_ctx->rsa_n_data = key->n_data;
    pal_ctx->rsa_n_len = key->n_len;

    pal_ctx->rsa_e_data = key->e_data;
    pal_ctx->rsa_e_len = key->e_len;

    pal_ctx->rsa_d_data = key->d_data;
    pal_ctx->rsa_d_len = key->d_len;

    pal_ctx->rsa_key_type = PAL_RSA_KEY_TYPE_EXP;

    return;

}

static inline int rsa_sign(const unsigned char *from, int flen,
        unsigned char *to, size_t *to_len, PROV_RSA_CTX * ctx)
{
    int ret = 0, priv_sz;
    pal_rsa_ctx_t pal_ctx = {0};

    pal_ctx.padding = ctx->pad_type;

    /* PSS mode is not supported in HW at this point of time.
     * we build the PSS-encoded block in SW and pass it to PAL with padding set to NONE (zero) */
    if (pal_ctx.padding == RSA_PKCS1_PSS_PADDING)
    {
        pal_ctx.padding = RTE_CRYPTO_RSA_PADDING_NONE;
    }
    pal_ctx.async_cb = provider_ossl_handle_async_job;

    if ((pal_ctx.use_crt_method = ctx->key->use_crt) == 1)
	rsa_xform_crt_setup(ctx->key, &pal_ctx);
    else
	rsa_xform_non_crt_setup(ctx->key, &pal_ctx);


    ret = pal_rsa_priv_enc(&pal_ctx, flen, from, to);

    *to_len = ret;

    return ret;
}

static inline int
rsa_verify( unsigned char * decrypt_buf, const unsigned char *sign,
        int signlen, PROV_RSA_CTX * ctx)
{

    int ret = 0, priv_sz;
    pal_rsa_ctx_t pal_ctx = {0};

    pal_ctx.padding = ctx->pad_type;

    /* PSS mode is not supported in HW at this point of time.
     * we build the PSS-encoded block in SW and pass it to PAL with padding set to NONE (zero) */
    if (pal_ctx.padding == RSA_PKCS1_PSS_PADDING)
    {
        pal_ctx.padding = RTE_CRYPTO_RSA_PADDING_NONE;
    }
    pal_ctx.async_cb = provider_ossl_handle_async_job;

    rsa_xform_non_crt_setup(ctx->key, &pal_ctx);

    ret = pal_rsa_pub_dec(&pal_ctx, signlen, sign, decrypt_buf);

    if( ret < 0)
    {
        fprintf(stderr,"%s: pal_rsa_pub_dec failed\n",__func__);
        return -1;
    }

    return ret;

}


static int prov_rsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
        size_t sigsize, const unsigned char *tbs,
        size_t tbslen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;
    size_t rsasize = prov_rsa_key_len(prsactx->key);
    size_t sltmp = 0;
    int ret;

    if (!prov_is_running())
        return 0;

    if (sig == NULL) {
        *siglen = rsasize;
        return 1;
    }

    if (sigsize < rsasize) {
        fprintf(stderr,
                "%s:%d:%s(): out buffer size is %zu, should be at least "
                "%zu\n", __FILE__, __LINE__, __func__, sigsize, rsasize);
        return 0;
    }

    ret = rsa_sign(tbs, tbslen, sig, &sltmp, prsactx);

    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

int prov_rsa_verify_PKCS1_PSS_mgf1(prov_rsa_key_data *rsa, const unsigned char *mHash,
                              const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                              const unsigned char *EM, int sLen)
{
    int i;
    int ret = 0;
    int hLen, maskedDBLen, MSBits, emLen;
    const unsigned char *H;
    unsigned char *DB = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char H_[EVP_MAX_MD_SIZE];

    if (ctx == NULL)
        goto err;

    if (mgf1Hash == NULL)
        mgf1Hash = Hash;

    hLen = EVP_MD_get_size(Hash);
    if (hLen < 0)
        goto err;
    /*-
     * Negative sLen has special meanings:
     *      -1      sLen == hLen
     *      -2      salt length is autorecovered from signature
     *      -3      salt length is maximized
     *      -4      salt length is autorecovered from signature
     *      -N      reserved
     */
    if (sLen == RSA_PSS_SALTLEN_DIGEST) {
        sLen = hLen;
    } else if (sLen < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        ERR_raise(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
        goto err;
    }

    MSBits = (rsa->n_len - 1) & 0x7;
    emLen = rsa->n_len;
    if (EM[0] & (0xFF << MSBits)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_FIRST_OCTET_INVALID);
        goto err;
    }
    if (MSBits == 0) {
        EM++;
        emLen--;
    }
    if (emLen < hLen + 2) {
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (sLen == RSA_PSS_SALTLEN_MAX) {
        sLen = emLen - hLen - 2;
    } else if (sLen > emLen - hLen - 2) { /* sLen can be small negative */
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        goto err;
    }
    if (EM[emLen - 1] != 0xbc) {
        ERR_raise(ERR_LIB_RSA, RSA_R_LAST_OCTET_INVALID);
        goto err;
    }
    maskedDBLen = emLen - hLen - 1;
    H = EM + maskedDBLen;
    DB = OPENSSL_malloc(maskedDBLen);
    if (DB == NULL)
        goto err;
    if (PKCS1_MGF1(DB, maskedDBLen, H, hLen, mgf1Hash) < 0)
        goto err;
    for (i = 0; i < maskedDBLen; i++)
        DB[i] ^= EM[i];
    if (MSBits)
        DB[0] &= 0xFF >> (8 - MSBits);
    for (i = 0; DB[i] == 0 && i < (maskedDBLen - 1); i++) ;
    if (DB[i++] != 0x1) {
        ERR_raise(ERR_LIB_RSA, RSA_R_SLEN_RECOVERY_FAILED);
        goto err;
    }
    if (sLen != RSA_PSS_SALTLEN_AUTO
            && sLen != RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
            && (maskedDBLen - i) != sLen) {
        ERR_raise_data(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED,
                       "expected: %d retrieved: %d", sLen,
                       maskedDBLen - i);
        goto err;
    }
    if (!EVP_DigestInit_ex(ctx, Hash, NULL)
        || !EVP_DigestUpdate(ctx, zeroes, sizeof(zeroes))
        || !EVP_DigestUpdate(ctx, mHash, hLen))
        goto err;
    if (maskedDBLen - i) {
        if (!EVP_DigestUpdate(ctx, DB + i, maskedDBLen - i))
            goto err;
    }
    if (!EVP_DigestFinal_ex(ctx, H_, NULL))
        goto err;
    if (memcmp(H_, H, hLen)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
        ret = 0;
    } else {
        ret = 1;
    }

 err:
    OPENSSL_free(DB);
    EVP_MD_CTX_free(ctx);

    return ret;

}

static int prov_rsa_verify(void *vctx, const unsigned char *sig,
        size_t siglen, const unsigned char *tbs,
        size_t tbslen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;
    unsigned char decrypt_buf[siglen];
    int ret = 0;

    if (!prov_is_running())
        return 0;

    ret = rsa_verify(decrypt_buf, sig, siglen, prsactx);

    if ( memcmp(decrypt_buf, tbs, tbslen) || (ret <= 0) ) {
        fprintf(stderr, "compare failed\n");
        return 0;
    }

    return 1;
}

static void rsa_freectx(void *vctx)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;

    if (prsactx == NULL)
        return;

    __prov_rsa_freedata(prsactx->key);
    EVP_MD_CTX_free(prsactx->mdctx);
    EVP_MD_free(prsactx->md);
    EVP_MD_free(prsactx->mgf1_md);
    OPENSSL_free(prsactx->propq);
    free_tbuf(prsactx);
    OPENSSL_clear_free(prsactx, sizeof(*prsactx));

    return;
}

static int rsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;
    const OSSL_PARAM *p;
    int pad_type;
    int saltlen;

    if (prsactx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    /* EVP_PKEY_CTX_set_rsa_padding */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {

        switch (p->data_type) {
            case OSSL_PARAM_INTEGER:
                if (!OSSL_PARAM_get_int(p, &pad_type))
                    return 0;
                break;
            case OSSL_PARAM_UTF8_STRING:
                {
                    int i;

                    if (p->data == NULL)
                        return 0;
                    fprintf(stderr, "%s(): rsa pad type %p\n", __func__,
                            p->data);
                    for (i = 0; padding_item[i].id != 0; i++) {
                        if (strcmp(p->data, padding_item[i].ptr)
                                == 0) {
                            pad_type = padding_item[i].id;
                            break;
                        }
                    }
                }
                break;
            default:
                fprintf(stderr,
                        "%s:%d:%s(): Expected types are OSSL_PARAM_INTEGER,"
                        "OSSL_PARAM_UTF8_STRING\n", __FILE__, __LINE__,
                        __func__);
                return 0;
        }

        switch (pad_type) {
            case RSA_PKCS1_PADDING:
                prsactx->pad_type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
                break;
            case RSA_NO_PADDING:
                prsactx->pad_type = RTE_CRYPTO_RSA_PADDING_NONE;
                break;
            case RSA_PKCS1_PSS_PADDING:
                 prsactx->pad_type = RSA_PKCS1_PSS_PADDING;
                if ((prsactx->operation
                     & (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY)) == 0) {
                    fprintf(stderr,
                           "%s:%d:%s(): RSA PSS padding only allowed for sign and verify operations\n",
                            __FILE__, __LINE__, __func__);
                    return 0;
                }
                break;
            default:
                fprintf(stderr,
                        "%s:%d:%s(): RSA padding modes supported by mrvl_dpdk_provider"
                        " are %s, %s %d\n", __FILE__, __LINE__, __func__,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15,
                        OSSL_PKEY_RSA_PAD_MODE_NONE, pad_type);
                return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (prsactx->pad_type != RSA_PKCS1_PSS_PADDING) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "PSS saltlen can only be specified if "
                           "PSS padding has been specified first");
            return 0;
        }

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &saltlen))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                saltlen = RSA_PSS_SALTLEN_DIGEST;
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                saltlen = RSA_PSS_SALTLEN_MAX;
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                saltlen = RSA_PSS_SALTLEN_AUTO;
            else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX) == 0)
                saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
            else
                saltlen = atoi(p->data);
            break;
        default:
            return 0;
        }

        /*
         * RSA_PSS_SALTLEN_AUTO_DIGEST_MAX seems curiously named in this check.
         * Contrary to what it's name suggests, it's the currently lowest
         * saltlen number possible.
         */
        if (saltlen < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }

        if (prov_rsa_pss_restricted(prsactx)) {
            switch (saltlen) {
            case RSA_PSS_SALTLEN_AUTO:
            case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
                if (prsactx->operation == EVP_PKEY_OP_VERIFY) {
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH,
                                   "Cannot use autodetected salt length");
                    return 0;
                }
                break;
            case RSA_PSS_SALTLEN_DIGEST:
                if (prsactx->min_saltlen > EVP_MD_get_size(prsactx->md)) {
                    ERR_raise_data(ERR_LIB_PROV,
                                   PROV_R_PSS_SALTLEN_TOO_SMALL,
                                   "Should be more than %d, but would be "
                                   "set to match digest size (%d)",
                                   prsactx->min_saltlen,
                                   EVP_MD_get_size(prsactx->md));
                    return 0;
                }
                break;
            default:
                if (saltlen >= 0 && saltlen < prsactx->min_saltlen) {
                    ERR_raise_data(ERR_LIB_PROV,
                                   PROV_R_PSS_SALTLEN_TOO_SMALL,
                                   "Should be more than %d, "
                                   "but would be set to %d",
                                   prsactx->min_saltlen, saltlen);
                    return 0;
                }
            }
        }
    }
    prsactx->saltlen = saltlen;
    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rsa_settable_ctx_params(void *vctx,
        ossl_unused void *provctx)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;

    return settable_ctx_params;
}

// DIGEST FUNCTION START
static int rsa_digest_sign_final(void *vprsactx, unsigned char *sig,
        size_t *siglen, size_t sigsize)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vprsactx;
    unsigned char digest[PROV_MAX_MD_SIZE];
    const unsigned char *encoded_digest = NULL;
    int md_type = EVP_MD_type(prsactx->md);
    unsigned char *tmp = NULL;
    unsigned int dlen = 0;
    size_t encoded_len = 0;
    int ret = 0;

    if (unlikely
            (prsactx->mdctx == NULL || md_type == NID_undef)) {
        fprintf(stderr, "%s:%d%s() Sanity check failed\n",__FILE__, __LINE__, __func__);
        return 0;
    }

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to rsa_sign.
     */
    if (sig == NULL) {
        *siglen = (size_t) prov_rsa_key_len(prsactx->key);
        return 1;
    }

    if (unlikely(!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))) {
        fprintf(stderr,
                "%s:%d%s() Error in computing the message digest\n",__FILE__, __LINE__, __func__);
        return 0;
    }

    switch (prsactx->pad_type) {
        case RTE_CRYPTO_RSA_PADDING_PKCS1_5 || RTE_CRYPTO_RSA_PADDING_NONE:
        {
            /* Compute the EMSA-PKCS1-V1_5 encoded digest. This encoding is not
            * applicable to RSA-PSS sign. PSS mode is not supported in HW at this
            * point of time. */
            if (md_type == NID_md5_sha1) {
                if (dlen != SSL_SIG_LENGTH) {
                    fprintf(stderr,
                        "%s:%d:%s(): Invalid digest size for MD5+SHA1\n",__FILE__, __LINE__, __func__);
                    return 0;
                }
                encoded_len = SSL_SIG_LENGTH;
                encoded_digest = digest;
            } else {
                if (!encode_pkcs1(&tmp, &encoded_len, md_type, digest, dlen))
                    goto err;
                encoded_digest = tmp;
            }

            if (encoded_len + RSA_PKCS1_PADDING_SIZE >
                    prov_rsa_key_len(prsactx->key)) {
                fprintf(stderr,
                        "%s:%d:%s(): Encoded digest too big for RSA key\n",
                        __FILE__, __LINE__, __func__);
                goto err;
            }

            ret = prov_rsa_sign(vprsactx, sig, siglen, sigsize, encoded_digest,
                    (size_t) encoded_len);
        }
        break;

        case RSA_PKCS1_PSS_PADDING:
            /* Check PSS restrictions */
            if (prov_rsa_pss_restricted(prsactx)) {
                switch (prsactx->saltlen) {
                case RSA_PSS_SALTLEN_DIGEST:
                    if (prsactx->min_saltlen > EVP_MD_get_size(prsactx->md)) {
                        ERR_raise_data(ERR_LIB_PROV,
                                       PROV_R_PSS_SALTLEN_TOO_SMALL,
                                       "minimum salt length set to %d, "
                                       "but the digest only gives %d",
                                       prsactx->min_saltlen,
                                       EVP_MD_get_size(prsactx->md));
                        return 0;
                    }
                default:
                    if (prsactx->saltlen >= 0
                        && prsactx->saltlen < prsactx->min_saltlen) {
                        ERR_raise_data(ERR_LIB_PROV,
                                       PROV_R_PSS_SALTLEN_TOO_SMALL,
                                       "minimum salt length set to %d, but the"
                                       "actual salt length is only set to %d",
                                       prsactx->min_saltlen,
                                       prsactx->saltlen);
                        return 0;
                    }
                    break;
                }
            }
            if (!setup_tbuf(prsactx))
                return 0;
            if (!prov_padding_add_PKCS1_PSS_mgf1(prsactx->key,
                                                prsactx->tbuf, digest,
                                                prsactx->md, prsactx->mgf1_md,
                                                prsactx->saltlen)) {
                ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                return 0;
            }
            ret = prov_rsa_sign(vprsactx, sig, siglen, sigsize, prsactx->tbuf,
                                prsactx->key->n_len);
            clean_tbuf(prsactx);
            break;

        default:
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           "Only X.931, PKCS#1 v1.5 or PSS padding allowed");
            return 0;
    }
err:
    OPENSSL_free(tmp);
    return ret;
}

static int rsa_digest_verify_final(void *vprsactx,
        const unsigned char *sig, size_t siglen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vprsactx;
    size_t decrypt_len = 0, encoded_len = 0;
    unsigned int digest_len;
    unsigned char digest_buf[PROV_MAX_MD_SIZE];
    unsigned char decrypt_buf[siglen];
    unsigned char *encoded = NULL;
    unsigned char *tmp;
    int ret = 0;

    if (unlikely
            (prsactx->mdctx == NULL)) {
        fprintf(stderr, "%s:%d%s() Sanity check failed\n",__FILE__, __LINE__, __func__);
        return 0;
    }

    if (!EVP_DigestFinal_ex(prsactx->mdctx, digest_buf, &digest_len)) {
        fprintf(stderr,
                "%s:%d%s() Error in computing the message digest\n",__FILE__, __LINE__, __func__);
        return 0;
    }

    switch (prsactx->pad_type) {
        case RTE_CRYPTO_RSA_PADDING_PKCS1_5 || RTE_CRYPTO_RSA_PADDING_NONE:
            {
                ret = rsa_verify(decrypt_buf, sig, siglen, vprsactx);
                decrypt_len = ret;

                if ((ret < 0) || ((size_t) digest_len > decrypt_len)) {
                    fprintf(stderr,
                        "%s:%d:%s(): Error in decrypting the sign (or) mdlen %zu >  dlen %zu\n",
                        __FILE__, __LINE__, __func__,(size_t) digest_len, decrypt_len);
                    return 0;
                }

                /*
                * If recovering the digest, extract a digest-sized output from the end
                * of |decrypt_buf| for |encode_pkcs1|, then compare the decryption
                * output as in a standard verification.
                */
                tmp = decrypt_buf + decrypt_len - digest_len;

                if (unlikely
                    (!encode_pkcs1
                    (&encoded, &encoded_len, EVP_MD_type(prsactx->md), tmp,
                    digest_len))) {
                        fprintf(stderr, "%s:%d:%s(): Error in encode_pkcs1\n", __FILE__,
                            __LINE__, __func__);
                        goto err;
                    }

                if (encoded_len != decrypt_len
                    || memcmp(encoded, decrypt_buf, encoded_len) != 0) {
                        fprintf(stderr, "%s:%d:%s(): Digest verification NOT OK\n",
                            __FILE__, __LINE__, __func__);
                    goto err;
                }

                ret = 1;
            }
            break;

        case RSA_PKCS1_PSS_PADDING:
            {
                size_t mdsize;

                /*
                 * We need to check this for the RSA_verify_PKCS1_PSS_mgf1()
                 * call
                 */
                mdsize = EVP_MD_get_size(prsactx->md);
                if (digest_len != mdsize) {
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                                   "Should be %d, but got %d",
                                   mdsize, digest_len);
                    return 0;
                }

                if (!setup_tbuf(prsactx))
                    return 0;
                ret = rsa_verify(decrypt_buf, sig, siglen, prsactx);
                if (ret <= 0) {
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    return 0;
                }
                if ( memcmp(decrypt_buf, digest_buf, digest_len) || (ret <= 0) ) {
                    fprintf(stderr, "compare failed\n");
                    return 0;
                }
                ret = prov_rsa_verify_PKCS1_PSS_mgf1(prsactx->key, digest_buf,
                                                prsactx->md, prsactx->mgf1_md,
                                                prsactx->tbuf,
                                                prsactx->saltlen);
                if (ret <= 0) {
                    ERR_raise(ERR_LIB_PROV, ERR_R_RSA_LIB);
                    return 0;
                }
                return 1;
            }
        default:
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           "Only X.931, PKCS#1 v1.5 or PSS padding allowed");
            return 0;
        }
err:
    OPENSSL_free(encoded);
    return ret;
}

static int rsa_digest_signverify_update(void *vprsactx,
        const unsigned char *data,
        size_t datalen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vprsactx;

    if (prsactx == NULL || prsactx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(prsactx->mdctx, data, datalen);
}

static int rsa_digest_sign(void *vprsactx, unsigned char *sig,
        size_t *siglen, size_t sigsize,
        const unsigned char *data, size_t datalen)
{

    return rsa_digest_signverify_update(vprsactx, data, datalen)
        && rsa_digest_sign_final(vprsactx, sig, siglen, sigsize);
}

static int rsa_digest_verify(void *vprsactx, const unsigned char *sig,
        size_t siglen, const unsigned char *data,
        size_t datalen)
{
    return rsa_digest_signverify_update(vprsactx, data, datalen)
        && rsa_digest_verify_final(vprsactx, sig, siglen);
}

static inline int rsa_setup_md(PROV_RSA_CTX * prsactx, const char *mdname,
        const char *mdprops)
{

    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(prsactx->libctx, mdname, mdprops);
        size_t mdname_len = strlen(mdname);

        if (md == NULL) {
            fprintf(stderr,
                    "%s:%d:%s(): Error fetching message digest algorithm %s\n",
                    __FILE__, __LINE__, __func__, mdname);
            ERR_print_errors_fp(stderr);
            EVP_MD_free(md);
            return 0;
        }

        if (mdname_len >= sizeof(prsactx->mdname)) {
            fprintf(stderr,
                    "%s:%d:%s(): string len of `%s` exceeds name buffer length\n",
                    __FILE__, __LINE__, __func__, mdname);
            EVP_MD_free(md);
            return 0;
        }

        /* Release existing message digest context and EVP_MD */
        EVP_MD_CTX_free(prsactx->mdctx);
        EVP_MD_free(prsactx->md);

        prsactx->mdctx = NULL;
        prsactx->md = md;
        OPENSSL_strlcpy(prsactx->mdname, mdname, sizeof(prsactx->mdname));
    }

    return 1;
}

static int rsa_digest_signverify_init(void *vprsactx, const char *mdname,
        void *vrsa,
        const OSSL_PARAM params[],
        int operation)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vprsactx;
    const char *properties = "provider=default";

    if (!rsa_signverify_init(vprsactx, vrsa, params, operation))
        return 0;

    if (mdname != NULL
            && (mdname[0] == '\0'
                || OPENSSL_strcasecmp(prsactx->mdname, mdname) != 0)
            && !rsa_setup_md(prsactx, mdname, properties))
        return 0;

    //prsactx->flag_allow_md = 0;

    if (prsactx->mdctx == NULL) {
        prsactx->mdctx = EVP_MD_CTX_new();
        if (prsactx->mdctx == NULL)
            goto error;
    }

    if (!EVP_DigestInit_ex2(prsactx->mdctx, prsactx->md, params))
        goto error;

    return 1;

error:
    EVP_MD_CTX_free(prsactx->mdctx);
    prsactx->mdctx = NULL;
    return 0;
}

static int rsa_digest_sign_init(void *vprsactx, const char *mdname,
        void *vrsa, const OSSL_PARAM params[])
{
    return rsa_digest_signverify_init(vprsactx, mdname, vrsa,
            params, EVP_PKEY_OP_SIGN);
}

static int rsa_digest_verify_init(void *vprsactx, const char *mdname,
        void *vrsa, const OSSL_PARAM params[])
{
    return rsa_digest_signverify_init(vprsactx, mdname, vrsa,
            params, EVP_PKEY_OP_VERIFY);
}

// DIEST FUNCTION END

const OSSL_DISPATCH prov_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) rsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) rsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) prov_rsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) rsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) prov_rsa_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) rsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) rsa_dupctx },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        (void (*)(void)) rsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (void (*)(void)) rsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        (void (*)(void)) rsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        (void (*)(void)) rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        (void (*)(void)) rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        (void (*)(void)) rsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        (void (*)(void)) rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        (void (*)(void)) rsa_digest_verify_final },
    { 0, NULL }
};
