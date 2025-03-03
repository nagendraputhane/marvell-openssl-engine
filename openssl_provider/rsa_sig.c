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
#include "pal/pal.h"
#include "pal/pal_rsa.h"
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
} PROV_RSA_CTX;

static inline int prov_rsa_check_modlen(prov_rsa_key_data * key)
{
    int16_t modlen = key->n_len;

    return pal_asym_xform_capability_check_modlen(modlen);
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
    dstctx->propq = NULL;

    if (srcctx->key != NULL) {
        (void) PROV_ATOMIC_INC(srcctx->key->refcnt);
        dstctx->key = srcctx->key;
    }

    if (srcctx->md != NULL) {
        EVP_MD_up_ref(srcctx->md);
        dstctx->md = srcctx->md;
    }

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx)) {
            fprintf(stderr, "%s:%d:%s(): Error in duplicating mdctx\n");
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

static inline int
rsa_signverify_init(void *vctx, void *provkey,
        const OSSL_PARAM params[], int operation)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;

    if (!prov_is_running() || prsactx == NULL)
        return 0;

    if (provkey == NULL && prsactx->key == NULL) {
        fprintf(stderr, "%s:%d:%s(): RSA key is not set\n", __func__);
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

    if(!prov_asym_get_valid_devid_qid(&pal_ctx.dev_id, &pal_ctx.qp_id))
        return -1;

    pal_ctx.padding = ctx->pad_type;
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

    if(!prov_asym_get_valid_devid_qid(&pal_ctx.dev_id, &pal_ctx.qp_id))
        return -1;

    pal_ctx.padding = ctx->pad_type;
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
    OPENSSL_free(prsactx->propq);
    OPENSSL_clear_free(prsactx, sizeof(*prsactx));

    return;
}

static int rsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *) vctx;
    const OSSL_PARAM *p;
    int pad_type;

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
                    fprintf(stderr, "%s(): rsa pad type %s\n", __func__,
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
            default:
                fprintf(stderr,
                        "%s:%d:%s(): RSA padding modes supported by mrvl_dpdk_provider"
                        " are %s, %s %d\n", __FILE__, __LINE__, __func__,
                        OSSL_PKEY_RSA_PAD_MODE_PKCSV15,
                        OSSL_PKEY_RSA_PAD_MODE_NONE, pad_type);
                return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
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
            (prsactx->mdctx == NULL || md_type == NID_undef
             || prsactx->pad_type != RTE_CRYPTO_RSA_PADDING_PKCS1_5)) {
        fprintf(stderr, "%s:%d%s() Sanity check failed\n");
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
                "%s:%d%s() Error in computing the message digest\n");
        return 0;
    }

    /* Compute the EMSA-PKCS1-V1_5 encoded digest. This encoding is not
     * applicable to RSA-PSS sign. PSS mode is not supported in HW at this
     * point of time. */
    if (md_type == NID_md5_sha1) {
        if (dlen != SSL_SIG_LENGTH) {
            fprintf(stderr,
                    "%s:%d:%s(): Invalid digest size for MD5+SHA1\n");
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
            (prsactx->mdctx == NULL
             || prsactx->pad_type != RTE_CRYPTO_RSA_PADDING_PKCS1_5)) {
        fprintf(stderr, "%s:%d%s() Sanity check failed\n");
        return 0;
    }

    if (!EVP_DigestFinal_ex(prsactx->mdctx, digest_buf, &digest_len)) {
        fprintf(stderr,
                "%s:%d%s() Error in computing the message digest\n");
        return 0;
    }

    ret = rsa_verify(decrypt_buf, sig, siglen, vprsactx);

    decrypt_len = ret;

    if ((ret < 0) || ((size_t) digest_len > decrypt_len)) {
        fprintf(stderr,
                "%s:%d:%s(): Error in decrypting the sign (or) mdlen %zu >  dlen %zu\n",
                __FILE__, __LINE__, __func__, digest_len, decrypt_len);
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
