/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "prov.h"
#include "ciphercommon.h"
#include "ciphercommon_aead.h"
#include "pal/pal.h"
#include "pal/pal_gcm.h"

#define PROV_CIPHER_GCM_TAG_MAX_SIZE    16
#define SSL_MAX_PIPELINES   32

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

typedef struct __attribute__((aligned(OCTEON_CACHE_LINE_SIZE))) {
    pal_gcm_ctx_t pal_ctx;
    uint8_t buf[16];
    int tls_aad_pad_sz;
    int taglen;
    uint8_t key_set:1;
    uint8_t iv_set:1;
    uint8_t iv_gen:1;

    OSSL_LIB_CTX *libctx;    /* Needed for rand calls */
} PROV_AES_GCM_CTX;

/*
 * provider functions to export aes gcm
 */
OSSL_FUNC_cipher_encrypt_init_fn prov_aes_gcm_einit;
OSSL_FUNC_cipher_decrypt_init_fn prov_aes_gcm_dinit;
OSSL_FUNC_cipher_update_fn prov_aes_gcm_stream_update;
OSSL_FUNC_cipher_final_fn prov_aes_gcm_stream_final;
OSSL_FUNC_cipher_cipher_fn prov_aes_gcm_cipher;
OSSL_FUNC_cipher_get_ctx_params_fn prov_aes_gcm_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn prov_aes_gcm_set_ctx_params;
static void prov_aes_gcm_freectx(void *vctx);
static void *prov_aes_gcm_newctx(void *provctx, size_t kbits);


static inline int
prov_hw_aes_gcm_init_key(PROV_AES_GCM_CTX *gcm_ctx, const unsigned char *key,
        int key_len, pal_gcm_ctx_t *pal_ctx)
{
    int retval;

    if (key == NULL)
        return 1;

    if(!prov_sym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->sym_queue))
        return 0;

    pal_ctx->keylen = key_len;
    memcpy(pal_ctx->key, key, key_len);
    gcm_ctx->key_set = 1;

    retval = pal_create_aead_session(PAL_CRYPTO_AEAD_AES_GCM,
            pal_ctx, EVP_AEAD_TLS1_AAD_LEN, 0);
    if (retval < 0) {
        engine_log(ENG_LOG_ERR, "AEAD Sesion creation failed.\n");
        return 0;
    }

    retval = pal_create_cipher_session(PAL_CRYPTO_CIPHER_AES_CTR,
            pal_ctx);
    if (retval < 0) {
        engine_log(ENG_LOG_ERR, "Cipher Sesion creation failed.\n");
        return 0;
    }

    pal_ctx->numpipes = 0;
    return 1;
}


static int getivgen(PROV_AES_GCM_CTX *gcm_ctx, unsigned char *out, size_t olen)
{
    pal_gcm_ctx_t *ctx = &gcm_ctx->pal_ctx;

    if (gcm_ctx->iv_gen == 0 || gcm_ctx->key_set == 0)
        return 0;

    memcpy((uint8_t *)ctx->iv + ctx->ivlen - olen,
            &ctx->iv[2], olen);

    if (olen <= 0 || olen > ctx->ivlen)
        olen = ctx->ivlen;

    memcpy(out, &ctx->iv[2], olen);
    /*
     * Invocation field will be at least 8 bytes in size and
     * so no need to check wrap around or increment more than
     * last 8 bytes.
     */
    ctx->iv[2]++;
    gcm_ctx->iv_set = 1;
    return 1;
}

static inline int
gcm_tls_iv_set_fixed(PROV_AES_GCM_CTX *gcm_ctx, unsigned char *iv,
        size_t len)
{
    pal_gcm_ctx_t *ctx = &gcm_ctx->pal_ctx;

    /* Special case: -1 length restores whole IV */
    if (len == (size_t)-1) {
        memcpy(ctx->iv, iv, ctx->ivlen);
        gcm_ctx->iv_gen = 1;
        return 1;
    }
    /* Fixed field must be at least 4 bytes and invocation field at least 8 */
    if ((len < EVP_GCM_TLS_FIXED_IV_LEN)
            || (ctx->ivlen - (int)len) < EVP_GCM_TLS_EXPLICIT_IV_LEN)
        return 0;
    if (len > 0)
        memcpy((uint8_t *)ctx->iv, iv, len);
    if (ctx->enc
            && RAND_bytes_ex(gcm_ctx->libctx, (uint8_t *)&ctx->iv[2], ctx->ivlen - len, 0) <= 0)
        return 0;
    gcm_ctx->iv_gen = 1;
    return 1;
}

static int setivinv(PROV_AES_GCM_CTX *gcm_ctx, unsigned char *in, size_t inl)
{
    pal_gcm_ctx_t *ctx = &gcm_ctx->pal_ctx;

    if (!gcm_ctx->iv_gen
            || !gcm_ctx->key_set
            || ctx->enc)
        return 0;

    memcpy((uint8_t *)ctx->iv + ctx->ivlen - inl, in, inl);
    gcm_ctx->iv_set = 1;
    return 1;
}

static int provider_aes_gcm_ctx_control(void *vctx, int enc, int arg, void * ptr)
{

    PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *)vctx;
    if (enc)
    {
        if (!getivgen(ctx, (unsigned char *) ptr, arg))
            return 0;
    }
    else
    {
        if (!setivinv(ctx,  (unsigned char *)ptr, arg))
            return 0;
    }

    return 1;
}


/*
 * Normal crypto application
 */
static inline int
crypto_gcm_cipher(PROV_AES_GCM_CTX *gcm_ctx, unsigned char *out,
        size_t* outl, const unsigned char *in, size_t len)
{
    int ret = 0;
    pal_gcm_ctx_t *prov_ctx = &gcm_ctx->pal_ctx;
    int enc = prov_ctx->enc;

    if (in != NULL) {
        if (out == NULL) {
            if (!prov_ctx->aad) {
                prov_ctx->aad =  pal_malloc(sizeof(uint8_t) * len);
                if (!prov_ctx->aad)
                {
                    fprintf(stderr, "AAD memory alloc failed\n");
                    return -1;
                }
            }

            memcpy(prov_ctx->aad, in, len);
            if ((size_t)prov_ctx->aad_len != len) {

                ret = pal_create_aead_session(PAL_CRYPTO_AEAD_AES_GCM,
                        prov_ctx, len, 1);
                if (ret < 0) {
                    engine_log(ENG_LOG_ERR, "Create aead session "
                            "failed\n");
                    return ret;
                }

            }
            prov_ctx->aad_len = len;
            *outl = len;
            return 1;
        }
    } else {
        if (!enc) {
            if (gcm_ctx->taglen < 0)
                return -1;

            memcpy(prov_ctx->auth_tag,
                    gcm_ctx->buf, 16);
            return 1;
        }
        memcpy(prov_ctx->auth_tag, gcm_ctx->buf, 16);
        gcm_ctx->taglen = 16;
        /* Don't reuse the IV */
        return 1;
    }

    ret = pal_crypto_gcm_non_tls_cipher(prov_ctx, out,in, len, gcm_ctx->buf);
    *outl = ret;
    return ret;
}

static inline int prov_hw_aes_gcm_cipher(PROV_AES_GCM_CTX *gcm_ctx, unsigned char *out,
        size_t* outl, const unsigned char *in, size_t len)
{
    int ret = 0;
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *wctx = NULL;

    pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;

    /* If not set up, return error */
    if (!gcm_ctx->key_set)
        return -1;

    job = ASYNC_get_current_job();
    if (job != NULL)
        wctx = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

    if (pal_ctx->tls_aad_len >= 0)
    {
        /* Bydefault number of pipe is one */
        if (pal_ctx->numpipes == 0) {
            pal_ctx->numpipes = 1;
            pal_ctx->input_buf = (uint8_t **)&in;
            pal_ctx->output_buf = &out;
            pal_ctx->input_len = &len;
        }

        /* Encrypt/decrypt must be performed in place */
        if (out != in ||
                len < (pal_ctx->tls_exp_iv_len + pal_ctx->tls_tag_len))
            return -1;

        ret = pal_aes_gcm_tls_cipher(pal_ctx, gcm_ctx->buf, (void*)gcm_ctx, wctx);
        gcm_ctx->iv_set = 0;

        if (ret < 0)
            return -1;
        else
        {
            *outl = ret;
            return 1;
        }

    }

    if (!gcm_ctx->iv_set)
        return -1;

    ret = crypto_gcm_cipher(gcm_ctx, out, outl, in, len);
    if (ret < 0)
        return -1;
    else
        ret = 1;

    return ret;
}

static inline int
gcm_tls1_aad(PROV_AES_GCM_CTX *gcm_ctx,  pal_gcm_ctx_t *pal_ctx, unsigned char *aad, size_t aad_len)
{
    unsigned char *buf;
    size_t len;

    if (!prov_is_running() || aad_len != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    /* Save the aad for later use. */
    buf = gcm_ctx->buf;
    memcpy(buf, aad, aad_len);
    pal_ctx->tls_aad_len = aad_len;
    len = buf[aad_len - 2] << 8 | buf[aad_len - 1];
    /* Correct length for explicit iv. */
    if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
        return 0;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

    /* If decrypting correct for tag too. */
    if (!pal_ctx->enc) {
        if (len < EVP_GCM_TLS_TAG_LEN)
            return 0;
        len -= EVP_GCM_TLS_TAG_LEN;
    }
    buf[aad_len - 2] = (unsigned char)(len >> 8);
    buf[aad_len - 1] = (unsigned char)(len & 0xff);

    /* For pipeline */
    if (pal_ctx->aad_cnt < SSL_MAX_PIPELINES) {
        memcpy(pal_ctx->aad_pipe[pal_ctx->aad_cnt],
                buf, aad_len);
        pal_ctx->aad_cnt++;
    } else {
        fprintf(stderr, "In a single go, max. AAD count is 32\n");
        return 0;
    }

    /* Extra padding: tag appended to record. */
    return EVP_GCM_TLS_TAG_LEN;
}

int prov_aes_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AES_GCM_CTX *gcm_ctx = (PROV_AES_GCM_CTX *)vctx;
    pal_gcm_ctx_t *ctx = &gcm_ctx->pal_ctx;
    OSSL_PARAM *p;
    size_t sz;
    int ret;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }


    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        size_t taglen = (gcm_ctx->taglen != -1) ? gcm_ctx->taglen :
            PROV_CIPHER_GCM_TAG_MAX_SIZE;
        if (!OSSL_PARAM_set_size_t(p, taglen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (ctx->ivlen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }

        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)
                && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (ctx->ivlen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)
                && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }


    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, gcm_ctx->tls_aad_pad_sz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        sz = p->data_size;
        if (sz == 0
                || sz > EVP_GCM_TLS_TAG_LEN
                || !ctx->enc
                || gcm_ctx->taglen < 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->auth_tag, sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
    if (p != NULL) {
        if (!getivgen(gcm_ctx, p->data, p->data_size))
            return 0;
    }

    return 1;
}

int prov_aes_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_GCM_CTX *gcm_ctx = (PROV_AES_GCM_CTX *)vctx;
    pal_gcm_ctx_t *ctx = &gcm_ctx->pal_ctx;
    const OSSL_PARAM *p;
    size_t sz;
    void *vp;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        vp = ctx->aad;
        if (!OSSL_PARAM_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || ctx->enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return 0;
        }
        gcm_ctx->taglen = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || sz > sizeof(ctx->iv)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->ivlen = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        sz = gcm_tls1_aad(gcm_ctx, ctx, p->data, p->data_size);
        if (sz == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_AAD);
            return 0;
        }
        gcm_ctx->tls_aad_pad_sz = sz;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (gcm_tls_iv_set_fixed(gcm_ctx, p->data, p->data_size) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
    if (p != NULL) {
        if (p->data == NULL
                || p->data_type != OSSL_PARAM_OCTET_STRING
                || !setivinv(gcm_ctx, p->data, p->data_size))
            return 0;
    }

    return 1;
}

void prov_gcm_initctx(void *provctx, PROV_AES_GCM_CTX *gcm_ctx, size_t keybits)
{
    pal_gcm_ctx_t *prov_ctx = &gcm_ctx->pal_ctx;

    memset(gcm_ctx, 0, sizeof(PROV_AES_GCM_CTX));
    gcm_ctx->key_set = 0;
    prov_ctx->ivlen = PAL_AES_GCM_IV_LENGTH;
    prov_ctx->keylen = keybits / 8;
    gcm_ctx->taglen = -1;
    prov_ctx->aad_len = -1;
    gcm_ctx->iv_gen = 0;
    prov_ctx->tls_aad_len = -1;
    prov_ctx->numpipes = 0;
    gcm_ctx->libctx = PROV_LIBCTX_OF(provctx);
    prov_ctx->aad_cnt = 0;
    prov_ctx->tls_exp_iv_len = EVP_GCM_TLS_EXPLICIT_IV_LEN;
    prov_ctx->tls_tag_len = EVP_GCM_TLS_TAG_LEN;
    prov_ctx->sym_queue = 0;
    prov_ctx->iv_cb = provider_aes_gcm_ctx_control;
    prov_ctx->async_cb = provider_ossl_handle_async_job;
}

static void *prov_aes_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_AES_GCM_CTX *ctx;

    if (!prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        prov_gcm_initctx(provctx, ctx, keybits);

    return ctx;
}

static void prov_aes_gcm_freectx(void *vctx)
{
    PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *)vctx;

    if (ctx->pal_ctx.aad)
    {
        pal_free(ctx->pal_ctx.aad);
        ctx->pal_ctx.aad = NULL;
    }

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static int gcm_init_internal(void *vctx, const unsigned char *key, size_t keylen,
        const unsigned char *iv, size_t ivlen,
        const OSSL_PARAM params[], int enc)
{
    PROV_AES_GCM_CTX *gcm_ctx = (PROV_AES_GCM_CTX *)vctx;

    pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;

    if (!prov_is_running())
        return 0;

    pal_ctx->enc = enc;

    if (iv != NULL) {
        if (ivlen == 0 || ivlen > sizeof(pal_ctx->iv)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        pal_ctx->ivlen = ivlen;
        memcpy(pal_ctx->iv, iv, ivlen);
        gcm_ctx->iv_set = 1;
    }

    if (key != NULL) {
        if (keylen != pal_ctx->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!prov_hw_aes_gcm_init_key(gcm_ctx, key, pal_ctx->keylen, pal_ctx))
            return 0;
    }
    return prov_aes_gcm_set_ctx_params(gcm_ctx, params);
}

int prov_aes_gcm_einit(void *vctx, const unsigned char *key, size_t keylen,
        const unsigned char *iv, size_t ivlen,
        const OSSL_PARAM params[])
{
    return gcm_init_internal(vctx, key, keylen, iv, ivlen, params, 1);
}

int prov_aes_gcm_dinit(void *vctx, const unsigned char *key, size_t keylen,
        const unsigned char *iv, size_t ivlen,
        const OSSL_PARAM params[])
{
    return gcm_init_internal(vctx, key, keylen, iv, ivlen, params, 0);
}

int prov_aes_gcm_stream_update(void *vctx, unsigned char *out, size_t *outl,
        size_t outsize, const unsigned char *in, size_t inl)
{
    PROV_AES_GCM_CTX *gcm_ctx = (PROV_AES_GCM_CTX *)vctx;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (prov_hw_aes_gcm_cipher(gcm_ctx, out, outl, in, inl) <= 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }
    return 1;
}

int prov_aes_gcm_stream_final(void *vctx, unsigned char *out, size_t *outl,
        size_t outsize)
{
    PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *)vctx;
    int i;

    if (!prov_is_running())
        return 0;

    i = prov_hw_aes_gcm_cipher(ctx, out, outl, NULL, 0);
    if (i <= 0)
        return 0;

    *outl = 0;
    return 1;
}

int prov_aes_gcm_cipher(void *vctx,
        unsigned char *out, size_t *outl, size_t outsize,
        const unsigned char *in, size_t inl)
{
    PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *)vctx;

    if (!prov_is_running())
        return 0;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (prov_hw_aes_gcm_cipher(ctx, out, outl, in, inl) <= 0)
        return 0;

    *outl = inl;
    return 1;
}

/* prov_aes128gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96);

/* prov_aes256gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96);

