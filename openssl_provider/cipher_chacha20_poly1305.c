/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <stdint.h>
#include <openssl/proverr.h>
#include "prov.h"
#include "ciphercommon.h"
#include "pal.h"
#include "pal_cpoly.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define PROV_CIPHER_CPOLY_BLOCK_SIZE		1
#define PROV_CIPHER_POLY1305_BLOCK_SIZE		16
#define PROV_CIPHER_CPOLY_IV_LEN			12
#define PROV_CIPHER_CPOLY_MAX_IVLEN         12
#define SSL_MAX_PIPELINES   32
#define PROV_CIPHER_CPOLY_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

/*
 * provider functions to export aes gcm
 */
static OSSL_FUNC_cipher_newctx_fn prov_chacha20_poly1305_newctx;
static OSSL_FUNC_cipher_freectx_fn prov_chacha20_poly1305_freectx;
static OSSL_FUNC_cipher_encrypt_init_fn prov_chacha20_poly1305_einit;
static OSSL_FUNC_cipher_decrypt_init_fn prov_chacha20_poly1305_dinit;
static OSSL_FUNC_cipher_get_params_fn prov_chacha20_poly1305_get_params;
static OSSL_FUNC_cipher_final_fn prov_chacha20_poly1305_final;
static OSSL_FUNC_cipher_cipher_fn prov_chacha20_poly1305_cipher;
static OSSL_FUNC_cipher_get_ctx_params_fn prov_chacha20_poly1305_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn prov_chacha20_poly1305_set_ctx_params;
#define prov_chacha20_poly1305_settable_ctx_params prov_cipher_aead_settable_ctx_params
#define prov_chacha20_poly1305_gettable_params prov_cipher_generic_gettable_params
#define prov_chacha20_poly1305_update prov_chacha20_poly1305_cipher

static inline int prov_hw_chacha20_poly1305_init_key(pal_cpoly_ctx_t *pal_ctx,
        const unsigned char *key, int key_len, int enc)
{
    if (key == NULL)
        return 1;

    pal_ctx->key_len = key_len;
    memcpy(pal_ctx->key, key, key_len);
    pal_ctx->auth_taglen = PAL_CPOLY_AEAD_DIGEST_LEN;
    pal_ctx->aad_len = EVP_AEAD_TLS1_AAD_LEN;
    pal_ctx->numpipes = 0;

    int retval = pal_create_cpoly_aead_session(
            pal_ctx, pal_ctx->aad_len, 0);
    if (retval < 0) {
        fprintf(stderr, "%s() AEAD Sesion creation failed\n", __func__);
        return 0;
    }
    return 1;
}


static inline int chacha20_poly1305_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
        size_t *outl, const unsigned char *in, size_t len)
{
    int retval = 0, enc;
    enc = pal_ctx->enc;

    if (in != NULL) {
        if (out == NULL) {
            memcpy(pal_ctx->aad, in, len);
            if ((size_t)pal_ctx->aad_len != len) {
                retval = pal_create_cpoly_aead_session(pal_ctx, len, 1);
                if (retval < 0)
                    return retval;

            }
            pal_ctx->aad_len = len;
            *outl = len;
            return 1;
        }
    } else {
        if (!enc) {
            if (pal_ctx->auth_taglen < 0)
                return -1;
            memcpy(pal_ctx->auth_tag, pal_ctx->buf,
                    PAL_CPOLY_AEAD_DIGEST_LEN);
            return 1;
        }
        memcpy(pal_ctx->auth_tag, pal_ctx->buf,
                PAL_CPOLY_AEAD_DIGEST_LEN);
        pal_ctx->auth_taglen = PAL_CPOLY_AEAD_DIGEST_LEN;
        return 1;
    }

    retval = pal_chacha20_poly1305_non_tls_crypto(pal_ctx, out, in, len, pal_ctx->queue, pal_ctx->buf);
    *outl = retval;

    return retval;
}

static inline int prov_hw_chacha20_poly1305_cipher(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
        size_t *outl, const unsigned char *in, size_t len)
{
    int ret = 0;
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *wctx = NULL;

    /* Bydefault number of pipe is one */
    if (pal_ctx->numpipes == 0) {
        pal_ctx->numpipes = 1;
        pal_ctx->input_len = malloc(sizeof(int));
        pal_ctx->input_len[0] = len;
        pal_ctx->output_buf = &out;
        /* As it's inplace */
        pal_ctx->input_buf = &out;
    }

    job = ASYNC_get_current_job();
    if (job != NULL)
        wctx = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

    if (pal_ctx->tls_aad_len >= 0) {

        if ((in != out) || (len < EVP_CHACHAPOLY_TLS_TAG_LEN))
            return -1;

        ret = pal_chacha20_poly1305_tls_cipher(pal_ctx, out, in, len, 0, wctx);
        if (ret <= 0)
            return 0;
        else
        {
            *outl = ret;
            return 1;
        }
    }
    else
        ret = chacha20_poly1305_crypto(pal_ctx, out, outl, in, len);

    if (ret <= 0)
        return 0;

    return ret;
}

static void *prov_chacha20_poly1305_newctx(void *provctx)
{
    pal_cpoly_ctx_t *ctx;

    if (!prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(pal_cpoly_ctx_t));
        ctx->iv_len = PROV_CIPHER_CPOLY_IV_LEN;
        ctx->key_len = PAL_CPOLY_KEY_LEN;
        ctx->auth_taglen = -1;
        ctx->aad_len = -1;
        ctx->tls_aad_len = -1;
        ctx->async_cb = provider_ossl_handle_async_job;
        ctx->tls_tag_len = EVP_CHACHAPOLY_TLS_TAG_LEN;
    }
    return ctx;
}

static void prov_chacha20_poly1305_freectx(void *vctx)
{
    pal_cpoly_ctx_t *ctx = (pal_cpoly_ctx_t *)vctx;

    if (ctx != NULL) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static int prov_chacha20_poly1305_get_params(OSSL_PARAM params[])
{
    return prov_cipher_generic_get_params(params, 0, PROV_CIPHER_CPOLY_FLAGS,
            PAL_CPOLY_KEY_LEN * 8,
            PROV_CIPHER_CPOLY_BLOCK_SIZE * 8,
            PROV_CIPHER_CPOLY_IV_LEN * 8);
}

static int prov_chacha20_poly1305_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    pal_cpoly_ctx_t *pal_ctx = (pal_cpoly_ctx_t *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, pal_ctx->iv_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, PAL_CPOLY_KEY_LEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pal_ctx->auth_taglen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pal_ctx->tls_aad_pad_sz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!pal_ctx->enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > PROV_CIPHER_POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        memcpy(p->data, pal_ctx->auth_tag, p->data_size);
    }

    return 1;
}

static const OSSL_PARAM chacha20_poly1305_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_END
};
    static const OSSL_PARAM *prov_chacha20_poly1305_gettable_ctx_params
(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return chacha20_poly1305_known_gettable_ctx_params;
}

static int chacha_poly1305_tls_aad_init(pal_cpoly_ctx_t *pal_ctx,
        unsigned char *aad, size_t alen)
{
    uint8_t i;
    /* Save AAD for later use */
    if (alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;
    memcpy(pal_ctx->buf, aad, alen);
    /* Save sequence number for IV update */
    for (i = 0; i < 8; i++) {
        pal_ctx->seq_num[pal_ctx->aad_cnt][i] =
            ((uint8_t *)aad)[i];
    }
    pal_ctx->tls_aad_len = alen;
    unsigned int len = pal_ctx->buf[alen - 2] << 8 |
        pal_ctx->buf[alen - 1];
    if (!pal_ctx->enc) {
        if (len < PAL_CPOLY_AEAD_DIGEST_LEN)
            return -1;
        len -= PAL_CPOLY_AEAD_DIGEST_LEN;
        pal_ctx->buf[alen - 2] = (len >> 8) & 0xFF;
        pal_ctx->buf[alen - 1] = len & 0xFF;
    }
    if (pal_ctx->aad_cnt < SSL_MAX_PIPELINES) {
        memcpy(pal_ctx->aad_pipe[pal_ctx->aad_cnt],
                pal_ctx->buf, alen);
        pal_ctx->aad_cnt++;
    }
    return PAL_CPOLY_AEAD_DIGEST_LEN;
}

static int prov_chacha20_poly1305_set_ctx_params(void *vctx,
        const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    pal_cpoly_ctx_t *pal_ctx = (pal_cpoly_ctx_t *)vctx;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != PAL_CPOLY_KEY_LEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len == 0 || len > PROV_CIPHER_CPOLY_MAX_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        pal_ctx->iv_len = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > PROV_CIPHER_POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) {
            if (pal_ctx->enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(pal_ctx->auth_tag, p->data, p->data_size);
        }
        pal_ctx->auth_taglen = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        len = chacha_poly1305_tls_aad_init(pal_ctx, p->data, p->data_size);
        if (len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        pal_ctx->tls_aad_pad_sz = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size != PROV_CIPHER_CPOLY_IV_LEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(pal_ctx->iv, p->data, p->data_size);
    }

    /* ignore OSSL_CIPHER_PARAM_AEAD_MAC_KEY */
    return 1;
}

static int chacha20_poly1305_init_internal(void *vctx, const unsigned char *key, size_t keylen,
        const unsigned char *iv, size_t ivlen,
        const OSSL_PARAM params[], int enc)
{
    pal_cpoly_ctx_t *pal_ctx = (pal_cpoly_ctx_t *)vctx;

    if (!prov_is_running())
        return 0;

    pal_ctx->enc = enc;

    if (iv != NULL) {
        if (ivlen == 0 || ivlen > sizeof(pal_ctx->iv)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        pal_ctx->iv_len = ivlen;
        memcpy(pal_ctx->iv, iv, ivlen);
    }

    if (key != NULL) {
        if (keylen != pal_ctx->key_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!prov_hw_chacha20_poly1305_init_key(pal_ctx, key, pal_ctx->key_len, enc))
        {
            return 0;
        }
    }
    return prov_chacha20_poly1305_set_ctx_params(pal_ctx, params);
}

static int prov_chacha20_poly1305_einit(void *vctx, const unsigned char *key,
        size_t keylen, const unsigned char *iv,
        size_t ivlen, const OSSL_PARAM params[])
{
    return chacha20_poly1305_init_internal(vctx, key, keylen, iv, ivlen, params, 1);
}

static int prov_chacha20_poly1305_dinit(void *vctx, const unsigned char *key,
        size_t keylen, const unsigned char *iv,
        size_t ivlen, const OSSL_PARAM params[])
{
    return chacha20_poly1305_init_internal(vctx, key, keylen, iv, ivlen, params, 0);

}

static int prov_chacha20_poly1305_cipher(void *vctx, unsigned char *out,
        size_t *outl, size_t outsize,
        const unsigned char *in, size_t inl)
{
    pal_cpoly_ctx_t *cpolly_ctx = (pal_cpoly_ctx_t *)vctx;

    if (!prov_is_running())
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!prov_hw_chacha20_poly1305_cipher(cpolly_ctx, out, outl, in, inl))
        return 0;

    return 1;
}
static int prov_chacha20_poly1305_final(void *vctx, unsigned char *out, size_t *outl,
        size_t outsize)
{
    pal_cpoly_ctx_t *cpolly_ctx = (pal_cpoly_ctx_t *)vctx;

    if (!prov_is_running())
        return 0;

    if (prov_hw_chacha20_poly1305_cipher(cpolly_ctx, out, outl, NULL, 0) <= 0)
        return 0;

    *outl = 0;
    return 1;
}

/* ossl_chacha20_ossl_poly1305_functions */
const OSSL_DISPATCH prov_chacha20_prov_poly1305_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))prov_chacha20_poly1305_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))prov_chacha20_poly1305_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))prov_chacha20_poly1305_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))prov_chacha20_poly1305_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))prov_chacha20_poly1305_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))prov_chacha20_poly1305_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))prov_chacha20_poly1305_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,
        (void (*)(void))prov_chacha20_poly1305_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))prov_chacha20_poly1305_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
        (void (*)(void))prov_chacha20_poly1305_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))prov_chacha20_poly1305_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))prov_chacha20_poly1305_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))prov_chacha20_poly1305_settable_ctx_params },
    { 0, NULL }
};

