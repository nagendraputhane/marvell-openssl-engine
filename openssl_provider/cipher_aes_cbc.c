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

/* For SSL3_VERSION */
#include <openssl/prov_ssl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "prov.h"
#include "ciphercommon.h"
#include "pal.h"
#include "pal_cbc.h"

#define PROV_CIPHER_AES128_CBC_KEYBITS   128
#define PROV_CIPHER_AES256_CBC_KEYBITS   256
#define PROV_CIPHER_AES256_CBC_BLKBITS   128
#define PROV_CIPHER_AES_BLOCK_SIZE		 16
/* Max padding including padding length byte */
#define PROV_CIPHER_CBC_MAX_PADDING 256

typedef struct __attribute__((aligned(OCTEON_CACHE_LINE_SIZE))) {
    pal_cbc_ctx_t pal_ctx;

    unsigned char oiv[GENERIC_BLOCK_SIZE];
    unsigned char buf[GENERIC_BLOCK_SIZE];
    unsigned char iv[GENERIC_BLOCK_SIZE];

    OSSL_LIB_CTX *libctx;
    unsigned char *tlsmac;

    size_t keylen;
    size_t ivlen;
    size_t blocksize;
    size_t bufsz;
    size_t tlsmacsize;
    size_t removetlsfixed;

    unsigned int tlsversion;
    unsigned int num;
    unsigned int pad : 1;
    unsigned int enc : 1;
    unsigned int iv_set : 1;
    unsigned int updated : 1;
    unsigned int use_bits : 1;
    unsigned int mode;

    int allocated;
    int removetlspad;
} PROV_AES_CBC_CTX;

/*
 * provider functions to export aes cbc
 */
OSSL_FUNC_cipher_encrypt_init_fn prov_aes_cbc_einit;
OSSL_FUNC_cipher_decrypt_init_fn prov_aes_cbc_dinit;
OSSL_FUNC_cipher_update_fn prov_aes_cbc_block_update;
OSSL_FUNC_cipher_final_fn prov_aes_cbc_block_final;
OSSL_FUNC_cipher_cipher_fn prov_aes_cbc_cipher;
OSSL_FUNC_cipher_get_ctx_params_fn prov_aes_cbc_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn prov_aes_cbc_set_ctx_params;
void prov_aes_cbc_freectx(void *vctx);
static void *prov_aes_cbc_newctx(void *provctx, size_t kbits);

static inline int prov_hw_aes_cbc_initkey(PROV_AES_CBC_CTX *cbc_ctx, const uint8_t *key,
        size_t key_len, int enc)
{
    pal_cbc_ctx_t *pal_ctx = &cbc_ctx->pal_ctx;

    if(cbc_ctx->iv == NULL || key == NULL)
        return 0;

    return pal_aes_cbc_create_session(pal_ctx, key, cbc_ctx->iv, enc, key_len);
}

static inline int prov_hw_aes_cbc_cipher(PROV_AES_CBC_CTX *cbc_ctx, unsigned char *out,
        const unsigned char *in, size_t inl)
{
    pal_cbc_ctx_t *pal_ctx = &cbc_ctx->pal_ctx;
    pal_ctx->async_cb = provider_ossl_handle_async_job;
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *wctx = NULL;
    int ret = 0;

    job = ASYNC_get_current_job();
    if (job != NULL)
        wctx = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

    ret = pal_aes_cbc_cipher( pal_ctx, out, in, inl, cbc_ctx->iv, cbc_ctx->enc, pal_ctx->sym_queue, wctx);

    if(ret < 0)
        return 0;

    return ret;
}

static void *prov_aes_cbc_newctx(void *provctx, size_t kbits)
{
    PROV_AES_CBC_CTX *cbc_ctx;

    if (!prov_is_running())
        return NULL;

    cbc_ctx = OPENSSL_zalloc(sizeof(*cbc_ctx));
    if (cbc_ctx == NULL) {
        return NULL;
    }

    cbc_ctx->pad = 1;
    cbc_ctx->keylen = ((kbits) / 8);
    cbc_ctx->ivlen = PROV_CIPHER_AES_CBC_IV_LENGTH;
    cbc_ctx->mode = EVP_CIPH_CBC_MODE;
    cbc_ctx->blocksize = PROV_CIPHER_AES256_CBC_BLKBITS / 8;
    cbc_ctx->pal_ctx.numpipes = 0;
    cbc_ctx->allocated = 1;
    pal_sym_session_cbc_init(&cbc_ctx->pal_ctx);
    if (provctx != NULL)
        cbc_ctx->libctx = PROV_LIBCTX_OF(provctx);
    return cbc_ctx;
}

void prov_aes_cbc_freectx(void *vctx)
{
    PROV_AES_CBC_CTX *ctx = (PROV_AES_CBC_CTX *)vctx;

    if (ctx != NULL && ctx->allocated) {
        OPENSSL_free(ctx->tlsmac);
        ctx->allocated = 0;
        ctx->tlsmac = NULL;
        pal_sym_session_cbc_cleanup(&ctx->pal_ctx);
    }

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static int prov_aes_cbc_initiv(PROV_AES_CBC_CTX *ctx, const unsigned char *iv,
        size_t ivlen)
{
    if (ivlen != ctx->ivlen
            || ivlen > sizeof(ctx->iv)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        return 0;
    }
    ctx->iv_set = 1;
    memcpy(ctx->iv, iv, ivlen);
    memcpy(ctx->oiv, iv, ivlen);
    return 1;
}

static int aes_cbc_init_internal(PROV_AES_CBC_CTX *ctx,
        const unsigned char *key, size_t keylen,
        const unsigned char *iv, size_t ivlen,
        const OSSL_PARAM params[], int enc)
{
    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = enc ? 1 : 0;

    if (!prov_is_running())
        return 0;

    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (!prov_aes_cbc_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && ctx->iv_set
            && (ctx->mode == EVP_CIPH_CBC_MODE
                || ctx->mode == EVP_CIPH_CFB_MODE
                || ctx->mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);

    if (key != NULL) {
        if (keylen != ctx->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!prov_hw_aes_cbc_initkey(ctx, key, ctx->keylen, enc))
            return 0;
    }
    return prov_aes_cbc_set_ctx_params(ctx, params);
}

int prov_aes_cbc_einit(void *vctx, const unsigned char *key,
        size_t keylen, const unsigned char *iv,
        size_t ivlen, const OSSL_PARAM params[])
{
    return aes_cbc_init_internal((PROV_AES_CBC_CTX *)vctx, key, keylen,
            iv, ivlen, params, 1);
}

int prov_aes_cbc_dinit(void *vctx, const unsigned char *key,
        size_t keylen, const unsigned char *iv,
        size_t ivlen, const OSSL_PARAM params[])
{
    return aes_cbc_init_internal((PROV_AES_CBC_CTX *)vctx, key, keylen,
            iv, ivlen, params, 0);
}

int prov_aes_cbc_block_update(void *vctx, unsigned char *out,
        size_t *outl, size_t outsize,
        const unsigned char *in, size_t inl)
{
    size_t outlint = 0;
    PROV_AES_CBC_CTX *ctx = (PROV_AES_CBC_CTX *)vctx;
    size_t blksz = ctx->blocksize;
    size_t nextblocks;

    if (ctx->tlsversion > 0) {
        /*
         * Each update call corresponds to a TLS record and is individually
         * padded
         */

        /* Sanity check inputs */
        if (in == NULL
                || in != out
                || outsize < inl
                || !ctx->pad) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        if (ctx->enc) {
            unsigned char padval;
            size_t padnum, loop;

            /* Add padding */

            padnum = blksz - (inl % blksz);

            if (outsize < inl + padnum) {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }

            if (padnum > PROV_CIPHER_CBC_MAX_PADDING) {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
            padval = (unsigned char)(padnum - 1);
            if (ctx->tlsversion == SSL3_VERSION) {
                if (padnum > 1)
                    memset(out + inl, 0, padnum - 1);
                *(out + inl + padnum - 1) = padval;
            } else {
                /* we need to add 'padnum' padding bytes of value padval */
                for (loop = inl; loop < inl + padnum; loop++)
                    out[loop] = padval;
            }
            inl += padnum;
        }

        if ((inl % blksz) != 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }


        /* Shouldn't normally fail */
        if (!prov_hw_aes_cbc_cipher(ctx, out, in, inl)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        if (ctx->allocated) {
            OPENSSL_free(ctx->tlsmac);
            ctx->allocated = 0;
            ctx->tlsmac = NULL;
        }

        /* This only fails if padding is publicly invalid */
        *outl = inl;
        if (!ctx->enc
                && !prov_cipher_tlsunpadblock(ctx->libctx, ctx->tlsversion,
                    out, outl,
                    blksz, &ctx->tlsmac, &ctx->allocated,
                    ctx->tlsmacsize, 0)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        return 1;
    }

    if (ctx->bufsz != 0)
        nextblocks = prov_cipher_fillblock(ctx->buf, &ctx->bufsz, blksz,
                &in, &inl);
    else
        nextblocks = inl & ~(blksz-1);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (ctx->bufsz == blksz && (ctx->enc || inl > 0 || !ctx->pad)) {
        if (outsize < blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!prov_hw_aes_cbc_cipher(ctx, out, ctx->buf, blksz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufsz = 0;
        outlint = blksz;
        out += blksz;
    }
    if (nextblocks > 0) {
        if (!ctx->enc && ctx->pad && nextblocks == inl) {
            if (!(inl >= blksz)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            nextblocks -= blksz;
        }
        outlint += nextblocks;
        if (outsize < outlint) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
    }
    if (nextblocks > 0) {
        if (!prov_hw_aes_cbc_cipher(ctx, out, in, nextblocks)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        in += nextblocks;
        inl -= nextblocks;
    }
    if (inl != 0
            && !prov_cipher_trailingdata(ctx->buf, &ctx->bufsz, blksz, &in, &inl)) {
        /* ERR_raise already called */
        return 0;
    }

    *outl = outlint;
    return inl == 0;
}

int prov_aes_cbc_block_final(void *vctx, unsigned char *out,
        size_t *outl, size_t outsize)
{
    PROV_AES_CBC_CTX *ctx = (PROV_AES_CBC_CTX *)vctx;
    size_t blksz = ctx->blocksize;

    if (!prov_is_running())
        return 0;

    if (ctx->tlsversion > 0) {
        /* We never finalize TLS, so this is an error */
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (ctx->enc) {
        if (ctx->pad) {
            prov_cipher_padblock(ctx->buf, &ctx->bufsz, blksz);
        } else if (ctx->bufsz == 0) {
            *outl = 0;
            return 1;
        } else if (ctx->bufsz != blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }

        if (outsize < blksz) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!prov_hw_aes_cbc_cipher(ctx, out, ctx->buf, blksz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufsz = 0;
        *outl = blksz;
        return 1;
    }

    /* Decrypting */
    if (ctx->bufsz != blksz) {
        if (ctx->bufsz == 0 && !ctx->pad) {
            *outl = 0;
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }

    if (!prov_hw_aes_cbc_cipher(ctx, ctx->buf, ctx->buf, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (ctx->pad && !prov_cipher_unpadblock(ctx->buf, &ctx->bufsz, blksz)) {
        /* ERR_raise already called */
        return 0;
    }

    if (outsize < ctx->bufsz) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    memcpy(out, ctx->buf, ctx->bufsz);
    *outl = ctx->bufsz;
    ctx->bufsz = 0;
    return 1;
}

int prov_aes_cbc_cipher(void *vctx, unsigned char *out, size_t *outl,
        size_t outsize, const unsigned char *in,
        size_t inl)
{
    PROV_AES_CBC_CTX *ctx = (PROV_AES_CBC_CTX *)vctx;

    if (!prov_is_running())
        return 0;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!prov_hw_aes_cbc_cipher(ctx, out, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}

int prov_aes_cbc_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AES_CBC_CTX *ctx = (PROV_AES_CBC_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen)
            && !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)
            && !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
            && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

int prov_aes_cbc_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_CBC_CTX *ctx = (PROV_AES_CBC_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
    if (p != NULL) {
        unsigned int bits;

        if (!OSSL_PARAM_get_uint(p, &bits)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->use_bits = bits ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->tlsversion)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->tlsmacsize)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        unsigned int num;

        if (!OSSL_PARAM_get_uint(p, &num)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->num = num;
    }
    return 1;
}

/* prov_aes256cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, PROV_CIPHER_AES256_CBC_KEYBITS,
        PROV_CIPHER_AES256_CBC_BLKBITS, 128, block)

    /* prov_aes128cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, PROV_CIPHER_AES128_CBC_KEYBITS,
        PROV_CIPHER_AES256_CBC_BLKBITS, 128, block)

