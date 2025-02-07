/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "crypto/modes.h"
#include "prov.h"

#define MAXCHUNK    ((size_t)1 << (sizeof(long) * 8 - 2))
#define MAXBITCHUNK ((size_t)1 << (sizeof(size_t) * 8 - 4))

#define GENERIC_BLOCK_SIZE 16
#define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */
#define IV_STATE_BUFFERED      1  /* iv has been copied to the iv buffer */
#define IV_STATE_COPIED        2  /* iv has been copied from the iv buffer */
#define IV_STATE_FINISHED      3  /* the iv has been used - so don't reuse it */

#define PROV_CIPHER_FUNC(type, name, args) typedef type (* OSSL_##name##_fn)args

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD             0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
#define PROV_CIPHER_FLAG_CTS              0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
#define PROV_CIPHER_FLAG_RAND_KEY         0x0010

size_t prov_cipher_fillblock(unsigned char *buf, size_t *buflen,
                             size_t blocksize,
                             const unsigned char **in, size_t *inlen);
int prov_cipher_trailingdata(unsigned char *buf, size_t *buflen,
                             size_t blocksize,
                             const unsigned char **in, size_t *inlen);
void prov_cipher_padblock(unsigned char *buf, size_t *buflen, size_t blocksize);
int prov_cipher_unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize);
int prov_cipher_tlsunpadblock(OSSL_LIB_CTX *libctx, unsigned int tlsversion,
                              unsigned char *buf, size_t *buflen, size_t blocksize,
                              unsigned char **mac, int *alloced, size_t macsize, int aead);

/*
 * Below get/set method definitions are common to multiple ciphers
 */
OSSL_FUNC_cipher_gettable_params_fn     prov_cipher_generic_gettable_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn prov_cipher_generic_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn prov_cipher_generic_settable_ctx_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn prov_cipher_aead_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn prov_cipher_aead_settable_ctx_params;

int prov_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags,
                                   size_t kbits, size_t blkbits, size_t ivbits);

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(name)                         \
static const OSSL_PARAM name##_known_gettable_ctx_params[] = {                 \
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),                         \
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),                              \
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),                    \
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
};                                                                             \
const OSSL_PARAM * name##_gettable_ctx_params(ossl_unused void *cctx,          \
                                              ossl_unused void *provctx)       \
{                                                                              \
    return name##_known_gettable_ctx_params;                                   \
}

#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(name)                         \
static const OSSL_PARAM name##_known_settable_ctx_params[] = {                 \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),                          \
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
#define CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
};                                                                             \
const OSSL_PARAM * name##_settable_ctx_params(ossl_unused void *cctx,          \
                                              ossl_unused void *provctx)       \
{                                                                              \
    return name##_known_settable_ctx_params;                                   \
}

#define IMPLEMENT_generic_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,\
                                      blkbits, ivbits, typ)                    \
const OSSL_DISPATCH prov_##alg##kbits##lcmode##_functions[] = {                \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },                    \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) prov_##alg##_##lcmode##_freectx },     \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))prov_##alg##_##lcmode##_einit },   \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))prov_##alg##_##lcmode##_dinit },   \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))prov_##alg##_##lcmode##_##typ##_update },\
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))prov_##alg##_##lcmode##_##typ##_final },  \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))prov_##alg##_##lcmode##_cipher },        \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))prov_##alg##_##lcmode##_get_ctx_params },                \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))prov_##alg##_##lcmode##_set_ctx_params },                \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))prov_cipher_generic_gettable_params },                   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))prov_cipher_generic_gettable_ctx_params },               \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))prov_cipher_generic_settable_ctx_params },                \
    { 0, NULL }                                                                \
};


#define IMPLEMENT_generic_cipher_genfn(alg, UCALG, lcmode, UCMODE, flags,      \
                                       kbits, blkbits, ivbits, typ)            \
static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lcmode##_get_params;   \
static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])          \
{                                                                              \
    return prov_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,    \
                                          flags, kbits, blkbits, ivbits);      \
}                                                                              \
static OSSL_FUNC_cipher_newctx_fn alg##_##kbits##_##lcmode##_newctx;           \
static void * alg##_##kbits##_##lcmode##_newctx(void *provctx)                 \
{                                                                              \
  return prov_##alg##_##lcmode##_newctx(provctx, kbits);                       \
}                                                                              \

#define IMPLEMENT_generic_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits,     \
                                 blkbits, ivbits, typ)                         \
IMPLEMENT_generic_cipher_genfn(alg, UCALG, lcmode, UCMODE, flags, kbits,       \
                               blkbits, ivbits, typ)                           \
IMPLEMENT_generic_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,        \
                              blkbits, ivbits, typ)
