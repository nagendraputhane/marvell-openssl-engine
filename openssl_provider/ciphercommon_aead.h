/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

#define IMPLEMENT_aead_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)  \
static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;       \
static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])              \
{                                                                              \
    return prov_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,    \
                                          flags, kbits, blkbits, ivbits);      \
}                                                                              \
static OSSL_FUNC_cipher_newctx_fn alg##kbits##lc##_newctx;                     \
static void * alg##kbits##lc##_newctx(void *provctx)                           \
{                                                                              \
    return prov_##alg##_##lc##_newctx(provctx, kbits);                                \
}                                                                              \
const OSSL_DISPATCH prov_##alg##kbits##lc##_functions[] = {                    \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))alg##kbits##lc##_newctx },      \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))prov_##alg##_##lc##_freectx },        \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))prov_##alg##_##lc##_einit },      \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))prov_##alg##_##lc##_dinit },      \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))prov_##alg##_##lc##_stream_update },    \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))prov_##alg##_##lc##_stream_final },      \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))prov_##alg##_##lc##_cipher },           \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lc##_get_params },                    \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void)) prov_##alg##_##lc##_get_ctx_params },                           \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void)) prov_##alg##_##lc##_set_ctx_params },                           \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))prov_cipher_generic_gettable_params },                   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))prov_cipher_aead_gettable_ctx_params },                  \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))prov_cipher_aead_settable_ctx_params },                  \
    { 0, NULL }                                                                \
}
