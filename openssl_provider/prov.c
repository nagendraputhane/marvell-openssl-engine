/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <prov/names.h>
#include "prov.h"

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=dpdk_provider", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)
#define NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#define CPT_PROV_DESCS_EC "DPDK EC implementation"
#define CPT_PROV_DESCS_RSA "DPDK RSA implementation"

/* Sym Cipher */
extern const OSSL_DISPATCH prov_aes256cbc_functions[];
extern const OSSL_DISPATCH prov_aes128cbc_functions[];
extern const OSSL_DISPATCH prov_aes256gcm_functions[];
extern const OSSL_DISPATCH prov_aes128gcm_functions[];
extern const OSSL_DISPATCH prov_aes256cbc_hmac_sha1_functions[];
extern const OSSL_DISPATCH prov_aes128cbc_hmac_sha1_functions[];
extern const OSSL_DISPATCH prov_chacha20_prov_poly1305_functions[];

/* Asym Cipher */
extern const OSSL_DISPATCH prov_rsa_asym_cipher_functions[];

/* Signature */
extern const OSSL_DISPATCH prov_rsa_signature_functions[];
extern const OSSL_DISPATCH prov_ecdsa_signature_functions[];

/* Key Exchange */
extern const OSSL_DISPATCH prov_ecdh_keyexch_functions[];

/* Key Management */
extern const OSSL_DISPATCH prov_ec_keymgmt_functions[];
extern const OSSL_DISPATCH prov_rsa_keymgmt_functions[];

int prov_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg) ;

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn prov_get_params;
static OSSL_FUNC_provider_query_operation_fn prov_query;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *prov_gettable_params(void *provctx)
{
    return prov_param_types;
}

int pause_async_job(void)
{
        ASYNC_JOB *job = ASYNC_get_current_job();
        if (job != NULL) {
                ASYNC_WAIT_CTX *wctx = ASYNC_get_wait_ctx(job);
                if (wctx != NULL) {
                        size_t numfds = 0;
                        ASYNC_WAIT_CTX_get_all_fds(wctx, NULL, &numfds);
                        /* If wctx does not have an fd, then set it.
                         * This is needed for the speed test which select()s
                         * on fd
                         */
                        if (numfds == 0)
                                ASYNC_WAIT_CTX_set_wait_fd(wctx, NULL, zero_fd,
                                                           NULL, NULL);
                }
                ASYNC_pause_job();
        }
        return 0;
}

static inline void invoke_async_callback(ASYNC_WAIT_CTX *wctx_p)
{
    int (*callback)(void *arg);
    void *args;

    if(ASYNC_WAIT_CTX_get_callback(wctx_p, &callback, &args))
        (*callback)(args);
}

int provider_ossl_handle_async_job(void *resumed_wctx, void *wctx_p, int numpipes,
    uint8_t *job_qsz, async_pipe_job_t *pip_jobs, bool pause_job)
{
  uint8_t job_index = 0, k = 0, wctx_found = 0;

  if (pause_job == ASYNC_JOB_PAUSE)
    return pause_async_job();

  if ((*job_qsz == 0))
  {
    pip_jobs[0].wctx_p = wctx_p;
    pip_jobs[0].counter = 1;
    *job_qsz = 1;
    if (pip_jobs[0].counter == numpipes)
    {
      if ((resumed_wctx == NULL) || (resumed_wctx != pip_jobs[0].wctx_p))
        invoke_async_callback(pip_jobs[0].wctx_p);
      (*job_qsz)--;
    }
  }
  else
  {
    for (job_index=0; job_index < *job_qsz; job_index++)
    {
      if (wctx_p == pip_jobs[job_index].wctx_p)
      {
        wctx_found = 1;
        pip_jobs[job_index].counter++;
        if (pip_jobs[job_index].counter == numpipes)
        {
          if ((resumed_wctx == NULL) || (resumed_wctx != pip_jobs[job_index].wctx_p))
            invoke_async_callback(pip_jobs[job_index].wctx_p);
          for (k = job_index; k < (*job_qsz - 1); k++)
          {
            pip_jobs[k].wctx_p = pip_jobs[k+1].wctx_p;
            pip_jobs[k].counter = pip_jobs[k+1].counter;
          }
          (*job_qsz)--;
        }
      }
    }
    if (!wctx_found) {
      pip_jobs[*job_qsz].wctx_p = wctx_p;
      (*job_qsz)++;
    }
  }

  return 0;

}

static int prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL DPDK Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, prov_is_running()))
        return 0;
    return 1;
}

static int aes_cbc_capable() {
    return pal_is_hw_sym_algos_supported(PAL_CRYPTO_CIPHER_AES_CBC);
}

static int aes_gcm_capable() {
    return pal_is_hw_sym_algos_supported(PAL_CRYPTO_CIPHER_AES_GCM);
}

static int chacha20_poly1305_capable() {
    return pal_is_hw_sym_algos_supported(PAL_CRYPTO_AEAD_CHACHA20_POLY1305);
}

static const OSSL_ALGORITHM_CAPABLE prov_ciphers[] = {
    ALGC(PROV_NAMES_AES_256_CBC, prov_aes256cbc_functions, aes_cbc_capable),
    ALGC(PROV_NAMES_AES_128_CBC, prov_aes128cbc_functions, aes_cbc_capable),
    ALGC(PROV_NAMES_AES_256_GCM, prov_aes256gcm_functions, aes_gcm_capable),
    ALGC(PROV_NAMES_AES_128_GCM, prov_aes128gcm_functions, aes_gcm_capable),
    // ALG(PROV_NAMES_AES_128_CBC_HMAC_SHA1, prov_aes128cbc_hmac_sha1_functions),
    // ALG(PROV_NAMES_AES_256_CBC_HMAC_SHA1, prov_aes256cbc_hmac_sha1_functions),
    ALGC(PROV_NAMES_ChaCha20_Poly1305, prov_chacha20_prov_poly1305_functions, chacha20_poly1305_capable),
    // { { NULL, NULL, NULL }, NULL }
    { NULL, NULL, NULL }
};

static OSSL_ALGORITHM prov_supported_ciphers[NELEM(prov_ciphers)];

static const OSSL_ALGORITHM prov_signature[] = {
    { PROV_NAMES_RSA, "provider=dpdk_provider", prov_rsa_signature_functions },
    { PROV_NAMES_ECDSA, "provider=dpdk_provider", prov_ecdsa_signature_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM prov_asym_cipher[] = {
    // { PROV_NAMES_RSA, "provider=dpdk_provider", prov_rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM prov_keyexch[] = {
    { PROV_NAMES_ECDH, "provider=dpdk_provider", prov_ecdh_keyexch_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM prov_keymgmt[] = {
    { PROV_NAMES_EC, "provider=dpdk_provider", prov_ec_keymgmt_functions,
      CPT_PROV_DESCS_EC },
    { PROV_NAMES_RSA, "provider=dpdk_provider", prov_rsa_keymgmt_functions,
      CPT_PROV_DESCS_RSA },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *prov_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    /* Let OpenSSL core cache the returned array */
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_CIPHER:
       return prov_supported_ciphers;
    case OSSL_OP_KEYMGMT:
	return prov_keymgmt;
    case OSSL_OP_KEYEXCH:
	return prov_keyexch;
    case OSSL_OP_SIGNATURE:
        return prov_signature;
    case OSSL_OP_ASYM_CIPHER:
        return prov_asym_cipher;
    }
    return NULL;
}

static void prov_teardown(void *provctx)
{
    prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
                                (void (*)(void))prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))prov_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))prov_get_capabilities },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                               const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out,
                               void **provctx)
{
    OSSL_LIB_CTX *libctx = NULL;

    if ((*provctx = prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new_child(handle, in)) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }

    /* libctx needed to fallback to another (default) provider for any implementaion */
    prov_ctx_set0_libctx(*provctx, libctx);
    prov_ctx_set0_handle(*provctx, handle);

    *out = prov_dispatch_table;

    if (provplt_setup() < 0) {
        OSSL_LIB_CTX_free(libctx);
        prov_ctx_free(*provctx);
        *provctx = NULL;
    }
    prov_cache_exported_algorithms(prov_ciphers, prov_supported_ciphers);

    return 1;
}
