/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef _PROV_H
#define _PROV_H

#include <openssl/async.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/core.h>
#include <prov/provider_util.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "pal.h"

#define CPT_PROVIDER_DEFAULT_SESSIONS              (128 << 10)
#define CPT_PROVIDER_DEFAULT_SYM_QP_DESC_COUNT     2048
#define CPT_PROVIDER_DEFAULT_MBUFS                 4096
#define CPT_PROVIDER_DEFAULT_SYM_OPS               4096
#define CPT_PROVIDER_DEFAULT_ASYM_QP_DESC_COUNT    512
#define CPT_PROVIDER_DEFAULT_POOL_CACHE_SIZE       512
#define CPT_PROVIDER_DEFAULT_ASYM_OPS              1024

#define CPT_PROVIDER_MBUF_CUSTOM_BUF_SIZE	(32 * 1024)
#define MIN(a, b)				((a) < (b) ? (a) : (b))
#define PROV_CIPHER_AES_CBC_IV_LENGTH	    16

#define PCURVES_MAX_PRIME_LEN		72 /* P521 curve */

# define PROV_ATOMIC_INC(x)              \
	            (__sync_add_and_fetch(&(x), 1))

# define PROV_ATOMIC_DEC(x)              \
	            (__sync_sub_and_fetch(&(x), 1))
# define PROV_ATOMIC_INC_N(x, n)              \
	            (__sync_add_and_fetch(&(x), n))

# define PROV_ATOMIC_DEC_N(x, n)              \
	            (__sync_sub_and_fetch(&(x), n))

void provplt_teardown(void);
int provplt_setup(void);

extern OSSL_ASYNC_FD zero_fd;
extern int asym_dev_id[];
extern int asym_queues[];
extern int sym_dev_id[];
extern int sym_queues[];

extern char prov_name[];
extern char des_ec[];
extern char des_rsa[];
extern char pal_name[];

typedef struct prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;         /* For all provider modules */
} PROV_CTX;

/*
 * To be used anywhere the library context needs to be passed, such as to
 * fetching functions.
 */
# define PROV_LIBCTX_OF(provctx)        \
    prov_ctx_get0_libctx((provctx))

int provider_ossl_handle_async_job(void *resumed_wctx, void *wctx_p, int numpipes,
    uint8_t *job_qsz, async_pipe_job_t *pip_jobs, bool pause_job);

int pause_async_job(void);

/* Return 1 if CPT is ready to do work */
static inline int prov_is_running(void)
{
    return 1;
}

static inline PROV_CTX *prov_ctx_new(void)
{
    return (PROV_CTX *)OPENSSL_zalloc(sizeof(PROV_CTX));
}

static inline void prov_ctx_free(PROV_CTX *ctx)
{
    OPENSSL_free(ctx);
}

static inline void prov_ctx_set0_libctx(PROV_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    if (ctx != NULL)
        ctx->libctx = libctx;
}

static inline void prov_ctx_set0_handle(PROV_CTX *ctx, const OSSL_CORE_HANDLE *handle)
{
    if (ctx != NULL)
        ctx->handle = handle;
}

static inline OSSL_LIB_CTX *prov_ctx_get0_libctx(PROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->libctx;
}

static inline const OSSL_CORE_HANDLE *prov_ctx_get0_handle(PROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->handle;
}

static void prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in,
                                         OSSL_ALGORITHM *out)
{
    int i, j;

    if (out[0].algorithm_names == NULL) {
        for (i = j = 0; in[i].alg.algorithm_names != NULL; ++i) {
            if (in[i].capable == NULL || in[i].capable())
                out[j++] = in[i].alg;
        }
        out[j++] = in[i].alg;
    }
}

static inline int prov_asym_get_valid_devid_qid(int *devid, int *queue)
{
    int thread_id = pal_get_thread_id();

    if(thread_id == -1 || asym_dev_id[thread_id] == -1) {
        fprintf(stderr, "Invalid thread_id %d\n", thread_id);
        return 0;
    }

    *devid = asym_dev_id[thread_id];
    *queue = asym_queues[thread_id];
    return 1;
}

static inline int prov_sym_get_valid_devid_qid(int *devid, int *queue)
{
    int thread_id = pal_get_thread_id();

    if(thread_id == -1 || sym_dev_id[thread_id] == -1) {
        fprintf(stderr, "Invalid thread_id %d\n", thread_id);
        return 0;
    }

    *devid = sym_dev_id[thread_id];
    *queue = sym_queues[thread_id];
    return 1;
}

#endif /* _PROV_H */
