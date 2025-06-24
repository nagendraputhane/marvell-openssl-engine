/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _CPT_ENGINE_H
#define _CPT_ENGINE_H

#include "pal.h"
#include <openssl/async.h>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/tls1.h>
#include <openssl/async.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#if OPENSSL_API_LEVEL >= 30000
#include <crypto/modes.h>
#include <openssl/evp.h>
#else
#include <modes_local.h>
#include <evp_local.h>
#endif

/*Note: MAX_ASYNC_JOBS(cn106xx,cn96xx, cn98xx) value is 36. So due to this min mbufs, sym/asym ops set as 36. Also AES-GCM requires two sessions per operation, so min sessions set as 72.*/
#define CPT_ENGINE_MAX_SESSIONS                  (INT_MAX/2)
#define CPT_ENGINE_DEFAULT_SESSIONS              (128 << 10)
#define CPT_ENGINE_MIN_SESSIONS                  72
#define CPT_ENGINE_MAX_MBUFS                     (INT_MAX/2)
#define CPT_ENGINE_DEFAULT_MBUFS                 4096
#define CPT_ENGINE_MIN_MBUFS                     36
#define CPT_ENGINE_MAX_SYM_OPS                   (INT_MAX/2)
#define CPT_ENGINE_DEFAULT_SYM_OPS               4096
#define CPT_ENGINE_MIN_SYM_OPS                   36
#define CPT_ENGINE_MAX_ASYM_OPS                  (INT_MAX/2)
#define CPT_ENGINE_DEFAULT_ASYM_OPS              1024
#define CPT_ENGINE_MIN_ASYM_OPS                  36
#define CPT_ENGINE_MAX_POOL_CACHE_SIZE           512
#define CPT_ENGINE_DEFAULT_POOL_CACHE_SIZE       512
#define CPT_ENGINE_MIN_POOL_CACHE_SIZE           0
#define CPT_ENGINE_MAX_ASYM_QP_DESC_COUNT        8192
#define CPT_ENGINE_DEFAULT_ASYM_QP_DESC_COUNT    512
#define CPT_ENGINE_MIN_ASYM_QP_DESC_COUNT        32
#define CPT_ENGINE_MAX_SYM_QP_DESC_COUNT         8192
#define CPT_ENGINE_DEFAULT_SYM_QP_DESC_COUNT     2048
#define CPT_ENGINE_MIN_SYM_QP_DESC_COUNT         32
#define CPT_ENGINE_RTE_MBUF_CUSTOM_BUF_SIZE	(32 * 1024)
#define RSA_SHIFT 0
#define EC_SHIFT 1
#define GCM_SHIFT 2
#define CBC_SHIFT 3
#define CPOLY_SHIFT 4
#define SHIFT_OSSL_BITS 8
#define ALG_MASK(alg) ((1<<alg##_SHIFT)<<SHIFT_OSSL_BITS)
#define SET_ENGINE_ALG_FLAGS(e, updated_flag)(ENGINE_set_flags(e, updated_flag))
#define IS_ALG_ENABLED(e, alg)(ENGINE_get_flags(e)&ALG_MASK(alg))
#define ASYM_ALG_SUPPORT_MASK (((1<<RSA_SHIFT)|(1<<EC_SHIFT)) << SHIFT_OSSL_BITS)
#define SYM_ALG_SUPPORT_MASK (((1<<GCM_SHIFT)|(1<<CBC_SHIFT)|(1<<CPOLY_SHIFT)) << SHIFT_OSSL_BITS)
#define ALL_ALG_SUPPORT_MASK (ASYM_ALG_SUPPORT_MASK | SYM_ALG_SUPPORT_MASK)
#define CHECK_LIMIT_AND_ASSIGN(value, max, min)((value>max)?max:((value<min)?min:value))
#define CPT_ENGINE_MAX_NUM_POOL 5
#define HW_OFFLOAD_PKT_SZ_THRESHOLD_MAX           16384
#define HW_OFFLOAD_PKT_SZ_THRESHOLD_DEFAULT       0
#define HW_OFFLOAD_PKT_SZ_THRESHOLD_MIN           0
#define CPT_ENGINE_CTRL_CMD_EAL_PARAMS               (ENGINE_CMD_BASE + 1)
#define CPT_ENGINE_CTRL_CMD_EAL_INIT                 (ENGINE_CMD_BASE + 2)
#define CPT_ENGINE_CTRL_CMD_EAL_PID_IN_FP            (ENGINE_CMD_BASE + 3)
#define CPT_ENGINE_CTRL_CMD_EAL_CORE_BY_CPU          (ENGINE_CMD_BASE + 4)
#define CPT_ENGINE_CTRL_CMD_EAL_CPTVF_BY_CPU         (ENGINE_CMD_BASE + 5)
#define CPT_ENGINE_CTRL_CMD_CRYPTO_DRIVER            (ENGINE_CMD_BASE + 6)
#define CPT_ENGINE_CTRL_CMD_CPTVF_QUEUES             (ENGINE_CMD_BASE + 7)
#define CPT_ENGINE_CTRL_CMD_ENGINE_ALG_SUPPORT       (ENGINE_CMD_BASE + 8)
#define CPT_ENGINE_CTRL_CMD_DPDK_QP_CONF_PARAMS      (ENGINE_CMD_BASE + 9)
#define CPT_ENGINE_CTRL_CMD_HW_OFFLOAD_THRESH_PKTSZ  (ENGINE_CMD_BASE + 10)
#define CPT_ENGINE_CTRL_CMD_ENG_LOG_LEVEL            (ENGINE_CMD_BASE + 11)
#define CPT_ENGINE_CTRL_CMD_ENG_LOG_FILE             (ENGINE_CMD_BASE + 12)
#define CPT_ENGINE_CTRL_CMD_POLL                     (ENGINE_CMD_BASE + 13)
#define CPT_ENGINE_GET_NUM_REQUESTS_IN_FLIGHT        (ENGINE_CMD_BASE + 14)

#define GET_NUM_ASYM_REQUESTS_IN_FLIGHT             1
#define GET_NUM_KDF_REQUESTS_IN_FLIGHT              2
#define GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT  3
#define GET_NUM_ASYM_MB_ITEMS_IN_QUEUE              4
#define GET_NUM_KDF_MB_ITEMS_IN_QUEUE               5
#define GET_NUM_SYM_MB_ITEMS_IN_QUEUE               6

#define ARMv8_AES_set_encrypt_key aes_v8_set_encrypt_key
#define ARMv8_AES_encrypt aes_v8_encrypt
#define ARMv8_AES_set_decrypt_key aes_v8_set_decrypt_key
#define ARMv8_AES_decrypt aes_v8_decrypt

extern unsigned int queues_per_vf[];
extern int asym_dev_id[];
extern int asym_queues[];
extern int sym_dev_id[];
extern int sym_queues[];
extern unsigned int dev_in_use;

int engine_log(uint32_t level, const char *fmt, ...);

void ENGINE_load_cpt_engine(void);
const EVP_CIPHER *cpt_engine_aes_128_cbc(void);
const EVP_CIPHER *cpt_engine_aes_256_cbc(void);
const EVP_CIPHER *cpt_engine_aes_128_gcm(void);
const EVP_CIPHER *cpt_engine_aes_256_gcm(void);
const EVP_CIPHER *cpt_engine_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *cpt_engine_aes_256_cbc_hmac_sha1(void);
/* CHACHA20-POLY1305 */
const EVP_CIPHER *cpt_engine_chacha20_poly1305(void);
void ossl_handle_async_asym_job(void **wctx);

int ossl_handle_async_job(void *resumed_wctx, void *wctx_p, int numpipes,
    uint8_t *job_qsz, async_pipe_job_t *pip_jobs, bool pause_job);

int ARMv8_AES_set_encrypt_key(const unsigned char *userKey, const int bits,
			      AES_KEY *key);
void ARMv8_AES_encrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);
int ARMv8_AES_set_decrypt_key(const unsigned char *userKey, const int bits,
			      AES_KEY *key);
void ARMv8_AES_decrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);

#endif /* _CPT_ENGINE_H */
