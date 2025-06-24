/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PAL_COMMON_PAL_H__
#define __PAL_COMMON_PAL_H__

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_version.h>


#if defined CRYPTO_OCTEONTX2
#include "pal_otx2.h"
#elif defined(CRYPTO_A80X0)
#include "pal_a80x0.h"
#else
#include "pal_openssl.h"
#endif

#define OCTEON_CACHE_LINE_SIZE 128
#define SSL_MAX_PIPELINES	32
#define  EVP_AEAD_TLS1_AAD_LEN    13
#define MAX_DEQUEUE_OPS           32
#define MAX_ENQUEUE_ATTEMPTS			20
#define PAL_CPOLY_IV_LEN          12
#define PAL_NUM_DEQUEUED_OPS		  32
#define MAX_PIPE_JOBS             64
#define PAL_AES_BLOCK_SIZE		    16
#define PAL_MAX_CPT_SYM_DEVICES	  48
#define PAL_MAX_CPT_ASYM_DEVICES	24
#define PAL_AES_GCM_IV_LENGTH		  12
#define PAL_AES_CBC_IV_LENGTH		  16
#define MIN(a, b)				((a) < (b) ? (a) : (b))
#define MAX(a, b)				((a) > (b) ? (a) : (b))
#define ASYM_OP_POOL_INDEX        0
#define SYM_OP_POOL_INDEX         3
#define ASYM_SESSION_POOL_INDEX   1
#define MBUF_POOL_INDEX           2
#define SYM_SESSION_POOL_INDEX    4
#define CACHE_FLUSH_THRESHOLD_MULTIPLIER 1.5
#define CACHESZ_LIMIT(n)((n>1)?((n/CACHE_FLUSH_THRESHOLD_MULTIPLIER)-1):0)
#define PAL_CPT_DIGEST_LEN			64
#define PAL_MAX_THREADS  RTE_MAX_LCORE

#define PAL_IV_OFFSET			\
	(sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define PAL_MAX_CPT_DEVICES	\
	(PAL_MAX_CPT_SYM_DEVICES + PAL_MAX_CPT_ASYM_DEVICES)

/* use the maximum iv length(GCM, CBC, CPOLY) so that GCM,CBC,CPOLY
 * can ack crypto operations for each other */
#define PAL_COP_METADATA_OFF                                    \
	(PAL_IV_OFFSET + MAX(PAL_CPOLY_IV_LEN,            \
	MAX(PAL_AES_CBC_IV_LENGTH, PAL_AES_GCM_IV_LENGTH)))

#define PAL_MAX_DRIVER_NAME_LEN 64

# define CPT_ATOMIC_INC(cpt_int)              \
	            (__sync_add_and_fetch(&(cpt_int), 1))

# define CPT_ATOMIC_DEC(cpt_int)              \
	            (__sync_sub_and_fetch(&(cpt_int), 1))
# define CPT_ATOMIC_INC_N(cpt_int, n)              \
	            (__sync_add_and_fetch(&(cpt_int), n))

# define CPT_ATOMIC_DEC_N(cpt_int, n)              \
	            (__sync_sub_and_fetch(&(cpt_int), n))

enum async_job_action {
	ASYNC_JOB_POST_FINISH,
	ASYNC_JOB_PAUSE
};

typedef struct pal_rsa_ctx pal_rsa_ctx_t;

enum engine_log_error {
	ENG_LOG_STDERR = 0,
	ENG_LOG_EMERG = 1,
	ENG_LOG_ERR = 2,
	ENG_LOG_INFO = 3
};

typedef enum pal_crypto_aead_algorithm {
  PAL_CRYPTO_AEAD_AES_GCM = RTE_CRYPTO_AEAD_AES_GCM,
  PAL_CRYPTO_AEAD_CHACHA20_POLY1305 = RTE_CRYPTO_AEAD_CHACHA20_POLY1305,
} pal_crypto_aead_algorithm_t;

typedef enum pal_crypto_cipher_algorithm {
  PAL_CRYPTO_CIPHER_AES_CBC = RTE_CRYPTO_CIPHER_AES_CBC,
  PAL_CRYPTO_CIPHER_AES_CTR = RTE_CRYPTO_CIPHER_AES_CTR,
  PAL_CRYPTO_CIPHER_AES_CBC_HMAC_SHA1 = RTE_CRYPTO_AUTH_SHA1_HMAC ,
  PAL_CRYPTO_CIPHER_AES_GCM
} pal_crypto_cipher_algorithm_t;

typedef struct  pal_cryptodev_config {
  int *q_per_dev;
  int *asym_qs;
  int *sym_qs;
	int *sym_dev_ids;
	int *asym_dev_ids;
  int dev_in_use;
  int sym_qp_descs;
  int asym_qp_descs;
  int nb_mbufs;
  int nb_ops;
  int nb_sessions;
  int pool_cache_size;
	int custom_mbuf_sz;
	int digest_len;
	int nb_sym_ops;
	int nb_asym_ops;
} pal_cryptodev_config_t;

typedef struct dpdk_pools {
  struct rte_mempool *mbuf_pool;
  struct rte_mempool *sym_ses_pool;
  struct rte_mempool *sym_op_pool;
  struct rte_mempool *asym_sess_pool;
  struct rte_mempool *asym_op_pool;
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
  struct rte_mempool *sym_sess_priv_pool;
#endif
} dpdk_pools_t;

typedef struct ossl_cry_op_status {
	int is_complete;
	int is_successful;
	int numpipes;
  void *wctx_p;
} pal_cry_op_status_t;

typedef struct async_pipe_job {
    void *wctx_p;
    int counter;
} async_pipe_job_t;

int pal_plt_init(void);
int engine_log(uint32_t level, const char *fmt, ...);
int ossl_log(uint32_t level, const char *fmt, ...);
void pal_register_log_fp_and_level(FILE* fp, uint32_t level);
int pal_crypto_init(int argc, char **argv, bool rte_eal_init, char *);
void pal_crypto_uninit();
int pal_crypto_get_num_devices(void);
int pal_cryptodev_config(pal_cryptodev_config_t *config);
int pal_asym_create_session(uint16_t dev_id, struct rte_crypto_asym_xform *xform,
    struct rte_cryptodev_asym_session **sess);
struct rte_cryptodev_sym_session *pal_sym_create_session(uint16_t dev_id,
    struct rte_crypto_sym_xform *xform,  uint8_t reconfigure,
    struct rte_cryptodev_sym_session *ses);
int pal_sym_session_cleanup(struct rte_cryptodev_sym_session *session, int dev_id);

bool pal_is_hw_sym_algos_supported(int algo);
void pal_get_prop_name_and_desc(char* name,int len,
                                    char* rsa_desc, int rsa_len,
                                    char* ec_desc, int ec_len);
void pal_get_provider_name(char *name, int len);

int pal_cryptodev_configuration(pal_cryptodev_config_t *config);
int pal_get_sym_valid_dev(int index);
int pal_set_hw_offload_pktsz_thresh(uint16_t pkt_sz_thresh);
typedef int (*async_job) (void *resumed_wctx, void *wctx_p, int numpipes,
        uint8_t *job_qsz, async_pipe_job_t *pip_jobs, bool pause_job);
void * pal_pktbuf_alloc(size_t len, size_t predata_len);
void *pal_pktbuf_realloc(void *ptr, size_t len, size_t predata_len);
void pal_pktbuf_free(void *ptr);
int pal_get_thread_id();
int pal_plt_init();
void * pal_malloc(size_t len);
void pal_free(void *);

#endif //__PAL_HH__
