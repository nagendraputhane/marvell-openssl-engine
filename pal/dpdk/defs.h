/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "pal.h"
#include "pal_rsa.h"

#define ARMv8_AES_set_encrypt_key aes_v8_set_encrypt_key
#define ARMv8_AES_encrypt aes_v8_encrypt
#define ARMv8_AES_set_decrypt_key aes_v8_set_decrypt_key
#define ARMv8_AES_decrypt aes_v8_decrypt
extern const char *crypto_name;
extern int asym_dev_id[];
extern int asym_queues[];
extern int sym_dev_id[];
extern int sym_queues[];
#define OTX2_DEV_DOMAIN                 2
#define OTX2_NUM_ARGS           12
#define OTX2_NUM_PER_BUS                8
#define OTX2_DEF_DEV_BUS                        "10"
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#define CPT_PROVIDER_DEFAULT_SESSIONS              (128 << 10)
#define CPT_PROVIDER_DEFAULT_SYM_QP_DESC_COUNT     2048
#define CPT_PROVIDER_DEFAULT_MBUFS                 4096
#define CPT_PROVIDER_DEFAULT_SYM_OPS               4096
#define CPT_PROVIDER_DEFAULT_ASYM_QP_DESC_COUNT    512
#define CPT_PROVIDER_DEFAULT_POOL_CACHE_SIZE       512
#define CPT_PROVIDER_DEFAULT_ASYM_OPS              1024
#define CPT_PROVIDER_MBUF_CUSTOM_BUF_SIZE       (32 * 1024)

static inline int asym_get_valid_devid_qid(int *devid, int *queue)
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

static inline int sym_get_valid_devid_qid(int *devid, int *queue)
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

typedef enum pal_rsa_key_type {
  PAL_RSA_KEY_TYPE_EXP = RTE_RSA_KEY_TYPE_EXP,
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
  PAL_RSA_KEY_TYPE_QT = RTE_RSA_KEY_TYPE_QT
#else
  PAL_RSA_KEY_TYPE_QT = RTE_RSA_KET_TYPE_QT
#endif
} pal_rsa_key_type_t;

typedef struct pal_rsa_ctx {
  int dev_id;
  int qp_id;
  int pad_type;
  int rsa_key_type;
  uint8_t *rsa_n_data;
  uint8_t *rsa_e_data;
  uint8_t *rsa_d_data;
  uint8_t *rsa_qt_p_data;
  uint8_t *rsa_qt_q_data;
  uint8_t *rsa_qt_dP_data;
  uint8_t *rsa_qt_dQ_data;
  uint8_t *rsa_qt_qInv_data;
  int rsa_n_len;
  int rsa_e_len;
  int rsa_d_len;
  int rsa_qt_p_len;
  int rsa_qt_q_len;
  int rsa_qt_dP_len;
  int rsa_qt_dQ_len;
  int rsa_qt_qInv_len;
  int padding;
  int use_crt_method;
  async_job async_cb;
  uint8_t *wctx_p;
} pal_rsa_ctx_t;

typedef struct pal_cbc_ctx {
	struct rte_cryptodev_sym_session *cry_session;
	/* Below members are for pipeline */
	uint8_t **input_buf;
	uint8_t **output_buf;
	long int *input_len;
	int hw_offload_pkt_sz_threshold;
	int sym_queue;
	int dev_id; /* cpt dev_id*/
	uint8_t numpipes;
	async_job async_cb;
}pal_cbc_ctx_t;

int pal_asym_create_session(uint16_t dev_id, struct rte_crypto_asym_xform *xform,
	struct rte_cryptodev_asym_session **sess);
struct rte_cryptodev_sym_session *pal_sym_create_session(uint16_t dev_id,
	struct rte_crypto_sym_xform *xform,  uint8_t reconfigure,
	struct rte_cryptodev_sym_session *ses);
int pal_sym_session_cleanup(struct rte_cryptodev_sym_session *session, int dev_id);

static inline void pal_sym_session_init(pal_cbc_ctx_t *pal_ctx)
{
	pal_ctx->cry_session = NULL;
}
