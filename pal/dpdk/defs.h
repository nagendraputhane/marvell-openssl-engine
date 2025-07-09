/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __DPDK_DEFS_H__
#define __DPDK_DEFS_H__

#include "pal.h"
#include "pal_rsa.h"

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
#define PAL_MAX_THREADS  RTE_MAX_LCORE

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

int asym_create_session(uint16_t dev_id, struct rte_crypto_asym_xform *xform,
	struct rte_cryptodev_asym_session **sess);
struct rte_cryptodev_sym_session *sym_create_session(uint16_t dev_id,
	struct rte_crypto_sym_xform *xform,  uint8_t reconfigure,
	struct rte_cryptodev_sym_session *ses);
int sym_session_cleanup(struct rte_cryptodev_sym_session *session, int dev_id);
int asym_get_valid_devid_qid(int *devid, int *queue);
int sym_get_valid_devid_qid(int *devid, int *queue);
static inline void pal_sym_session_cbc_init(pal_cbc_ctx_t *pal_ctx)
{
	pal_ctx->cry_session = NULL;
}

#endif
