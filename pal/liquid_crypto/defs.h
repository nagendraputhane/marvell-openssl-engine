/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __PAL_LC_DEFS_H__
#define __PAL_LC_DEFS_H__
#include <dao_liquid_crypto.h>
#include "pal_rsa.h"

#define TEST_LC_TIMEOUT 10

enum ossl_log_error {
	OSSL_LOG_STDERR = 0,
	OSSL_LOG_EMERG = 1,
	OSSL_LOG_ERR = 2,
	OSSL_LOG_INFO = 3
};
struct global_params {
	uint8_t dev_id;
	uint16_t qp_id;
	struct dao_lc_info info;
};

extern struct global_params glb_params;

int op_dequeue(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res);
int ossl_log(uint32_t level, const char *fmt, ...);

typedef enum pal_rsa_key_type {
	PAL_RSA_KEY_TYPE_EXP=0,
	PAL_RSA_KEY_TYPE_QT
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
	int out_len;
	uint8_t is_completed;
	uint8_t is_success;
} pal_rsa_ctx_t;


#define PAL_ASSERT(cond, error_msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "%s\n", (error_msg)); \
			return 0; \
		} \
	} while (0)

typedef struct pal_cbc_ctx {
	struct dao_lc_sym_ctx cry_session;
	struct dao_lc_cmd_event event;
	/* Below members are for pipeline */
	//struct dao_lc_buf *input_buf;
	//struct dao_lc_buf *output_buf;
	uint8_t **input_buf;
	uint8_t **output_buf;
	long int *input_len;
	int hw_offload_pkt_sz_threshold;
	int sym_queue;
	int dev_id; /* cpt dev_id*/
	uint8_t numpipes;
	async_job async_cb;
} pal_cbc_ctx_t;

int sym_create_session(uint16_t dev_id,
		struct dao_lc_sym_ctx cry_session,struct dao_lc_cmd_event *event, uint8_t reconfigure, uint64_t sess_cookie);
int sym_session_cleanup(struct dao_lc_cmd_event *event, int dev_id);
static int sess_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *ev);
static inline int sym_get_valid_devid_qid(int *devid, int *queue)
{
	*devid = glb_params.dev_id;
	*queue = glb_params.qp_id;
	return 1;
}

static inline void pal_sym_session_init(pal_cbc_ctx_t *pal_ctx)
{
	memset(&pal_ctx->cry_session, 0, sizeof(pal_ctx->cry_session));
	memset(&pal_ctx->event, 0, sizeof(pal_ctx->event));
}
#endif
