/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#ifndef __PAL_LC_DEFS_H__
#define __PAL_LC_DEFS_H__
#include <dao_liquid_crypto.h>
#include "liquid_crypto_priv.h"
#include "pal_rsa.h"

#define TEST_LC_TIMEOUT 10
typedef int (*iv_func_ptr)(void *, int, int, void *);

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

typedef struct pal_cpoly_ctx {
    struct dao_lc_sym_ctx cry_session;
	struct dao_lc_cmd_event event;
	uint8_t **input_buf;
    uint8_t **output_buf;
    size_t *input_len;
	uint8_t seq_num[SSL_MAX_PIPELINES][8];
    char aad_pipe[SSL_MAX_PIPELINES][TLS_AAD_LEN];
    uint8_t key[32];
    uint8_t aad[16];
    uint8_t auth_tag[16];
    unsigned char buf[16]; /* Buffer of partial blocks processed via update calls */
    uint8_t iv[12];
    uint32_t aad_cnt;
    int key_len;
    int tls_tag_len;
    int enc;
    int iv_len;
    int auth_taglen;
    int aad_len;
    int tls_aad_len;
    int tls_aad_pad_sz;
    int numpipes;
    int hw_offload_pkt_sz_threshold;
    int queue;
    int dev_id;
    async_job async_cb;
}pal_cpoly_ctx_t;

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

typedef struct pal_gcm_ctx {
	struct dao_lc_sym_ctx aead_cry_session;
	struct dao_lc_sym_ctx cipher_cry_session;
	struct dao_lc_cmd_event aead_event;
	struct dao_lc_cmd_event cipher_event;
	struct dao_lc_sym_op *op;
	uint8_t **input_buf;
	uint8_t **output_buf;
	long int *input_len;
	long int *output_len;
	char aad_pipe[SSL_MAX_PIPELINES][TLS_AAD_LEN];
	uint8_t key[32];
	uint64_t iv[3];
	uint8_t auth_tag[16];
	uint32_t aad_cnt;
	/* Below members are for pipeline */
	volatile int numpipes;
	int aad_len;
	int ivlen;
	int tls_aad_len;
	int tls_exp_iv_len;
	int tls_tag_len;
	int enc;
	int sym_queue;
	int dev_id; /* cpt dev_id*/
	int hw_offload_pkt_sz_threshold;
	uint16_t hw_off_pkt_sz_thrsh;
	uint8_t *aad;
	uint8_t keylen;
	uint8_t is_tlsv_1_3;
	iv_func_ptr iv_cb;
	async_job async_cb;
} pal_gcm_ctx_t;

int prepare_lc_buf(struct dao_lc_buf **head, uint8_t *data, long int len);
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

static inline void pal_sym_session_cbc_init(pal_cbc_ctx_t *pal_ctx)
{
	memset(&pal_ctx->cry_session, 0, sizeof(pal_ctx->cry_session));
	memset(&pal_ctx->event, 0, sizeof(pal_ctx->event));
}
#endif
