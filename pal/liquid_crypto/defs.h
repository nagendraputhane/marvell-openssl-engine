
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

