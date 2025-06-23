/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal_rsa.h"
#include "pal.h"
#include <openssl/bn.h>
#include "defs.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

RSA_METHOD * default_rsa_meth;

extern int cpt_num_asym_requests_in_flight;
extern dpdk_pools_t *pools;
const struct rte_cryptodev_asymmetric_xform_capability *asym_rsa_xform_cap = NULL;
static inline void
setup_non_crt_pub_op_xform(struct rte_crypto_asym_xform *rsa_xform,
                           pal_rsa_ctx_t *pal_ctx);

int pal_asym_xform_capability_check_modlen(int16_t modlen)
{
  return rte_cryptodev_asym_xform_capability_check_modlen(
            asym_rsa_xform_cap, modlen);
}

static int asym_sess_create(struct rte_crypto_asym_xform *rsa_xform,
			    struct rte_cryptodev_asym_session **sess, int dev_id)
{
	int ret = 0;

	/* Create Asym Session */
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	ret = rte_cryptodev_asym_session_create(dev_id, rsa_xform,
						pools->asym_sess_pool,
						(void **)sess);
	if (unlikely(ret < 0)) {
		engine_log(ENG_LOG_ERR,	"line %u FAILED: %s", __LINE__,
			"Session creation failed");
		return -1;
	}
#else
	*sess = rte_cryptodev_asym_session_create(pools->asym_sess_pool);
	if (unlikely(sess == NULL)) {
		engine_log(ENG_LOG_ERR,	"line %u FAILED: %s", __LINE__,
			"Session creation failed");
		return -1;
	}

	ret = rte_cryptodev_asym_session_init(dev_id, *sess, rsa_xform,
					      pools->asym_sess_pool);
	if (unlikely(ret < 0)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"unable to config asym session");
		rte_cryptodev_asym_session_free(*sess);
		return -1;
	}
#endif
	return 1;
}

static void asym_sess_destroy(struct rte_cryptodev_asym_session *sess, int dev_id)
{
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	rte_cryptodev_asym_session_free(dev_id, sess);
#else
	rte_cryptodev_asym_session_clear(dev_id, sess);
	rte_cryptodev_asym_session_free(sess);
#endif
}

static int queue_ops(struct rte_crypto_op *cry_op, pal_rsa_ctx_t *pal_ctx)
{
	int nb_ops = 0;
	struct rte_crypto_op *result_op[MAX_DEQUEUE_OPS];
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	uint8_t **wctx_p = NULL;
	uint32_t op_size = 0;

	op_size = __rte_crypto_op_get_priv_data_size(pools->asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);
	wctx_p = (uint8_t **) rsa_xform + 1;
	*wctx_p = pal_ctx->wctx_p;

	if (rte_cryptodev_enqueue_burst(pal_ctx->dev_id, pal_ctx->qp_id, &cry_op, 1) != 1) {
		engine_log(ENG_LOG_ERR, "Error in cryptodev enqueue\n");
		return -1;
	}

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);
  if(pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

	while (cry_op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED) {
		nb_ops = rte_cryptodev_dequeue_burst(pal_ctx->dev_id, pal_ctx->qp_id, result_op,
							 MAX_DEQUEUE_OPS);
		if (nb_ops == 0 && pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	if (cry_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		engine_log(ENG_LOG_ERR, "Crypto (RSA) op status is not success!\n");
		return -1;
	}
	return 1;
}

void setup_crt_priv_op_xform(struct rte_crypto_asym_xform *rsa_xform, pal_rsa_ctx_t *pal_ctx)
{
	rsa_xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;
	rsa_xform->rsa.key_type = pal_ctx->rsa_key_type;
  rsa_xform->rsa.n.data = pal_ctx->rsa_n_data;
  rsa_xform->rsa.n.length = pal_ctx->rsa_n_len;
	rsa_xform->rsa.e.data = pal_ctx->rsa_e_data;
	rsa_xform->rsa.e.length = pal_ctx->rsa_e_len;
  rsa_xform->rsa.qt.p.data = pal_ctx->rsa_qt_p_data;
  rsa_xform->rsa.qt.p.length = pal_ctx->rsa_qt_p_len;
  rsa_xform->rsa.qt.q.data = pal_ctx->rsa_qt_q_data;
  rsa_xform->rsa.qt.q.length = pal_ctx->rsa_qt_q_len;
  rsa_xform->rsa.qt.dP.data = pal_ctx->rsa_qt_dP_data;
  rsa_xform->rsa.qt.dP.length = pal_ctx->rsa_qt_dP_len;
  rsa_xform->rsa.qt.dQ.data = pal_ctx->rsa_qt_dQ_data;
  rsa_xform->rsa.qt.dQ.length = pal_ctx->rsa_qt_dQ_len;
  rsa_xform->rsa.qt.qInv.data = pal_ctx->rsa_qt_qInv_data;
  rsa_xform->rsa.qt.qInv.length = pal_ctx->rsa_qt_qInv_len;
}

/*
 * API Description: Performs RSA private encryption.
 *
 * pal_rsa_ctx_t *pal_ctx: RSA context.
 * int flen: Length of input data.
 * const unsigned char *from: Input data.
 * unsigned char *to: Buffer for encrypted output.
 *
 * Return Value: Length of encrypted data on success, -1 on failure.
 */
int pal_rsa_priv_enc(pal_rsa_ctx_t *pal_ctx, int flen,
    const unsigned char *from, unsigned char *to)
{
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0;

	if(!asym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->qp_id))
		return -1;

	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(pools->asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(pools->asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup private xform operations */
	if (pal_ctx->use_crt_method)
		setup_crt_priv_op_xform(rsa_xform, pal_ctx);
	else
    /* Pub and priv only d option is mandatory */
		setup_non_crt_pub_op_xform(rsa_xform, pal_ctx);

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess, pal_ctx->dev_id);
	if (unlikely(ret < 0)) {
		rte_crypto_op_free(cry_op);
		return -1;
	}

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	asym_op->rsa.message.data = from;
	asym_op->rsa.message.length = flen;
	asym_op->rsa.sign.length = flen;
	asym_op->rsa.sign.data = to;
	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (pal_ctx->padding == PAL_RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op, pal_ctx) < 0))
		ret = -1;
        else
           ret = asym_op->rsa.sign.length;

	asym_sess_destroy(sess, pal_ctx->dev_id);
	rte_crypto_op_free(cry_op);

	return ret;
}

static inline void
setup_non_crt_pub_op_xform(struct rte_crypto_asym_xform *rsa_xform,
                           pal_rsa_ctx_t *pal_ctx)
{
   memset(rsa_xform, 0, sizeof(struct rte_crypto_asym_xform));
   rsa_xform->rsa.n.data = pal_ctx->rsa_n_data;
   rsa_xform->rsa.n.length = pal_ctx->rsa_n_len;
   rsa_xform->rsa.e.data = pal_ctx->rsa_e_data;
   rsa_xform->rsa.e.length = pal_ctx->rsa_e_len;
   if(pal_ctx->rsa_d_data)
   {
      rsa_xform->rsa.d.data = pal_ctx->rsa_d_data;
      rsa_xform->rsa.d.length = pal_ctx->rsa_d_len;
      rsa_xform->rsa.key_type = pal_ctx->rsa_key_type;
   }
   rsa_xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;
}

/*
 * API Description: Performs RSA Public decryption.
 *
 * pal_rsa_ctx_t *pal_ctx: RSA context.
 * int flen: Length of input data.
 * const unsigned char *from: Input data.
 * unsigned char *to: Buffer for encrypted output.
 *
 * Return Value: Length of decrypted data on success, -1 on failure.
 */
int pal_rsa_pub_dec(pal_rsa_ctx_t *pal_ctx, int flen,
    const unsigned char *from, unsigned char *to)
{
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0;

	if(!asym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->qp_id))
        	return -1;

	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(pools->asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(pools->asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup public xform opertions */
	setup_non_crt_pub_op_xform(rsa_xform, pal_ctx);

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess, pal_ctx->dev_id);
	if (unlikely(ret < 0)) {
		rte_crypto_op_free(cry_op);
		return -1;
	}

	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;

	/* Octeon PMDs (otx2/cnxk) overwrite decrypted result in rsa.sign.data
	 * Note: Openssl PMD does not return decrypted result and it is not supported.
	 */
	if (to != from)
		memcpy(to, from, flen);
	asym_op->rsa.sign.data = to;
	asym_op->rsa.sign.length = flen;

	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (pal_ctx->padding == PAL_RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op, pal_ctx) < 0))
		ret = -1;
	else
		ret = asym_op->rsa.sign.length;

	asym_sess_destroy(sess, pal_ctx->dev_id);
	rte_crypto_op_free(cry_op);

	return ret;
}

/*
 * API Description: Performs RSA Public encryption.
 *
 * pal_rsa_ctx_t *pal_ctx: RSA context.
 * int flen: Length of input data.
 * const unsigned char *from: Input data.
 * unsigned char *to: Buffer for encrypted output.
 *
 * Return Value: 1 on success, -1 on failure.
 */
int pal_rsa_pub_enc(pal_rsa_ctx_t *pal_ctx, int flen,
    const unsigned char *from, unsigned char *to)
{
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0;

	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(pools->asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(pools->asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup public xform operations */
	setup_non_crt_pub_op_xform(rsa_xform, pal_ctx);

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif
	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess, pal_ctx->dev_id);
	if (unlikely(ret < 0)) {
		rte_crypto_op_free(cry_op);
		return -1;
	}

	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_ENCRYPT;

	asym_op->rsa.message.length = flen;
	asym_op->rsa.message.data = from;
	asym_op->rsa.cipher.length = 0;
	asym_op->rsa.cipher.data = to;
	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (pal_ctx->padding == PAL_RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op, pal_ctx) < 0))
		ret = -1;

	asym_sess_destroy(sess, pal_ctx->dev_id);
	rte_crypto_op_free(cry_op);

	return ret;
}

/*
 * API Description: Performs RSA Private decryption.
 *
 * pal_rsa_ctx_t *pal_ctx: RSA context.
 * int flen: Length of input data.
 * const unsigned char *from: Input data.
 * unsigned char *to: Buffer for encrypted output.
 *
 * Return Value: Length of decrypted data on success, -1 on failure.
 */

int pal_rsa_priv_dec(pal_rsa_ctx_t *pal_ctx, int flen,
    const unsigned char *from, unsigned char *to)
{
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0;

	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(pools->asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(pools->asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup priv xform opertions */
	setup_crt_priv_op_xform(rsa_xform, pal_ctx);

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif
	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess, pal_ctx->dev_id);
	if (unlikely(ret < 0)) {
		rte_crypto_op_free(cry_op);
		return -1;
	}
	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_DECRYPT;

	asym_op->rsa.message.data = to;
	asym_op->rsa.message.length = 0;
	asym_op->rsa.cipher.data = from;
	asym_op->rsa.cipher.length = flen;
	if (pal_ctx->padding == PAL_RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (pal_ctx->padding == PAL_RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif
	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op, pal_ctx) < 0))
		ret = -1;
	else
		ret = asym_op->rsa.message.length;

	asym_sess_destroy(sess, pal_ctx->dev_id);
	rte_crypto_op_free(cry_op);

	return ret;
}
