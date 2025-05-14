/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include "pal.h"

#include <openssl/objects.h>

#include "pal_ecdsa.h"

#define MAX_DEQUEUE_OPS 32

extern int cpt_num_asym_requests_in_flight;
extern dpdk_pools_t *pools;

static int ecdsa_sess_create(struct rte_crypto_asym_xform *ecdsa_xform,
			     struct rte_cryptodev_asym_session **sess, int devid)
{
	int ret;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	ret = rte_cryptodev_asym_session_create(devid, ecdsa_xform,
						pools->asym_sess_pool,
						(void **)sess);
	if (ret < 0) {
		engine_log(ENG_LOG_ERR, "Asym session create failed\n");
		return 0;
	}
#else
	*sess = rte_cryptodev_asym_session_create(pools->asym_sess_pool);
	if (*sess == NULL) {
		engine_log(ENG_LOG_ERR, "Asym session create failed\n");
		return 0;
	}

	ret = rte_cryptodev_asym_session_init(devid, *sess, ecdsa_xform,
					      pools->asym_sess_pool);

	if (ret < 0) {
		engine_log(ENG_LOG_ERR, "Asym session init failed\n");
		rte_cryptodev_asym_session_free(*sess);
		*sess = NULL;
		return 0;
	}
#endif
	return 1;
}

static int ecdh_sess_create(struct rte_crypto_asym_xform *ecdh_xform,
                             struct rte_cryptodev_asym_session **sess,
                             int devid)
{
  int ret;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
  ret = rte_cryptodev_asym_session_create(devid, ecdh_xform,
      pools->asym_sess_pool,
      (void **)sess);
  if (ret < 0)
    return 0;
#else
  *sess = rte_cryptodev_asym_session_create(pools->asym_sess_pool);
  if (*sess == NULL)
    return 0;

  ret = rte_cryptodev_asym_session_init(devid, *sess, ecdh_xform,
      pools->asym_sess_pool);

  if (ret < 0) {
    engine_log(ENG_LOG_ERR, "Asym session init failed\n");
    rte_cryptodev_asym_session_free(*sess);
    *sess = NULL;
    return 0;
  }
#endif

  return 1;
}

/**
 * @returns 1 on success, 0 on auth failure, and -1 on error
 */
static int perform_crypto_op(struct rte_crypto_op *crypto_op, pal_ecdsa_ctx_t *pal_ctx)
{
	struct rte_crypto_op *result_ops[MAX_DEQUEUE_OPS];
	struct rte_crypto_asym_xform *asym_xform = NULL;
	uint8_t **wctx_p = NULL;
	uint16_t nb_ops;

	if (rte_cryptodev_enqueue_burst(pal_ctx->devid, pal_ctx->queue, &crypto_op, 1) != 1) {
		engine_log(ENG_LOG_ERR, "Could not enqueue the crypto opeation\n");
		return -1;
	}

	asym_xform = __rte_crypto_op_get_priv_data(crypto_op,
			sizeof(struct rte_crypto_asym_xform));
	wctx_p = (uint8_t **) asym_xform + 1;
	*wctx_p = pal_ctx->wctx_p;

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);
  if(pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

	while (crypto_op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED) {
		nb_ops = rte_cryptodev_dequeue_burst(pal_ctx->devid, pal_ctx->queue, result_ops,
							 MAX_DEQUEUE_OPS);
		if (nb_ops == 0 && pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	if (crypto_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		if (crypto_op->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED)
			return 0;
		else {
			engine_log(ENG_LOG_ERR,
				"Crypto (ECDSA) operation not success (err: %d)", crypto_op->status);
			return -1;
		}
	}

	return 1;
}

/**
 * @returns 1 on success, 0 on failure
 * Conforms to OpenSSL's ECDSA_sign semantics
 */
int pal_ecdsa_sign(pal_ecdsa_ctx_t *pal_ctx)
{
	const int xform_size = sizeof(struct rte_crypto_asym_xform);
	struct rte_crypto_ecdsa_op_param *ecdsa_param = NULL;
	struct rte_crypto_asym_xform *asym_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *crypto_op = NULL;
  struct rte_crypto_ec_point *cp;
	int ret = 0;

	crypto_op = rte_crypto_op_alloc(pools->asym_op_pool,
					RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (crypto_op == NULL)
		return 0;

	asym_xform = __rte_crypto_op_get_priv_data(crypto_op, xform_size);

  memset(asym_xform, 0, sizeof(*asym_xform));
	asym_op = &crypto_op->asym[0];
	ecdsa_param = &asym_op->ecdsa;

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 99)
    ecdsa_param->pkey.data = pal_ctx->pkey;
    ecdsa_param->pkey.length = pal_ctx->pkey_len;
#else
    asym_xform->ec.pkey.length = pal_ctx->pkey_len;
    asym_xform->ec.pkey.data = pal_ctx->pkey;
#endif

    asym_xform->next = NULL;
    asym_xform->xform_type = pal_ctx->xform_type;
    asym_xform->ec.curve_id = pal_ctx->curve_id; 

    if (!ecdsa_sess_create(asym_xform, &sess, pal_ctx->devid))
		goto err;

	if (rte_crypto_op_attach_asym_session(crypto_op, sess) != 0)
		goto err;

  ecdsa_param->k.data = pal_ctx->secret;
  ecdsa_param->k.length = pal_ctx->secret_len;
	ecdsa_param->op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	ecdsa_param->message.data = pal_malloc(pal_ctx->dlen);
	ecdsa_param->message.length = pal_ctx->dlen;

	if (ecdsa_param->message.data == NULL)
		goto err;

	memcpy(ecdsa_param->message.data, pal_ctx->dgst, pal_ctx->dlen);
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 99)
  cp = &ecdsa_param->q;
#else
  cp = &asym_xform->ec.q;
#endif

  cp->x.data = pal_ctx->x_data;
  cp->x.length = pal_ctx->x_data_len;
  cp->y.data = pal_ctx->y_data;
  cp->y.length = pal_ctx->y_data_len;

  ecdsa_param->r.data = pal_ctx->rdata;
  ecdsa_param->s.data = pal_ctx->sdata;
  ecdsa_param->r.length = pal_ctx->rlen;
  ecdsa_param->s.length = pal_ctx->slen;

	if (ecdsa_param->r.data == NULL || ecdsa_param->s.data == NULL)
		goto err;

  if (perform_crypto_op(crypto_op, pal_ctx) != 1)
    goto err;

  pal_ctx->rlen = ecdsa_param->r.length;
  pal_ctx->slen = ecdsa_param->s.length;
  ret = 1;
err:
	if (sess != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		rte_cryptodev_asym_session_clear(pal_ctx->devid, sess);
		rte_cryptodev_asym_session_free(sess);
#else
		rte_cryptodev_asym_session_free(pal_ctx->devid, sess);
#endif
	}
	if (crypto_op != NULL)
		rte_crypto_op_free(crypto_op);

  pal_free(ecdsa_param->message.data);
  ecdsa_param->message.data = NULL;
	return ret;
}

/**
 * @returns 1 on successful verification, 0 on verification failure, -1 on error
 */
int pal_ecdsa_verify(pal_ecdsa_ctx_t *pal_ctx)
{
	int ret = -1;
	const int xform_size = sizeof(struct rte_crypto_asym_xform);
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_xform *asym_xform = NULL;
	struct rte_crypto_ecdsa_op_param *ecdsa_param = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *crypto_op = NULL;
  struct rte_crypto_ec_point *cp;
	int rlen;
	int slen;

	crypto_op = rte_crypto_op_alloc(pools->asym_op_pool,
					RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (crypto_op == NULL)
		return -1;

	asym_xform = __rte_crypto_op_get_priv_data(crypto_op, xform_size);

	if (asym_xform == NULL)
		return -1;

  memset(asym_xform, 0, sizeof(*asym_xform));
  asym_xform->next = NULL;
  asym_xform->xform_type = pal_ctx->xform_type;
	asym_xform->ec.curve_id = pal_ctx->curve_id;

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 99)
  cp = &ecdsa_param->q;
#else
  cp = &asym_xform->ec.q;
#endif
  cp->x.data = pal_ctx->x_data;
  cp->x.length = pal_ctx->x_data_len;
  cp->y.data = pal_ctx->y_data;
  cp->y.length = pal_ctx->y_data_len;



	if (!ecdsa_sess_create(asym_xform, &sess, pal_ctx->devid))
		goto err;

	if (rte_crypto_op_attach_asym_session(crypto_op, sess) != 0)
		goto err;

  memset(asym_xform, 0, sizeof(*asym_xform));
	asym_op = &crypto_op->asym[0];
	ecdsa_param = &asym_op->ecdsa;

	asym_op = &crypto_op->asym[0];
	ecdsa_param = &asym_op->ecdsa;
	memset(&ecdsa_param->k, 0, sizeof(rte_crypto_param));
	;
	ecdsa_param->op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
	ecdsa_param->message.data = pal_malloc(pal_ctx->dlen);
	ecdsa_param->message.length = pal_ctx->dlen;

	if (ecdsa_param->message.data == NULL)
		goto err;

	memcpy(ecdsa_param->message.data, pal_ctx->dgst, pal_ctx->dlen);

	ecdsa_param->r.data = pal_ctx->rdata;
	ecdsa_param->s.data = pal_ctx->sdata;
	ecdsa_param->r.length = pal_ctx->rlen;
	ecdsa_param->s.length = pal_ctx->slen;

	if (ecdsa_param->r.data == NULL || ecdsa_param->s.data == NULL)
		goto err;

	ret = perform_crypto_op(crypto_op, pal_ctx);

err:
	if(sess != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		rte_cryptodev_asym_session_clear(pal_ctx->devid, sess);
		rte_cryptodev_asym_session_free(sess);
#else
		rte_cryptodev_asym_session_free(pal_ctx->devid, sess);
#endif
	}
	if ( crypto_op != NULL)
		rte_crypto_op_free(crypto_op);
  if (ecdsa_param->message.data != NULL) {
    pal_free(ecdsa_param->message.data);
    ecdsa_param->message.data = NULL;
  }

	return ret;
}

int pal_ecdsa_ec_point_multiplication( pal_ecdsa_ctx_t *pal_ctx)
{
  struct rte_crypto_asym_op *asym_op = NULL;
  struct rte_crypto_op *op = NULL;
  struct rte_cryptodev_asym_session *sess = NULL;
  struct rte_crypto_asym_xform *xform;
  int ret = -1;

  /* set up crypto op data structure */

  op = rte_crypto_op_alloc(pools->asym_op_pool,
      RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op) {
    RTE_LOG(ERR, USER1, " line %u FAILED: %s asym_op_pool %p\n",
        __LINE__, "Failed to allocate asymmetric crypto"
        "operation struct", pools->asym_op_pool);
    goto error_exit;
  }

  xform = __rte_crypto_op_get_priv_data(op,
      sizeof(struct rte_crypto_asym_xform));

  memset(xform, 0, sizeof(*xform));
  xform->next = NULL;
  xform->xform_type = pal_ctx->xform_type;
  xform->ec.curve_id = pal_ctx->curve_id;

  if (!ecdh_sess_create(xform, &sess, pal_ctx->devid))
    goto error_exit;

  /* attach asymmetric crypto session to crypto operations */
  rte_crypto_op_attach_asym_session(op, sess);

  asym_op = op->asym;
  asym_op->ecpm.p.x.data = pal_ctx->x_data;
  asym_op->ecpm.p.x.length = pal_ctx->x_data_len;
  asym_op->ecpm.p.y.data = pal_ctx->y_data;
  asym_op->ecpm.p.y.length = pal_ctx->y_data_len;
  asym_op->ecpm.scalar.data = pal_ctx->scalar_data;
  asym_op->ecpm.scalar.length = pal_ctx->scalar_data_len;

  asym_op->ecpm.r.x.data = pal_ctx->rxbuf;
  asym_op->ecpm.r.y.data = pal_ctx->rybuf;

  ret = perform_crypto_op(op, pal_ctx);
  if (ret < 1) {
    ret = 0;
    RTE_LOG(ERR, USER1,
        "%s: EC Point arithmetic failure: ret: %d",
        __func__, ret);
    return ret;
  }

  ret = asym_op->ecpm.r.x.length;
error_exit:
  rte_crypto_op_free(op);
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
  rte_cryptodev_asym_session_clear(pal_ctx->devid, sess);

  if (rte_cryptodev_asym_session_free(sess) != 0)
    engine_log(ENG_LOG_ERR, "Could not free the asym session properly\n");
#else
  if (rte_cryptodev_asym_session_free(pal_ctx->devid, sess) != 0)
    engine_log(ENG_LOG_ERR, "Could not free the asym session properly\n");
#endif

  return ret;
}
