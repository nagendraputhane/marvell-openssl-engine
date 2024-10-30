/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal.h"
#include "pal_common.h"

extern dpdk_pools_t *pools;

struct rte_cryptodev_sym_session *
pal_sym_create_session(uint16_t dev_id,
                       struct rte_crypto_sym_xform *xform,
                       uint8_t reconfigure,
                       struct rte_cryptodev_sym_session *ses)
{
  int retval;

  if (reconfigure)
    pal_sym_session_cleanup(ses, dev_id);

  /* Create Crypto session*/
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
    ses = rte_cryptodev_sym_session_create(dev_id, xform, pools->sym_ses_pool);
  if (!ses) {
    engine_log(ENG_LOG_ERR, "Could not create session.\n");
    return NULL;
  }
#else
  ses = rte_cryptodev_sym_session_create(pools->sym_ses_pool);
  if (!ses) {
    engine_log(ENG_LOG_ERR, "Could not create session.\n");
    return NULL;
  }

  if (rte_cryptodev_sym_session_init(dev_id, ses, 
        xform, pools->sym_ses_priv_pool) < 0) {
    engine_log(ENG_LOG_ERR, "Session could not be initialized "
        "for the crypto device\n");
    return NULL; 
  }
#endif

  return ses;

}

bool pal_is_hw_sym_algos_supported(int algo)
{
  struct rte_cryptodev_sym_capability_idx idx;
  struct rte_cryptodev_symmetric_capability *cap;

  switch (algo) {
    case PAL_CRYPTO_CIPHER_AES_CBC:
      idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
      idx.algo.cipher = RTE_CRYPTO_CIPHER_AES_CBC;
      break;
    case PAL_CRYPTO_CIPHER_AES_GCM:
      idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;
      idx.algo.aead = RTE_CRYPTO_AEAD_AES_GCM;
      break;
    case PAL_CRYPTO_CIPHER_AES_CBC_HMAC_SHA1:
      idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;
      idx.algo.auth = RTE_CRYPTO_AUTH_SHA1_HMAC;
      break;
    case PAL_CRYPTO_AEAD_CHACHA20_POLY1305:
      idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;
      idx.algo.aead = RTE_CRYPTO_AEAD_CHACHA20_POLY1305;
      break;
    default:
      engine_log(ENG_LOG_ERR, "Invalid algo\n");
      return false;
  }

  cap = rte_cryptodev_sym_capability_get(0, &idx);

  return cap? true:false;

}

int pal_sym_session_cleanup(struct rte_cryptodev_sym_session *session, int dev_id)
{
  int retval = 0;
	if (session != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_clear(dev_id, session);
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to clear session. ret=%d\n",
				retval);
		retval = rte_cryptodev_sym_session_free(session);
#else
		retval = rte_cryptodev_sym_session_free(dev_id, session);
#endif
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to free session. ret=%d\n",
				retval);
	}

	return 1;

}

int pal_asym_create_session(uint16_t dev_id, struct rte_crypto_asym_xform *xform,
                            struct rte_cryptodev_asym_session **sess)
{
  int ret;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	ret = rte_cryptodev_asym_session_create(dev_id, xform,
						pools->asym_sess_pool, (void **)sess);
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

	ret = rte_cryptodev_asym_session_init(devid, *sess, xform,
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

int pal_sym_poll(uint8_t dev_id, uint16_t qp_id,  async_job async_cb)
{
	int (*callback)(void *arg);
	void *args;
	struct rte_crypto_op *result_op[MAX_DEQUEUE_OPS];
	pal_cry_op_status_t *new_st_ptr[PAL_NUM_DEQUEUED_OPS];
	pal_cry_op_status_t current_job;
	int i, j, k, ret = 0;
	uint16_t num_dequeued_ops = 0;
	async_pipe_job_t pipe_asyncjobs[MAX_PIPE_JOBS];
	uint8_t present = 0;
	uint8_t pipe_job_qsz = 0;

	j = 0;
	do {
		num_dequeued_ops = rte_cryptodev_dequeue_burst(
				dev_id, qp_id,
				&result_op[0],
				PAL_NUM_DEQUEUED_OPS);
		/* Check the status of dequeued operations */
		for (i = 0; i < num_dequeued_ops; i++) {
			new_st_ptr[i] = rte_crypto_op_ctod_offset(result_op[i],
					pal_cry_op_status_t *, PAL_COP_METADATA_OFF);
			new_st_ptr[i]->is_complete = 1;

			/* Check if operation was processed successfully */
			if (result_op[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
				new_st_ptr[i]->is_successful = 0;
			else {
				new_st_ptr[i]->is_successful = 1;
				if(new_st_ptr[i]->wctx_p)
				    async_cb(NULL, new_st_ptr[i]->wctx_p,
						  new_st_ptr[i]->numpipes, &pipe_job_qsz,
						  &pipe_asyncjobs[0], 0);
			}
		}
	} while (pipe_job_qsz>0);

  return 0;
}

int pal_asym_poll(uint8_t dev_id, uint16_t qp_id, user_callback_fn callback)
{
  uint32_t op_size = __rte_crypto_op_get_priv_data_size(pools->asym_op_pool);
  struct rte_crypto_asym_xform *rsa_xform = NULL;
  void **wctx_p = NULL;
  struct rte_crypto_op *result_op[MAX_DEQUEUE_OPS];

  uint16_t nb_ops = rte_cryptodev_dequeue_burst(dev_id, qp_id, result_op,
               MAX_DEQUEUE_OPS);

  for (uint16_t i = 0; i < nb_ops; i++) {
    struct rte_crypto_op *cry_op = result_op[i];
    rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);
    wctx_p = (void **) rsa_xform + 1;
    callback(wctx_p);
  }
}

int pal_get_thread_id()
{
	unsigned int lcore = rte_lcore_id();

	if (lcore == LCORE_ID_ANY) {
		engine_log(ENG_LOG_ERR, "%s: lcore :%d\n", __FUNCTION__, lcore);
		return -1;
	}

  return lcore;
}
