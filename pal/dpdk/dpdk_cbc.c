/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

/**
 * @file pal_cbc.c
 * @brief PAL CBC implementation
 */

#include "pal_cbc.h"
#include "defs.h"

extern int cpt_num_cipher_pipeline_requests_in_flight;
extern  dpdk_pools_t *pools;

/**
 * Function: pal_aes_cbc_cipher
 */
int pal_aes_cbc_cipher(pal_cbc_ctx_t *pal_ctx, unsigned char *out,
			   const unsigned char *in, size_t inl, unsigned char *iv, int enc,
          int sym_queue, void *wctx)
{
  void *buf;
  uint8_t *iv_ptr;
  struct rte_mbuf *mbuf;
  uint8_t pip_jb_qsz = 0;
  const unsigned char *next_iv;
  pal_cry_op_status_t current_job;
  int i, j, k, numpipes, numalloc, ret;
  async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
  unsigned char saved_iv[PAL_AES_CBC_IV_LENGTH];
  volatile uint16_t num_enqueued_ops, num_dequeued_ops;
  struct rte_crypto_op **enq_op_ptr = NULL, *deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
  pal_cry_op_status_t **status_ptr = NULL, *new_st_ptr[PAL_NUM_DEQUEUED_OPS];

  numpipes = pal_ctx->numpipes;
  /* Bydefault number of pipe is one */
  if (numpipes == 0) {
    numpipes = 1;
    pal_ctx->output_buf = &out;
    pal_ctx->input_buf = (uint8_t **)&in;
    pal_ctx->input_len = &inl;
  }

  enq_op_ptr = pal_malloc(sizeof(struct rte_crypto_op *) * numpipes);
  status_ptr = pal_malloc(sizeof(pal_cry_op_status_t *) * numpipes);
  if (unlikely(enq_op_ptr == NULL || status_ptr == NULL)) {
    engine_log(ENG_LOG_ERR, "pal_malloc failed\n");
    numalloc = 0;
    ret = -1;
    goto free_resources;
  }

  for (i = 0; i < numpipes; i++) {
    if (pal_ctx->input_len[i] < PAL_AES_CBC_IV_LENGTH) {
      engine_log (ENG_LOG_ERR, "Invalid input length\n");
      ret = -1;
      goto free_resources;
    }
    // For decrytion, save the last iv_len bytes of ciphertext as next IV.
    if (!enc) {
      next_iv = pal_ctx->input_buf[i] +
        pal_ctx->input_len[i] - PAL_AES_CBC_IV_LENGTH;
      memcpy(saved_iv, next_iv, PAL_AES_CBC_IV_LENGTH);
    }
    enq_op_ptr[i] = rte_crypto_op_alloc(pools->sym_op_pool,
        RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    if (unlikely(enq_op_ptr[i] == NULL)) {
      engine_log(ENG_LOG_ERR, "Not enough crypto operations available\n");
      numalloc = i;
      ret = -1;
      goto free_resources;
    }
    mbuf = rte_pktmbuf_alloc(pools->mbuf_pool);
    if (unlikely(mbuf == NULL)) {
      engine_log(ENG_LOG_ERR, "Not enough mbufs available\n");
      /* roll back last crypto op */
      rte_mempool_put(pools->sym_op_pool, enq_op_ptr[i]);
      numalloc = i;
      ret = -1;
      goto free_resources;
    }
    /* Get data buf pointer pointing to start of pkt */
    buf = rte_pktmbuf_mtod_offset(mbuf, char *, 0);
    memcpy(buf, pal_ctx->input_buf[i], pal_ctx->input_len[i]);

    enq_op_ptr[i]->sym->m_src = mbuf;
    enq_op_ptr[i]->sym->cipher.data.offset = 0;
    enq_op_ptr[i]->sym->cipher.data.length = pal_ctx->input_len[i];

    iv_ptr = rte_crypto_op_ctod_offset(enq_op_ptr[i], uint8_t *,
        PAL_IV_OFFSET);

    memcpy(iv_ptr, iv, PAL_AES_CBC_IV_LENGTH);
    status_ptr[i] = rte_crypto_op_ctod_offset(enq_op_ptr[i],
        pal_cry_op_status_t *, PAL_COP_METADATA_OFF);
    status_ptr[i]->is_complete = 0;
    status_ptr[i]->is_successful = 0;
    status_ptr[i]->numpipes = numpipes;
    status_ptr[i]->wctx_p = wctx;

    rte_crypto_op_attach_sym_session(enq_op_ptr[i], pal_ctx->cry_session);
    mbuf = NULL;
  }

  /* Enqueue this crypto operation in the crypto device */
  for (k = 0, num_enqueued_ops = 0;
      (num_enqueued_ops < numpipes && k < MAX_ENQUEUE_ATTEMPTS); k++) {
    num_enqueued_ops +=
      rte_cryptodev_enqueue_burst(
          pal_ctx->dev_id, sym_queue,
          &enq_op_ptr[num_enqueued_ops],
          numpipes - num_enqueued_ops);
  }
  if (unlikely(num_enqueued_ops < numpipes)) {
    engine_log(ENG_LOG_ERR, "Enqueue failed - too many attempts\n");
    numalloc = numpipes;
    ret = -1;
    goto free_resources;
  }
  CPT_ATOMIC_INC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);

  if(wctx && pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

  CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);

  j = 0;
  while (status_ptr[0]->is_successful == 0) {
    do {
      num_dequeued_ops = rte_cryptodev_dequeue_burst(
          pal_ctx->dev_id,sym_queue,
          &deq_op_ptr[0],PAL_NUM_DEQUEUED_OPS);

      for (i = 0; i < num_dequeued_ops; i++) {
        new_st_ptr[i] = rte_crypto_op_ctod_offset(deq_op_ptr[i],
            pal_cry_op_status_t *, PAL_COP_METADATA_OFF);
        new_st_ptr[i]->is_complete = 1;
        /* Check if operation was processed successfully */
        if (deq_op_ptr[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
          engine_log(ENG_LOG_ERR, "Crypto (CBC) op status is not success (err:%d)\n",
              deq_op_ptr[i]->status);
          new_st_ptr[i]->is_successful = 0;
        } else {
          new_st_ptr[i]->is_successful = 1;
          if(new_st_ptr[i]->wctx_p)
            pal_ctx->async_cb(status_ptr[0]->wctx_p, new_st_ptr[i]->wctx_p,
                new_st_ptr[i]->numpipes, &pip_jb_qsz, &pip_jobs[0], ASYNC_JOB_POST_FINISH);
        }
      }
    } while (pip_jb_qsz>0);
  }

  for (i = 0; i < numpipes; i++) {
    buf = rte_pktmbuf_mtod_offset(enq_op_ptr[i]->sym->m_src, char *, 0);
    memcpy(pal_ctx->output_buf[i], buf, pal_ctx->input_len[i]);
    // For encryption, copy last 16 bytes of ciphertext to IV
    if (enc)
      next_iv = (pal_ctx->output_buf[i] + pal_ctx->input_len[i]
          - PAL_AES_CBC_IV_LENGTH);
    else
      next_iv = saved_iv;
    memcpy(iv, next_iv, PAL_AES_CBC_IV_LENGTH);
    rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
    enq_op_ptr[i]->sym->m_src = NULL;
  }
  rte_mempool_put_bulk(pools->sym_op_pool, (void **)enq_op_ptr, numpipes);
  ret = 1;

free_resources:
  if (unlikely(ret < 0)) {
    for (i = 0; i < numalloc; i++) {
      rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
      enq_op_ptr[i]->sym->m_src = NULL;
    }
    rte_mempool_put_bulk(pools->sym_op_pool, (void **)enq_op_ptr, numalloc);
  }
  if (enq_op_ptr != NULL) {
    pal_free(enq_op_ptr);
    enq_op_ptr = NULL;
  }
  if (status_ptr != NULL) {
    pal_free(status_ptr);
    status_ptr = NULL;
  }
  pal_ctx->output_buf = NULL;
  pal_ctx->input_buf = NULL;
  pal_ctx->input_len = NULL;
  pal_ctx->numpipes = 0;

  return ret;
}

int pal_aes_cbc_cleanup(pal_cbc_ctx_t *pal_ctx)
{
  int retval;

  if (pal_ctx->cry_session != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
    retval = rte_cryptodev_sym_session_clear(
        pal_ctx->dev_id, (struct rte_cryptodev_sym_session *)
        pal_ctx->cry_session);
    if (retval < 0)
      engine_log(ENG_LOG_ERR, "FAILED to clear session. ret=%d\n",
          retval);
    retval = rte_cryptodev_sym_session_free(
        (struct rte_cryptodev_sym_session *)
        pal_ctx->cry_session);
#else
    retval = rte_cryptodev_sym_session_free(pal_ctx->dev_id,
        (struct rte_cryptodev_sym_session *)
        pal_ctx->cry_session);
#endif
    if (retval < 0)
      engine_log(ENG_LOG_ERR, "FAILED to free session. ret=%d\n",
          retval);
  }
  pal_ctx->cry_session = NULL;

  return 1;
}

/**
 * Function: pal_aes_cbc_create_session
 * ------------------------------------
 *  Create AES CBC session
 *  ctx: pointer to the context
 *  key: pointer to the key
 *  iv: pointer to the iv
 *  enc: encrypt or decrypt
 *  key_len: length of the key
 *  returns: 1 on success, 0 on failure
 */

int pal_aes_cbc_create_session(pal_cbc_ctx_t *pal_ctx, const unsigned char *key,
				const unsigned char *iv, int enc, int key_len)
{
  int ret = 0;

  if(!sym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->sym_queue))
        return 0;

  if(key != NULL) {
    struct rte_crypto_sym_xform cipher_xform = {
      .next = NULL,
      .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
      .cipher = { .op = enc ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
        RTE_CRYPTO_CIPHER_OP_DECRYPT,
        .algo = RTE_CRYPTO_CIPHER_AES_CBC,
        .key = { .length = key_len },
        .iv = { .offset = PAL_IV_OFFSET,
          .length = PAL_AES_CBC_IV_LENGTH } }
    };

    cipher_xform.cipher.key.data = (const uint8_t *)key;

    /* Create crypto session and initialize it for the crypto device. */
    pal_ctx->cry_session = pal_sym_create_session(pal_ctx->dev_id,
        &cipher_xform, 0,pal_ctx->cry_session);
    if (!pal_ctx->cry_session) {
      engine_log(ENG_LOG_ERR, "Could not create session.\n");
      return 0;
    }
  }

  pal_ctx->numpipes = 0;

  return 1;
}
