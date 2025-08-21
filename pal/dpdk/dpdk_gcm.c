/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <pal_gcm.h>
extern int cpt_num_cipher_pipeline_requests_in_flight;
extern dpdk_pools_t *pools;

/*
 * Create AEAD Session
 */
int pal_create_aead_session(pal_crypto_aead_algorithm_t algo,
			       pal_gcm_ctx_t *pal_ctx, int aad_len,
			       uint8_t reconfigure)
{
	struct rte_crypto_sym_xform aead_xform;
	int retval;

	if(!sym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->sym_queue))
        	return 0;

	/* Setup AEAD Parameters */
	aead_xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	aead_xform.next = NULL;
	aead_xform.aead.algo = algo;
	aead_xform.aead.op = CRYPTO_OP(pal_ctx->enc);
	aead_xform.aead.key.data = pal_ctx->key;
	aead_xform.aead.key.length = pal_ctx->keylen;
	aead_xform.aead.iv.offset = PAL_IV_OFFSET;
	aead_xform.aead.iv.length = PAL_AES_GCM_IV_LENGTH;
	aead_xform.aead.digest_length = PAL_AEAD_DIGEST_LENGTH;
	aead_xform.aead.aad_length = aad_len;

	pal_ctx->aead_cry_session = sym_create_session( pal_ctx->dev_id,
              &aead_xform, reconfigure, pal_ctx->aead_cry_session);

	return 0;
}

/*
 * Create CIPHER Session for Crypto operation only
 */
int pal_create_cipher_session( pal_crypto_cipher_algorithm_t algo,
				                       pal_gcm_ctx_t *pal_ctx, uint8_t reconfigure)
{
	struct rte_crypto_sym_xform cipher_xform = {
		.next = NULL,
		.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
		.cipher = { .op = pal_ctx->enc ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
					RTE_CRYPTO_CIPHER_OP_DECRYPT,
			    .algo = algo,
			    .key = { .length = pal_ctx->keylen },
			    .iv = { .offset = PAL_IV_OFFSET,
				    .length = PAL_AES_CTR_IV_LENGTH } }
	};
	cipher_xform.cipher.key.data = (uint8_t *)pal_ctx->key;

	pal_ctx->cipher_cry_session = sym_create_session( pal_ctx->dev_id, &cipher_xform, reconfigure, pal_ctx->cipher_cry_session);

	return 0;
}

static int create_crypto_operation_pl(pal_gcm_ctx_t *pal_ctx,
		const uint8_t *in, int len, uint8_t pipe_index)
{
	unsigned int aad_pad_len = 0, plaintext_pad_len = 0;

	pal_ctx->ops[pipe_index] = rte_crypto_op_alloc(pools->sym_op_pool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (unlikely(pal_ctx->ops[pipe_index] == NULL)) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_ops for pipe: %d\n", pipe_index);
		return -1;
	}
	struct rte_crypto_sym_op *sym_op = pal_ctx->ops[pipe_index]->sym;
	if (pal_ctx->tls_aad_len >= 0) {
		aad_pad_len = RTE_ALIGN_CEIL(pal_ctx->tls_aad_len, 16);
		sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibufs[pipe_index], aad_pad_len);
		sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(
				pal_ctx->ibufs[pipe_index]);
		memcpy(sym_op->aead.aad.data, pal_ctx->aad_pipe[pipe_index],
				pal_ctx->tls_aad_len);
	}
	/* Append IV at the end of the crypto operation*/
	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(pal_ctx->ops[pipe_index],
			uint8_t *, PAL_IV_OFFSET);
	if (iv_ptr == NULL)
		engine_log(ENG_LOG_ERR, "IV_PTR is null\n");
	rte_memcpy(iv_ptr, pal_ctx->iv, pal_ctx->ivlen);
	if (pal_ctx->tls_aad_len >= 0 || pal_ctx->aad_len >= 0) {
		uint8_t *plaintext, *ciphertext;
		/* Append plaintext/ciphertext */
		if (CRYPTO_OP(pal_ctx->enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			plaintext = (uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibufs[pipe_index], plaintext_pad_len);
			memcpy(plaintext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibufs[pipe_index], pal_ctx->tls_tag_len);
			memset(sym_op->aead.digest.data, 0, pal_ctx->tls_tag_len);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					pal_ctx->ibufs[pipe_index], plaintext_pad_len + aad_pad_len);
		} else {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			ciphertext = (uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibufs[pipe_index], plaintext_pad_len);
			memcpy(ciphertext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibufs[pipe_index], pal_ctx->tls_tag_len);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					pal_ctx->ibufs[pipe_index], plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, in + len, pal_ctx->tls_tag_len);
		}
		sym_op->aead.data.length = len;
		sym_op->aead.data.offset = aad_pad_len;
	}
	return 0;
}

/* Below API added for TLS1_2 protocol
 *
 * AAD data is alway set via control function in case of TLS1_2
 * IV is updating by XOR'ing with sequence number
 * Here, len value is comming from SSL layer is equal to
 * (PT/CT length + AUTH tag len) for both encryption/decryption.
 *
 * Return: correct outlen on success, <0 on failure
 */
int pal_aes_gcm_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *buf,
                               void *usr_ctx, void *wctx)
{
	int ret;
	uint8_t pip_jb_qsz = 0;
	pal_cry_op_status_t current_job;
	uint8_t i, j, k, numpipes, numalloc;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	pal_cry_op_status_t **status_ptr = NULL;
	volatile uint16_t num_enqueued_ops, num_dequeued_ops;
	struct rte_crypto_op *deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	pal_cry_op_status_t *new_st_ptr[PAL_NUM_DEQUEUED_OPS];

	numpipes = pal_ctx->numpipes;

	status_ptr = pal_malloc(sizeof(pal_cry_op_status_t *) * numpipes);
	if (unlikely(status_ptr == NULL)) {
		engine_log(ENG_LOG_ERR, "pal_malloc failed\n");
		numalloc = 0;
		ret = -1;
		goto free_resources;
	}

	for (i = 0; i < numpipes; i++) {
		/* Set IV from start of buffer or generate IV and write to
		 * start of buffer. */
		if (pal_ctx->iv_cb(
					usr_ctx, pal_ctx->enc,
					pal_ctx->tls_exp_iv_len, pal_ctx->output_buf[i]) < 0) {
			engine_log (ENG_LOG_ERR, "Failed to set IV from start of buffer\n");
		}
		pal_ctx->input_buf[i] += pal_ctx->tls_exp_iv_len;
		if (numpipes == 0 || numpipes == 1) {
			pal_ctx->output_buf[i] += pal_ctx->tls_exp_iv_len;
		}
		pal_ctx->input_len[i] -= pal_ctx->tls_exp_iv_len + pal_ctx->tls_tag_len;
				/* Get a burst of mbufs */
		pal_ctx->ibufs[i] = rte_pktmbuf_alloc(pools->mbuf_pool);
		if (unlikely(pal_ctx->ibufs[i] == NULL)) {
			engine_log (ENG_LOG_ERR, "Not enough mbufs available\n");
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		/* Create crypto session and initialize it for the crypto device */
		ret = create_crypto_operation_pl(pal_ctx, pal_ctx->input_buf[i],
				pal_ctx->input_len[i], i);
		if (unlikely(ret < 0)) {
			/* roll back last buf */
			rte_pktmbuf_free(pal_ctx->ibufs[i]);
			pal_ctx->ibufs[i] = NULL;
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		rte_crypto_op_attach_sym_session(pal_ctx->ops[i], pal_ctx->aead_cry_session);
		pal_ctx->ops[i]->sym->m_src = pal_ctx->ibufs[i];
		status_ptr[i] = rte_crypto_op_ctod_offset(pal_ctx->ops[i], pal_cry_op_status_t *,
				PAL_COP_METADATA_OFF);
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx;
	}
	/* Enqueue this crypto operation in the crypto device. */
	for (k = 0, num_enqueued_ops = 0;
	    (num_enqueued_ops < numpipes && k < MAX_ENQUEUE_ATTEMPTS); k++) {
		num_enqueued_ops +=
			rte_cryptodev_enqueue_burst(
				pal_ctx->dev_id, pal_ctx->sym_queue,
				&pal_ctx->ops[num_enqueued_ops],
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

	while (status_ptr[0]->is_successful == 0) {
		do {
			num_dequeued_ops = rte_cryptodev_dequeue_burst(
					pal_ctx->dev_id, pal_ctx->sym_queue,
					&deq_op_ptr[0],
					PAL_NUM_DEQUEUED_OPS);

			/* Check the status of dequeued operations */
			for (j = 0; j < num_dequeued_ops; j++) {
				new_st_ptr[j] = rte_crypto_op_ctod_offset(deq_op_ptr[j],
						pal_cry_op_status_t *, PAL_COP_METADATA_OFF);
				new_st_ptr[j]->is_complete = 1;
				/* Check if operation was processed successfully */
				if (deq_op_ptr[j]->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		            engine_log(ENG_LOG_ERR, "Crypto (GCM-TLS) op status is not success (err:%d)\n",
							deq_op_ptr[j]->status);
					new_st_ptr[j]->is_successful = 0;
				} else {
					new_st_ptr[j]->is_successful = 1;
					if(new_st_ptr[j]->wctx_p)
					    pal_ctx->async_cb(status_ptr[0]->wctx_p,
							    new_st_ptr[j]->wctx_p, new_st_ptr[j]->numpipes,
							    &pip_jb_qsz, &pip_jobs[0], ASYNC_JOB_POST_FINISH);
				}
			}
		} while(pip_jb_qsz>0);
	}

	for (i = 0; i < numpipes; i++) {
		void *buf = rte_pktmbuf_mtod_offset(pal_ctx->ops[i]->sym->m_src, char *,
				pal_ctx->ops[i]->sym[0].aead.data.offset);
		memcpy(pal_ctx->output_buf[i], buf, pal_ctx->input_len[i]);
		memcpy(pal_ctx->output_buf[i] + pal_ctx->input_len[i],
				pal_ctx->ops[i]->sym[0].aead.digest.data, pal_ctx->tls_tag_len);
		rte_pktmbuf_free(pal_ctx->ops[i]->sym->m_src);
		pal_ctx->ops[i]->sym->m_src = NULL;

        if (pal_ctx->enc)
            ret =  pal_ctx->input_len[i] + pal_ctx->tls_exp_iv_len + pal_ctx->tls_tag_len;
        else
            ret = pal_ctx->input_len[i];

	}
	rte_mempool_put_bulk(pools->sym_op_pool, (void **)pal_ctx->ops, numpipes);
	for (j = 0; j < numpipes; j++)
		pal_ctx->ops[j] = NULL;
free_resources:
	if (unlikely(ret < 0)) {
		for (i = 0; i < numalloc; i++) {
			rte_pktmbuf_free(pal_ctx->ops[i]->sym->m_src);
			pal_ctx->ops[i]->sym->m_src = NULL;
			rte_mempool_put(pools->sym_op_pool, pal_ctx->ops[i]);
			pal_ctx->ops[i] = NULL;
		}
	}
	if (status_ptr != NULL) {
		pal_free(status_ptr);
		status_ptr = NULL;
	}

  pal_ctx->input_buf = NULL;
  pal_ctx->input_len = NULL;
  pal_ctx->output_buf = NULL;
  pal_ctx->aad_cnt = 0;
  pal_ctx->numpipes = 0;
  pal_ctx->tls_aad_len = -1;

  return ret;
}

/*
 * Common crypto operation for both TLS and Crypto case
 */
static int create_crypto_operation(pal_gcm_ctx_t *pal_ctx,
				   const uint8_t *in, int len, unsigned char *buf)
{
	unsigned int aad_pad_len = 0, plaintext_pad_len = 0;

	/* Generate Crypto op data structure */
	pal_ctx->op = rte_crypto_op_alloc(pools->sym_op_pool,
					   RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (pal_ctx->op == NULL)
		engine_log(ENG_LOG_ERR, "Failed to create crypto_op\n");

	struct rte_crypto_sym_op *sym_op = pal_ctx->op->sym;
	if (pal_ctx->tls_aad_len >= 0) {
		aad_pad_len = RTE_ALIGN_CEIL(pal_ctx->tls_aad_len, 16);
		sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(
			pal_ctx->ibuf, aad_pad_len);

		sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(pal_ctx->ibuf);
		memcpy(sym_op->aead.aad.data, buf, pal_ctx->tls_aad_len);

	} else if (pal_ctx->aad_len >= 0) {
		aad_pad_len = RTE_ALIGN_CEIL(pal_ctx->aad_len, 16);
		sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(
			pal_ctx->ibuf, aad_pad_len);

		sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(pal_ctx->ibuf);
		memcpy(sym_op->aead.aad.data, pal_ctx->aad,
		       pal_ctx->aad_len);
	} else {
		pal_ctx->op->sym->cipher.data.offset = 0;
		pal_ctx->op->sym->cipher.data.length = len;
	}

	/* Append IV at the end of the crypto operation*/
	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(pal_ctx->op, uint8_t *,
						    PAL_IV_OFFSET);
	if (iv_ptr == NULL)
		engine_log(ENG_LOG_ERR, "IV_PTR is null\n");

	rte_memcpy(iv_ptr, pal_ctx->iv, pal_ctx->ivlen);

	if (pal_ctx->tls_aad_len >= 0 || pal_ctx->aad_len >= 0) {
		uint8_t *plaintext, *ciphertext;

		/* Append plaintext/ciphertext */
		if (CRYPTO_OP(pal_ctx->enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			plaintext = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibuf, plaintext_pad_len);

			memcpy(plaintext, in, len);

			/* Append digest data */
			sym_op->aead.digest.data =
				(uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibuf, pal_ctx->tls_tag_len);
			memset(sym_op->aead.digest.data, 0,
			       pal_ctx->tls_tag_len);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
				pal_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);

		} else {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			ciphertext = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibuf, plaintext_pad_len);

			memcpy(ciphertext, in, len);

			/* Append digest data */
			sym_op->aead.digest.data =
				(uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibuf, pal_ctx->tls_tag_len);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
				pal_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
                        rte_memcpy(sym_op->aead.digest.data, in + len, pal_ctx->tls_tag_len);
		}
		sym_op->aead.data.length = len;
		sym_op->aead.data.offset = aad_pad_len;
	}

	return 0;
}

/*
 *Pure crypto application (Cipher case only)
 */
static int crypto_ctr_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
			     const unsigned char *in, size_t len, unsigned char *buf)
{
	struct rte_mbuf *mbuf = NULL;

	pal_cry_op_status_t *status_curr_job;
	int rv = -1;
	/*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
	/* AAD data is stored in pal_ctx->aad */

	/* Create crypto session and initialize it for the
     * crypto device.
     */
	int retval;

	pal_ctx->ibuf = rte_pktmbuf_alloc(pools->mbuf_pool);

	if (pal_ctx->ibuf == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create a mbuf\n");
		return -1;
	}

	void *dbuf = rte_pktmbuf_append(pal_ctx->ibuf, len);
	if (dbuf == NULL) {
		engine_log(ENG_LOG_ERR, "Not enough room in the mbuf\n");
		return 0;
	}

	/* get databuf pointer pointing to start of pkt. */
	dbuf = rte_pktmbuf_mtod_offset(pal_ctx->ibuf, char *, 0);
	memcpy(dbuf, in, len);

	/* Create AEAD operation */
	retval = create_crypto_operation(pal_ctx, in, len, buf);
	if (retval < 0)
		return retval;

	rte_crypto_op_attach_sym_session(pal_ctx->op,
					 pal_ctx->cipher_cry_session);
	pal_ctx->op->sym->m_src = pal_ctx->ibuf;

	status_curr_job =
		rte_crypto_op_ctod_offset(pal_ctx->op, pal_cry_op_status_t *,
					  PAL_COP_METADATA_OFF);

	status_curr_job->is_complete = 0;
	status_curr_job->is_successful = 0;

	/* Enqueue this crypto operation in the crypto device. */
	uint16_t num_enqueued_ops =
		rte_cryptodev_enqueue_burst(pal_ctx->dev_id, pal_ctx->sym_queue, &pal_ctx->op, 1);

	if (num_enqueued_ops != 1) {
		engine_log(ENG_LOG_ERR, "Crypto operation enqueue failed\n");
		return 0;
	}

	uint16_t num_dequeued_ops;
	struct rte_crypto_op *dequeued_ops[PAL_NUM_DEQUEUED_OPS];

  while (!status_curr_job->is_complete) {
    if(pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

		num_dequeued_ops =
			rte_cryptodev_dequeue_burst(pal_ctx->dev_id, pal_ctx->sym_queue,
                dequeued_ops,
                PAL_NUM_DEQUEUED_OPS);

		for (int j = 0; j < num_dequeued_ops; j++) {
			pal_cry_op_status_t *status_of_job;
			status_of_job = rte_crypto_op_ctod_offset(
				dequeued_ops[j], pal_cry_op_status_t *,
				PAL_COP_METADATA_OFF);

			status_of_job->is_complete = 1;
			/* Check if operation was processed successfully */
			if (dequeued_ops[j]->status !=
			    RTE_CRYPTO_OP_STATUS_SUCCESS) {
		        engine_log(ENG_LOG_ERR, "Crypto (CTR) op status is not success (err:%d)\n",
				       dequeued_ops[j]->status);
				status_of_job->is_successful = 0;
			} else {
				status_of_job->is_successful = 1;
			}
		}
	}

	mbuf = pal_ctx->op->sym->m_src;

	if (!status_curr_job->is_successful) {
		rv = -1;
		goto err;
	}

	buf = rte_pktmbuf_mtod_offset(mbuf, char *,
				      pal_ctx->op->sym->cipher.data.offset);
	memcpy(out, buf, len);
	rv = len;

err:
	rte_mempool_put_bulk(pools->sym_op_pool, (void **)&pal_ctx->op, 1);
	rte_pktmbuf_free(mbuf);
	pal_ctx->tls_aad_len = -1;
	return rv;
}

/*
 * Normal crypto application
 */
int pal_crypto_gcm_non_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
			                            const unsigned char *in, size_t len,
                                  unsigned char *buf)
{
	int ret;
	struct rte_mbuf *mbuf = NULL;

	if (pal_ctx->aad_len == -1) {
		int ret = crypto_ctr_cipher(pal_ctx, out, in, len, buf);
		return ret;
	}
	pal_cry_op_status_t *status_curr_job;
	int rv = -1;
	/*
   * Set IV from start of buffer or generate IV and write to start of
   * buffer.
   */
	/* AAD data is stored in pal_ctx->aad */

	/* Create crypto session and initialize it for the
   * crypto device.
   */
	int retval;

	pal_ctx->ibuf = rte_pktmbuf_alloc(pools->mbuf_pool);

	if (pal_ctx->ibuf == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create a mbuf\n");
		return -1;
	}

	/* Create AEAD operation */
	retval = create_crypto_operation(pal_ctx, in, len, buf);
	if (retval < 0)
		return retval;
	rte_crypto_op_attach_sym_session(pal_ctx->op,
					 pal_ctx->aead_cry_session);

	pal_ctx->op->sym->m_src = pal_ctx->ibuf;

	status_curr_job =
		rte_crypto_op_ctod_offset(pal_ctx->op, pal_cry_op_status_t *,
					  PAL_COP_METADATA_OFF);

	status_curr_job->is_complete = 0;
	status_curr_job->is_successful = 0;
	void *dbuf;
	/* Enqueue this crypto operation in the crypto device. */
	uint16_t num_enqueued_ops =
		rte_cryptodev_enqueue_burst(pal_ctx->dev_id, pal_ctx->sym_queue, &pal_ctx->op, 1);

	if (num_enqueued_ops != 1) {
		engine_log(ENG_LOG_ERR, "Crypto operation enqueue failed\n");
		return 0;
	}

	uint16_t num_dequeued_ops;
	struct rte_crypto_op *dequeued_ops[PAL_NUM_DEQUEUED_OPS];

	while (!status_curr_job->is_complete) {
    if(pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

		num_dequeued_ops =
			rte_cryptodev_dequeue_burst(pal_ctx->dev_id, pal_ctx->sym_queue,
                dequeued_ops,
                PAL_NUM_DEQUEUED_OPS);

		for (int j = 0; j < num_dequeued_ops; j++) {
			pal_cry_op_status_t *status_of_job;
			status_of_job = rte_crypto_op_ctod_offset(
				dequeued_ops[j], pal_cry_op_status_t *,
				PAL_COP_METADATA_OFF);

			status_of_job->is_complete = 1;
			/* Check if operation was processed successfully */
			if (dequeued_ops[j]->status !=
			    RTE_CRYPTO_OP_STATUS_SUCCESS) {
		        engine_log(ENG_LOG_ERR, "Crypto (GCM) op status is not success (err:%d)\n",
				       dequeued_ops[j]->status);
				status_of_job->is_successful = 0;
			} else {
				status_of_job->is_successful = 1;
			}
		}
	}

	mbuf = pal_ctx->op->sym->m_src;

	if (!status_curr_job->is_successful) {
		rv = -1;
		goto err;
	}

	dbuf = rte_pktmbuf_mtod_offset(mbuf, char *,
				      pal_ctx->op->sym[0].aead.data.offset);
	memcpy(out, dbuf, len);
	rv = len;
	if (pal_ctx->enc) {
		memcpy(out + len, pal_ctx->op->sym[0].aead.digest.data, pal_ctx->tls_tag_len);
		memcpy(buf, pal_ctx->op->sym[0].aead.digest.data,
		       pal_ctx->tls_tag_len);
	}
err:
	rte_mempool_put_bulk(pools->sym_op_pool, (void **)&pal_ctx->op, 1);
	rte_pktmbuf_free(mbuf);
	pal_ctx->tls_aad_len = -1;
	pal_ctx->aad_len = -1;
	return rv;
}

int pal_crypto_gcm_tls_1_3_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
                                        const unsigned char *in, size_t len,
                                  unsigned char *buf, void *wctx)
{
    int ret;
    struct rte_mbuf *mbuf = NULL;
	uint8_t pip_jb_qsz = 0;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];

    if (pal_ctx->aad_len == -1) {
        int ret = crypto_ctr_cipher(pal_ctx, out, in, len, buf);
        return ret;
    }

    pal_cry_op_status_t *status_curr_job;
    int rv = -1;
    /*
   * Set IV from start of buffer or generate IV and write to start of
   * buffer.
   */
    /* AAD data is stored in pal_ctx->aad */

    /* Create crypto session and initialize it for the
   * crypto device.
   */
    int retval;

    pal_ctx->ibuf = rte_pktmbuf_alloc(pools->mbuf_pool);

    if (pal_ctx->ibuf == NULL) {
        engine_log(ENG_LOG_ERR, "Failed to create a mbuf\n");
        return -1;
    }

    /* Create AEAD operation */
    retval = create_crypto_operation(pal_ctx, in, len, buf);
    if (retval < 0)
        return retval;
    rte_crypto_op_attach_sym_session(pal_ctx->op,
                     pal_ctx->aead_cry_session);

    pal_ctx->op->sym->m_src = pal_ctx->ibuf;

    status_curr_job =
        rte_crypto_op_ctod_offset(pal_ctx->op, pal_cry_op_status_t *,
                      PAL_COP_METADATA_OFF);

    status_curr_job->is_complete = 0;
    status_curr_job->is_successful = 0;
    status_curr_job->wctx_p = wctx;
    status_curr_job->numpipes = 1;

    void *dbuf;
    /* Enqueue this crypto operation in the crypto device. */
    uint16_t num_enqueued_ops =
        rte_cryptodev_enqueue_burst(pal_ctx->dev_id, pal_ctx->sym_queue, &pal_ctx->op, 1);

    if (num_enqueued_ops != 1) {
        engine_log(ENG_LOG_ERR, "Crypto operation enqueue failed\n");
        return 0;
    }

    CPT_ATOMIC_INC(cpt_num_cipher_pipeline_requests_in_flight);

  if(wctx && pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

    CPT_ATOMIC_DEC(cpt_num_cipher_pipeline_requests_in_flight);

    uint16_t num_dequeued_ops;
    struct rte_crypto_op *dequeued_ops[PAL_NUM_DEQUEUED_OPS];

    while (!status_curr_job->is_complete) {
        num_dequeued_ops =
            rte_cryptodev_dequeue_burst(pal_ctx->dev_id, pal_ctx->sym_queue,
                dequeued_ops,
                PAL_NUM_DEQUEUED_OPS);

        for (int j = 0; j < num_dequeued_ops; j++) {
            pal_cry_op_status_t *status_of_job;
            status_of_job = rte_crypto_op_ctod_offset(
                dequeued_ops[j], pal_cry_op_status_t *,
                PAL_COP_METADATA_OFF);

            status_of_job->is_complete = 1;
            /* Check if operation was processed successfully */
            if (dequeued_ops[j]->status !=
                RTE_CRYPTO_OP_STATUS_SUCCESS) {
                engine_log(ENG_LOG_ERR, "Crypto (GCM) op status is not success (err:%d)\n",
                       dequeued_ops[j]->status);
                status_of_job->is_successful = 0;
            } else {
                status_of_job->is_successful = 1;
                    if(status_of_job->wctx_p)
                        pal_ctx->async_cb(status_of_job->wctx_p,
                                status_curr_job->wctx_p, status_of_job->numpipes,
                                &pip_jb_qsz, &pip_jobs[0], ASYNC_JOB_POST_FINISH);


            }
        }
    }

    mbuf = pal_ctx->op->sym->m_src;

    if (!status_curr_job->is_successful) {
        rv = -1;
        goto err;
    }

    dbuf = rte_pktmbuf_mtod_offset(mbuf, char *,
                      pal_ctx->op->sym[0].aead.data.offset);
    memcpy(out, dbuf, len);
    rv = len;
    if (pal_ctx->enc) {
	memcpy(out + len, pal_ctx->op->sym[0].aead.digest.data, pal_ctx->tls_tag_len);
	/* copy digest in external buf */
	memcpy(buf, pal_ctx->op->sym[0].aead.digest.data,
               pal_ctx->tls_tag_len);
    }
err:
    rte_mempool_put_bulk(pools->sym_op_pool, (void **)&pal_ctx->op, 1);
    rte_pktmbuf_free(mbuf);
    pal_ctx->tls_aad_len = -1;
    pal_ctx->aad_len = -1;
    return rv;
}

int pal_sym_session_gcm_cleanup(pal_gcm_ctx_t *pal_ctx)
{
	int retval;

        retval = sym_session_cleanup(pal_ctx->aead_cry_session, pal_ctx->dev_id);
        retval &= sym_session_cleanup(pal_ctx->cipher_cry_session, pal_ctx->dev_id);

	return retval;
}
