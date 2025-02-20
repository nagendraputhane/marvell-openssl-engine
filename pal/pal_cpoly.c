/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal/pal_cpoly.h"

extern int cpt_num_cipher_pipeline_requests_in_flight;
extern dpdk_pools_t *pools;

/*
 * Create AEAD Session
 */
int pal_create_cpoly_aead_session(pal_cpoly_ctx_t *pal_ctx,
					int aad_len, uint8_t reconfigure)
{
	int retval;

	struct rte_crypto_sym_xform aead_xform = {
			.next = NULL,
			.type = RTE_CRYPTO_SYM_XFORM_AEAD,
			.aead = {
				.op = pal_ctx->enc ? RTE_CRYPTO_AEAD_OP_ENCRYPT :
					RTE_CRYPTO_AEAD_OP_DECRYPT,
				.algo = RTE_CRYPTO_AEAD_CHACHA20_POLY1305,
				.key = {.length = PAL_CPOLY_KEY_LEN},
				.iv = { .offset = PAL_IV_OFFSET,
					.length = PAL_CPOLY_IV_LEN},
				.digest_length = PAL_CPOLY_AEAD_DIGEST_LEN,
				.aad_length = aad_len
			},
	};
	aead_xform.aead.key.data = pal_ctx->key;
	aead_xform.aead.key.length = pal_ctx->key_len;

  pal_ctx->cry_session = pal_sym_create_session( pal_ctx->dev_id, &aead_xform, reconfigure,
      pal_ctx->cry_session);

  if (pal_ctx->cry_session == NULL) {
    engine_log(ENG_LOG_ERR, "Could not create session.\n");
    return -1;
  }

	return 1;

}

static int create_crypto_operation_pl(pal_cpoly_ctx_t *pal_ctx,
		const uint8_t *in, int len, int enc, uint8_t pipe_index)
{
	unsigned int aad_pad_len = 0, plaintext_pad_len = 0;
	uint8_t updated_iv[12];

	pal_ctx->ops[pipe_index] = rte_crypto_op_alloc(pools->sym_op_pool,
					RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (unlikely(pal_ctx->ops[pipe_index] == NULL)) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_ops for pipe: %d\n",
			pipe_index);
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
	if (pal_ctx->tls_aad_len > 0) {
		memcpy(updated_iv, pal_ctx->iv, pal_ctx->iv_len);
		/* Updating IV value by XORing with sequence number */
		for (uint8_t i = 0; i < 8; i++)
			updated_iv[i + 4] = pal_ctx->seq_num[pipe_index][i] ^
						pal_ctx->iv[i + 4];
		rte_memcpy(iv_ptr, updated_iv, pal_ctx->iv_len);
	} else {
		rte_memcpy(iv_ptr, pal_ctx->iv, pal_ctx->iv_len);
	}
	if (pal_ctx->tls_aad_len >= 0 || pal_ctx->aad_len >= 0) {
		uint8_t *plaintext, *ciphertext;
		/* Append plaintext/ciphertext */
		if (CRYPTO_OP(enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			plaintext = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibufs[pipe_index], plaintext_pad_len);
			memcpy(plaintext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data =
					(uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibufs[pipe_index],
					pal_ctx->tls_tag_len);
			memset(sym_op->aead.digest.data, 0,
			       pal_ctx->tls_tag_len);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					pal_ctx->ibufs[pipe_index],
					plaintext_pad_len + aad_pad_len);
		} else {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			ciphertext = (uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibufs[pipe_index],
					plaintext_pad_len);
			memcpy(ciphertext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data =
					(uint8_t *)rte_pktmbuf_append(
					pal_ctx->ibufs[pipe_index],
					pal_ctx->tls_tag_len);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					pal_ctx->ibufs[pipe_index],
					plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, in + len,
				   pal_ctx->tls_tag_len);
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
 * (PT/CT length + AUTH tag len) for both encryption/decryption.*/

int pal_chacha20_poly1305_tls_cipher(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, void *wctx)
{
	int enc;
	uint8_t pip_jb_qsz = 0;
	pal_cry_op_status_t current_job;
	pal_cry_op_status_t **status_ptr = NULL;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint16_t num_enqueued_ops, num_dequeued_ops;
	uint8_t i, j, numpipes, numalloc, k, ret = 0;
	pal_cry_op_status_t *new_st_ptr[PAL_NUM_DEQUEUED_OPS];
	struct rte_crypto_op *deq_op_ptr[PAL_NUM_DEQUEUED_OPS];

	numpipes = pal_ctx->numpipes;

	status_ptr = malloc(sizeof(pal_cry_op_status_t *) * numpipes);
	if (unlikely(status_ptr == NULL)) {
		engine_log(ENG_LOG_ERR, "Malloc failed\n");
		numalloc = 0;
		ret = -1;
		goto free_resources;
	}

	for (i = 0; i < numpipes; i++) {
		pal_ctx->input_len[i] -= pal_ctx->tls_tag_len;
		/* Get a burst of mbufs */
		pal_ctx->ibufs[i] = rte_pktmbuf_alloc(pools->mbuf_pool);
		if (unlikely(pal_ctx->ibufs[i] == NULL)) {
			engine_log(ENG_LOG_ERR, "Not enough mbufs available\n");
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		/* Create crypto session and initialize it for
		 * the crypto device
		 */
		ret = create_crypto_operation_pl(pal_ctx,
				pal_ctx->input_buf[i], pal_ctx->input_len[i],
				pal_ctx->enc, i);
		if (unlikely(ret < 0)) {
			/* roll back last buf */
			rte_pktmbuf_free(pal_ctx->ibufs[i]);
			pal_ctx->ibufs[i] = NULL;
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		rte_crypto_op_attach_sym_session(pal_ctx->ops[i],
						 pal_ctx->cry_session);
		pal_ctx->ops[i]->sym->m_src = pal_ctx->ibufs[i];
		status_ptr[i] = rte_crypto_op_ctod_offset(pal_ctx->ops[i],
				pal_cry_op_status_t *,
				PAL_COP_METADATA_OFF);
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx;
	}

	for (k=0, num_enqueued_ops=0;
	    ((num_enqueued_ops < numpipes) && (k < MAX_ENQUEUE_ATTEMPTS)); k++) {
		num_enqueued_ops +=
			rte_cryptodev_enqueue_burst(
				pal_ctx->dev_id, sym_queue,
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
					pal_ctx->dev_id, sym_queue,
					&deq_op_ptr[0], PAL_NUM_DEQUEUED_OPS);
			for (i = 0; i < num_dequeued_ops; i++) {
				new_st_ptr[i] = rte_crypto_op_ctod_offset(
						deq_op_ptr[i], pal_cry_op_status_t *,
						PAL_COP_METADATA_OFF);
				new_st_ptr[i]->is_complete = 1;
				/* Check if operation was processed successfully  */
				if (deq_op_ptr[i]->status !=
						RTE_CRYPTO_OP_STATUS_SUCCESS) {
		            engine_log(ENG_LOG_ERR, "Crypto (CPOLY) op status is not success (err:%d)\n",
							deq_op_ptr[i]->status);
					new_st_ptr[i]->is_successful = 0;
				} else {
					new_st_ptr[i]->is_successful = 1;
					if(new_st_ptr[i]->wctx_p)
					    pal_ctx->async_cb(status_ptr[0]->wctx_p,
							   new_st_ptr[i]->wctx_p, new_st_ptr[i]->numpipes,
							   &pip_jb_qsz, &pip_jobs[0], ASYNC_JOB_POST_FINISH);
				}
			}
		} while(pip_jb_qsz>0);
	}

	for (i = 0; i < numpipes; i++) {
		void *buf = rte_pktmbuf_mtod_offset(
				pal_ctx->ops[i]->sym->m_src, char *,
				pal_ctx->ops[i]->sym[0].aead.data.offset);
		memcpy(pal_ctx->output_buf[i], buf, pal_ctx->input_len[i]);
		memcpy(pal_ctx->output_buf[i] + pal_ctx->input_len[i],
				pal_ctx->ops[i]->sym[0].aead.digest.data,
				pal_ctx->tls_tag_len);
		rte_pktmbuf_free(pal_ctx->ops[i]->sym->m_src);
		pal_ctx->ops[i]->sym->m_src = NULL;
	}
	rte_mempool_put_bulk(pools->sym_op_pool, (void **)pal_ctx->ops,
			     numpipes);
	for (int j = 0; j < numpipes; j++)
		pal_ctx->ops[j] = NULL;
	ret = 1;
free_resources:
	if (unlikely(ret < 0)) {
		for (i = 0; i < numalloc; i++) {
			rte_pktmbuf_free(pal_ctx->ops[i]->sym->m_src);
			pal_ctx->ops[i]->sym->m_src = NULL;
			rte_mempool_put(pools->sym_op_pool, pal_ctx->ops[i]);
			pal_ctx->ops[i] = NULL;
		}
	}
	pal_ctx->numpipes = 0;
	pal_ctx->aad_cnt = 0;
	if (status_ptr != NULL) {
		free(status_ptr);
		status_ptr = NULL;
	}

	return ret;
}

static int
create_crypto_operation(pal_cpoly_ctx_t *pal_ctx, const uint8_t *in, int len,
    unsigned char *buf)
{

  struct rte_crypto_sym_op *sym_op;
	unsigned int aad_pad_len = 16, plaintext_pad_len = 0;
	uint8_t *plaintext, *ciphertext, i, updated_iv[12];

	/* Generate crypto op data structure */
	pal_ctx->op = rte_crypto_op_alloc(pools->sym_op_pool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (pal_ctx->op == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_op : %d\n", __LINE__);
		return -1;
	}

	sym_op = pal_ctx->op->sym;
	sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(pal_ctx->ibuf,
		aad_pad_len);
	sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(pal_ctx->ibuf);
	if (pal_ctx->tls_aad_len > 0) {
		memcpy(sym_op->aead.aad.data, buf,pal_ctx->tls_aad_len);
	} else {
		memcpy(sym_op->aead.aad.data, pal_ctx->aad, pal_ctx->aad_len);
	}

	/* Append IV at the end of the crypto operation */
	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(pal_ctx->op, uint8_t *,
			PAL_IV_OFFSET);
	if (iv_ptr == NULL)
		engine_log(ENG_LOG_ERR, "IV_PTR is null: %d\n", __LINE__);
	/* XORing iv with sequence no: is not needed in TLS1.3 since it is
	 * already being done inside openssl */
	rte_memcpy(iv_ptr, pal_ctx->iv, pal_ctx->iv_len);

	if (CRYPTO_OP(pal_ctx->enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
		plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
		plaintext = (uint8_t *)rte_pktmbuf_append(pal_ctx->ibuf,
				plaintext_pad_len);
		memcpy(plaintext, in, len);

		/* Append digest data* */
		if (pal_ctx->tls_aad_len >= 0) {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibuf, PAL_CPOLY_AEAD_DIGEST_LEN);
			memset(sym_op->aead.digest.data, 0, PAL_CPOLY_AEAD_DIGEST_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(pal_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
		} else {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibuf, pal_ctx->auth_taglen);
			memset(sym_op->aead.digest.data, 0, pal_ctx->auth_taglen);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(pal_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
		}
	} else {
		plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
		ciphertext = (uint8_t *)rte_pktmbuf_append(pal_ctx->ibuf,
				plaintext_pad_len);
		memcpy(ciphertext, in, len);
		/* Append digest data* */
		if (pal_ctx->tls_aad_len >= 0) {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibuf, PAL_CPOLY_AEAD_DIGEST_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(pal_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, in+len,
				PAL_CPOLY_AEAD_DIGEST_LEN);
		} else {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				pal_ctx->ibuf, pal_ctx->auth_taglen);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(pal_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, pal_ctx->auth_tag,
				pal_ctx->auth_taglen);
		}
	}
	sym_op->aead.data.length = len;
	sym_op->aead.data.offset = aad_pad_len;

	return 0;
}

int pal_chacha20_poly1305_non_tls_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, unsigned char *buf)
{
	int enc, rv = -1;
	struct rte_mbuf *mbuf = NULL;
	pal_cry_op_status_t *status_ptr, *new_st_ptr;
	uint16_t num_enqueued_ops, num_dequeued_ops;
	struct rte_crypto_op *dequeued_ops[1];

	enc = pal_ctx->enc;

	pal_ctx->ibuf = rte_pktmbuf_alloc(pools->mbuf_pool);
	if (pal_ctx->ibuf == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create a mbuf: %d\n", __LINE__);
		return -1;
	}

	/* Clear mbuf payload */
	memset(rte_pktmbuf_mtod(pal_ctx->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(pal_ctx->ibuf));

	/* Create AEAD operation */
	rv = create_crypto_operation(pal_ctx, in, len,  buf);
	if (rv < 0)
		return rv;

	rte_crypto_op_attach_sym_session(pal_ctx->op, pal_ctx->cry_session);
	pal_ctx->op->sym->m_src = pal_ctx->ibuf;

	status_ptr = rte_crypto_op_ctod_offset (pal_ctx->op,
			pal_cry_op_status_t *, PAL_COP_METADATA_OFF);

	status_ptr->is_complete = 0;
	status_ptr->is_successful = 0;

	num_enqueued_ops =
		rte_cryptodev_enqueue_burst(pal_ctx->dev_id,
				sym_queue, &pal_ctx->op, 1);

	if (num_enqueued_ops < 1) {
		engine_log(ENG_LOG_ERR, "\nCrypto operation enqueue failed: %d\n", __LINE__);
		return 0;
	}

	while (!status_ptr->is_complete) {
    pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

		num_dequeued_ops = rte_cryptodev_dequeue_burst(
			pal_ctx->dev_id, sym_queue, dequeued_ops, 1);

		if (num_dequeued_ops > 0) {
			new_st_ptr = rte_crypto_op_ctod_offset(
				dequeued_ops[0], pal_cry_op_status_t *,
				PAL_COP_METADATA_OFF);

			new_st_ptr->is_complete = 1;
			if (dequeued_ops[0]->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
				engine_log(ENG_LOG_ERR, "Operation were not processed"
					"correctly err: %d", dequeued_ops[0]->status);
				new_st_ptr->is_successful = 0;
			} else {
				new_st_ptr->is_successful = 1;
			}
		}
	}
	mbuf = pal_ctx->op->sym->m_src;

	if (!status_ptr->is_successful) {
		rv = -1;
		engine_log(ENG_LOG_ERR, "Job not process\n");
		goto err;
	}

	void *dbuf = rte_pktmbuf_mtod_offset(mbuf, char *,
				pal_ctx->op->sym[0].aead.data.offset);

	memcpy(out, dbuf, len);
	if (enc == 1) {
		memcpy (buf, pal_ctx->op->sym[0].aead.digest.data,
			PAL_CPOLY_AEAD_DIGEST_LEN);
		memcpy (pal_ctx->auth_tag, pal_ctx->op->sym[0].aead.digest.data,
			PAL_CPOLY_AEAD_DIGEST_LEN);
	}
	rv = len;

err:
	rte_mempool_put_bulk(pools->sym_op_pool, (void **)&pal_ctx->op, 1);
	rte_pktmbuf_free(mbuf);

	return rv;
}

int pal_chacha20_poly1305_tls_1_3_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
    const unsigned char *in, size_t len, int sym_queue, unsigned char *buf, void *wctx)
{
    int enc, rv = -1;
	uint8_t pip_jb_qsz = 0;
    struct rte_mbuf *mbuf = NULL;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
    pal_cry_op_status_t *status_ptr, *new_st_ptr;
    uint16_t num_enqueued_ops, num_dequeued_ops;
    struct rte_crypto_op *dequeued_ops[1];

    enc = pal_ctx->enc;

    pal_ctx->ibuf = rte_pktmbuf_alloc(pools->mbuf_pool);
    if (pal_ctx->ibuf == NULL) {
        engine_log(ENG_LOG_ERR, "Failed to create a mbuf: %d\n", __LINE__);
        return -1;
    }

    /* Clear mbuf payload */
    memset(rte_pktmbuf_mtod(pal_ctx->ibuf, uint8_t *), 0,
            rte_pktmbuf_tailroom(pal_ctx->ibuf));

    /* Create AEAD operation */
    rv = create_crypto_operation(pal_ctx, in, len,  buf);
    if (rv < 0)
        return rv;

    rte_crypto_op_attach_sym_session(pal_ctx->op, pal_ctx->cry_session);
    pal_ctx->op->sym->m_src = pal_ctx->ibuf;

    status_ptr = rte_crypto_op_ctod_offset (pal_ctx->op,
            pal_cry_op_status_t *, PAL_COP_METADATA_OFF);

    status_ptr->is_complete = 0;
    status_ptr->is_successful = 0;
    status_ptr->wctx_p = wctx;
    status_ptr->numpipes = 1;

    num_enqueued_ops =
        rte_cryptodev_enqueue_burst(pal_ctx->dev_id,
                sym_queue, &pal_ctx->op, 1);

    if (num_enqueued_ops < 1) {
        engine_log(ENG_LOG_ERR, "\nCrypto operation enqueue failed: %d\n", __LINE__);
        return 0;
    }

	CPT_ATOMIC_INC(cpt_num_cipher_pipeline_requests_in_flight);

    if(wctx && pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

	CPT_ATOMIC_DEC(cpt_num_cipher_pipeline_requests_in_flight);

    while (!status_ptr->is_complete) {
        num_dequeued_ops = rte_cryptodev_dequeue_burst(
            pal_ctx->dev_id, sym_queue, dequeued_ops, 1);

        if (num_dequeued_ops > 0) {
            new_st_ptr = rte_crypto_op_ctod_offset(
                dequeued_ops[0], pal_cry_op_status_t *,
                PAL_COP_METADATA_OFF);

            new_st_ptr->is_complete = 1;
            if (dequeued_ops[0]->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
                engine_log(ENG_LOG_ERR, "Operation were not processed"
                    "correctly err: %d", dequeued_ops[0]->status);
                new_st_ptr->is_successful = 0;
            } else {
                new_st_ptr->is_successful = 1;
                if(new_st_ptr->wctx_p)
                    pal_ctx->async_cb(status_ptr->wctx_p,
                            new_st_ptr->wctx_p, new_st_ptr->numpipes,
                            &pip_jb_qsz, &pip_jobs[0], ASYNC_JOB_POST_FINISH);

            }
        }
    }
    mbuf = pal_ctx->op->sym->m_src;

    if (!status_ptr->is_successful) {
        rv = -1;
        engine_log(ENG_LOG_ERR, "Job not process\n");
        goto err;
    }


    void *dbuf = rte_pktmbuf_mtod_offset(mbuf, char *,
                pal_ctx->op->sym[0].aead.data.offset);

    memcpy(out, dbuf, len);
    if (enc == 1) {
        memcpy (buf, pal_ctx->op->sym[0].aead.digest.data,
            PAL_CPOLY_AEAD_DIGEST_LEN);
        memcpy (pal_ctx->auth_tag, pal_ctx->op->sym[0].aead.digest.data,
            PAL_CPOLY_AEAD_DIGEST_LEN);
    }
    rv = len;

err:
    rte_mempool_put_bulk(pools->sym_op_pool, (void **)&pal_ctx->op, 1);
    rte_pktmbuf_free(mbuf);

    return rv;
}
