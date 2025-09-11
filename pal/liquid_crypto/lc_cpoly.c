/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal_cpoly.h"
extern int cpt_num_cipher_pipeline_requests_in_flight;

/*
 * Create AEAD Session
 */
int pal_create_cpoly_aead_session(pal_cpoly_ctx_t *pal_ctx,
					int aad_len, uint8_t reconfigure)
{
	int ret = 0;
	if (!sym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->queue))
	{
		ossl_log(OSSL_LOG_ERR, "Invalid device ID or queue ID\n");
		return 0;
	}
	pal_ctx->cry_session.opcode = DAO_LC_SYM_OPCODE_FC;
	pal_ctx->cry_session.fc.iv_source = DAO_LC_FC_IV_SRC_OP;
	pal_ctx->cry_session.fc.enc_cipher =  DAO_LC_FC_ENC_CIPHER_CHACHA;
	pal_ctx->cry_session.fc.hash_type = DAO_LC_HASH_TYPE_POLY1305;
	pal_ctx->cry_session.iv_len = pal_ctx->iv_len;
	pal_ctx->cry_session.fc.mac_len = PAL_CPOLY_AEAD_DIGEST_LEN;
	pal_ctx->cry_session.fc.aes_key_len = pal_ctx->key_len == PAL_CPOLY_KEY_LEN ? DAO_LC_FC_AES_KEY_LEN_256 : -1 ;

	if(pal_ctx->cry_session.fc.aes_key_len == -1)
	{
		ossl_log(OSSL_LOG_ERR, "Invalid key length: %d\n", pal_ctx->key_len);
		return -1;

	}

	memcpy(pal_ctx->cry_session.fc.encr_key, pal_ctx->key, pal_ctx->key_len);

	uint64_t sess_cookie = (uint64_t)pal_ctx;

	ret = sym_create_session(pal_ctx->dev_id, pal_ctx->cry_session, &pal_ctx->event, 0, sess_cookie);
	if (ret == 0)
	{
		ossl_log(OSSL_LOG_ERR, "Could not create session.\n");
		return 0;
	}

	PAL_ASSERT(pal_ctx->event.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	PAL_ASSERT(pal_ctx->event.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	PAL_ASSERT(pal_ctx->event.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");
	return 1;
}

static int create_crypto_operation_pl(pal_cpoly_ctx_t *pal_ctx,
		const uint8_t *in, int len, int enc, uint8_t pipe_index)
{
	return 0;
}

/* Below API added for TLS1_2 protocol
 *
 * AAD data is alway set via control function in case of TLS1_2
 * IV is updating by XOR'ing with sequence number
 * Here, len value is comming from SSL layer is equal to
 * (PT/CT length + AUTH tag len) for both encryption/decryption.
 * @returns correct outlen on success, <0 on failure
*/

int pal_chacha20_poly1305_tls_cipher(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
		const unsigned char *in, size_t len, int sym_queue, void *wctx)
{
	int enc;
	uint8_t pip_jb_qsz = 0;
	pal_cry_op_status_t current_job;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint16_t num_enqueued_ops, num_dequeued_ops;
	uint8_t i, j, numpipes, numalloc, k, ret = 0;
	pal_cry_op_status_t *new_st_ptr[PAL_NUM_DEQUEUED_OPS],*status_ptr[SSL_MAX_PIPELINES];
	struct dao_lc_sym_op enq_op_ptr[SSL_MAX_PIPELINES];
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	struct dao_lc_buf *in_buf[SSL_MAX_PIPELINES], *out_buf[SSL_MAX_PIPELINES];
	uint8_t dev_id = glb_params.dev_id;
	sym_queue = glb_params.qp_id;
	uint8_t updated_iv[12];

	numpipes = pal_ctx->numpipes;

	for(int i = 0; i<numpipes; i++) {

		pal_ctx->input_len[i] -= pal_ctx->tls_tag_len;

		status_ptr[i] = pal_malloc(sizeof(pal_cry_op_status_t));
		if (unlikely(!status_ptr[i])) {
			ossl_log(OSSL_LOG_ERR, "Failed to allocate status\n");
			ret = -1;
			goto free_resources;
		}

		status_ptr[i]->is_successful = 0;
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx;

		if (prepare_lc_buf(&in_buf[i], pal_ctx->input_buf[i], pal_ctx->input_len[i] + pal_ctx->tls_tag_len) < 0) {
			ret = -1;
			goto free_resources;
		}

		if (prepare_lc_buf(&out_buf[i], pal_ctx->output_buf[i], pal_ctx->input_len[i] + pal_ctx->tls_tag_len) < 0) {
			ret = -1;
			goto free_resources;
		}

		if (pal_ctx->tls_aad_len > 0) {
		memcpy(updated_iv, pal_ctx->iv, pal_ctx->iv_len);
		/* Updating IV value by XORing with sequence number */
		for (uint8_t j= 0; j< 8; j++)
			updated_iv[j+4] = pal_ctx->seq_num[i][j]^
						pal_ctx->iv[j+ 4];
		}
		enq_op_ptr[i].op_cookie = (uint64_t)status_ptr[i];
		enq_op_ptr[i].sess_id = pal_ctx->event.sess_event.sess_id;
		enq_op_ptr[i].aad = pal_ctx->aad_pipe[i];
		enq_op_ptr[i].aad_len = pal_ctx->tls_aad_len;
		enq_op_ptr[i].encrypt = pal_ctx->enc;
		enq_op_ptr[i].in_buffer = in_buf[i];
		enq_op_ptr[i].out_buffer = out_buf[i];
		enq_op_ptr[i].cipher_offset = 0;
		enq_op_ptr[i].cipher_len = pal_ctx->input_len[i];
		enq_op_ptr[i].cipher_iv = updated_iv;
		enq_op_ptr[i].auth_len = 0;
		enq_op_ptr[i].auth_offset = 0;
		enq_op_ptr[i].auth_iv = NULL;
		/* If digest is NULL, the auth tag is placed/read right after ciphered data in the buffer. */
		enq_op_ptr[i].digest = NULL;

	}
/* Enqueue this crypto operation in the crypto device */
	for (k = 0, num_enqueued_ops = 0;
			(num_enqueued_ops < numpipes && k < MAX_ENQUEUE_ATTEMPTS); k++)
	{
		num_enqueued_ops +=
			dao_liquid_crypto_sym_enqueue_burst(
				dev_id, sym_queue,
				&enq_op_ptr[num_enqueued_ops],
				numpipes - num_enqueued_ops);
	}

	if (unlikely(num_enqueued_ops < numpipes))
	{
		ossl_log(OSSL_LOG_ERR, "Enqueue failed - too many attempts\n");
		numalloc = numpipes;
		ret = -1;
		goto free_resources;
	}

	CPT_ATOMIC_INC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);

	/* Handle asynchronous callback */
	if (wctx && pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);


	while (!status_ptr[numpipes-1]->is_complete)
	{
		do
		{
			num_dequeued_ops = dao_liquid_crypto_dequeue_burst(
				dev_id, sym_queue, deq_op_ptr, PAL_NUM_DEQUEUED_OPS);
			if(unlikely(!num_dequeued_ops && wctx && pal_ctx->async_cb)) {
				pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
				continue;
			}

			for (i = 0; i < num_dequeued_ops; i++)
			{
				new_st_ptr[i] = (pal_cry_op_status_t *)deq_op_ptr[i].op_cookie;
				new_st_ptr[i]->is_complete = 1;

				/* Check if operation was processed successfully */
				if (deq_op_ptr[i].res.cn9k.compcode != DAO_CPT_COMP_GOOD ||
					deq_op_ptr[i].res.cn9k.uc_compcode != DAO_UC_SUCCESS)
				{
					ossl_log(OSSL_LOG_ERR, "Crypto op status is not success (err:%d)\n",
							deq_op_ptr[i].res.cn9k.compcode);
					new_st_ptr[i]->is_successful = 0;
				}
				else
				{
					new_st_ptr[i]->is_successful = 1;
					if (new_st_ptr[i]->wctx_p && pal_ctx->async_cb)
						pal_ctx->async_cb(status_ptr[0]->wctx_p, new_st_ptr[i]->wctx_p,
							new_st_ptr[i]->numpipes, &pip_jb_qsz, &pip_jobs[0], ASYNC_JOB_POST_FINISH);
				}
			}
		} while (pip_jb_qsz > 0);
	}

	CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);

	for (i = 0; i < numpipes; i++)
	{
		if (pal_ctx->enc) {
			// Return total length:  ciphertext + tag
			ret = pal_ctx->input_len[i] + pal_ctx->tls_tag_len;
		} else {
			// No tag to append in case of decryption.
			ret = pal_ctx->input_len[i];
		}
	}


free_resources:
	for (i = 0; i < numpipes; i++) {
		struct dao_lc_buf *seg = in_buf[i], *next;
		while (seg) {
			next = seg->next;
			pal_free(seg);
			seg = next;
		}
		seg = out_buf[i];
		while (seg) {
			next = seg->next;
			pal_free(seg);
			seg = next;
		}
		if (status_ptr[i]) pal_free(status_ptr[i]);
	}

	pal_ctx->input_buf = NULL;
	pal_ctx->input_len = NULL;
	pal_ctx->output_buf = NULL;
	pal_ctx->aad_cnt = 0;
	pal_ctx->numpipes = 0;
	pal_ctx->tls_aad_len = -1;

	return ret;
}

int pal_chacha20_poly1305_non_tls_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, unsigned char *buf)
{
	int ret = -1;
	struct dao_lc_sym_op enq_op_ptr[1];
	struct dao_lc_buf *in_buf, *out_buf;
	pal_cry_op_status_t *status;
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	uint16_t num_dequeued_ops = 0;
	uint8_t dev_id = glb_params.dev_id;
	sym_queue = glb_params.qp_id;

	// Allocate status
	status = pal_malloc(sizeof(pal_cry_op_status_t));
	if (unlikely(!status)) {
		ossl_log(OSSL_LOG_ERR, "Failed to allocate op or status\n");
		goto cleanup;
	}

	status->is_successful = 0;
	status->is_complete = 0;
	if (prepare_lc_buf(&in_buf, (uint8_t *)in, len + pal_ctx->tls_tag_len) < 0) {
		ossl_log(OSSL_LOG_ERR, "Failed to prepare input buffer\n");
		goto cleanup;
	}

	if (prepare_lc_buf(&out_buf, (uint8_t *)out, len + pal_ctx->tls_tag_len) < 0) {
		ossl_log(OSSL_LOG_ERR, "Failed to prepare output buffer\n");
		goto cleanup;
	}

	in_buf->frag_len += pal_ctx->tls_tag_len + pal_ctx->aad_len;
	in_buf->total_len += pal_ctx->tls_tag_len + pal_ctx->aad_len;
	out_buf->frag_len += pal_ctx->tls_tag_len + pal_ctx->aad_len;
	out_buf->total_len += pal_ctx->tls_tag_len + pal_ctx->aad_len;


	enq_op_ptr[0].op_cookie = (uint64_t)status;
	enq_op_ptr[0].sess_id = pal_ctx->event.sess_event.sess_id;
	enq_op_ptr[0].aad = pal_ctx->aad;
	enq_op_ptr[0].aad_len = pal_ctx->aad_len;
	enq_op_ptr[0].encrypt = !!pal_ctx->enc;
	enq_op_ptr[0].in_buffer = in_buf;
	enq_op_ptr[0].out_buffer = out_buf;
	enq_op_ptr[0].cipher_offset = 0;
	enq_op_ptr[0].cipher_len = len;
	enq_op_ptr[0].cipher_iv = (uint8_t *) pal_ctx->iv;
	enq_op_ptr[0].auth_len = 0;
	enq_op_ptr[0].auth_offset = 0;
	enq_op_ptr[0].auth_iv = NULL;
	enq_op_ptr[0].digest = NULL;
	// Enqueue the operation
	if (dao_liquid_crypto_sym_enqueue_burst(dev_id, sym_queue, &enq_op_ptr[0], 1) != 1) {
		ossl_log(OSSL_LOG_ERR, "Crypto enqueue failed\n");
		goto cleanup;
	}

	// Poll for completion
	while (!status->is_complete) {
		num_dequeued_ops = dao_liquid_crypto_dequeue_burst(dev_id, sym_queue, deq_op_ptr, PAL_NUM_DEQUEUED_OPS);

		if (num_dequeued_ops == 0 && pal_ctx->async_cb) {
			pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
			continue;
		}

		for (int i = 0; i < num_dequeued_ops; i++) {
			pal_cry_op_status_t *st = (pal_cry_op_status_t *)deq_op_ptr[i].op_cookie;
			st->is_complete = 1;
			st->is_successful = (deq_op_ptr[i].res.cn9k.compcode == DAO_CPT_COMP_GOOD &&
								 deq_op_ptr[i].res.cn9k.uc_compcode == DAO_UC_SUCCESS);

			if (!st->is_successful) {
				ossl_log(OSSL_LOG_ERR, "Crypto cpoly op failed (compcode=%d, uc_compcode=%d)\n",
							deq_op_ptr[i].res.cn9k.compcode,
							deq_op_ptr[i].res.cn9k.uc_compcode);
			}
		}
	}

	if (unlikely(!status->is_successful)) {
		ret = -1;
		goto cleanup;
	}

	if (pal_ctx->enc)
	{
		/* copy authentication tag (digest) in external buf
		   used by get_params and ctrl_cmd */
		memcpy(buf, (uint8_t *)out + len, pal_ctx->tls_tag_len);
	}

	ret = len;

cleanup:
	while (in_buf) {
		struct dao_lc_buf *next = in_buf->next;
		pal_free(in_buf);
		in_buf = next;
	}
	while (out_buf) {
		struct dao_lc_buf *next = out_buf->next;
		pal_free(out_buf);
		out_buf = next;
	}
	if (status) pal_free(status);

	pal_ctx->tls_aad_len = -1;

	return ret;
}



int pal_chacha20_poly1305_tls_1_3_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, unsigned char *buf, void *wctx)
{

	int enc;
	uint8_t pip_jb_qsz = 0;
	pal_cry_op_status_t current_job;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint16_t num_enqueued_ops, num_dequeued_ops;
	uint8_t i, j, numpipes, numalloc, k, ret = 0;
	pal_cry_op_status_t *new_st_ptr[PAL_NUM_DEQUEUED_OPS],*status_ptr[SSL_MAX_PIPELINES];
	struct dao_lc_sym_op enq_op_ptr[SSL_MAX_PIPELINES];
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	struct dao_lc_buf *in_buf[SSL_MAX_PIPELINES], *out_buf[SSL_MAX_PIPELINES];
	uint8_t dev_id = glb_params.dev_id;
	sym_queue = glb_params.qp_id;
	uint8_t updated_iv[12];

	numpipes = pal_ctx->numpipes;

	for(int i = 0; i<numpipes; i++) {

		if(!pal_ctx->enc)
		{
			pal_ctx->input_len[i] -= pal_ctx->tls_tag_len;
		}

		status_ptr[i] = pal_malloc(sizeof(pal_cry_op_status_t));
		if (unlikely(!status_ptr[i])) {
			ossl_log(OSSL_LOG_ERR, "Failed to allocate status\n");
			ret = -1;
			goto free_resources;
		}

		status_ptr[i]->is_successful = 0;
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx;

		if (prepare_lc_buf(&in_buf[i], pal_ctx->input_buf[i], pal_ctx->input_len[i] + pal_ctx->tls_tag_len) < 0) {
			ret = -1;
			goto free_resources;
		}

		if (prepare_lc_buf(&out_buf[i], pal_ctx->output_buf[i], pal_ctx->input_len[i] + pal_ctx->tls_tag_len) < 0) {
			ret = -1;
			goto free_resources;
		}

		enq_op_ptr[i].op_cookie = (uint64_t)status_ptr[i];
		enq_op_ptr[i].sess_id = pal_ctx->event.sess_event.sess_id;
		enq_op_ptr[i].aad = pal_ctx->aad_pipe[i];
		enq_op_ptr[i].aad_len = pal_ctx->tls_aad_len;
		enq_op_ptr[i].encrypt = pal_ctx->enc;
		enq_op_ptr[i].in_buffer = in_buf[i];
		enq_op_ptr[i].out_buffer = out_buf[i];
		enq_op_ptr[i].cipher_offset = 0;
		enq_op_ptr[i].cipher_len = pal_ctx->input_len[i];
		enq_op_ptr[i].cipher_iv = (uint8_t *)pal_ctx->iv;
		enq_op_ptr[i].auth_len = 0;
		enq_op_ptr[i].auth_offset = 0;
		enq_op_ptr[i].auth_iv = NULL;
		/* If digest is NULL, the auth tag is placed/read right after ciphered data in the buffer. */
		enq_op_ptr[i].digest = NULL;

	}
/* Enqueue this crypto operation in the crypto device */
	for (k = 0, num_enqueued_ops = 0;
			(num_enqueued_ops < numpipes && k < MAX_ENQUEUE_ATTEMPTS); k++)
	{
		num_enqueued_ops +=
			dao_liquid_crypto_sym_enqueue_burst(
				dev_id, sym_queue,
				&enq_op_ptr[num_enqueued_ops],
				numpipes - num_enqueued_ops);
	}

	if (unlikely(num_enqueued_ops < numpipes))
	{
		ossl_log(OSSL_LOG_ERR, "Enqueue failed - too many attempts\n");
		numalloc = numpipes;
		ret = -1;
		goto free_resources;
	}

	CPT_ATOMIC_INC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);

	/* Handle asynchronous callback */
	if (wctx && pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);


	while (!status_ptr[0]->is_complete)
	{
		do
		{
			num_dequeued_ops = dao_liquid_crypto_dequeue_burst(
				dev_id, sym_queue, deq_op_ptr, PAL_NUM_DEQUEUED_OPS);
			if(unlikely(!num_dequeued_ops && wctx && pal_ctx->async_cb)) {
				pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
				continue;
			}

			for (i = 0; i < num_dequeued_ops; i++)
			{
				new_st_ptr[i] = (pal_cry_op_status_t *)deq_op_ptr[i].op_cookie;
				new_st_ptr[i]->is_complete = 1;

				/* Check if operation was processed successfully */
				if (deq_op_ptr[i].res.cn9k.compcode != DAO_CPT_COMP_GOOD ||
					deq_op_ptr[i].res.cn9k.uc_compcode != DAO_UC_SUCCESS)
				{
					ossl_log(OSSL_LOG_ERR, "Crypto op status is not success (err:%d)\n",
							deq_op_ptr[i].res.cn9k.compcode);
					new_st_ptr[i]->is_successful = 0;
				}
				else
				{
					new_st_ptr[i]->is_successful = 1;
					if (new_st_ptr[i]->wctx_p && pal_ctx->async_cb)
						pal_ctx->async_cb(status_ptr[0]->wctx_p, new_st_ptr[i]->wctx_p,
							new_st_ptr[i]->numpipes, &pip_jb_qsz, &pip_jobs[0], ASYNC_JOB_POST_FINISH);
				}
			}
		} while (pip_jb_qsz > 0);
	}

	CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);

	for (i = 0; i < numpipes; i++)
	{
		if (pal_ctx->enc) {
			// Return total length:  ciphertext + tag
			ret = pal_ctx->input_len[i] + pal_ctx->tls_tag_len;
		} else {
			// No tag to append
			ret = pal_ctx->input_len[i];
		}
	}


free_resources:
	for (i = 0; i < numpipes; i++) {
		struct dao_lc_buf *seg = in_buf[i], *next;
		while (seg) {
			next = seg->next;
			pal_free(seg);
			seg = next;
		}
		seg = out_buf[i];
		while (seg) {
			next = seg->next;
			pal_free(seg);
			seg = next;
		}
		if (status_ptr[i]) pal_free(status_ptr[i]);
	}

	pal_ctx->input_buf = NULL;
	pal_ctx->input_len = NULL;
	pal_ctx->output_buf = NULL;
	pal_ctx->aad_cnt = 0;
	pal_ctx->numpipes = 0;
	pal_ctx->tls_aad_len = -1;

	return ret;
}

int pal_sym_session_cpoly_cleanup(pal_cpoly_ctx_t *pal_ctx)
{
	int ret;
	ret = sym_session_cleanup(&pal_ctx->event, pal_ctx->dev_id);
	return ret;
}
