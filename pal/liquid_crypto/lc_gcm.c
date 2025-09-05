/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <pal_gcm.h>
#include "liquid_crypto_priv.h"
extern int cpt_num_cipher_pipeline_requests_in_flight;

/*
 * Create AEAD Session
 */
int pal_create_aead_session(pal_crypto_aead_algorithm_t algo,
				pal_gcm_ctx_t *pal_ctx, int aad_len,
				uint8_t reconfigure)
{
	int ret = 0;

	if(!sym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->sym_queue))
		return 0;

	pal_ctx->aead_cry_session.opcode = DAO_LC_SYM_OPCODE_FC;
	pal_ctx->aead_cry_session.fc.iv_source = DAO_LC_FC_IV_SRC_OP;
	pal_ctx->aead_cry_session.fc.enc_cipher = DAO_LC_FC_ENC_CIPHER_AES_GCM;
	pal_ctx->aead_cry_session.iv_len = PAL_AES_GCM_IV_LENGTH;
	pal_ctx->aead_cry_session.fc.mac_len = PAL_AEAD_DIGEST_LENGTH;

	pal_ctx->aead_cry_session.fc.aes_key_len =
				(pal_ctx->keylen == PAL_AES128_GCM_KEY_LENGTH) ? DAO_LC_FC_AES_KEY_LEN_128 :
				(pal_ctx->keylen == PAL_AES256_GCM_KEY_LENGTH) ? DAO_LC_FC_AES_KEY_LEN_256 :
				-1;

	if (pal_ctx->aead_cry_session.fc.aes_key_len == -1)
	{
		engine_log(ENG_LOG_ERR, "Invalid key length: %d\n", pal_ctx->keylen);
		return -1;
	}

	memcpy(pal_ctx->aead_cry_session.fc.encr_key, pal_ctx->key, pal_ctx->keylen);

	uint64_t sess_cookie = (uint64_t)pal_ctx;
	ret = sym_create_session(pal_ctx->dev_id, pal_ctx->aead_cry_session, &pal_ctx->aead_event, reconfigure, sess_cookie);
	if (ret == 0)
	{
		engine_log(ENG_LOG_ERR, "Could not create session.\n");
		return -1;
	}

	PAL_ASSERT(pal_ctx->aead_event.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	PAL_ASSERT(pal_ctx->aead_event.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	PAL_ASSERT(pal_ctx->aead_event.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");

	return 0;
}

/*
 * Create CIPHER Session for Crypto operation only
 */
int pal_create_cipher_session( pal_crypto_cipher_algorithm_t algo,
								pal_gcm_ctx_t *pal_ctx, uint8_t reconfigure)
{
	/**
	 * @note Currently, CTR cipher mode is not supported from the DAO LC API.

	int ret = 0;
	if(!sym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->sym_queue))
		return 0;

	pal_ctx->cipher_cry_session.opcode = DAO_LC_SYM_OPCODE_FC;
	pal_ctx->cipher_cry_session.fc.iv_source = DAO_LC_FC_IV_SRC_OP;
	pal_ctx->cipher_cry_session.fc.enc_cipher = DAO_LC_FC_ENC_CIPHER_AES_CTR;
	pal_ctx->cipher_cry_session.iv_len = PAL_AES_CTR_IV_LENGTH;

	pal_ctx->cipher_cry_session.fc.aes_key_len =
				(pal_ctx->keylen == PAL_AES128_GCM_KEY_LENGTH) ? DAO_LC_FC_AES_KEY_LEN_128 :
				(pal_ctx->keylen == PAL_AES256_GCM_KEY_LENGTH) ? DAO_LC_FC_AES_KEY_LEN_256 :
				-1;

	if (pal_ctx->cipher_cry_session.fc.aes_key_len == -1)
	{
		engine_log(ENG_LOG_ERR, "Invalid key length: %d\n", pal_ctx->keylen);
		return -1;
	}

	memcpy(pal_ctx->cipher_cry_session.fc.encr_key, pal_ctx->key, pal_ctx->keylen);

	uint64_t sess_cookie = (uint64_t)pal_ctx;
	ret = sym_create_session(pal_ctx->dev_id, pal_ctx->cipher_cry_session, &pal_ctx->cipher_event, 0, sess_cookie);
	if (ret == 0)
	{
		engine_log(ENG_LOG_ERR, "Could not create session.\n");
		return -1;
	}

	PAL_ASSERT(pal_ctx->cipher_event.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	PAL_ASSERT(pal_ctx->cipher_event.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	PAL_ASSERT(pal_ctx->cipher_event.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");
*/
	return 0;
}

static inline int prepare_lc_buf(struct dao_lc_buf **head, uint8_t *data, long int len)
{
	long int remaining = len;
	long int copied = 0;
	struct dao_lc_buf *seg_buf = NULL, *prev = NULL;
	*head = NULL;

	while (remaining > 0) {
		long int seg = remaining > LIQUID_CRYPTO_BUF_SZ_MAX ? LIQUID_CRYPTO_BUF_SZ_MAX : remaining;

		seg_buf = pal_malloc(sizeof(struct dao_lc_buf));
		if (unlikely(!seg_buf)) {
			engine_log(ENG_LOG_ERR, "Failed to allocate segment buffer\n");
			return -1;
		}

		seg_buf->data = data + copied;
		seg_buf->frag_len = seg;
		seg_buf->total_len = len;
		seg_buf->next = NULL;

		if (!*head) {
			*head = seg_buf;
		} else {
			prev->next = seg_buf;
	}

		prev = seg_buf;
		copied += seg;
		remaining -= seg;
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
 * Return: correct outlen on success, < 0 on failure
 */
int pal_aes_gcm_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *buf,
							void *usr_ctx, void *wctx)
{
	int ret = 0, i, k, numalloc = 0;
	int numpipes = pal_ctx->numpipes > 0 ? pal_ctx->numpipes : 1;
	struct dao_lc_sym_op enq_op_ptr[SSL_MAX_PIPELINES];
	struct dao_lc_buf *in_buf[SSL_MAX_PIPELINES], *out_buf[SSL_MAX_PIPELINES];
	pal_cry_op_status_t *status_ptr[SSL_MAX_PIPELINES],*new_st_ptr[PAL_NUM_DEQUEUED_OPS];
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	uint8_t dev_id = glb_params.dev_id;
	int sym_queue = glb_params.qp_id;
	volatile uint16_t num_enqueued_ops, num_dequeued_ops;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint8_t pip_jb_qsz = 0;

	for (i = 0; i < numpipes; i++) {
		/* Set IV from start of buffer or generate IV and write to
		 * start of buffer. */
		if (pal_ctx->iv_cb(usr_ctx, pal_ctx->enc,
				pal_ctx->tls_exp_iv_len, pal_ctx->output_buf[i]) < 0)
		{
			engine_log(ENG_LOG_ERR, "Failed to set IV\n");
			ret = -1;
			goto free_resources;
		}

		pal_ctx->input_buf[i] += pal_ctx->tls_exp_iv_len;
		if (numpipes == 0 || numpipes == 1) {
			pal_ctx->output_buf[i] += pal_ctx->tls_exp_iv_len;
		}
		pal_ctx->input_len[i] -= pal_ctx->tls_exp_iv_len + pal_ctx->tls_tag_len;

		status_ptr[i] = pal_malloc(sizeof(pal_cry_op_status_t));
		if (unlikely(!status_ptr[i])) {
			engine_log(ENG_LOG_ERR, "Failed to allocate status\n");
			ret = -1;
			goto free_resources;
		}

		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
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
		enq_op_ptr[i].sess_id = pal_ctx->aead_event.sess_event.sess_id;
		enq_op_ptr[i].aad = pal_ctx->aad_pipe[i];
		enq_op_ptr[i].aad_len = pal_ctx->tls_aad_len;
		enq_op_ptr[i].encrypt = !!pal_ctx->enc;
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
		engine_log(ENG_LOG_ERR, "Enqueue failed - too many attempts\n");
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
					fprintf(stderr, "Crypto op status is not success (err:%d)\n",
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
			// Return total length: IV + ciphertext + tag
			ret = pal_ctx->input_len[i] + pal_ctx->tls_exp_iv_len + pal_ctx->tls_tag_len;
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

/*
 * Pure crypto application (Cipher case only)
 */
static int crypto_ctr_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
				const unsigned char *in, size_t len, unsigned char *buf)
{
	int ret = -1;
	struct dao_lc_sym_op enq_op_ptr[1];
	struct dao_lc_buf *in_buf, *out_buf;
	pal_cry_op_status_t *status;
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	uint16_t num_dequeued_ops = 0;
	uint8_t dev_id = glb_params.dev_id;
	int sym_queue = glb_params.qp_id;

	// Allocate operation and status
	status = pal_malloc(sizeof(pal_cry_op_status_t));
	if (unlikely(!status)) {
		engine_log(ENG_LOG_ERR, "Failed to allocate op or status\n");
		goto cleanup;
	}

	status->is_complete = 0;
	status->is_successful = 0;

	// Prepare input buffer
	if (prepare_lc_buf(&in_buf, (uint8_t *)in, len) < 0) {
		engine_log(ENG_LOG_ERR, "Failed to prepare input buffer\n");
		goto cleanup;
	}

	if (prepare_lc_buf(&out_buf, (uint8_t *)out, len) < 0) {
		engine_log(ENG_LOG_ERR, "Failed to prepare output buffer\n");
		goto cleanup;
	}
	// Fill LC operation fields
	enq_op_ptr[0].op_cookie = (uint64_t)status;
	enq_op_ptr[0].sess_id = pal_ctx->cipher_event.sess_event.sess_id;
	enq_op_ptr[0].in_buffer = in_buf;
	enq_op_ptr[0].out_buffer = out_buf;
	enq_op_ptr[0].cipher_offset = 0;
	enq_op_ptr[0].cipher_len = len;
	enq_op_ptr[0].cipher_iv = (uint8_t *)pal_ctx->iv;
	enq_op_ptr[0].aad = NULL;
	enq_op_ptr[0].aad_len = 0;
	enq_op_ptr[0].digest = NULL;
	enq_op_ptr[0].encrypt = !!pal_ctx->enc;
	enq_op_ptr[0].auth_len = 0;
	enq_op_ptr[0].auth_offset = 0;
	enq_op_ptr[0].auth_iv = NULL;

	// Enqueue the operation
	if (dao_liquid_crypto_sym_enqueue_burst(dev_id, sym_queue, &enq_op_ptr[0], 1) != 1) {
		engine_log(ENG_LOG_ERR, "Crypto enqueue failed\n");
		goto cleanup;
	}

	// Poll for completion using batch dequeue
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
				engine_log(ENG_LOG_ERR, "Crypto CTR op failed (compcode=%d, uc_compcode=%d)\n",
							deq_op_ptr[i].res.cn9k.compcode,
							deq_op_ptr[i].res.cn9k.uc_compcode);
			}
		}
	}

	if (!status->is_successful) {
		ret = -1;
		goto cleanup;
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

	return ret;
}

/*
 * Normal crypto application
 */
int pal_crypto_gcm_non_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
					const unsigned char *in, size_t len,
					unsigned char *buf)
{
	int ret = -1;

	// If no AAD is set, fallback to CTR mode
	if (pal_ctx->aad_len == -1) {
		return crypto_ctr_cipher(pal_ctx, out, in, len, buf);
	}

	struct dao_lc_sym_op enq_op_ptr[1];
	struct dao_lc_buf *in_buf, *out_buf;
	pal_cry_op_status_t *status;
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	uint16_t num_dequeued_ops = 0;
	uint8_t dev_id = glb_params.dev_id;
	int sym_queue = glb_params.qp_id;

	// Allocate status
	status = pal_malloc(sizeof(pal_cry_op_status_t));
	if (unlikely(!status)) {
		engine_log(ENG_LOG_ERR, "Failed to allocate op or status\n");
		goto cleanup;
	}

	status->is_successful = 0;
	status->is_complete = 0;

	if (prepare_lc_buf(&in_buf, (uint8_t *)in, len + pal_ctx->tls_tag_len) < 0) {
		engine_log(ENG_LOG_ERR, "Failed to prepare input buffer\n");
		goto cleanup;
	}

	if (prepare_lc_buf(&out_buf, (uint8_t *)out, len + pal_ctx->tls_tag_len) < 0) {
		engine_log(ENG_LOG_ERR, "Failed to prepare input buffer\n");
		goto cleanup;
	}

	enq_op_ptr[0].op_cookie = (uint64_t)status;
	enq_op_ptr[0].sess_id = pal_ctx->aead_event.sess_event.sess_id;
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
	/* If digest is NULL, the auth tag is placed/read right after ciphered data in the buffer. */
	enq_op_ptr[0].digest = NULL;

	// Enqueue the operation
	if (dao_liquid_crypto_sym_enqueue_burst(dev_id, sym_queue, &enq_op_ptr[0], 1) != 1) {
		engine_log(ENG_LOG_ERR, "Crypto enqueue failed\n");
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
				engine_log(ENG_LOG_ERR, "Crypto GCM op failed (compcode=%d, uc_compcode=%d)\n",
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
	pal_ctx->aad_len = -1;

	return ret;
}

int pal_crypto_gcm_tls_1_3_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
								const unsigned char *in, size_t len,
								unsigned char *buf, void *wctx)
{
	int ret = -1;

	// If no AAD is set, fallback to CTR mode
	if (pal_ctx->aad_len == -1) {
		return crypto_ctr_cipher(pal_ctx, out, in, len, buf);
	}

	struct dao_lc_sym_op enq_op_ptr[1];
	struct dao_lc_buf *in_buf, *out_buf;
	pal_cry_op_status_t *status;
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	uint16_t num_dequeued_ops = 0;
	uint8_t dev_id = glb_params.dev_id;
	int sym_queue = glb_params.qp_id;

	// Allocate status
	status = pal_malloc(sizeof(pal_cry_op_status_t));
	if (unlikely(!status)) {
		engine_log(ENG_LOG_ERR, "Failed to allocate op or status\n");
		goto cleanup;
	}

	status->is_successful = 0;
	status->is_complete = 0;

	if (prepare_lc_buf(&in_buf, (uint8_t *)in, len + pal_ctx->tls_tag_len) < 0) {
		engine_log(ENG_LOG_ERR, "Failed to prepare input buffer\n");
		goto cleanup;
	}

	if (prepare_lc_buf(&out_buf, (uint8_t *)out, len + pal_ctx->tls_tag_len) < 0) {
		engine_log(ENG_LOG_ERR, "Failed to prepare input buffer\n");
		goto cleanup;
	}

	enq_op_ptr[0].op_cookie = (uint64_t)status;
	enq_op_ptr[0].sess_id = pal_ctx->aead_event.sess_event.sess_id;
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
	/* If digest is NULL, the auth tag is placed/read right after ciphered data in the buffer. */
	enq_op_ptr[0].digest = NULL;

	// Enqueue the operation
	if (dao_liquid_crypto_sym_enqueue_burst(dev_id, sym_queue, &enq_op_ptr[0], 1) != 1) {
		engine_log(ENG_LOG_ERR, "Crypto enqueue failed\n");
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
				engine_log(ENG_LOG_ERR, "Crypto GCM op failed (compcode=%d, uc_compcode=%d)\n",
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
		memcpy(buf, (uint8_t *) out + len, pal_ctx->tls_tag_len);
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
	pal_ctx->aad_len = -1;

	return ret;
}

int pal_sym_session_gcm_cleanup(pal_gcm_ctx_t *pal_ctx)
{
	int ret;

	ret = sym_session_cleanup(&pal_ctx->aead_event, pal_ctx->dev_id);
	//ret &= sym_session_cleanup(&pal_ctx->cipher_event, pal_ctx->dev_id);

	return ret;
}
