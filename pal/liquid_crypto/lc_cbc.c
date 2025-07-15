/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <rte_cycles.h>

#include <hw/cpt.h>

#include "pal_cbc.h"
#include "liquid_crypto_priv.h"

extern int cpt_num_cipher_pipeline_requests_in_flight;

#define FREE_RESOURCES(start, end) \
	do { \
		for (int i = (start); i < (end); i++) { \
			if (total_memory[i] != NULL) \
				pal_free(total_memory[i]); \
		} \
	} while (0)

int pal_aes_cbc_cipher(pal_cbc_ctx_t *pal_ctx, unsigned char *out, const unsigned char *in,
						size_t inl, unsigned char *iv, int enc, int sym_queue, void *wctx)
{
	uint8_t dev_id = glb_params.dev_id;
	sym_queue = glb_params.qp_id;
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	struct dao_lc_buf *in_buf[MAX_PIPE_JOBS], *out_buf[MAX_PIPE_JOBS];
	unsigned char saved_iv[PAL_AES_CBC_IV_LENGTH];
	const unsigned char *next_iv;
	struct dao_lc_sym_op enq_op_ptr[MAX_PIPE_JOBS];
	pal_cry_op_status_t *status_ptr[MAX_PIPE_JOBS], *new_st_ptr[PAL_NUM_DEQUEUED_OPS];
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint8_t pip_jb_qsz = 0;
	int ret = 1, numpipes, k, i, chain_buf_cnt;
	volatile uint16_t num_enqueued_ops, num_dequeued_ops;
	void *total_memory[MAX_PIPE_JOBS];
	uintptr_t base;

	numpipes = pal_ctx->numpipes;
	/* Bydefault number of pipe is one */
	if (numpipes == 0)
	{
		numpipes = 1;
		pal_ctx->output_buf = &out;
		pal_ctx->input_buf = (uint8_t **)&in;
		pal_ctx->input_len = &inl;
	}

	chain_buf_cnt = (inl + LIQUID_CRYPTO_BUF_SZ_MAX - 1) / LIQUID_CRYPTO_BUF_SZ_MAX;

	for (i = 0; i < numpipes; i++)
	{
		if (pal_ctx->input_len[i] < PAL_AES_CBC_IV_LENGTH)
		{
			engine_log(ENG_LOG_ERR, "Invalid input length\n");
			ret = -1;
			goto exit;
		}
		// For decrytion, save the last iv_len bytes of ciphertext as next IV.
		if (!enc)
		{
			next_iv = pal_ctx->input_buf[i] +
						pal_ctx->input_len[i] - PAL_AES_CBC_IV_LENGTH;
			memcpy(saved_iv, next_iv, PAL_AES_CBC_IV_LENGTH);
		}

		/**
		 * Allocates a memory block for each operation in the total_memory.
		 *
		 * The allocated memory size is calculated as the sum of:
		 * - Twice the size of `struct dao_lc_buf` multiplied by `chain_buf_cnt` (for input and output buffers).
		 * - The size of a `pal_cry_op_status_t` (operation status).
		 * - Three times the cache line size (`RTE_CACHE_LINE_SIZE`) multiplied by `chain_buf_cnt` (for alignment or padding).
		 *   (One for aligning `in_buf`, one for `out_buf`, and one for `status_ptr`)
		 *
		 * This ensures that all necessary structures and buffers for a cryptographic operation are allocated contiguously,
		 * potentially improving cache performance and simplifying memory management.
		 *
		 */
		total_memory[i] = (void *)pal_malloc(
			(sizeof(struct dao_lc_buf) * 2 * chain_buf_cnt) +
			sizeof(pal_cry_op_status_t) + (3 * RTE_CACHE_LINE_SIZE * chain_buf_cnt));
		if (unlikely(total_memory[i] == NULL))
		{
			engine_log(ENG_LOG_ERR, "Not enough crypto operations available\n");
			ret = -1;
			FREE_RESOURCES(0, i);
			goto exit;
		}

		/*
		* This ensures that all structures are optimally aligned for cache efficiency.
		*/
		base = (uintptr_t)total_memory[i];
		in_buf[i] = (struct dao_lc_buf *)RTE_PTR_ALIGN((void *)base, RTE_CACHE_LINE_SIZE);
		out_buf[i] = (struct dao_lc_buf *)RTE_PTR_ALIGN((void *)(in_buf[i] + chain_buf_cnt), RTE_CACHE_LINE_SIZE);
		status_ptr[i] = (pal_cry_op_status_t *)RTE_PTR_ALIGN((void *)(out_buf[i] + chain_buf_cnt), RTE_CACHE_LINE_SIZE);
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx;

		/* Perform crypto operation */
		enq_op_ptr[i].op_cookie = (uint64_t)status_ptr[i];
		enq_op_ptr[i].sess_id = pal_ctx->event.sess_event.sess_id;

		enq_op_ptr[i].encrypt = !!enc;

		if (likely(pal_ctx->input_len[i] <= LIQUID_CRYPTO_BUF_SZ_MAX))
		{
			in_buf[i]->data = pal_ctx->input_buf[i];
			in_buf[i]->total_len = pal_ctx->input_len[i];
			in_buf[i]->frag_len = pal_ctx->input_len[i];
			out_buf[i]->data = pal_ctx->output_buf[i];
			out_buf[i]->total_len = pal_ctx->input_len[i];
			out_buf[i]->frag_len = pal_ctx->input_len[i];
			in_buf[i]->next = NULL;
			out_buf[i]->next = NULL;
		}
		else
		{
			long int remaining = pal_ctx->input_len[i];
			long int copied = 0;
			struct dao_lc_buf *seg_buf = in_buf[i];
			seg_buf->total_len = pal_ctx->input_len[i];
			seg_buf->next = NULL;

			int j = 1;
			while (remaining > 0)
			{
				long int seg = remaining > LIQUID_CRYPTO_BUF_SZ_MAX ? LIQUID_CRYPTO_BUF_SZ_MAX : remaining;
				seg_buf->data = (uint8_t *)(pal_ctx->input_buf[i] + copied);
				seg_buf->frag_len = seg;
				copied += seg;
				remaining -= seg;
				if (remaining > 0)
				{
					seg_buf->next = (struct dao_lc_buf *)RTE_PTR_ALIGN((void *)(in_buf[i] + j++), RTE_CACHE_LINE_SIZE);
					seg_buf = seg_buf->next;
				}
				else
				{
					seg_buf->next = NULL;
				}
			}
		}
		enq_op_ptr[i].in_buffer = in_buf[i];
		enq_op_ptr[i].out_buffer = out_buf[i];
		enq_op_ptr[i].cipher_offset = 0;
		enq_op_ptr[i].cipher_len = pal_ctx->input_len[i];
		enq_op_ptr[i].cipher_iv = iv;
		enq_op_ptr[i].auth_iv = NULL;
		enq_op_ptr[i].auth_len = 0;
		enq_op_ptr[i].auth_offset = 0;
		enq_op_ptr[i].aad = NULL;
		enq_op_ptr[i].aad_len = 0;
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
		ret = -1;
		FREE_RESOURCES(num_enqueued_ops, numpipes);
		for (k = 0; k < num_enqueued_ops; k++)
			status_ptr[k]->numpipes = num_enqueued_ops;
	}

	CPT_ATOMIC_INC_N(cpt_num_cipher_pipeline_requests_in_flight, num_enqueued_ops);
	/* Handle asynchronous callback */
	if (wctx && pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

	/* Dequeue and process operations */
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

	/* Decrement pipeline requests in flight */
	CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, num_enqueued_ops);

	for (i = 0; i < num_enqueued_ops; i++)
	{
		/* Returns -1 if any of the pipe in the async job is failed. */
		if (unlikely(!status_ptr[i]->is_successful))
			ret = -1;
		// For encryption, copy last 16 bytes of ciphertext to IV
		if (enc)
			next_iv = (pal_ctx->output_buf[i] + pal_ctx->input_len[i] - PAL_AES_CBC_IV_LENGTH);
		else
			next_iv = saved_iv;
		memcpy(iv, next_iv, PAL_AES_CBC_IV_LENGTH);
		pal_free(total_memory[i]);
	}

exit:

	pal_ctx->output_buf = NULL;
	pal_ctx->input_buf = NULL;
	pal_ctx->input_len = NULL;
	pal_ctx->numpipes = 0;

	return ret;
}

int pal_aes_cbc_create_session(pal_cbc_ctx_t *pal_ctx, const unsigned char *key, const unsigned char *iv,
								int enc, int key_len)
{
	int ret = 0;
	if (!sym_get_valid_devid_qid(&pal_ctx->dev_id, &pal_ctx->sym_queue))
	{
		engine_log(ENG_LOG_ERR, "Invalid device ID or queue ID\n");
		return 0;
	}
	if (key != NULL)
	{
		pal_ctx->cry_session.opcode = DAO_LC_SYM_OPCODE_FC;
		pal_ctx->cry_session.fc.iv_source = DAO_LC_FC_IV_SRC_OP;
		pal_ctx->cry_session.fc.enc_cipher = DAO_LC_FC_ENC_CIPHER_AES_CBC;
		pal_ctx->cry_session.iv_len = PAL_AES_CBC_IV_LENGTH;
		memcpy(pal_ctx->cry_session.fc.encr_key, key, key_len);
		pal_ctx->cry_session.fc.aes_key_len = (key_len == PAL_AES128_CBC_KEY_LENGTH) ? DAO_LC_FC_AES_KEY_LEN_128 : (key_len == PAL_AES256_CBC_KEY_LENGTH) ? DAO_LC_FC_AES_KEY_LEN_256 : -1;
		if (pal_ctx->cry_session.fc.aes_key_len == -1)
		{
			engine_log(ENG_LOG_ERR, "Invalid key length: %d\n", key_len);
			return 0;
		}
	}

	uint64_t sess_cookie = (uint64_t)pal_ctx;

	ret = sym_create_session(pal_ctx->dev_id, pal_ctx->cry_session, &pal_ctx->event, 0, sess_cookie);

	if (ret == 0)
	{
		engine_log(ENG_LOG_ERR, "Could not create session.\n");
		return 0;
	}

	PAL_ASSERT(pal_ctx->event.event_type == DAO_LC_CMD_EVENT_SESS_CREATE, "Invalid event type");
	PAL_ASSERT(pal_ctx->event.sess_event.sess_id != DAO_LC_SESS_ID_INVALID, "Invalid session ID");
	PAL_ASSERT(pal_ctx->event.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");
	return 1;
}

int pal_sym_session_cbc_cleanup(pal_cbc_ctx_t *pal_ctx)
{
	return sym_session_cleanup(&pal_ctx->event, pal_ctx->dev_id);
}
