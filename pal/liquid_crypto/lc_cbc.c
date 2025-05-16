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

static int
sess_event_dequeue(uint8_t dev_id, struct dao_lc_cmd_event *ev)
{
	uint64_t timeout;
	int ret;

	/* Set a timeout of 1 second. */
	timeout = rte_get_timer_cycles() + rte_get_timer_hz();

	do
	{
		ret = dao_liquid_crypto_cmd_event_dequeue(dev_id, ev, 1);
		if (ret == 1)
			break;

		if (rte_get_timer_cycles() > timeout)
		{
			fprintf(stderr, "Operation timed out\n");
			break;
		}
	} while (ret == 0);

	if (ret != 1)
	{
		fprintf(stderr, "Could not dequeue operation\n");
		return -1;
	}

	return 0;
}

int pal_aes_cbc_cipher(pal_cbc_ctx_t *pal_ctx, unsigned char *out, const unsigned char *in,
						size_t inl, unsigned char *iv, int enc, int sym_queue, void *wctx)
{
	uint8_t dev_id = glb_params.dev_id;
	sym_queue = glb_params.qp_id;
	struct dao_lc_res deq_op_ptr[PAL_NUM_DEQUEUED_OPS];
	struct dao_lc_buf *in_buf[MAX_PIPE_JOBS] = {NULL};
	unsigned char saved_iv[PAL_AES_CBC_IV_LENGTH];
	const unsigned char *next_iv;
	struct dao_lc_sym_op *enq_op_ptr[MAX_PIPE_JOBS] = {NULL};
	pal_cry_op_status_t *status_ptr[MAX_PIPE_JOBS] = {NULL}, *new_st_ptr[PAL_NUM_DEQUEUED_OPS];
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint8_t pip_jb_qsz = 0;
	int ret = 1, numpipes, numalloc = 0, k, i;
	volatile uint16_t num_enqueued_ops, num_dequeued_ops;

	numpipes = pal_ctx->numpipes;
	/* Bydefault number of pipe is one */
	if (numpipes == 0)
	{
		numpipes = 1;
		pal_ctx->output_buf = &out;
		pal_ctx->input_buf = (uint8_t **)&in;
		pal_ctx->input_len = &inl;
	}

	memset(&deq_op_ptr, 0, sizeof(deq_op_ptr));

	for (i = 0; i < numpipes; i++)
	{
		if (pal_ctx->input_len[i] < PAL_AES_CBC_IV_LENGTH)
		{
			engine_log(ENG_LOG_ERR, "Invalid input length\n");
			ret = -1;
			goto free_resources;
		}
		// For decrytion, save the last iv_len bytes of ciphertext as next IV.
		if (!enc)
		{
			next_iv = pal_ctx->input_buf[i] +
						pal_ctx->input_len[i] - PAL_AES_CBC_IV_LENGTH;
			memcpy(saved_iv, next_iv, PAL_AES_CBC_IV_LENGTH);
		}
		enq_op_ptr[i] = (struct dao_lc_sym_op *)(pal_malloc(sizeof(struct dao_lc_sym_op)));
		if (unlikely(enq_op_ptr[i] == NULL))
		{
			engine_log(ENG_LOG_ERR, "Not enough crypto operations available\n");
			ret = -1;
			numalloc = i;
			goto free_resources;
		}
		status_ptr[i] = (pal_cry_op_status_t *)(pal_malloc(sizeof(pal_cry_op_status_t)));
		if (unlikely(status_ptr[i] == NULL))
		{
			engine_log(ENG_LOG_ERR, "Not enough crypto operation status available\n");
			ret = -1;
			numalloc = i;
			goto free_resources;
		}
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx;

		/* Perform crypto operation */
		enq_op_ptr[i]->op_cookie = (uint64_t)status_ptr[i];
		enq_op_ptr[i]->sess_id = pal_ctx->event.sess_event.sess_id;

		enq_op_ptr[i]->encrypt = !!enc;
		in_buf[i] = (struct dao_lc_buf *)(pal_malloc(sizeof(struct dao_lc_buf)));
		if (unlikely(in_buf[i] == NULL))
		{
			engine_log(ENG_LOG_ERR, "Failed to allocate memory for input buffer\n");
			ret = -1;
			numalloc = i;
			goto free_resources;
		}

		if (likely(pal_ctx->input_len[i] <= LIQUID_CRYPTO_BUF_SZ_MAX))
		{
			in_buf[i]->data = pal_ctx->input_buf[i];
			in_buf[i]->total_len = pal_ctx->input_len[i];
			in_buf[i]->seg_len = pal_ctx->input_len[i];
		}
		else
		{
			long int remaining = pal_ctx->input_len[i];
			long int copied = 0;
			struct dao_lc_buf *seg_buf = in_buf[i];
			seg_buf->total_len = pal_ctx->input_len[i];
			seg_buf->next = NULL;

			while (remaining > 0)
			{
				long int seg = remaining > LIQUID_CRYPTO_BUF_SZ_MAX ? LIQUID_CRYPTO_BUF_SZ_MAX : remaining;
				seg_buf->data = (uint8_t *)(pal_ctx->input_buf[i] + copied);
				seg_buf->seg_len = seg;
				copied += seg;
				remaining -= seg;
				if (remaining > 0)
				{
					seg_buf->next = pal_malloc(sizeof(struct dao_lc_buf));
					if (unlikely(seg_buf->next == NULL))
					{
						engine_log(ENG_LOG_ERR, "Failed to allocate memory for input buffer struct\n");
						ret = -1;
						numalloc = i;
						goto free_resources;
					}
					seg_buf = seg_buf->next;
					memset(seg_buf, 0, sizeof(struct dao_lc_buf));
				}
				else
				{
					seg_buf->next = NULL;
				}
			}
		}
		enq_op_ptr[i]->in_buffer = in_buf[i];
		enq_op_ptr[i]->cipher_offset = 0;
		enq_op_ptr[i]->cipher_len = pal_ctx->input_len[i];
		enq_op_ptr[i]->cipher_iv = iv;
	}

	/* Enqueue this crypto operation in the crypto device */
	for (k = 0, num_enqueued_ops = 0;
			(num_enqueued_ops < numpipes && k < MAX_ENQUEUE_ATTEMPTS); k++)
	{
		num_enqueued_ops +=
			dao_liquid_crypto_sym_enqueue_burst(
				dev_id, sym_queue,
				enq_op_ptr[num_enqueued_ops],
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
	CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);

	for (i = 0; i < numpipes; i++)
	{
		/* Returns -1 if any of the pipe in the async job is failed. */
		if (unlikely(!status_ptr[i]->is_successful))
			ret = -1;
		memcpy(pal_ctx->output_buf[i], enq_op_ptr[i]->in_buffer->data, pal_ctx->input_len[i]);
		// For encryption, copy last 16 bytes of ciphertext to IV
		if (enc)
			next_iv = (pal_ctx->output_buf[i] + pal_ctx->input_len[i] - PAL_AES_CBC_IV_LENGTH);
		else
			next_iv = saved_iv;
		memcpy(iv, next_iv, PAL_AES_CBC_IV_LENGTH);
		pal_free(enq_op_ptr[i]);
		// Free all segments in the input buffer chain
		struct dao_lc_buf *seg = in_buf[i], *next_seg;
		while (seg) {
			next_seg = seg->next;
			pal_free(seg);
			seg = next_seg;
		}
		pal_free(status_ptr[i]);
	}

free_resources:
	if (unlikely(ret < 0))
	{
		for (i = 0; i < numalloc; i++)
		{
			if (enq_op_ptr[i])
			{
				pal_free(enq_op_ptr[i]);
				enq_op_ptr[i] = NULL;
			}
			if (status_ptr[i])
			{
				pal_free(status_ptr[i]);
				status_ptr[i] = NULL;
			}
			// Free all segments in the input buffer chain
			struct dao_lc_buf *seg = in_buf[i], *next_seg;
			while (seg)
			{
				next_seg = seg->next;
				pal_free(seg);
				seg = next_seg;
			}
			in_buf[i] = NULL;
		}
	}
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

int pal_aes_cbc_cleanup(pal_cbc_ctx_t *pal_ctx)
{
	int ret;
	uint64_t sess_cookie;
	if (&pal_ctx->cry_session != NULL)
	{
		sess_cookie = pal_ctx->event.sess_event.sess_cookie;
		ret = dao_liquid_crypto_sym_sess_destroy(pal_ctx->dev_id, pal_ctx->event.sess_event.sess_id,
													sess_cookie);
		if (ret < 0)
		{
			printf("Could not destroy session");
			return -1;
		}
		ret = sess_event_dequeue(pal_ctx->dev_id, &pal_ctx->event);
		if (ret < 0)
		{
			printf("Could not dequeue session event");
			return -1;
		}
	}

	PAL_ASSERT(pal_ctx->event.event_type == DAO_LC_CMD_EVENT_SESS_DESTROY, "Invalid event type");
	PAL_ASSERT(pal_ctx->event.sess_event.sess_cookie == sess_cookie, "Invalid operation cookie");
	return 1;
}