
/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */


#include "pal_aes_cbc_hmac_sha1.h"
/*
 * AES HMAC SHA Implementation
 */

extern dpdk_pools_t *pools;

int aes_cbc_hmac_sha1_setup_session(aes_cbc_hmac_sha1_ctx_t *pal_ctx)
{
	struct rte_crypto_sym_xform cipher_xform = {
		.next = NULL,
		.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
		.cipher = { .op = pal_ctx->enc ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
			RTE_CRYPTO_CIPHER_OP_DECRYPT,
			.algo = RTE_CRYPTO_CIPHER_AES_CBC,
			.key = { .length = pal_ctx->keylen },
			.iv = { .offset = PAL_AES_CBC_HMAC_SHA_IV_OFFSET,
				.length = PAL_AES_CBC_IV_LENGTH } }
	};

	struct rte_crypto_sym_xform auth_xform = {
		.next = NULL,
		.type = RTE_CRYPTO_SYM_XFORM_AUTH,
		.auth = { .op = pal_ctx->enc ? RTE_CRYPTO_AUTH_OP_GENERATE :
			 RTE_CRYPTO_AUTH_OP_VERIFY,
			.algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
			.key = { .length = SHA_DIGEST_LENGTH},
			.digest_length = SHA_DIGEST_LENGTH}
	};

	struct rte_crypto_sym_xform *first_xform;

	if (pal_ctx->enc) {
		first_xform = &auth_xform;
		auth_xform.next = &cipher_xform;
	} else {
		first_xform = &cipher_xform;
		cipher_xform.next = &auth_xform;
	}

	auth_xform.auth.key.data = pal_ctx->hmac_key;
	cipher_xform.cipher.key.data = (const uint8_t *)pal_ctx->key;

	pal_ctx->cry_session = sym_create_session(pal_ctx->dev_id, first_xform, 0, NULL);

	return 1;
}

int pal_aes_cbc_hmac_sha1_create_session(aes_cbc_hmac_sha1_ctx_t *pal_ctx,
		const unsigned char *key, const unsigned char *iv,
		int enc, int key_len)
{
	if (iv != NULL)
		memcpy(pal_ctx->iv, iv, PAL_AES_CBC_IV_LENGTH);

	if (key != NULL) {
		memcpy(pal_ctx->key, key, key_len);

	    pal_ctx->keylen = key_len;
	    pal_ctx->enc = enc;
      aes_cbc_hmac_sha1_setup_session(pal_ctx);
	    pal_ctx->numpipes = 0;
	    pal_ctx->payload_length = PAL_AES_SHA1_NO_PAYLOAD_LENGTH;
    }

	return 1;
}

static inline uint8_t *
pktmbuf_mtod_offset(struct rte_mbuf *mbuf, int offset)
{
	struct rte_mbuf *m;

	for (m = mbuf; (m != NULL) && (offset > m->data_len); m = m->next)
		offset -= m->data_len;

	if (m == NULL) {
		printf("pktmbuf_mtod_offset: offset out of buffer\n");
		return NULL;
	}
	return rte_pktmbuf_mtod_offset(m, uint8_t *, offset);
}

static inline rte_iova_t
pktmbuf_iova_offset(struct rte_mbuf *mbuf, int offset)
{
	struct rte_mbuf *m;

	for (m = mbuf; (m != NULL) && (offset > m->data_len); m = m->next)
		offset -= m->data_len;

	if (m == NULL) {
		printf("pktmbuf_iova_offset: offset out of buffer\n");
		return 0;
	}
	return rte_pktmbuf_iova_offset(m, offset);
}

int pal_aes_cbc_hmac_sha1_cipher(aes_cbc_hmac_sha1_ctx_t *pal_ctx, unsigned char *out,
			                           const unsigned char *in, size_t inl,
                                 int sym_queue, int iv_len)
{
	int numpipes = 1;
	unsigned int pad_len = 0;
	size_t plen = pal_ctx->payload_length;
	pal_cry_op_status_t **status_ptr, **new_st_ptr;
	struct rte_crypto_op **enq_op_ptr, **deq_op_ptr;
	size_t sha_data_len = 0, sha_data_off = 0;

	numpipes = pal_ctx->numpipes;

	pal_ctx->payload_length = PAL_AES_SHA1_NO_PAYLOAD_LENGTH;

	if (inl % PAL_AES_BLOCK_SIZE)
		return 0;

	/* Minimum packet size.
	 * PAL_AES_BLOCK_SIZE bytes explicit IV +
	 * SHA_DIGEST_LENGTH bytes HMAC +
	 * one byte data +
	 * padding
	 */
	if (inl < (3 * PAL_AES_BLOCK_SIZE))
		return 0;

	/* Bydefault number of pipes is one */
	if (numpipes == 0) {
		numpipes = 1;
		pal_ctx->input_len = malloc(sizeof(int));
		pal_ctx->input_len[0] = inl;
		pal_ctx->output_buf = &out;
		/* As it's inplace */
		pal_ctx->input_buf = &out;
	}

	char *sha_data_buf[numpipes];
	void *buf_digest[numpipes];
	void *buf_pad_len[numpipes];
	char *buf[numpipes];
	uint16_t i, num_dequeued_ops, num_enqueued_ops;
	struct rte_mbuf *mbuf;
	uint8_t *iv_ptr;
	void *buf_ptr;

	enq_op_ptr = malloc(sizeof(struct rte_crypto_op *) * numpipes);
	deq_op_ptr = malloc(sizeof(struct rte_crypto_op *) * numpipes);
	status_ptr = malloc(sizeof(pal_cry_op_status_t *) * numpipes);
	new_st_ptr = malloc(sizeof(pal_cry_op_status_t *) * numpipes);

	for (i = 0; i < numpipes; i++) {

		enq_op_ptr[i] = rte_crypto_op_alloc(
		pools->sym_op_pool , RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (enq_op_ptr[i] == NULL) {
			engine_log(ENG_LOG_ERR, "Not enough crypto operations available\n");
			return 0;
		}
		/* Get a burst of mbufs */
		mbuf = rte_pktmbuf_alloc(pools->mbuf_pool);
		if (mbuf == NULL) {
			engine_log(ENG_LOG_ERR, "Not enough crypto ops available\n");
			return 0;
		}

    if (pal_ctx->enc) {
      if (plen == PAL_AES_SHA1_NO_PAYLOAD_LENGTH) {
        /* Even for speed test and other tests without
         * payload follow tls proto
         */
        plen = pal_ctx->input_len[i] -
          SHA_DIGEST_LENGTH -
          ((pal_ctx->input_len[i] -
            SHA_DIGEST_LENGTH) %
           PAL_AES_BLOCK_SIZE);
        iv_len = PAL_AES_BLOCK_SIZE;
      } else if (pal_ctx->input_len[i] !=
          (long)((plen + SHA_DIGEST_LENGTH +
              PAL_AES_BLOCK_SIZE)
            & -PAL_AES_BLOCK_SIZE))
        return 0;

      sha_data_off += iv_len;

      /* First AES_BLOCK is encrypted using software
       * as per current flexi crypto
       */
      pal_ctx->iv_cb(pal_ctx->key, pal_ctx->keylen, pal_ctx->input_buf[numpipes-1-i],
          pal_ctx->output_buf[numpipes-1-i], pal_ctx->iv, pal_ctx->enc);
      memcpy(pal_ctx->iv, pal_ctx->output_buf[numpipes-1-i],
          PAL_AES_CBC_IV_LENGTH);

      /* reserve space for input digest */
      /* For TLS it is AAD + payload */
      sha_data_len = pal_ctx->tls_aad_len + plen -
        sha_data_off;
      sha_data_buf[i] = rte_pktmbuf_append(mbuf,
          sha_data_len);
      if (sha_data_buf[i] == NULL) {
        engine_log(ENG_LOG_ERR, "Not enough room in the mbuf\n");
        return 0;
      }
      memset(sha_data_buf[i], 0, sha_data_len);
      memcpy(sha_data_buf[i], pal_ctx->tls_aad[i],
          pal_ctx->tls_aad_len);
      memcpy((sha_data_buf[i]+pal_ctx->tls_aad_len),
          (in+sha_data_off), (plen-sha_data_off));

      /* reserve space for digest */
      buf_digest[i] = rte_pktmbuf_append(mbuf,
          SHA_DIGEST_LENGTH);
      memset(buf_digest[i], 0, SHA_DIGEST_LENGTH);

      /* reserve space for padding */
      pad_len = pal_ctx->input_len[i] - plen -
        SHA_DIGEST_LENGTH;
      buf_pad_len[i] = rte_pktmbuf_append(mbuf, pad_len);
      memset(buf_pad_len[i], (pad_len-1), pad_len);

      enq_op_ptr[i]->sym->m_src = mbuf;
      enq_op_ptr[i]->sym->cipher.data.offset =
        pal_ctx->tls_aad_len;
      enq_op_ptr[i]->sym->cipher.data.length = plen -
        sha_data_off + SHA_DIGEST_LENGTH +
        pad_len;
      enq_op_ptr[i]->sym->auth.digest.data =
        pktmbuf_mtod_offset(mbuf, sha_data_len);
      enq_op_ptr[i]->sym->auth.digest.phys_addr =
        pktmbuf_iova_offset(mbuf, sha_data_len);
      enq_op_ptr[i]->sym->auth.data.offset = 0;
      enq_op_ptr[i]->sym->auth.data.length = sha_data_len;

      pal_ctx->output_buf[i] += PAL_AES_BLOCK_SIZE;
      pal_ctx->input_len[i] -= PAL_AES_BLOCK_SIZE;

    } else {
			unsigned char pad_data[PAL_AES_BLOCK_SIZE];
			unsigned char pad_iv[PAL_AES_CBC_IV_LENGTH];
			unsigned int pad;
			size_t data_len;

			memcpy(pad_data, pal_ctx->output_buf[i] +
				pal_ctx->input_len[i]-PAL_AES_BLOCK_SIZE,
				PAL_AES_BLOCK_SIZE);
			memcpy(pad_iv, pal_ctx->output_buf[i]+
					pal_ctx->input_len[i]-
					(2*PAL_AES_BLOCK_SIZE),
					PAL_AES_CBC_IV_LENGTH);

      pal_ctx->iv_cb(pal_ctx->key, pal_ctx->keylen, pad_data,
          pad_data, pad_iv, pal_ctx->enc);

			memcpy(pal_ctx->iv, pal_ctx->input_buf[i],
					PAL_AES_CBC_IV_LENGTH);

			pal_ctx->input_buf[i] += PAL_AES_BLOCK_SIZE;
			pal_ctx->input_len[i] -= PAL_AES_BLOCK_SIZE;

			pad = pad_data[PAL_AES_BLOCK_SIZE-1];
			data_len = pal_ctx->input_len[i] -
				(SHA_DIGEST_LENGTH + pad + 1);
			pal_ctx->tls_aad[i][pal_ctx->tls_aad_len - 2] =
					data_len >> 8;
			pal_ctx->tls_aad[i][pal_ctx->tls_aad_len - 1] =
			data_len;

			/* rte_pktmbuf_append returns the pointer to appended
			 * data.
			 */
			buf[i] = rte_pktmbuf_append(mbuf,
					(inl+pal_ctx->tls_aad_len));
			if (buf[i] == NULL) {
				engine_log(ENG_LOG_ERR, "Not enough room in the mbuf\n");
				return 0;
			}
			memcpy(buf[i], pal_ctx->tls_aad[i],
					pal_ctx->tls_aad_len);
			memcpy(buf[i]+pal_ctx->tls_aad_len,
					pal_ctx->input_buf[i],
					pal_ctx->input_len[i]);
			enq_op_ptr[i]->sym->m_src = mbuf;
			enq_op_ptr[i]->sym->cipher.data.offset =
					pal_ctx->tls_aad_len;
			enq_op_ptr[i]->sym->cipher.data.length =
					pal_ctx->input_len[i];
			enq_op_ptr[i]->sym->auth.digest.data =
					pktmbuf_mtod_offset(mbuf,
					(data_len + pal_ctx->tls_aad_len));
			enq_op_ptr[i]->sym->auth.digest.phys_addr =
					pktmbuf_iova_offset(mbuf, (data_len +
					pal_ctx->tls_aad_len));
			enq_op_ptr[i]->sym->auth.data.offset = 0;
			enq_op_ptr[i]->sym->auth.data.length =
			pal_ctx->tls_aad_len + data_len;
		}

		iv_ptr = rte_crypto_op_ctod_offset(enq_op_ptr[i], uint8_t *,
			PAL_AES_CBC_HMAC_SHA_IV_OFFSET);

		memcpy(iv_ptr, pal_ctx->iv, PAL_AES_CBC_IV_LENGTH);

		status_ptr[i] = rte_crypto_op_ctod_offset(
				enq_op_ptr[i], pal_cry_op_status_t *,
				PAL_COP_METADATA_OFF_CBC_HMAC_SHA);

		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;

		rte_crypto_op_attach_sym_session(enq_op_ptr[i],
				pal_ctx->cry_session);

	}
	/* Enqueue this crypto operation in the crypto device. */
	num_enqueued_ops = rte_cryptodev_enqueue_burst(pal_ctx->dev_id,
			sym_queue, enq_op_ptr, numpipes);

	if (num_enqueued_ops < numpipes) {
		rte_mempool_put_bulk(pools->sym_op_pool, (void **)enq_op_ptr,
					 numpipes);
		for (i = 0; i < numpipes; i++)
			rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
		printf("\n %d Crypto operations enqueue failed.\n",
				(numpipes - num_enqueued_ops));
		return 0;
	}

	/*
	 * Assumption is that 1 operation is dequeued since only
	 * one operation is enqueued.
	 */
	num_dequeued_ops = 0;
	while (num_dequeued_ops != numpipes) {

    if(pal_ctx->async_cb)
      pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

		num_dequeued_ops += rte_cryptodev_dequeue_burst(
				pal_ctx->dev_id, sym_queue,
				&deq_op_ptr[num_dequeued_ops], numpipes);
	}

	if (num_dequeued_ops == numpipes) {
		for (i = 0; i < numpipes; i++) {
			new_st_ptr[i] = rte_crypto_op_ctod_offset(deq_op_ptr[i],
					pal_cry_op_status_t *,
					PAL_COP_METADATA_OFF_CBC_HMAC_SHA);
			new_st_ptr[i]->is_complete = 1;
			/* Check if operation was processed successfully */
			if (deq_op_ptr[i]->status !=
					RTE_CRYPTO_OP_STATUS_SUCCESS) {
				new_st_ptr[i]->is_successful = 0;
				printf("\nSome operations were not processed\n"
					"correctly err: %d, i = %d\n",
					deq_op_ptr[i]->status, i);
			} else {
				new_st_ptr[i]->is_successful = 1;
			}
		}
	}
	for (i = 0; i < numpipes; i++) {
		buf_ptr = rte_pktmbuf_mtod_offset(enq_op_ptr[i]->sym->m_src,
				char *, pal_ctx->tls_aad_len);
		memcpy(pal_ctx->output_buf[i], buf_ptr,
				pal_ctx->input_len[i]);
		rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
		enq_op_ptr[i]->sym->m_src = NULL;
	}
	rte_mempool_put_bulk(pools->sym_op_pool, (void **)enq_op_ptr, numpipes);

	pal_ctx->aad_cnt = 0;
	pal_ctx->numpipes = 0;

	free(enq_op_ptr);
	free(deq_op_ptr);
	free(new_st_ptr);
	free(status_ptr);

	enq_op_ptr = NULL;
	deq_op_ptr = NULL;
	new_st_ptr = NULL;
	status_ptr = NULL;

	return 1;
}
