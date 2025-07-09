/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include "cpt_engine.h"
#include "cpt_engine_cpoly.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

EVP_CIPHER *chacha20_poly1305;
static const unsigned char zero[2*CHACHA_BLK_SIZE] = { 0 };

static int cpt_engine_chacha20_poly1305_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *ch, const unsigned char *uch, int val);
static int cpt_engine_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx);
static int cpt_engine_chacha20_poly1305_cipher(EVP_CIPHER_CTX *ctx, unsigned char *ch,
		const unsigned char *ch1, size_t ln);
static int cpt_engine_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *c, int type,
		int arg, void *ptr);

extern uint16_t hw_offload_pktsz_thresh;

static int chacha_init_key(ossl_cpoly_ctx_t *cpolly_ctx,
			   const unsigned char user_key[CHACHA_KEY_SIZE],
			   const unsigned char iv[CHACHA_CTR_SIZE])
{
	EVP_CHACHA_AEAD_CTX *actx = cpolly_ctx->actx;
	EVP_CHACHA_KEY *key = (EVP_CHACHA_KEY*)&actx->key;

	unsigned int i;

	if (user_key)
		for (i = 0; i < CHACHA_KEY_SIZE; i+=4) {
			key->key.d[i/4] = CHACHA_U8TOU32(user_key+i);
		}

	if (iv)
		for (i = 0; i < CHACHA_CTR_SIZE; i+=4) {
			key->counter[i/4] = CHACHA_U8TOU32(iv+i);
		}

	key->partial_len = 0;

	return 1;
}

static inline int
chacha20_poly1305_create_session(ossl_cpoly_ctx_t *cpolly_ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv)
{
  pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;

	cpolly_ctx->actx->len.aad = 0;
	cpolly_ctx->actx->len.text = 0;
	cpolly_ctx->actx->aad = 0;
	cpolly_ctx->actx->mac_inited = 0;
	cpolly_ctx->actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

	if (key != NULL) {

		pal_ctx->key_len = PAL_CPOLY_KEY_LEN;
		memcpy(pal_ctx->key, key, PAL_CPOLY_KEY_LEN);
		pal_ctx->auth_taglen = PAL_CPOLY_AEAD_DIGEST_LEN;
		pal_ctx->aad_len = EVP_AEAD_TLS1_AAD_LEN;
		pal_ctx->numpipes = 0;
		int retval = pal_create_cpoly_aead_session(
				pal_ctx, pal_ctx->aad_len, 0);
		if (retval < 0) {
			engine_log(ENG_LOG_ERR, "AEAD Sesion creation failed.\n");
			return 0;
		}

	}
	if (iv != NULL) {
		memcpy (pal_ctx->iv, iv, PAL_CPOLY_IV_LEN);
		unsigned char temp[CHACHA_CTR_SIZE] = { 0 };

		/* pad on the left */
		if (cpolly_ctx->actx->nonce_len <= CHACHA_CTR_SIZE)
			memcpy(temp + CHACHA_CTR_SIZE - cpolly_ctx->actx->nonce_len, iv,
					cpolly_ctx->actx->nonce_len);

		chacha_init_key(cpolly_ctx, key, temp);

		cpolly_ctx->actx->nonce[0] = cpolly_ctx->actx->key.counter[1];
		cpolly_ctx->actx->nonce[1] = cpolly_ctx->actx->key.counter[2];
		cpolly_ctx->actx->nonce[2] = cpolly_ctx->actx->key.counter[3];

	} else {
		chacha_init_key(cpolly_ctx, key, NULL);
	}

  return 1;
}

static int cpt_engine_chacha20_poly1305_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *key, const unsigned char *iv, int enc)
{
	unsigned int thread_id = pal_get_thread_id();
	ossl_cpoly_ctx_t *cpolly_ctx =
			(ossl_cpoly_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
  pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;

	if (iv == NULL && key == NULL)
		return 1;

	if (thread_id == LCORE_ID_ANY || sym_dev_id[thread_id] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for thread_id %d\n",
			__FUNCTION__, thread_id);
		return 0;
	}

	pal_ctx->dev_id = sym_dev_id[thread_id];
  pal_ctx->enc = enc;
  pal_ctx->tls_tag_len = EVP_CHACHAPOLY_TLS_TAG_LEN;
  pal_ctx->async_cb = ossl_handle_async_job;

  return chacha20_poly1305_create_session(cpolly_ctx, key, iv);
}

static int cpt_engine_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	int i;
	ossl_cpoly_ctx_t *cpolly_ctx = EVP_CIPHER_CTX_get_cipher_data(c);
  pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;
	int enc = EVP_CIPHER_CTX_encrypting(c);
	int ret = 0;

	switch (type) {
	case EVP_CTRL_INIT:
		memset(cpolly_ctx, 0, sizeof(ossl_cpoly_ctx_t));
		pal_ctx->iv_len = EVP_CIPHER_CTX_iv_length(c);
		memcpy(pal_ctx->iv, EVP_CIPHER_CTX_iv_noconst(c), pal_ctx->iv_len);
		pal_ctx->auth_taglen = -1;
		pal_ctx->aad_len = -1;
		pal_ctx->tls_aad_len = -1;
		pal_ctx->hw_offload_pkt_sz_threshold = hw_offload_pktsz_thresh;
		if (cpolly_ctx->actx == NULL)
			cpolly_ctx->actx =
				OPENSSL_zalloc(sizeof(EVP_CHACHA_AEAD_CTX) +
						Poly1305_ctx_size());
		if (cpolly_ctx->actx == NULL) {
			engine_log(ENG_LOG_ERR, "EVP_F_CHACHA20_POLY1305_CTRL, "
					"EVP_R_INITIALIZATION_ERROR \n");
			return 0;
		}
		cpolly_ctx->actx->len.aad = 0;
		cpolly_ctx->actx->len.text = 0;
		cpolly_ctx->actx->aad = 0;
		cpolly_ctx->actx->mac_inited = 0;
		cpolly_ctx->actx->tag_len = 0;
		cpolly_ctx->actx->nonce_len = 12;
		cpolly_ctx->actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
		memset(cpolly_ctx->actx->tls_aad, 0, POLY1305_BLOCK_SIZE);

		return 1;
	case EVP_CTRL_AEAD_SET_IVLEN:
		if (arg <= 0)
			return 0;
		if ((arg > EVP_MAX_IV_LENGTH) && (arg > pal_ctx->iv_len)) {
			if (pal_ctx->iv == NULL) {
				engine_log(ENG_LOG_INFO, "pal_ctx->iv is null\n");
				return 0;
			}
		}
		pal_ctx->iv_len = arg;
		cpolly_ctx->actx->nonce_len = arg;
		return 1;
	case EVP_CTRL_AEAD_SET_IV_FIXED:
		if (arg != 12)
			return 0;
		cpolly_ctx->actx->nonce[0] = cpolly_ctx->actx->key.counter[1]
			= CHACHA_U8TOU32((unsigned char *)ptr);
		cpolly_ctx->actx->nonce[1] = cpolly_ctx->actx->key.counter[2]
			= CHACHA_U8TOU32((unsigned char *)ptr+4);
		cpolly_ctx->actx->nonce[2] =cpolly_ctx->actx->key.counter[3]
			= CHACHA_U8TOU32((unsigned char *)ptr+8);
		return 1;

	case EVP_CTRL_AEAD_SET_TAG:
		if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(c) || ptr == NULL)
			return 0;
		memcpy(pal_ctx->auth_tag, ptr, arg);
		memcpy(cpolly_ctx->actx->tag, ptr, arg);
		pal_ctx->auth_taglen = arg;
		cpolly_ctx->actx->tag_len = arg;
		return 1;
	case EVP_CTRL_AEAD_GET_TAG:
		if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(c) ||
				((pal_ctx->auth_taglen < 0) && (cpolly_ctx->actx->tag_len < 0)))
			return 0;
		memcpy(ptr, pal_ctx->auth_tag, arg);
		return 1;
	case EVP_CTRL_AEAD_TLS1_AAD:
		/* Save AAD for later use */
		if (arg != EVP_AEAD_TLS1_AAD_LEN)
			return 0;
		unsigned char *aad = ptr;

		memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
		memcpy(cpolly_ctx->actx->tls_aad, ptr, EVP_AEAD_TLS1_AAD_LEN);
		aad = cpolly_ctx->actx->tls_aad;
		/* Save sequence number for IV update */
		for (i = 0; i < 8; i++) {
			pal_ctx->seq_num[pal_ctx->aad_cnt][i] =
							((uint8_t *)ptr)[i];
		}
		pal_ctx->tls_aad_len = arg;
		unsigned int len = EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8 |
						EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
		if (!EVP_CIPHER_CTX_encrypting(c)) {
			if (len < PAL_CPOLY_AEAD_DIGEST_LEN)
				return -1;
			len -= PAL_CPOLY_AEAD_DIGEST_LEN;
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = (len >> 8) & 0xFF;
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xFF;
			aad[arg - 2] = (len >> 8) & 0xFF;
			aad[arg - 1] = len & 0xFF;
		}
		cpolly_ctx->actx->tls_payload_length = len;
		if (pal_ctx->aad_cnt < SSL_MAX_PIPELINES) {
			memcpy(pal_ctx->aad_pipe[pal_ctx->aad_cnt],
				EVP_CIPHER_CTX_buf_noconst(c), arg);
			pal_ctx->aad_cnt++;
		}
		/*
		 * record sequence number is XORed with the IV as per RFC7905.
		 */
		cpolly_ctx->actx->key.counter[1] = cpolly_ctx->actx->nonce[0];
		cpolly_ctx->actx->key.counter[2] =
			cpolly_ctx->actx->nonce[1] ^ CHACHA_U8TOU32(aad);
		cpolly_ctx->actx->key.counter[3] =
			cpolly_ctx->actx->nonce[2] ^ CHACHA_U8TOU32(aad+4);
		cpolly_ctx->actx->mac_inited = 0;

		return PAL_CPOLY_AEAD_DIGEST_LEN;
	case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:
		pal_ctx->numpipes = arg;
		pal_ctx->output_buf = ptr;
		return 1;

	case EVP_CTRL_SET_PIPELINE_INPUT_BUFS:
		pal_ctx->numpipes = arg;
		pal_ctx->input_buf = ptr;
		return 1;

	case EVP_CTRL_SET_PIPELINE_INPUT_LENS:
		pal_ctx->numpipes = arg;
		pal_ctx->input_len = ptr;
		return 1;
	default:
		engine_log(ENG_LOG_INFO, "Default value = %d\n", type);
		return -1;
	}
}

/* sw_chacha20_poly1305_tls_cipher API is invoked if protocol version is TLS1.2
 * and data(PT/CT) len is less than hw_offload_pkt_sz_threshold
 * This API will use Chachapoly ARMv8 implementation for doing the operation.
 */
static int sw_chacha20_poly1305_tls_cipher(ossl_cpoly_ctx_t *cpolly_ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	EVP_CHACHA_AEAD_CTX *actx = (EVP_CHACHA_AEAD_CTX *)cpolly_ctx->actx;
  pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;
	size_t tail, tohash_len, buf_len, plen = actx->tls_payload_length;
	unsigned char *buf, *tohash, *ctr, storage[sizeof(zero) + 32];
	int enc = pal_ctx->enc;

	if (len != plen + POLY1305_BLOCK_SIZE)
		return -1;

	buf = storage + ((0 - (size_t)storage) & 15);   /* align */
	ctr = buf + CHACHA_BLK_SIZE;
	tohash = buf + CHACHA_BLK_SIZE - POLY1305_BLOCK_SIZE;

	if (plen <= CHACHA_BLK_SIZE) {
		size_t i;

		actx->key.counter[0] = 0;
		ChaCha20_ctr32(buf, zero, (buf_len = 2 * CHACHA_BLK_SIZE),
				actx->key.key.d, actx->key.counter);
		Poly1305_Init(POLY1305_ctx(actx), buf);
		actx->key.partial_len = 0;
		memcpy(tohash, actx->tls_aad, POLY1305_BLOCK_SIZE);
		tohash_len = POLY1305_BLOCK_SIZE;
		actx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
		actx->len.text = plen;

		if (enc) {
			for (i = 0; i < plen; i++) {
				out[i] = ctr[i] ^= in[i];
			}
		} else {
			for (i = 0; i < plen; i++) {
				unsigned char c = in[i];
				out[i] = ctr[i] ^ c;
				ctr[i] = c;
			}
		}

		in += i;
		out += i;

		tail = (0 - i) & (POLY1305_BLOCK_SIZE - 1);
		memset(ctr + i, 0, tail);
		ctr += i + tail;
		tohash_len += i + tail;
	} else {
		actx->key.counter[0] = 0;
		ChaCha20_ctr32(buf, zero, (buf_len = CHACHA_BLK_SIZE),
				actx->key.key.d, actx->key.counter);
		Poly1305_Init(POLY1305_ctx(actx), buf);
		actx->key.counter[0] = 1;
		actx->key.partial_len = 0;
		Poly1305_Update(POLY1305_ctx(actx), actx->tls_aad, POLY1305_BLOCK_SIZE);
		tohash = ctr;
		tohash_len = 0;
		actx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
		actx->len.text = plen;

		if (enc) {
			ChaCha20_ctr32(out, in, plen, actx->key.key.d, actx->key.counter);
			Poly1305_Update(POLY1305_ctx(actx), out, plen);
		} else {
			Poly1305_Update(POLY1305_ctx(actx), in, plen);
			ChaCha20_ctr32(out, in, plen, actx->key.key.d, actx->key.counter);
		}

		in += plen;
		out += plen;
		tail = (0 - plen) & (POLY1305_BLOCK_SIZE - 1);
		Poly1305_Update(POLY1305_ctx(actx), zero, tail);
	}

	{
		const union {
			long one;
			char little;
		} is_endian = { 1 };

		if (is_endian.little) {
			memcpy(ctr, (unsigned char *)&actx->len, POLY1305_BLOCK_SIZE);
		} else {
			ctr[0]  = (unsigned char)(actx->len.aad);
			ctr[1]  = (unsigned char)(actx->len.aad>>8);
			ctr[2]  = (unsigned char)(actx->len.aad>>16);
			ctr[3]  = (unsigned char)(actx->len.aad>>24);
			ctr[4]  = (unsigned char)(actx->len.aad>>32);
			ctr[5]  = (unsigned char)(actx->len.aad>>40);
			ctr[6]  = (unsigned char)(actx->len.aad>>48);
			ctr[7]  = (unsigned char)(actx->len.aad>>56);

			ctr[8]  = (unsigned char)(actx->len.text);
			ctr[9]  = (unsigned char)(actx->len.text>>8);
			ctr[10] = (unsigned char)(actx->len.text>>16);
			ctr[11] = (unsigned char)(actx->len.text>>24);
			ctr[12] = (unsigned char)(actx->len.text>>32);
			ctr[13] = (unsigned char)(actx->len.text>>40);
			ctr[14] = (unsigned char)(actx->len.text>>48);
			ctr[15] = (unsigned char)(actx->len.text>>56);
		}
		tohash_len += POLY1305_BLOCK_SIZE;
	}

	Poly1305_Update(POLY1305_ctx(actx), tohash, tohash_len);
	OPENSSL_cleanse(buf, buf_len);
	Poly1305_Final(POLY1305_ctx(actx), enc ? actx->tag
			: tohash);

	actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

	if (enc) {
		memcpy(out, actx->tag, POLY1305_BLOCK_SIZE);
	} else {
		if (CRYPTO_memcmp(tohash, in, POLY1305_BLOCK_SIZE)) {
			memset(out - (len - POLY1305_BLOCK_SIZE), 0,
					len - POLY1305_BLOCK_SIZE);
			return -1;
		}
	}

	return len;
}

static int chacha_cipher(ossl_cpoly_ctx_t *cpolly_ctx, unsigned char *out,
			const unsigned char *inp, size_t len)
{
	EVP_CHACHA_KEY *key = (EVP_CHACHA_KEY*)(&cpolly_ctx->actx->key);
	unsigned int n, rem, ctr32;

	if ((n = key->partial_len)) {
		while (len && n < CHACHA_BLK_SIZE) {
			*out++ = *inp++ ^ key->buf[n++];
			len--;
		}
		key->partial_len = n;

		if (len == 0)
			return 1;

		if (n == CHACHA_BLK_SIZE) {
			key->partial_len = 0;
			key->counter[0]++;
			if (key->counter[0] == 0)
				key->counter[1]++;
		}
	}

	rem = (unsigned int)(len % CHACHA_BLK_SIZE);
	len -= rem;
	ctr32 = key->counter[0];
	while (len >= CHACHA_BLK_SIZE) {
		size_t blocks = len / CHACHA_BLK_SIZE;
		/*
		 * 1<<28 is just a not-so-small yet not-so-large number...
		 * Below condition is practically never met, but it has to
		 * be checked for code correctness.
		 */
		if (sizeof(size_t)>sizeof(unsigned int) && blocks>(1U<<28))
			blocks = (1U<<28);

		/*
		 * As ChaCha20_ctr32 operates on 32-bit counter, caller
		 * has to handle overflow. 'if' below detects the
		 * overflow, which is then handled by limiting the
		 * amount of blocks to the exact overflow point...
		 */
		ctr32 += (unsigned int)blocks;
		if (ctr32 < blocks) {
			blocks -= ctr32;
			ctr32 = 0;
		}
		blocks *= CHACHA_BLK_SIZE;
		ChaCha20_ctr32(out, inp, blocks, key->key.d, key->counter);
		len -= blocks;
		inp += blocks;
		out += blocks;

		key->counter[0] = ctr32;
		if (ctr32 == 0) key->counter[1]++;
	}

	if (rem) {
		memset(key->buf, 0, sizeof(key->buf));
		ChaCha20_ctr32(key->buf, key->buf, CHACHA_BLK_SIZE,
				key->key.d, key->counter);
		for (n = 0; n < rem; n++)
			out[n] = inp[n] ^ key->buf[n];
		key->partial_len = rem;
	}

	return 1;
}

static inline void cpoly_mac_init(EVP_CHACHA_AEAD_CTX *actx)
{
	size_t plen = actx->tls_payload_length;

	actx->key.counter[0] = 0;
	ChaCha20_ctr32(actx->key.buf, zero, CHACHA_BLK_SIZE,
			actx->key.key.d, actx->key.counter);
	Poly1305_Init(POLY1305_ctx(actx), actx->key.buf);
	actx->key.counter[0] = 1;
	actx->key.partial_len = 0;
	actx->len.aad = actx->len.text = 0;
	actx->mac_inited = 1;
	if (plen != NO_TLS_PAYLOAD_LENGTH) {
		Poly1305_Update(POLY1305_ctx(actx), actx->tls_aad,
				EVP_AEAD_TLS1_AAD_LEN);
		actx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
		actx->aad = 1;
	}
}

static inline int
cpt_engine_chacha20_poly1305_both_crypto_tls_1_3(ossl_cpoly_ctx_t *cpolly_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, unsigned char *buf, ASYNC_WAIT_CTX *wctx )
{
  static int sw_cpoly_encrypt = 0, sw_cpoly_decrypt = 0;
	EVP_CHACHA_AEAD_CTX *actx = cpolly_ctx->actx;
  pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;
	size_t rem, plen = actx->tls_payload_length;
	int enc = pal_ctx->enc;

  if (in != NULL) {
      if (len < pal_ctx->hw_offload_pkt_sz_threshold) {

        if (!actx->mac_inited)
          cpoly_mac_init(actx);
        if (actx->aad) {                    /* wrap up aad */
          if ((rem = (size_t)actx->len.aad % POLY1305_BLOCK_SIZE))
            Poly1305_Update(POLY1305_ctx(actx), zero,
                POLY1305_BLOCK_SIZE - rem);
          actx->aad = 0;
        }

        actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
        if (plen == NO_TLS_PAYLOAD_LENGTH)
          plen = len;
        else if (len != plen + POLY1305_BLOCK_SIZE)
          return -1;

        if (enc) {                 /* plaintext */
          chacha_cipher(cpolly_ctx, out, in, plen);
          Poly1305_Update(POLY1305_ctx(actx), out, plen);
          in += plen;
          out += plen;
          actx->len.text += plen;
          sw_cpoly_encrypt = 1;
        } else {                            /* ciphertext */
          Poly1305_Update(POLY1305_ctx(actx), in, plen);
          chacha_cipher(cpolly_ctx, out, in, plen);
          in += plen;
          out += plen;
          actx->len.text += plen;
          sw_cpoly_decrypt = 1;
        }
        return len;
      }
  }
  if (((in == NULL) || (plen != len)) && (sw_cpoly_decrypt || sw_cpoly_encrypt)) {
    const union {
      long one;
      char little;
    } is_endian = { 1 };
    unsigned char temp[POLY1305_BLOCK_SIZE];

    if (actx->aad) {                        /* wrap up aad */
      if ((rem = (size_t)actx->len.aad % POLY1305_BLOCK_SIZE))
        Poly1305_Update(POLY1305_ctx(actx), zero,
            POLY1305_BLOCK_SIZE - rem);
      actx->aad = 0;
    }

    if ((rem = (size_t)actx->len.text % POLY1305_BLOCK_SIZE))
      Poly1305_Update(POLY1305_ctx(actx), zero,
          POLY1305_BLOCK_SIZE - rem);

    if (is_endian.little) {
      Poly1305_Update(POLY1305_ctx(actx),
          (unsigned char *)&actx->len, POLY1305_BLOCK_SIZE);
    } else {
      temp[0]  = (unsigned char)(actx->len.aad);
      temp[1]  = (unsigned char)(actx->len.aad>>8);
      temp[2]  = (unsigned char)(actx->len.aad>>16);
      temp[3]  = (unsigned char)(actx->len.aad>>24);
      temp[4]  = (unsigned char)(actx->len.aad>>32);
      temp[5]  = (unsigned char)(actx->len.aad>>40);
      temp[6]  = (unsigned char)(actx->len.aad>>48);
      temp[7]  = (unsigned char)(actx->len.aad>>56);
      temp[8]  = (unsigned char)(actx->len.text);
      temp[9]  = (unsigned char)(actx->len.text>>8);
      temp[10] = (unsigned char)(actx->len.text>>16);
      temp[11] = (unsigned char)(actx->len.text>>24);
      temp[12] = (unsigned char)(actx->len.text>>32);
      temp[13] = (unsigned char)(actx->len.text>>40);
      temp[14] = (unsigned char)(actx->len.text>>48);
      temp[15] = (unsigned char)(actx->len.text>>56);

      Poly1305_Update(POLY1305_ctx(actx), temp, POLY1305_BLOCK_SIZE);
    }
    Poly1305_Final(POLY1305_ctx(actx), enc ? actx->tag
        : temp);
    if (enc) {
      memcpy(pal_ctx->auth_tag, actx->tag, POLY1305_BLOCK_SIZE);
      sw_cpoly_encrypt = 0;
    } else {
      memcpy(pal_ctx->auth_tag, temp, POLY1305_BLOCK_SIZE);
      sw_cpoly_decrypt = 0;
    }
    actx->mac_inited = 0;

    if (in != NULL && len != plen) {        /* tls mode */
      if (enc) {
        memcpy(out, actx->tag, POLY1305_BLOCK_SIZE);
        memcpy(pal_ctx->auth_tag, actx->tag, POLY1305_BLOCK_SIZE);
        sw_cpoly_encrypt = 0;
      } else {
        if (CRYPTO_memcmp(temp, in, POLY1305_BLOCK_SIZE)) {
          memset(out - plen, 0, plen);
          return -1;
        }
        sw_cpoly_decrypt = 0;
      }
    } else if ((!enc) && sw_cpoly_decrypt) {
      if (CRYPTO_memcmp(temp, actx->tag, actx->tag_len))
        return -1;
      sw_cpoly_decrypt = 0;

    }
    return len;
  }
  if ((in == NULL)) {
    if ((!enc) && !sw_cpoly_decrypt) {
      if (pal_ctx->auth_taglen < 0)
        return -1;
      memcpy(pal_ctx->auth_tag, buf, PAL_CPOLY_AEAD_DIGEST_LEN);
      return 0;
    }
    if ((enc) && (!sw_cpoly_encrypt)) {
      memcpy(pal_ctx->auth_tag, buf, PAL_CPOLY_AEAD_DIGEST_LEN);
      pal_ctx->auth_taglen = PAL_CPOLY_AEAD_DIGEST_LEN;
    }
    return 0;
  }

  if(cpolly_ctx->is_tlsv_1_3)
    return pal_chacha20_poly1305_tls_1_3_crypto(pal_ctx, out, in, len, sym_queue, buf, wctx);
  else
     return pal_chacha20_poly1305_non_tls_crypto(pal_ctx, out, in, len, sym_queue, buf);
}

static inline int
cpoly_update_aad_create_aead_session(ossl_cpoly_ctx_t *cpolly_ctx, const unsigned char *in,
                                size_t len)
{
     int ret;
     uint16_t *tls_ver;
     EVP_CHACHA_AEAD_CTX *actx = cpolly_ctx->actx;
     pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;

      if (!actx->mac_inited)
        cpoly_mac_init(actx);

      Poly1305_Update(POLY1305_ctx(actx), in, len);
      actx->len.aad += len;
      actx->aad = 1;
      tls_ver = (uint16_t *) (in+1);

    if( *tls_ver>= TLS1_2_VERSION)
    cpolly_ctx->is_tlsv_1_3 = 1;

      memcpy(pal_ctx->aad, in, len);
      if (((size_t)pal_ctx->aad_len != len)) {
        int ret = pal_create_cpoly_aead_session(pal_ctx, len, 1);
        if (ret < 0)
          return ret;
        pal_ctx->aad_len = len;
      }
      return len;
}

static int
cpt_engine_chacha20_poly1305_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		                                const unsigned char *in, size_t len)
{
	int ret = 0;
	ASYNC_JOB *job = NULL;
	ASYNC_WAIT_CTX *wctx = NULL;
  int queue = sym_queues[pal_get_thread_id()];
	ossl_cpoly_ctx_t *cpolly_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
  pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;
  unsigned char * buf = EVP_CIPHER_CTX_buf_noconst(ctx);
	uint16_t datalen = (uint16_t)(len - EVP_CHACHAPOLY_TLS_TAG_LEN);

	/* Bydefault number of pipe is one */
	if (pal_ctx->numpipes == 0) {
		pal_ctx->numpipes = 1;
		pal_ctx->input_len = malloc(sizeof(int));
		pal_ctx->input_len[0] = len;
		pal_ctx->output_buf = &out;
		/* As it's inplace */
		pal_ctx->input_buf = &out;
	}

	job = ASYNC_get_current_job();
	if (job != NULL)
		wctx = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

  if (pal_ctx->tls_aad_len >= 0) {

    if ((in != out) || (len < EVP_CHACHAPOLY_TLS_TAG_LEN))
      return -1;

    if ((datalen < pal_ctx->hw_offload_pkt_sz_threshold) && (pal_ctx->numpipes == 1)) {
      ret = sw_chacha20_poly1305_tls_cipher(cpolly_ctx, out, in, len);
      pal_ctx->numpipes = 0;
      pal_ctx->aad_cnt = 0;
      return ret;
    }

    ret = pal_chacha20_poly1305_tls_cipher(pal_ctx, out, in, len, queue, wctx);
    if (ret < 0)
        return -1;
    else
        return 1;
  }

  if (in != NULL && out == NULL)
         return cpoly_update_aad_create_aead_session(cpolly_ctx, in, len);

    ret = cpt_engine_chacha20_poly1305_both_crypto_tls_1_3(cpolly_ctx, out, in, len, queue, buf, wctx);

	if (ret < 0)
		return -1;
	return ret;
}

static int cpt_engine_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx)
{
  int retval;

  ossl_cpoly_ctx_t *cpolly_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
  if (cpolly_ctx == NULL)
    return 0;

  pal_cpoly_ctx_t *pal_ctx = &cpolly_ctx->pal_ctx;

  pal_sym_session_cpoly_cleanup(pal_ctx);

  if (cpolly_ctx->actx)
    OPENSSL_free(cpolly_ctx->actx);

  pal_ctx->cry_session =  NULL;

  return 1;
}

const EVP_CIPHER *cpt_engine_chacha20_poly1305(void)
{
	if (chacha20_poly1305 != NULL)
		return chacha20_poly1305;

	chacha20_poly1305 = EVP_CIPHER_meth_new(NID_chacha20_poly1305,
			PAL_CPOLY_BLOCK_SIZE, PAL_CPOLY_KEY_LEN);

	EVP_CIPHER_meth_set_iv_length (chacha20_poly1305,
			PAL_CPOLY_IV_LEN);
	EVP_CIPHER_meth_set_init (chacha20_poly1305,
			cpt_engine_chacha20_poly1305_init_key);
	EVP_CIPHER_meth_set_do_cipher (chacha20_poly1305,
			cpt_engine_chacha20_poly1305_cipher);
	EVP_CIPHER_meth_set_cleanup (chacha20_poly1305,
			cpt_engine_chacha20_poly1305_cleanup);
	EVP_CIPHER_meth_set_ctrl(chacha20_poly1305,
			cpt_engine_chacha20_poly1305_ctrl);
	EVP_CIPHER_meth_set_flags(chacha20_poly1305, CPOLY_FLAGS);
	EVP_CIPHER_meth_set_impl_ctx_size (chacha20_poly1305,
			sizeof(ossl_cpoly_ctx_t));

	return chacha20_poly1305;
}
