/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "cpt_engine.h"
#include "cpt_engine_gcm.h"

#define AES_GCM_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
						| EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT \
						| EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY \
						| EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_GCM_MODE \
						| EVP_CIPH_FLAG_PIPELINE | EVP_CIPH_CUSTOM_IV_LENGTH )

extern uint16_t hw_offload_pktsz_thresh;
extern int cpt_num_cipher_pipeline_requests_in_flight;
/* AES-GCM */
static int cpt_engine_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx,
				       const unsigned char *key,
				       const unsigned char *iv, int enc);
static int cpt_engine_aes256_gcm_init_key(EVP_CIPHER_CTX *ctx,
				       const unsigned char *key,
				       const unsigned char *iv, int enc);

static int cpt_engine_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				  const unsigned char *in, size_t inl);
static int cpt_engine_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx);
static int cpt_engine_aes_gcm_init_key(EVP_CIPHER_CTX *ctx,
				    const unsigned char *key,
				    const unsigned char *iv, int enc,
				    int key_len);
static int cpt_engine_aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);
static int ossl_aes_gcm_ctx_control(void *ctx, int type, int arg, void *ptr);

EVP_CIPHER *_hidden_aes_128_gcm = NULL;
EVP_CIPHER *_hidden_aes_256_gcm = NULL;

const EVP_CIPHER *cpt_engine_aes_128_gcm(void)
{
	if (_hidden_aes_128_gcm != NULL)
		return _hidden_aes_128_gcm;

	_hidden_aes_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm,
					1, PAL_AES128_GCM_KEY_LENGTH);

	if (!EVP_CIPHER_meth_set_iv_length (_hidden_aes_128_gcm,
						PAL_AES_GCM_IV_LENGTH) ||
		!EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm,
				      cpt_engine_aes128_gcm_init_key) ||
	    !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm,
					   cpt_engine_aes_gcm_cipher) ||
	    !EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_gcm,
					 cpt_engine_aes_gcm_cleanup) ||
	    !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm, cpt_engine_aes_gcm_ctrl) ||
		!EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS) ||
	    !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm,
					       sizeof(ossl_gcm_ctx_t))) {
		EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
		_hidden_aes_128_gcm = NULL;
	}
	return _hidden_aes_128_gcm;
}

const EVP_CIPHER *cpt_engine_aes_256_gcm(void)
{
	if (_hidden_aes_256_gcm != NULL)
		return _hidden_aes_256_gcm;

	_hidden_aes_256_gcm = EVP_CIPHER_meth_new(NID_aes_256_gcm,
					1, PAL_AES256_GCM_KEY_LENGTH);

	if (!EVP_CIPHER_meth_set_iv_length (_hidden_aes_256_gcm,
						PAL_AES_GCM_IV_LENGTH) ||
		!EVP_CIPHER_meth_set_init(_hidden_aes_256_gcm,
				      cpt_engine_aes256_gcm_init_key) ||
	    !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_gcm,
					   cpt_engine_aes_gcm_cipher) ||
	    !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_gcm,
					 cpt_engine_aes_gcm_cleanup) ||
	    !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_gcm, cpt_engine_aes_gcm_ctrl) ||
		!EVP_CIPHER_meth_set_flags(_hidden_aes_256_gcm, AES_GCM_FLAGS) ||
	    !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_gcm,
					       sizeof(ossl_gcm_ctx_t))) {
		EVP_CIPHER_meth_free(_hidden_aes_256_gcm);
		_hidden_aes_256_gcm = NULL;
	}
	return _hidden_aes_256_gcm;
}

static inline int
engine_aes_gcm_session_create(ossl_gcm_ctx_t *gcm_ctx,
                             const unsigned char *key,
			                       const unsigned char *iv,
                             int key_len)
{
  int retval  = 0;
  pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;

	if (iv == NULL && key == NULL)
		return 1;

	if (key != NULL) {
		pal_ctx->keylen = key_len;
		memcpy(pal_ctx->key, key, key_len);
		gcm_ctx->key_set = 1;

		ARMv8_AES_set_encrypt_key(key, key_len * 8, &gcm_ctx->ks.ks);
		CRYPTO_gcm128_init(&gcm_ctx->gcm, &gcm_ctx->ks, (block128_f) ARMv8_AES_encrypt);
		gcm_ctx->ctr = (ctr128_f) ARMv8_AES_ctr32_encrypt_blocks;

		retval = pal_create_aead_session(PAL_CRYPTO_AEAD_AES_GCM,
						pal_ctx, EVP_AEAD_TLS1_AAD_LEN, 0);
		if (retval < 0) {
			engine_log(ENG_LOG_ERR, "AEAD Sesion creation failed.\n");
			return 0;
		}

		retval = pal_create_cipher_session(PAL_CRYPTO_CIPHER_AES_CTR,
						pal_ctx);
		if (retval < 0) {
			engine_log(ENG_LOG_ERR, "Cipher Sesion creation failed.\n");
			return 0;
		}
		if (iv == NULL && gcm_ctx->iv_set)
			iv = (const unsigned char*)&pal_ctx->iv;
		if (iv) {
			CRYPTO_gcm128_setiv(&gcm_ctx->gcm, iv, pal_ctx->ivlen);
			memcpy(pal_ctx->iv, iv, pal_ctx->ivlen);
			gcm_ctx->iv_set = 1;
		}
	} else {
		if (gcm_ctx->key_set)
			CRYPTO_gcm128_setiv(&gcm_ctx->gcm, iv, pal_ctx->ivlen);
		memcpy(pal_ctx->iv, iv, pal_ctx->ivlen);
		gcm_ctx->iv_set = 1;
		gcm_ctx->iv_gen = 0;
	}

	pal_ctx->numpipes = 0;
	return 1;
}

int cpt_engine_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
				const unsigned char *iv, int key_len)
{
  unsigned int thread_id = pal_get_thread_id();
	ossl_gcm_ctx_t *gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
  pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;


  if (thread_id == -1 || sym_dev_id[thread_id] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for thread_id %d\n",
			__FUNCTION__, thread_id);
		return 0;
	}
	pal_ctx->dev_id = sym_dev_id[thread_id];

  pal_ctx->enc = EVP_CIPHER_CTX_encrypting(ctx);
  pal_ctx->iv_cb = ossl_aes_gcm_ctx_control;
  pal_ctx->async_cb = ossl_handle_async_job;
  pal_ctx->tls_exp_iv_len = EVP_GCM_TLS_EXPLICIT_IV_LEN;
  pal_ctx->tls_tag_len = EVP_GCM_TLS_TAG_LEN;

	return engine_aes_gcm_session_create(gcm_ctx, key, iv, key_len);
}

int cpt_engine_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
				const unsigned char *iv, int enc)
{
	return cpt_engine_gcm_init_key(ctx, key, iv, PAL_AES128_GCM_KEY_LENGTH);
}

int cpt_engine_aes256_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
				const unsigned char *iv, int enc)
{
	return cpt_engine_gcm_init_key(ctx, key, iv, PAL_AES256_GCM_KEY_LENGTH);
}

/*
 * GCM ctrl function
 */

int cpt_engine_aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	ossl_gcm_ctx_t *gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(c);
  pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;
	unsigned char *buf;

	switch (type) {
	case EVP_CTRL_INIT:
		memset(gcm_ctx, 0, sizeof(ossl_gcm_ctx_t));
		gcm_ctx->key_set = 0;
		gcm_ctx->iv_set = 0;
		pal_ctx->ivlen = PAL_AES_GCM_IV_LENGTH;
		memcpy(pal_ctx->iv, EVP_CIPHER_CTX_iv_noconst(c),
		       pal_ctx->ivlen);
		gcm_ctx->taglen = -1;
		pal_ctx->aad_len = -1;
		gcm_ctx->iv_gen = 0;
		pal_ctx->tls_aad_len = -1;
		pal_ctx->hw_off_pkt_sz_thrsh = hw_offload_pktsz_thresh;

		return 1;

	//! Below control cmd added in openssl-1.1.1g version
	#if OPENSSL_VERSION_NUMBER >= 0x1010107fL
	case EVP_CTRL_GET_IVLEN:
		*(int *)ptr = pal_ctx->ivlen;
		return 1;
	#endif

	case EVP_CTRL_AEAD_SET_IVLEN:
		if (arg <= 0)
			return 0;
		/* Allocate memory for IV if needed */
		if ((arg > EVP_MAX_IV_LENGTH) && (arg > pal_ctx->ivlen)) {
			if (pal_ctx->iv == NULL)
				return 0;
		}
		pal_ctx->ivlen = arg;
		return 1;

	case EVP_CTRL_GCM_SET_IV_FIXED:
		/* Special case: -1 length restores whole IV */
		if (arg == -1) {
			memcpy(pal_ctx->iv, ptr, pal_ctx->ivlen - arg);
			gcm_ctx->iv_gen = 1;
			return 1;
		}
		/*
		 * Fixed field must be at least 4 bytes and invocation field
		 * at least 8.
		 */
		if ((arg < 4) || (pal_ctx->ivlen - arg) < 8)
			return 0;
		if (arg)
			memcpy((uint8_t *)pal_ctx->iv, ptr, arg);
		if (EVP_CIPHER_CTX_encrypting(c) &&
		    RAND_bytes((uint8_t *)&pal_ctx->iv[2],
			       pal_ctx->ivlen - arg) <= 0)
			return 0;
		gcm_ctx->iv_gen = 1;
		return 1;

	case EVP_CTRL_GCM_IV_GEN:
		if (gcm_ctx->iv_gen == 0 || gcm_ctx->key_set == 0)
			return 0;
		memcpy((uint8_t *)pal_ctx->iv + pal_ctx->ivlen - arg,
		       &pal_ctx->iv[2], arg);
		if (arg <= 0 || arg > pal_ctx->ivlen)
			arg = pal_ctx->ivlen;
		memcpy(ptr, &pal_ctx->iv[2], arg);
		CRYPTO_gcm128_setiv(&gcm_ctx->gcm,
				    (const uint8_t *)&pal_ctx->iv,
				    pal_ctx->ivlen);
		/*
		 * Invocation field will be at least 8 bytes in size and
		 * so no need to check wrap around or increment more than
		 * last 8 bytes.
		 */
		pal_ctx->iv[2]++;
		gcm_ctx->iv_set = 1;
		return 1;

	case EVP_CTRL_GCM_SET_IV_INV:
		if (gcm_ctx->iv_gen == 0 || gcm_ctx->key_set == 0 ||
		    EVP_CIPHER_CTX_encrypting(c))
			return 0;
		memcpy((uint8_t *)pal_ctx->iv + pal_ctx->ivlen - arg, ptr,
		       arg);
		CRYPTO_gcm128_setiv(&gcm_ctx->gcm,
				    (const uint8_t *)&pal_ctx->iv,
				    pal_ctx->ivlen);
		gcm_ctx->iv_set = 1;
		return 1;

	case EVP_CTRL_AEAD_TLS1_AAD:
		/* Save the AAD for later use */
		if (arg != EVP_AEAD_TLS1_AAD_LEN)
			return 0;
		memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
		pal_ctx->tls_aad_len = arg;
		{
			unsigned int len =
				EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8 |
				EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
			/* Correct length for explicit IV */
			if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
				return 0;
			len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
			/* If decrypting correct for tag too */
			if (!EVP_CIPHER_CTX_encrypting(c)) {
				if (len < EVP_GCM_TLS_TAG_LEN)
					return 0;
				len -= EVP_GCM_TLS_TAG_LEN;
			}
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
		}
		if (pal_ctx->aad_cnt < SSL_MAX_PIPELINES) {
			memcpy(pal_ctx->aad_pipe[pal_ctx->aad_cnt],
					EVP_CIPHER_CTX_buf_noconst(c), arg);
			pal_ctx->aad_cnt++;
		} else {
			engine_log(ENG_LOG_ERR, "In a single go, max. AAD count is 32\n");
			return 0;
		}

		/* Extra padding: tag appended to record */
		return EVP_GCM_TLS_TAG_LEN;

	case EVP_CTRL_AEAD_SET_TAG:
		if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(c))
			return 0;
		buf = EVP_CIPHER_CTX_buf_noconst(c);
		memcpy(pal_ctx->auth_tag, ptr, arg);
		memcpy(buf, ptr, arg);
		gcm_ctx->taglen = arg;
		return 1;

	case EVP_CTRL_AEAD_GET_TAG:
		if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(c) ||
		    gcm_ctx->taglen < 0)
			return 0;
		memcpy(ptr, pal_ctx->auth_tag, arg);
		return 1;

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
		return -1;
	}
}

int ossl_aes_gcm_ctx_control(void *ctx, int enc, int arg, void *ptr)
{

  int ret = 0;
  int type = enc ? EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV;

  if (EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx, type, arg, ptr) <= 0) {
    engine_log (ENG_LOG_ERR, "Failed to set IV from start of buffer\n");
    ret = -1;
  }

  return ret;
}


int
cpt_engine_sw_aes_gcm_tls_cipher(ossl_gcm_ctx_t *gcm_ctx, unsigned char *out,
		                              const unsigned char *in, size_t len,
                                  unsigned char *buf, EVP_CIPHER_CTX *ctx)
{
  int ret = 0;
  pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;

  if (EVP_CIPHER_CTX_ctrl(
        ctx, pal_ctx->enc ? EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
        EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0) {
    engine_log (ENG_LOG_ERR, "Failed to set IV from start of buffer\n");
    ret = -1;
    goto skip_free_buf;
  }
  if (CRYPTO_gcm128_aad(&gcm_ctx->gcm, buf, pal_ctx->tls_aad_len)) {
    engine_log (ENG_LOG_ERR, "Set AAD failed!!!\n");
    ret = -1;
    goto skip_free_buf;
  }
  /* Fix buffer and length to point to payload */
  in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
  out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
  len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
  if (pal_ctx->enc) {
    if (CRYPTO_gcm128_encrypt_ctr32(&gcm_ctx->gcm,
          in, out, len, gcm_ctx->ctr)) {
      engine_log (ENG_LOG_ERR, "ARM v8 Encrypt "
          "failed!!!\n");
      ret = -1;
      goto skip_free_buf;
    }
    out += len;
    /* Finally write tag */
    CRYPTO_gcm128_tag(&gcm_ctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
    ret = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
  } else {
    if (CRYPTO_gcm128_decrypt_ctr32(&gcm_ctx->gcm,
          in, out, len, gcm_ctx->ctr)) {
      engine_log (ENG_LOG_ERR, "ARM v8 Decrypt "
          "failed!!!\n");
      ret = -1;
      goto skip_free_buf;

    }/* Retrieve tag */
    CRYPTO_gcm128_tag(&gcm_ctx->gcm, buf,EVP_GCM_TLS_TAG_LEN);
    /* If tag mismatch wipe buffer */
    if (CRYPTO_memcmp(buf, in + len, EVP_GCM_TLS_TAG_LEN)) {
      OPENSSL_cleanse(out, len);
      engine_log (ENG_LOG_ERR, "TAG mismatch "
          "found!!!\n");
      ret = -1;
      goto skip_free_buf;
    }
    ret = len;

  }

skip_free_buf:
  pal_ctx->input_buf = NULL;
  pal_ctx->input_len = NULL;
  pal_ctx->output_buf = NULL;
  pal_ctx->aad_cnt = 0;
  pal_ctx->numpipes = 0;
  pal_ctx->tls_aad_len = -1;
  gcm_ctx->iv_set = 0;

  return ret;
}

static inline int
tls13_gcm_cipher(ossl_gcm_ctx_t *gcm_ctx, unsigned char *out,
			                            const unsigned char *in, size_t len,
                                  unsigned char *buf, ASYNC_WAIT_CTX *wctx)
{
  int ret = 0;
  static uint8_t sw_encrypt = 0, sw_decrypt = 0;
  pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;
  int enc = pal_ctx->enc;

  if (in != NULL) {
    if (enc) {
      if (len < pal_ctx->hw_off_pkt_sz_thrsh) {
        if (CRYPTO_gcm128_encrypt_ctr32(&gcm_ctx->gcm,
              in,
              out,
              len, gcm_ctx->ctr)) {
          pal_ctx->tls_aad_len = -1;
          pal_ctx->aad_len = -1;
          return -1;
        }
        sw_encrypt = 1;
        return len;
      }
    } else {
      if (len < pal_ctx->hw_off_pkt_sz_thrsh) {
        if (CRYPTO_gcm128_decrypt_ctr32(&gcm_ctx->gcm,
              in,
              out,
              len, gcm_ctx->ctr)) {
          pal_ctx->tls_aad_len = -1;
          pal_ctx->aad_len = -1;
          return -1;
        }
        sw_decrypt = 1;
        return len;
      }
    }
  } else {
    if (!enc) {
      if (gcm_ctx->taglen < 0)
        return -1;
      if (sw_decrypt) {
        ret = CRYPTO_gcm128_finish(&gcm_ctx->gcm, buf,
            gcm_ctx->taglen);
        if (ret != 0)
          return -1;
        sw_decrypt = 0;
      }
      memcpy(pal_ctx->auth_tag, buf, 16);
      gcm_ctx->iv_set = 0;
      return 0;
    }
    if (sw_encrypt) {
      CRYPTO_gcm128_tag(&gcm_ctx->gcm, buf, 16);
      sw_encrypt = 0;
    }
    memcpy(pal_ctx->auth_tag, buf, 16);
    gcm_ctx->taglen = 16;
    /* Don't reuse the IV */
    gcm_ctx->iv_set = 0;
    return 0;
  }

  ret = pal_crypto_gcm_tls_1_3_cipher(pal_ctx, out, in, len, buf, wctx);

	return ret;
}

static inline int
cpt_engine_crypto_gcm_non_tls_cipher(ossl_gcm_ctx_t *gcm_ctx, unsigned char *out,
                                        const unsigned char *in, size_t len,
                                  unsigned char *buf)
{
  int ret = 0;
  static uint8_t sw_encrypt = 0, sw_decrypt = 0;
  pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;
  int enc = pal_ctx->enc;

  if (in != NULL) {
    if (enc) {
      if (len < pal_ctx->hw_off_pkt_sz_thrsh) {
        if (CRYPTO_gcm128_encrypt_ctr32(&gcm_ctx->gcm,
              in,
              out,
              len, gcm_ctx->ctr)) {
          pal_ctx->tls_aad_len = -1;
          pal_ctx->aad_len = -1;
          return -1;
        }
        sw_encrypt = 1;
        return len;
      }
    } else {
      if (len < pal_ctx->hw_off_pkt_sz_thrsh) {
        if (CRYPTO_gcm128_decrypt_ctr32(&gcm_ctx->gcm,
              in,
              out,
              len, gcm_ctx->ctr)) {
          pal_ctx->tls_aad_len = -1;
          pal_ctx->aad_len = -1;
          return -1;
        }
        sw_decrypt = 1;
        return len;
      }
    }
  } else {
    if (!enc) {
      if (gcm_ctx->taglen < 0)
        return -1;
      if (sw_decrypt) {
        ret = CRYPTO_gcm128_finish(&gcm_ctx->gcm, buf,
            gcm_ctx->taglen);
        if (ret != 0)
          return -1;
        sw_decrypt = 0;
      }
      memcpy(pal_ctx->auth_tag, buf, 16);
      gcm_ctx->iv_set = 0;
      return 0;
    }
    if (sw_encrypt) {
      CRYPTO_gcm128_tag(&gcm_ctx->gcm, buf, 16);
      sw_encrypt = 0;
    }
    memcpy(pal_ctx->auth_tag, buf, 16);
    gcm_ctx->taglen = 16;
    /* Don't reuse the IV */
    gcm_ctx->iv_set = 0;
    return 0;
  }

  ret = pal_crypto_gcm_non_tls_cipher(pal_ctx, out, in, len, buf);

    return ret;
}

static inline int
aes_gcm_update_aad_create_aead_session(ossl_gcm_ctx_t *gcm_ctx, const unsigned char *in, size_t len)
{
    int ret;
    uint16_t *tls_ver;
    pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;

	tls_ver = (uint16_t *) (in+1);

	if( *tls_ver>= TLS1_2_VERSION)
		pal_ctx->is_tlsv_1_3 = 1;

      if (CRYPTO_gcm128_aad(&gcm_ctx->gcm, in, len))
        return -1;

      if (!pal_ctx->aad) {
          pal_ctx->aad =  pal_malloc(sizeof(uint8_t) * len);
          if (!pal_ctx->aad) {
            engine_log(ENG_LOG_ERR, "AAD memory alloc failed!!!\n");
            return -1;
          }
      }
      memcpy(pal_ctx->aad, in, len);
      if ((size_t)pal_ctx->aad_len != len) {
        ret = pal_create_aead_session(RTE_CRYPTO_AEAD_AES_GCM,
            pal_ctx, len, 1);
        if (ret < 0) {
          engine_log(ENG_LOG_ERR, "Create aead session "
              "failed\n");
          return ret;
        }
        pal_ctx->aad_len = len;
      }
      return len;
}

int cpt_engine_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			   const unsigned char *in, size_t len)
{
    int ret = 0;
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *wctx = NULL;
    int queue = sym_queues[pal_get_thread_id()];
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    ossl_gcm_ctx_t *gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;
    uint16_t datalen = (uint16_t)(len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN);

    /* If not set up, return error */
    if (!gcm_ctx->key_set)
        return -1;

    pal_ctx->enc = EVP_CIPHER_CTX_encrypting(ctx);
    pal_ctx->sym_queue = queue;
    job = ASYNC_get_current_job();
    if (job != NULL)
        wctx = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

    if (pal_ctx->tls_aad_len >= 0) {
        /* Bydefault number of pipe is one */
        if (pal_ctx->numpipes == 0) {
            pal_ctx->numpipes = 1;
            pal_ctx->input_buf = (uint8_t **)&in;
            pal_ctx->output_buf = &out;
            pal_ctx->input_len = &len;
        }

        /* Encrypt/decrypt must be performed in place */
        if (out != in ||
                len < (pal_ctx->tls_exp_iv_len + pal_ctx->tls_tag_len))
            return -1;

        if ((datalen < pal_ctx->hw_off_pkt_sz_thrsh) && (pal_ctx->numpipes == 1)) {
            ret = cpt_engine_sw_aes_gcm_tls_cipher(gcm_ctx, out, in, len, buf,
                    ctx);
            if (ret < 0)
                return -1;
        }

        /*
         * Handles all the cipher calls for TLS application mode where
         * TLS version is < TLS 1.3
         */
        ret = pal_aes_gcm_tls_cipher(pal_ctx, buf, (void*)ctx, wctx);
        gcm_ctx->iv_set = 0;
        if (ret < 0)
            return -1;
        else
           return 1;
    }

    if (!gcm_ctx->iv_set)
        return -1;

	if (in != NULL && out == NULL)
		return aes_gcm_update_aad_create_aead_session(gcm_ctx, in, len);

        /*
         * Handles all the cipher calls for TLS application mode where
         * TLS version is TLS 1.3
         */
	if (pal_ctx->is_tlsv_1_3)
		return tls13_gcm_cipher(gcm_ctx, out, in, len, buf, wctx);

        /* Handles all the cipher calls for crypto mode applications */
    ret = cpt_engine_crypto_gcm_non_tls_cipher(gcm_ctx, out, in, len, buf);
    if (ret < 0)
        return -1;
    else
        ret = 1;

    return ret;
}

int cpt_engine_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
	int retval;
	ossl_gcm_ctx_t *gcm_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	pal_gcm_ctx_t *pal_ctx = &gcm_ctx->pal_ctx;

	if (gcm_ctx == NULL)
		return 0;

	retval = pal_sym_session_gcm_cleanup(pal_ctx);

	if (retval <= 0)
		engine_log(ENG_LOG_ERR, "FAILED to free GCM Cipher crypto session %d\n", retval);

	pal_ctx->aead_cry_session = NULL;
	pal_ctx->cipher_cry_session = NULL;

	if (pal_ctx->aad)
	{
		pal_free(pal_ctx->aad);
		pal_ctx->aad = NULL;
	}

	return 1;
}
