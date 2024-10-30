/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "cpt_engine_cbc.h"
#include "cpt_engine.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

extern uint16_t hw_offload_pktsz_thresh;
extern int sym_queues[RTE_MAX_LCORE];
extern int sym_dev_id[RTE_MAX_LCORE];

static int cpt_engine_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				  const unsigned char *in, size_t inl);
static int cpt_engine_aes_cbc_cleanup(EVP_CIPHER_CTX *ctx);

static int cpt_engine_aes128_init_key(EVP_CIPHER_CTX *ctx,
				   const unsigned char *key,
				   const unsigned char *iv, int enc);
static int cpt_engine_aes256_init_key(EVP_CIPHER_CTX *ctx,
				   const unsigned char *key,
				   const unsigned char *iv, int enc);
int cpt_engine_aes_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type,
					int arg, void *ptr);

EVP_CIPHER *_hidden_aes_128_cbc = NULL;
EVP_CIPHER *_hidden_aes_256_cbc = NULL;

const EVP_CIPHER *cpt_engine_aes_128_cbc(void)
{
	if (_hidden_aes_128_cbc == NULL &&
	    ((_hidden_aes_128_cbc = EVP_CIPHER_meth_new(
		      NID_aes_128_cbc, PAL_AES_BLOCK_SIZE /* block sz */,
		      PAL_AES128_CBC_KEY_LENGTH /* key len */)) == NULL ||
	     !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc,
					    PAL_AES_CBC_IV_LENGTH) ||
	     !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc,
					EVP_CIPH_FLAG_DEFAULT_ASN1 |
					EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_PIPELINE) ||
	     !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc,
				       cpt_engine_aes128_init_key) ||
	     !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc,
					    cpt_engine_aes_cbc_cipher) ||
		 !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc, cpt_engine_aes_cbc_ctrl) ||
		 !EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_cbc,
					  cpt_engine_aes_cbc_cleanup) ||
	     !EVP_CIPHER_meth_set_impl_ctx_size(
		     _hidden_aes_128_cbc, sizeof(ossl_cbc_ctx_t)))) {
		EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
		_hidden_aes_128_cbc = NULL;
	}
	return _hidden_aes_128_cbc;
}

const EVP_CIPHER *cpt_engine_aes_256_cbc(void)
{
	if (_hidden_aes_256_cbc == NULL &&
	    ((_hidden_aes_256_cbc = EVP_CIPHER_meth_new(
		      NID_aes_256_cbc, PAL_AES_BLOCK_SIZE /* block sz */,
		      PAL_AES256_CBC_KEY_LENGTH /* key len */)) == NULL ||
	     !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc,
					    PAL_AES_CBC_IV_LENGTH) ||
	     !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc,
					EVP_CIPH_FLAG_DEFAULT_ASN1 |
					EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_PIPELINE) ||
	     !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc,
				       cpt_engine_aes256_init_key) ||
	     !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc,
					    cpt_engine_aes_cbc_cipher) ||
		 !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc, cpt_engine_aes_cbc_ctrl) ||
		 !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_cbc,
					  cpt_engine_aes_cbc_cleanup) ||
	     !EVP_CIPHER_meth_set_impl_ctx_size(
		     _hidden_aes_256_cbc, sizeof(ossl_cbc_ctx_t)))) {
		EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
		_hidden_aes_256_cbc = NULL;
	}
	return _hidden_aes_256_cbc;
}
  static inline
int cpt_engine_armv8_aes_cbc_init(ossl_cbc_ctx_t *cbc_ctx, const unsigned char *key,
    const unsigned char *iv, int enc, int key_len)
{
  int ret = 0;

  if(key != NULL) {
    if (enc) {
      ret = ARMv8_AES_set_encrypt_key(key, key_len * 8, &cbc_ctx->ks.ks);
      cbc_ctx->block = (block128_f) ARMv8_AES_encrypt;
      cbc_ctx->stream.cbc = (cbc128_f) ARMv8_AES_cbc_encrypt;
    } else {
      ret = ARMv8_AES_set_decrypt_key(key, key_len * 8, &cbc_ctx->ks.ks);
      cbc_ctx->block = (block128_f) ARMv8_AES_decrypt;
      cbc_ctx->stream.cbc = (cbc128_f) ARMv8_AES_cbc_encrypt;
    }
    if (ret < 0) {
      engine_log(ENG_LOG_ERR, "Set encrypt/decrypt key failed!!!\n");
      return 0;
    }
  }
  return ret;
}

static inline int cpt_engine_aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc, int key_len)
{
  int ret = 0;
  unsigned int thread_id = pal_get_thread_id();
  ossl_cbc_ctx_t *cbc_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
  pal_cbc_ctx_t *pal_ctx = &cbc_ctx->pal_ctx;

  pal_ctx->hw_offload_pkt_sz_threshold = hw_offload_pktsz_thresh;
  if (thread_id == -1 || sym_dev_id[thread_id] == -1) {
    engine_log(ENG_LOG_ERR, "%s: Queues not available for thread_id %d\n",
        __FUNCTION__, thread_id);
    return 0;
  }
  pal_ctx->dev_id = sym_dev_id[thread_id];

  if(iv == NULL && key == NULL)
    return 1;

  ret = cpt_engine_armv8_aes_cbc_init(cbc_ctx, key, iv, enc, key_len);
  if (ret < 0)
    return 0;

  return pal_aes_cbc_create_session(pal_ctx, key, iv, enc, key_len);
}

int cpt_engine_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
{
  return cpt_engine_aes_init_key(ctx, key, iv, enc,
      PAL_AES128_CBC_KEY_LENGTH);
}

int cpt_engine_aes256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
{
	return cpt_engine_aes_init_key(ctx, key, iv, enc,
					   PAL_AES256_CBC_KEY_LENGTH);
}

int cpt_engine_aes_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	ossl_cbc_ctx_t *cbc_ctx =
		(ossl_cbc_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
  pal_cbc_ctx_t *pal_ctx = &cbc_ctx->pal_ctx;

	switch (type) {
	case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:
		pal_ctx->numpipes = arg;
		pal_ctx->output_buf = ptr;
		break;
	case EVP_CTRL_SET_PIPELINE_INPUT_BUFS:
		pal_ctx->numpipes = arg;
		pal_ctx->input_buf = ptr;
		break;
	case EVP_CTRL_SET_PIPELINE_INPUT_LENS:
		pal_ctx->numpipes = arg;
		pal_ctx->input_len = ptr;
		break;
	default:
		return 0;
	}
	return 1;
}

int cpt_engine_aes_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
  ossl_cbc_ctx_t *cbc_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
  pal_cbc_ctx_t *pal_ctx = &cbc_ctx->pal_ctx;
  return pal_aes_cbc_cleanup(pal_ctx);
}

int cpt_engine_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			   const unsigned char *in, size_t inl)
{
  ASYNC_JOB *job = NULL;
  ASYNC_WAIT_CTX *wctx = NULL;
  uint16_t datalen = (uint16_t)(inl - PAL_AES_CBC_IV_LENGTH);
  ossl_cbc_ctx_t *cbc_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
  pal_cbc_ctx_t *pal_ctx = &cbc_ctx->pal_ctx;
  int enc = EVP_CIPHER_CTX_encrypting(ctx);
  unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
  int queue =  sym_queues[pal_get_thread_id()];

if ((datalen < pal_ctx->hw_offload_pkt_sz_threshold) && (pal_ctx->numpipes == 1)) {
    cbc_ctx->stream.cbc(in, out, inl, &cbc_ctx->ks, iv, enc);
    pal_ctx->output_buf = NULL;
    pal_ctx->input_buf = NULL;
    pal_ctx->input_len = NULL;
    pal_ctx->numpipes = 0;
    return 1;
  }
  pal_ctx->async_cb = ossl_handle_async_job;

  job = ASYNC_get_current_job();
  if (job != NULL)
    wctx = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

  return pal_aes_cbc_cipher(pal_ctx, out, in, inl, iv, enc, queue, wctx);
}
