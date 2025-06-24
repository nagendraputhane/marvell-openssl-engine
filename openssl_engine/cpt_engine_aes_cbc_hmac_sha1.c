/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal_aes_cbc_hmac_sha1.h"
#include "cpt_engine.h"

static int cpt_engine_aes_cbc_hmac_sha1_cipher(EVP_CIPHER_CTX *ctx,
    unsigned char *out, const unsigned char *in, size_t inl);
static int cpt_engine_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx);
static int cpt_engine_aes128_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
    const unsigned char *key,
    const unsigned char *iv, int enc);
static int cpt_engine_aes256_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
    const unsigned char *key,
    const unsigned char *iv, int enc);
static int cpt_engine_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type,
    int arg, void *ptr);
EVP_CIPHER *_hidden_aes_128_cbc_hmac_sha1;
EVP_CIPHER *_hidden_aes_256_cbc_hmac_sha1;

extern dpdk_pools_t dpdk_pools;

const EVP_CIPHER *cpt_engine_aes_128_cbc_hmac_sha1(void)
{
  if (_hidden_aes_128_cbc_hmac_sha1 == NULL) {
    _hidden_aes_128_cbc_hmac_sha1 = EVP_CIPHER_meth_new(
        NID_aes_128_cbc_hmac_sha1, PAL_AES_BLOCK_SIZE,
        PAL_AES128_CBC_KEY_LENGTH);
    if (_hidden_aes_128_cbc_hmac_sha1 != NULL) {
      if (!EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc_hmac_sha1,
            PAL_AES_CBC_IV_LENGTH) ||
          !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc_hmac_sha1,
            EVP_CIPH_CBC_MODE
            | EVP_CIPH_FLAG_DEFAULT_ASN1
            | EVP_CIPH_FLAG_AEAD_CIPHER
            | EVP_CIPH_FLAG_PIPELINE) ||
          !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc_hmac_sha1,
            cpt_engine_aes128_cbc_hmac_sha1_init_key) ||
          !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc_hmac_sha1,
            cpt_engine_aes_cbc_hmac_sha1_cipher) ||
          !EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_cbc_hmac_sha1,
            cpt_engine_aes_cbc_hmac_sha1_cleanup) ||
          !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc_hmac_sha1,
            cpt_engine_aes_cbc_hmac_sha1_ctrl) ||
          !EVP_CIPHER_meth_set_impl_ctx_size(
            _hidden_aes_128_cbc_hmac_sha1,
            sizeof(aes_cbc_hmac_sha1_ctx_t))) {
        EVP_CIPHER_meth_free(_hidden_aes_128_cbc_hmac_sha1);
        _hidden_aes_128_cbc_hmac_sha1 = NULL;
      }
    }
  }

  return _hidden_aes_128_cbc_hmac_sha1;
}

const EVP_CIPHER *cpt_engine_aes_256_cbc_hmac_sha1(void)
{
  if (_hidden_aes_256_cbc_hmac_sha1 == NULL) {
    _hidden_aes_256_cbc_hmac_sha1 = EVP_CIPHER_meth_new(
        NID_aes_256_cbc_hmac_sha1, PAL_AES_BLOCK_SIZE,
        PAL_AES256_CBC_KEY_LENGTH);
    if (_hidden_aes_256_cbc_hmac_sha1 != NULL) {
      if (!EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc_hmac_sha1,
            PAL_AES_CBC_IV_LENGTH) ||
          !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc_hmac_sha1,
            EVP_CIPH_CBC_MODE
            | EVP_CIPH_FLAG_DEFAULT_ASN1
            | EVP_CIPH_FLAG_AEAD_CIPHER
            | EVP_CIPH_FLAG_PIPELINE) ||
          !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc_hmac_sha1,
            cpt_engine_aes256_cbc_hmac_sha1_init_key) ||
          !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc_hmac_sha1,
            cpt_engine_aes_cbc_hmac_sha1_cipher) ||
          !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_cbc_hmac_sha1,
            cpt_engine_aes_cbc_hmac_sha1_cleanup) ||
          !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc_hmac_sha1,
            cpt_engine_aes_cbc_hmac_sha1_ctrl) ||
          !EVP_CIPHER_meth_set_impl_ctx_size(
            _hidden_aes_256_cbc_hmac_sha1,
            sizeof(aes_cbc_hmac_sha1_ctx_t))) {
        EVP_CIPHER_meth_free(_hidden_aes_256_cbc_hmac_sha1);
        _hidden_aes_256_cbc_hmac_sha1 = NULL;
      }
    }
  }

  return _hidden_aes_256_cbc_hmac_sha1;
}

  static int
cpt_engine_aes_cbc_initial_iv(const unsigned char *key, size_t len, unsigned char *in,
    unsigned char *out, const unsigned char *iv, int enc)
{
  AES_KEY aes_key;

  memset(&aes_key, 0, sizeof(AES_KEY));
  AES_set_encrypt_key(key, len*8, &aes_key);
  AES_cbc_encrypt(in, out, PAL_AES_BLOCK_SIZE, &aes_key, iv, enc);
}

int cpt_engine_aes128_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
    const unsigned char *key, const unsigned char *iv, int enc)
{

  aes_cbc_hmac_sha1_ctx_t *pal_ctx =(aes_cbc_hmac_sha1_ctx_t *)
    EVP_CIPHER_CTX_get_cipher_data(ctx);

  pal_ctx->enc = enc;
  pal_ctx->iv_cb = cpt_engine_aes_cbc_initial_iv;
  pal_ctx->async_cb = ossl_handle_async_job;
  return pal_aes_cbc_hmac_sha1_create_session(pal_ctx, key, iv, enc,
      PAL_AES128_CBC_KEY_LENGTH);
}

int cpt_engine_aes256_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
    const unsigned char *key, const unsigned char *iv, int enc)
{

  aes_cbc_hmac_sha1_ctx_t *pal_ctx =(aes_cbc_hmac_sha1_ctx_t *)
    EVP_CIPHER_CTX_get_cipher_data(ctx);

  pal_ctx->enc = enc;
  pal_ctx->iv_cb = cpt_engine_aes_cbc_initial_iv;
  pal_ctx->async_cb = ossl_handle_async_job;
  return pal_aes_cbc_hmac_sha1_create_session(pal_ctx, key, iv, enc,
      PAL_AES256_CBC_KEY_LENGTH);
}

int cpt_engine_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type,
    int arg, void *ptr)
{
  aes_cbc_hmac_sha1_ctx_t *pal_ctx =
    (aes_cbc_hmac_sha1_ctx_t *)
    EVP_CIPHER_CTX_get_cipher_data(ctx);

  if (pal_ctx == NULL)
    return 0;

  switch (type) {
    case EVP_CTRL_AEAD_SET_MAC_KEY:
      {
        if (ptr != NULL)
          memcpy(pal_ctx->hmac_key, ptr, arg);

        return 1;
      }
    case EVP_CTRL_AEAD_TLS1_AAD:
      {
        unsigned char *p = ptr;
        unsigned int len;

        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
          return -1;

        len = p[arg - 2] << 8 | p[arg - 1];

        if (EVP_CIPHER_CTX_encrypting(ctx)) {
          pal_ctx->payload_length = len;
          pal_ctx->tls_ver =
            p[arg - 4] << 8 | p[arg - 3];
          if (pal_ctx->tls_ver >= TLS1_1_VERSION) {
            if (len < PAL_AES_BLOCK_SIZE)
              return 0;
            len -= PAL_AES_BLOCK_SIZE;
            p[arg - 2] = len >> 8;
            p[arg - 1] = len;
          }
          if (pal_ctx->aad_cnt < SSL_MAX_PIPELINES) {
            memcpy(pal_ctx->tls_aad
                [pal_ctx->aad_cnt], ptr, arg);
            pal_ctx->aad_cnt++;
          }
          pal_ctx->tls_aad_len = arg;

          return (((len + SHA_DIGEST_LENGTH +
                  PAL_AES_BLOCK_SIZE)
                & -PAL_AES_BLOCK_SIZE)
              - len);
        } else {
          memcpy(pal_ctx->tls_aad[pal_ctx->aad_cnt],
              ptr, arg);
          pal_ctx->aad_cnt++;
          pal_ctx->payload_length = arg;
          pal_ctx->tls_aad_len = arg;

          return SHA_DIGEST_LENGTH;
        }
      }

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

int cpt_engine_aes_cbc_hmac_sha1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t inl)
{
  int iv_len = 0;
  aes_cbc_hmac_sha1_ctx_t *pal_ctx = (aes_cbc_hmac_sha1_ctx_t *)
    EVP_CIPHER_CTX_get_cipher_data(ctx);
  unsigned int thread_id = pal_get_thread_id();


  if (thread_id == -1 || sym_dev_id[thread_id] == -1) {
    engine_log(ENG_LOG_ERR, "%s: Queues not available for thread_id %d\n",
        __FUNCTION__, thread_id);
    return 0;
  }
  pal_ctx->dev_id = sym_dev_id[thread_id];
  pal_ctx->enc = EVP_CIPHER_CTX_encrypting(ctx);
  if (pal_ctx->tls_ver >= TLS1_1_VERSION)
    iv_len = PAL_AES_BLOCK_SIZE;

  return pal_aes_cbc_hmac_sha1_cipher(pal_ctx, out, in, inl, sym_queues[pal_get_thread_id()], iv_len);
}

int cpt_engine_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx)
{
  int dev_id = sym_dev_id[pal_get_thread_id()];
  aes_cbc_hmac_sha1_ctx_t *pal_ctx = (aes_cbc_hmac_sha1_ctx_t *)
    EVP_CIPHER_CTX_get_cipher_data(ctx);

  pal_sym_session_cleanup(pal_ctx->cry_session, dev_id);
  pal_ctx->cry_session = NULL;

  return 1;
}
