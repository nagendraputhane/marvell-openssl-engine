/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "cpt_engine.h"
#include "cpt_engine_rsa.h"
#include "pal/pal.h"
#include "pal/pal_rsa.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define populate_default_params(pal_ctx, padding,dev_id,queue, cb) \
  pal_ctx.padding = padding == RSA_PKCS1_PADDING ? PAL_RSA_PKCS1_PADDING : PAL_RSA_NO_PADDING; \
  pal_ctx.dev_id = dev_id; \
  pal_ctx.qp_id = queue; \
  pal_ctx.async_cb = cb;

/*
 * RSA implementation
 */

extern int asym_dev_id[];
extern int asym_queues[];

static int rsa_check_modlen(RSA *rsa)
{
	int ret;
	uint64_t plen;
	const BIGNUM *n;

	RSA_get0_key(rsa, &n, NULL, NULL);
	plen = BN_num_bytes(n);

	ret = pal_asym_xform_capability_check_modlen(plen);

	return ret;
}

static void setup_non_crt_pub_op_xform(pal_rsa_ctx_t *pal_ctx, RSA *rsa)
{
	uint64_t total_size = 0;
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;

	RSA_get0_key(rsa, &n, &e, &d);

	/* To avoid multiple malloc calls, doing it one time with total size of
	 * all parameters.
	 * Maximum length for a NON-CRT parameter is BN_num_bytes(d).
	 */
	if (d != NULL)
		total_size =
			BN_num_bytes(n) + BN_num_bytes(e) + BN_num_bytes(d);
	else
		total_size = BN_num_bytes(n) + BN_num_bytes(e);

  pal_ctx->rsa_n_data = (uint8_t *)pal_malloc(total_size);
	if (unlikely(pal_ctx->rsa_n_data == NULL)) {
		engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
				__LINE__, "pal_malloc failure");
		return;
	}
	pal_ctx->rsa_n_len  = BN_bn2bin(n, pal_ctx->rsa_n_data);

  pal_ctx->rsa_e_data = (uint8_t *)pal_ctx->rsa_n_data + pal_ctx->rsa_n_len;

  pal_ctx->rsa_e_len = BN_bn2bin(e, pal_ctx->rsa_e_data);

	if (d != NULL) {
    pal_ctx->rsa_key_type = PAL_RSA_KEY_TYPE_EXP;
    pal_ctx->rsa_d_data = (uint8_t *)pal_ctx->rsa_e_data + pal_ctx->rsa_e_len;
    pal_ctx->rsa_d_len = BN_bn2bin(d, pal_ctx->rsa_d_data);
	} else {
     pal_ctx->rsa_key_type = PAL_RSA_KEY_TYPE_QT;
    pal_ctx->rsa_qt_p_data = NULL;
    pal_ctx->rsa_qt_p_len = 0;
	}
}

static void setup_crt_priv_op_xform(pal_rsa_ctx_t *pal_ctx, RSA *rsa)
{
	uint64_t total_size = 0, crt_length = 0;
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *p;
	const BIGNUM *q;
	int ret = 0;

	RSA_get0_key(rsa, &n, &e, NULL);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

	pal_ctx->rsa_key_type = PAL_RSA_KEY_TYPE_QT;

	/* To avoid multiple malloc calls, doing it one time with total size of
	 * all parameters.
	 * Maximum length for a CRT parameter is BN_num_bytes(n)/2.
	 */
	total_size =
		BN_num_bytes(n) + BN_num_bytes(e) + 5 * (BN_num_bytes(n) / 2);
	crt_length = BN_num_bytes(n) / 2;

	pal_ctx->rsa_n_data = (uint8_t *)pal_malloc(total_size);
	if (unlikely(pal_ctx->rsa_n_data == NULL)) {
		engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
				__LINE__, "pal_malloc failure");
		return;
	}
	pal_ctx->rsa_n_len = BN_bn2bin(n, pal_ctx->rsa_n_data);

	pal_ctx->rsa_e_data =
		(uint8_t *)pal_ctx->rsa_n_data + pal_ctx->rsa_n_len;
	pal_ctx->rsa_e_len = BN_bn2bin(e, pal_ctx->rsa_e_data);

	pal_ctx->rsa_qt_p_data =
		(uint8_t *)pal_ctx->rsa_e_data  + pal_ctx->rsa_e_len;
	 pal_ctx->rsa_qt_p_len = BN_bn2bin(p, pal_ctx->rsa_qt_p_data);

	pal_ctx->rsa_qt_q_data  = (uint8_t *)pal_ctx->rsa_qt_p_data +
				   pal_ctx->rsa_qt_p_len;
	pal_ctx->rsa_qt_q_len  = BN_bn2bin(q, pal_ctx->rsa_qt_q_data);

	/* Microcode requires CRT parameters be prepadded with zeroes if length
	 * is lesser than modlength/2
	 */
	pal_ctx->rsa_qt_dP_data = (uint8_t *)pal_ctx->rsa_qt_q_data +
				    pal_ctx->rsa_qt_q_len;
	ret = BN_bn2bin(dmp1, pal_ctx->rsa_qt_dP_data + crt_length
		- BN_num_bytes(dmp1));
	if (ret == -1)
		fprintf(stderr, "Error: Conversion failed.\n");
	pal_ctx->rsa_qt_dP_len = crt_length;

	 pal_ctx->rsa_qt_dQ_data = (uint8_t *)pal_ctx->rsa_qt_dP_data +
				    pal_ctx->rsa_qt_dP_len;
	ret = BN_bn2bin(dmq1,  pal_ctx->rsa_qt_dQ_data + crt_length
		- BN_num_bytes(dmq1));
	if (ret == -1)
		fprintf(stderr, "Error: Conversion failed.\n");
	pal_ctx->rsa_qt_dQ_len = crt_length;

	pal_ctx->rsa_qt_qInv_data = (uint8_t *) pal_ctx->rsa_qt_dQ_data +
				      pal_ctx->rsa_qt_dQ_len;
	ret = BN_bn2bin(iqmp, pal_ctx->rsa_qt_qInv_data + crt_length
		- BN_num_bytes(iqmp));
	if (ret == -1)
		fprintf(stderr, "Error: Conversion failed.\n");
	pal_ctx->rsa_qt_qInv_len = crt_length;
}

static inline int is_crt_meth_possible (RSA *rsa)
{
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;
	const BIGNUM *p;
	const BIGNUM *q;

	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if (p == NULL || q == NULL || dmp1 == NULL || dmq1 == NULL ||
	    iqmp == NULL) {
		engine_log(ENG_LOG_ERR, "One or more CRT op params(p/q/dmp1/dmq1/iqmp)"
				" are NULL. Using non CRT method instead!!!\n");
		return 0;
	}
	return 1;
}

static int setup_noncrt_priv_op_xform(pal_rsa_ctx_t *pal_ctx, RSA *rsa)
{
	uint64_t total_size = 0;
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;

	RSA_get0_key(rsa, &n, &e, &d);
	if ((n == NULL) || (e == NULL) || (d == NULL)) {
		engine_log(ENG_LOG_ERR, "One or more non crt method params(n/e/d) "
				"are NULL");
		return -1;
	}

  pal_ctx->rsa_key_type = PAL_RSA_KEY_TYPE_EXP;
	total_size = BN_num_bytes(n) + BN_num_bytes(e) + BN_num_bytes(d);

  pal_ctx->rsa_n_data = (uint8_t *)pal_malloc(total_size);
	if (unlikely(pal_ctx->rsa_n_data == NULL)) {
		engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
				__LINE__, "pal_malloc failure");
		return -1;
	}
  pal_ctx->rsa_n_len = BN_bn2bin(n, pal_ctx->rsa_n_data);

  pal_ctx->rsa_e_data = (uint8_t *)pal_ctx->rsa_n_data + pal_ctx->rsa_n_len;
  pal_ctx->rsa_e_len = BN_bn2bin(e, pal_ctx->rsa_e_data);
  pal_ctx->rsa_d_data = (uint8_t *)pal_ctx->rsa_e_data + pal_ctx->rsa_e_len;
  pal_ctx->rsa_d_len = BN_bn2bin(d, pal_ctx->rsa_d_data);
	return 0;
}

/* Private encryption */
int cpt_engine_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding)
{
  uint8_t dev_id;
  int use_crt_method = 1;
  pal_rsa_ctx_t pal_ctx = {0};
	ASYNC_JOB *job = ASYNC_get_current_job();
  unsigned int thread_id = pal_get_thread_id();
	int ret = 0, verify_func_ret = 0;
	uint8_t *decrypt_msg = NULL;

	ret = rsa_check_modlen(rsa);
	if (ret != 0 ||
	   (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
	   (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
		RSA_set_method(rsa, default_rsa_meth);
		ret = RSA_meth_get_priv_enc(default_rsa_meth)(flen, from, to, rsa,
				padding);
		return ret;
	}
	if (!is_crt_meth_possible(rsa))
		use_crt_method = 0;

	if (job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

priv_enc_start:
	/* Setup private xform operations */
	if (use_crt_method)
		setup_crt_priv_op_xform(&pal_ctx, rsa);
	else {
		ret = setup_noncrt_priv_op_xform(&pal_ctx, rsa);
		if (unlikely(ret < 0)) {
			return -1;
		}
	}

  pal_ctx.use_crt_method = use_crt_method;
  populate_default_params(pal_ctx, padding,dev_id,
      asym_queues[thread_id], ossl_handle_async_job);

  ret = pal_rsa_priv_enc(&pal_ctx, flen, from, to);

  if (pal_ctx.rsa_n_data)
    pal_free(pal_ctx.rsa_n_data);
  if(ret >= 0)
    ret = RSA_size(rsa);

  if ((ret > 0) && (use_crt_method == 1)) {
    decrypt_msg = (uint8_t *)pal_malloc(RSA_size(rsa));
    if (unlikely(decrypt_msg == NULL)) {
      engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
          __LINE__, "pal_malloc failure");
      return -1;
    }

    verify_func_ret = cpt_engine_rsa_pub_dec(RSA_size(rsa), to, decrypt_msg, rsa,
        padding);
    if ((verify_func_ret < 0) ||
        (memcmp(from, decrypt_msg, flen) != 0)) {
      use_crt_method = 0;
      engine_log(ENG_LOG_ERR, "CRT method failed. Using non CRT method instead!!!\n");
      goto priv_enc_start;
    }
    pal_free(decrypt_msg);
  }

  return ret;
}

/* Public decryption */
int cpt_engine_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding)
{
  uint8_t dev_id;
  int ret = 0;
  pal_rsa_ctx_t pal_ctx = {0};
	ASYNC_JOB *job = ASYNC_get_current_job();
  unsigned int thread_id = pal_get_thread_id();

	if (thread_id == -1 || asym_dev_id[thread_id] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for thread_id %d\n",
			__FUNCTION__, thread_id);
		return -1;
	}
	dev_id = asym_dev_id[thread_id];
	if (job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

	ret = rsa_check_modlen(rsa);
	if (ret != 0 ||
	   (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
	   (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
		RSA_set_method(rsa, default_rsa_meth);
		ret = RSA_meth_get_pub_dec(default_rsa_meth)(flen, from, to, rsa,
				padding);
		return ret;
	}
  populate_default_params(pal_ctx, padding,dev_id,
      asym_queues[thread_id], ossl_handle_async_job);

	setup_non_crt_pub_op_xform(&pal_ctx, rsa);

  ret = pal_rsa_pub_dec(&pal_ctx, flen, from, to);

  if (pal_ctx.rsa_n_data)
    pal_free(pal_ctx.rsa_n_data);

  return ret;
}

/* public encryption*/
int cpt_engine_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding)
{
  uint8_t dev_id;
  int ret = 0;
  pal_rsa_ctx_t pal_ctx = {0};
	ASYNC_JOB *job = ASYNC_get_current_job();
  unsigned int thread_id = pal_get_thread_id();

	if (thread_id == -1 || asym_dev_id[thread_id] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for thread_id %d\n",
			__FUNCTION__, thread_id);
		return -1;
	}
	dev_id = asym_dev_id[thread_id];
	if (job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

  ret = rsa_check_modlen(rsa);
  if (ret != 0 ||
      (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
      (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
    RSA_set_method(rsa, default_rsa_meth);
    ret = RSA_meth_get_pub_enc(default_rsa_meth)(flen, from, to, rsa,
        padding);
    return ret;
  }

  populate_default_params(pal_ctx, padding,dev_id,
      asym_queues[thread_id], ossl_handle_async_job);

	setup_non_crt_pub_op_xform(&pal_ctx, rsa);

  ret = pal_rsa_pub_enc(&pal_ctx, flen, from, to);

  ret = ret < 0 ? ret : RSA_size(rsa);

  if (pal_ctx.rsa_n_data)
    pal_free(pal_ctx.rsa_n_data);

  return ret;
}

/* Private decryption */
int cpt_engine_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding)
{
  uint8_t dev_id;
  int ret = 0;
  pal_rsa_ctx_t pal_ctx = {0};
	ASYNC_JOB *job = ASYNC_get_current_job();
	unsigned int thread_id = pal_get_thread_id();

	if (thread_id == -1 || asym_dev_id[thread_id] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for thread_id %d\n",
			__FUNCTION__, thread_id);
		return -1;
	}
	dev_id = asym_dev_id[thread_id];
	if (job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

	ret = rsa_check_modlen(rsa);
	if (ret != 0 ||
	   (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
	   (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
		RSA_set_method(rsa, default_rsa_meth);
		ret = RSA_meth_get_priv_dec(default_rsa_meth)(flen, from, to, rsa,
				padding);
		return ret;
	}

  populate_default_params(pal_ctx, padding,dev_id,
      asym_queues[thread_id], ossl_handle_async_job);

  setup_crt_priv_op_xform(&pal_ctx, rsa);

  ret = pal_rsa_priv_dec(&pal_ctx, flen, from, to);

 if (pal_ctx.rsa_n_data)
    pal_free(pal_ctx.rsa_n_data);

 return ret;
}
