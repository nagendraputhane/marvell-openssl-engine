/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include "cpt_engine.h"
#include "pal/pal.h"
#include "pal/pal_ecdsa.h"
#include <rte_hexdump.h>

extern int asym_dev_id[];
extern int asym_queues[];

/**
 * Assumes that all the to-be-initialized pointers were set to NULL on function
 * call. i.e xform needs to have been memset/explicitly initialized to 0s
 *
 * @returns 1 on success, 0 on failure
 */
static int get_curve_id(const EC_GROUP *ecgroup)
{
  int curve_name = EC_GROUP_get_curve_name(ecgroup);
  pal_crypto_curve_id_t curve_id;

  switch (curve_name) {
    case NID_X9_62_prime192v1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP192R1;
      break;
    case NID_secp224r1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP224R1;
      break;
    case NID_X9_62_prime256v1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP256R1;
      break;
    case NID_secp384r1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP384R1;
      break;
    case NID_secp521r1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP521R1;
      break;
    default:
      /* Unsupported curve */
      return 0;
  }

  return curve_id;
}

static inline int ecdsa_get_valid_devid(int *devid, int *queue)
{
  int thread_id = pal_get_thread_id();

  if(thread_id == -1 || asym_dev_id[thread_id] == -1) {
    engine_log(ENG_LOG_ERR, "Invalid thread_id %d or invalid queue %d\n", thread_id,
        asym_queues[thread_id]);
    return 0;
  }

  *devid = asym_dev_id[thread_id];
  *queue = asym_queues[thread_id];
  return 1;
}

/**
 * @returns 1 on success, 0 on failure
 * Conforms to OpenSSL's ECDSA_sign semantics
 */
int ecdsa_sign(int type, const unsigned char *dgst, int dlen,
    unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
    const BIGNUM *r, EC_KEY *eckey)
{
  int devid = 0;
  int queue = 0;
  int ret = -1;
  pal_crypto_curve_id_t curve_id;
  BIGNUM *rbn = NULL;
  BIGNUM *sbn = NULL;
  BIGNUM *px = BN_new();
  BIGNUM *py = BN_new();
  BIGNUM *k = BN_new();
  ECDSA_SIG *sig_st = NULL;
  unsigned char *buf = NULL;
  int redo, rlen, slen, derlen;
  pal_ecdsa_ctx_t pal_ctx = {0};
  unsigned char *dup_buf = NULL;
  ASYNC_WAIT_CTX **wctx_p = NULL;
  const int max_rslen = PCURVES_MAX_PRIME_LEN;
  const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
  uint8_t rdata[PCURVES_MAX_DER_SIG_LEN] = {0};
  uint8_t sdata[PCURVES_MAX_DER_SIG_LEN] = {0};
	ASYNC_JOB *job = ASYNC_get_current_job();

  if(!ecdsa_get_valid_devid(&devid, &queue))
    goto err;

	if(job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

  curve_id = get_curve_id(ecgroup);
  if (!curve_id) {
    ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
    goto err;
  }

  EC_POINT_get_affine_coordinates_GFp(ecgroup, EC_KEY_get0_public_key(eckey), px, py, NULL);

  pal_ctx.x_data = bn_to_crypto_param(px);
  pal_ctx.x_data_len  = BN_num_bytes(px);
  pal_ctx.y_data = bn_to_crypto_param(py);;
  pal_ctx.y_data_len  = BN_num_bytes(py);
  pal_ctx.pkey = bn_to_crypto_param(EC_KEY_get0_private_key(eckey));
  pal_ctx.pkey_len = BN_num_bytes(EC_KEY_get0_private_key(eckey));
  pal_ctx.dgst = dgst;
  pal_ctx.dlen = dlen;
  pal_ctx.curve_id = curve_id;
  pal_ctx.devid = devid;
  pal_ctx.queue = queue;
  pal_ctx.xform_type = PAL_CRYPTO_ASYM_XFORM_ECDSA;
  pal_ctx.rdata = rdata;
  pal_ctx.sdata = sdata;
  pal_ctx.rlen = max_rslen;
  pal_ctx.slen = max_rslen;
  pal_ctx.async_cb = ossl_handle_async_job;

  do {
    redo = false;

    do {
      BN_rand_range(k, EC_GROUP_get0_order(ecgroup));
    } while (BN_is_zero(k));

    pal_ctx.secret = bn_to_crypto_param(k);
    pal_ctx.secret_len = BN_num_bytes(k);
    if (!pal_ctx.secret)
      goto err;

    if(!pal_ecdsa_sign(&pal_ctx))
      goto err;

    rbn = BN_bin2bn(rdata, pal_ctx.rlen, NULL);
    sbn = BN_bin2bn(sdata, pal_ctx.slen, NULL);

    if (rbn == NULL || sbn == NULL) {
      BN_free(rbn);
      BN_free(sbn);
      goto err;
    }

    if (BN_is_zero(rbn) || BN_is_zero(sbn)) {
      redo = true;
      BN_free(rbn);
      BN_free(sbn);
      sbn = NULL;
      rbn = NULL;
      pal_ctx.rlen = max_rslen;
      pal_ctx.slen = max_rslen;
    }
  } while (redo);

  sig_st = ECDSA_SIG_new();
  if (!ECDSA_SIG_set0(sig_st, rbn, sbn)) {
    BN_free(rbn);
    BN_free(sbn);
    goto err;
  }

  buf = malloc(PCURVES_MAX_DER_SIG_LEN);
  if (buf == NULL)
    goto err;

  dup_buf = buf;
  derlen = i2d_ECDSA_SIG(sig_st, &dup_buf);

  memcpy(sig, buf, derlen);
  *siglen = derlen;
  ret = 1;
err:
  if(sig_st)
    ECDSA_SIG_free(sig_st);
  BN_free(px);
  BN_free(py);
  BN_free(k);
  if(buf)
    free(buf);

  return ret;
}

/**
 * @returns 1 on successful verification, 0 on verification failure, -1 on error
 */
int ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
    const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
  int devid = 0;
  int queue = 0;
  pal_crypto_curve_id_t curve_id;
  pal_ecdsa_ctx_t pal_ctx = {0};
  const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
  const BIGNUM *rbn = NULL;
  const BIGNUM *sbn = NULL;
  ECDSA_SIG *sig_st = NULL;
  int rlen;
  int slen;
  BIGNUM *px = BN_new();
  BIGNUM *py = BN_new();
  int ret = 0;
  (void)type;
	ASYNC_JOB *job = ASYNC_get_current_job();

  if(!ecdsa_get_valid_devid(&devid, &queue))
    return 0;

	if(job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

  curve_id = get_curve_id(ecgroup);
  if (!curve_id) {
    ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
    goto err;
  }

  EC_POINT_get_affine_coordinates_GFp(ecgroup, EC_KEY_get0_public_key(eckey), px, py, NULL);

  if (d2i_ECDSA_SIG(&sig_st, &sigbuf, sig_len) == NULL)
    goto err;

  ECDSA_SIG_get0(sig_st, &rbn, &sbn);

  rlen = BN_num_bytes(rbn);
  slen = BN_num_bytes(sbn);

  pal_ctx.x_data = bn_to_crypto_param(px);
  pal_ctx.x_data_len  = BN_num_bytes(px);
  pal_ctx.y_data = bn_to_crypto_param(py);;
  pal_ctx.y_data_len  = BN_num_bytes(py);
  pal_ctx.rdata = malloc(rlen);
  pal_ctx.sdata = malloc(slen);
  pal_ctx.rlen = rlen;
  pal_ctx.slen = slen;
  pal_ctx.dgst = dgst;
  pal_ctx.dlen = dgst_len;
  pal_ctx.devid = devid;
  pal_ctx.curve_id = curve_id;
  pal_ctx.queue = queue;
  pal_ctx.xform_type = PAL_CRYPTO_ASYM_XFORM_ECDSA;
  pal_ctx.async_cb = ossl_handle_async_job;

  BN_bn2bin(rbn, pal_ctx.rdata);
  BN_bn2bin(sbn, pal_ctx.sdata);

  ret = pal_ecdsa_verify(&pal_ctx);
err:
  ECDSA_SIG_free(sig_st);
  if (pal_ctx.rdata)
    free(pal_ctx.rdata);
  if (pal_ctx.sdata)
    free(pal_ctx.sdata);

  return ret;
}

int ecdh_keygen(EC_KEY *eckey)
{
  int ok = 0;
  int devid = 0;
  int queue = 0;
  BIGNUM *rx, *ry;
  int prime_length;
  void *rxbuf = NULL;
  void *rybuf = NULL;
  const BIGNUM *order;
  const EC_GROUP *group;
  BIGNUM *priv_key = NULL;
  EC_POINT *pub_key = NULL;
  const EC_POINT *generator;
  const BIGNUM *const_priv_key;
  BIGNUM *px = BN_new();
  BIGNUM *py = BN_new();
  pal_ecdsa_ctx_t pal_ctx = {0};
  pal_crypto_curve_id_t curve_id;
	ASYNC_JOB *job = ASYNC_get_current_job();

  if(!ecdsa_get_valid_devid(&devid, &queue))
    return 0;

  group = EC_KEY_get0_group((const EC_KEY*)eckey);
  const_priv_key = EC_KEY_get0_private_key((const EC_KEY*)eckey);
  generator = EC_GROUP_get0_generator(group);

	if(job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

  if (const_priv_key == NULL) {
    priv_key = BN_secure_new();
    if (priv_key == NULL)
      goto err;
  } else
    priv_key = BN_dup(const_priv_key);

  order = EC_GROUP_get0_order(group);
  if (order == NULL)
    goto err;

  do
    if (!BN_rand_range(priv_key, order))
      goto err;
  while (BN_is_zero(priv_key)) ;

  pub_key = EC_POINT_new(group);
  if (pub_key == NULL)
    goto err;

  rxbuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
  rybuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
  if (rxbuf == NULL || rybuf == NULL)
    goto err;

  memset(rxbuf, 0, PCURVES_MAX_PRIME_LEN);
  memset(rybuf, 0, PCURVES_MAX_PRIME_LEN);

  curve_id = get_curve_id(group);
  if (!curve_id) {
    ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
    goto err;
  }

  EC_POINT_get_affine_coordinates_GFp(group, generator, px, py, NULL);

  pal_ctx.x_data = bn_to_crypto_param(px);
  pal_ctx.x_data_len  = BN_num_bytes(px);
  pal_ctx.y_data = bn_to_crypto_param(py);;
  pal_ctx.y_data_len  = BN_num_bytes(py);
  pal_ctx.scalar_data = bn_to_crypto_param(priv_key);
  pal_ctx.scalar_data_len  = BN_num_bytes(priv_key);
  pal_ctx.rxbuf = rxbuf;
  pal_ctx.rybuf = rybuf;
  pal_ctx.curve_id = curve_id;
  pal_ctx.devid = devid;
  pal_ctx.queue = queue;
  pal_ctx.xform_type = PAL_CRYPTO_ASYM_XFORM_ECPM;
  pal_ctx.rxbuf = rxbuf;
  pal_ctx.rybuf = rybuf;
  pal_ctx.async_cb = ossl_handle_async_job;

  if ((prime_length = pal_ecdsa_ec_point_multiplication(&pal_ctx)) == 0) {
    ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_POINT_ARITHMETIC_FAILURE);
    goto err;
  }

  rx = BN_bin2bn(rxbuf, prime_length, NULL);
  ry = BN_bin2bn(rybuf, prime_length, NULL);
  EC_POINT_set_affine_coordinates_GFp(group, pub_key, rx, ry,
      NULL);
  EC_KEY_set_private_key(eckey, priv_key);
  EC_KEY_set_public_key(eckey, pub_key);
  ok = 1;

err:
  if (rybuf)
    OPENSSL_free(rybuf);
  if (rxbuf)
    OPENSSL_free(rxbuf);
  if (pub_key)
    EC_POINT_free(pub_key);
  if (priv_key)
    BN_free(priv_key);
  return ok;
}

int ecdh_compute_key(unsigned char **pout, size_t *poutlen,
    const EC_POINT *pub_key, const EC_KEY *ecdh)
{

  int devid = 0;
  int queue = 0;
  BN_CTX *ctx;
  BIGNUM *x = NULL, *y = NULL;
  const BIGNUM *priv_key;
  const EC_GROUP *group;
  int ret = 0;
  size_t buflen;
  void *rxbuf = NULL;
  void *rybuf = NULL;
  BIGNUM *px = BN_new();
  BIGNUM *py = BN_new();
  pal_ecdsa_ctx_t pal_ctx = {0};
  pal_crypto_curve_id_t curve_id;
	ASYNC_JOB *job = ASYNC_get_current_job();

  if(!ecdsa_get_valid_devid(&devid, &queue))
    return 0;

  if ((ctx = BN_CTX_new()) == NULL)
    goto err;

	if(job)
		pal_ctx.wctx_p = (uint8_t *)ASYNC_get_wait_ctx(job);

  BN_CTX_start(ctx);
  x = BN_CTX_get(ctx);
  y = BN_CTX_get(ctx);
  if (x == NULL || y == NULL) {
    ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  priv_key = EC_KEY_get0_private_key(ecdh);
  if (priv_key == NULL) {
    ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_NO_PRIVATE_VALUE);
    goto err;
  }

  group = EC_KEY_get0_group(ecdh);
  if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
    if (!EC_GROUP_get_cofactor(group, x, NULL) ||
        !BN_mul(x, x, priv_key, ctx)) {
      ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    priv_key = x;
  }

  rxbuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
  rybuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
  if (rxbuf == NULL || rybuf == NULL)
    goto err;

  memset(rxbuf, 0, PCURVES_MAX_PRIME_LEN);
  memset(rybuf, 0, PCURVES_MAX_PRIME_LEN);

  curve_id = get_curve_id(group);
  if (!curve_id) {
    ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
    goto err;
  }

  EC_POINT_get_affine_coordinates_GFp(group, pub_key, px, py, NULL);

  pal_ctx.x_data = bn_to_crypto_param(px);
  pal_ctx.x_data_len  = BN_num_bytes(px);
  pal_ctx.y_data = bn_to_crypto_param(py);;
  pal_ctx.y_data_len  = BN_num_bytes(py);
  pal_ctx.scalar_data = bn_to_crypto_param(priv_key);
  pal_ctx.scalar_data_len  = BN_num_bytes(priv_key);
  pal_ctx.rxbuf = rxbuf;
  pal_ctx.rybuf = rybuf;
  pal_ctx.curve_id = curve_id;
  pal_ctx.devid = devid;
  pal_ctx.queue = queue;
  pal_ctx.xform_type = PAL_CRYPTO_ASYM_XFORM_ECPM;
  pal_ctx.rxbuf = rxbuf;
  pal_ctx.rybuf = rybuf;
  pal_ctx.async_cb = ossl_handle_async_job;

  if ((buflen = pal_ecdsa_ec_point_multiplication(&pal_ctx)) == 0) {
    ECerr(EC_F_ECDH_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
    goto err;
  }

  *pout = rxbuf;
  *poutlen = buflen;
  rxbuf = NULL;
  ret = 1;
err:
  if (rybuf)
    OPENSSL_free(rybuf);
  if (rxbuf)
    OPENSSL_free(rxbuf);
  if (ctx)
    BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  BN_free(py);
  BN_free(px);

  return ret;
}
