/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _PAL_GCM_H_
#define _PAL_GCM_H_

#include "pal/pal.h"

#define PAL_AEAD_DIGEST_LENGTH	  16
#define PAL_AES128_GCM_KEY_LENGTH	16
#define PAL_AES256_GCM_KEY_LENGTH	32
#define PAL_AES_CTR_IV_LENGTH	    16
#define TLS_HDR_SIZE                    13

#define ARMv8_AES_ctr32_encrypt_blocks aes_v8_ctr32_encrypt_blocks
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define CRYPTO_OP(c)                                                           \
	((c) ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT)

typedef int (*iv_func_ptr)(void *, int, int, void *);

typedef struct ossl_pal_ctx {
	uint8_t key[32];
	uint64_t iv[3];
	uint8_t *aad;
	uint8_t auth_tag[16];
	uint8_t keylen;
	uint8_t dev_id; /* cpt dev_id*/
	int aad_len;
	int ivlen;
	int tls_aad_len;
  int tls_exp_iv_len;
  int tls_tag_len;
  int enc;
  int sym_queue;
	int hw_offload_pkt_sz_threshold;
	struct rte_cryptodev_sym_session *aead_cry_session;
	struct rte_cryptodev_sym_session *cipher_cry_session;
	struct rte_crypto_op *op;
	struct rte_mbuf *ibuf;
	/* Below members are for pipeline */
	volatile int numpipes;
	uint8_t **input_buf;
	uint8_t **output_buf;
	long int *input_len;
	struct rte_crypto_op *ops[SSL_MAX_PIPELINES];
	struct rte_mbuf *ibufs[SSL_MAX_PIPELINES];
	uint32_t aad_cnt;
	char aad_pipe[SSL_MAX_PIPELINES][TLS_HDR_SIZE];
  uint16_t hw_off_pkt_sz_thrsh;
  iv_func_ptr iv_cb;
  async_job async_cb;
  uint8_t is_tlsv_1_3;
} pal_gcm_ctx_t;

int pal_crypto_gcm_tls_1_3_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
                                        const unsigned char *in, size_t len,
                                  unsigned char *buf, void *wctx);
int pal_crypto_gcm_non_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *out,
			     const unsigned char *in, size_t len, unsigned char *buf);
int pal_aes_gcm_tls_cipher(pal_gcm_ctx_t *pal_ctx, unsigned char *buf,
                            void *usr_ctx, void *wctx);
int pal_create_aead_session(pal_crypto_aead_algorithm_t algo,
			       pal_gcm_ctx_t *pal_ctx, int aad_len, uint8_t reconfigure);
int pal_create_cipher_session(pal_crypto_cipher_algorithm_t algo,
				pal_gcm_ctx_t *pal_ctx);
#endif /* _PAL_GCM_H_ */
