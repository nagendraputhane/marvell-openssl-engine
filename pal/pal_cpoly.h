/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#ifndef _PAL_CPOLY_H
#define _PAL_CPOLY_H

#include "pal.h"

#include <crypto/poly1305.h>
#include <crypto/chacha.h>

#define PAL_CPOLY_KEY_LEN			32
#define PAL_CPOLY_BLOCK_SIZE		1
#define PAL_CPOLY_AEAD_AAD_LEN	12
#define PAL_CPOLY_AEAD_DIGEST_LEN	16
#define TLS_HDR_SIZE	13
#define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
#define POLY1305_ctx(actx)    ((POLY1305 *)(actx + 1))

#define CRYPTO_OP(c)	\
	((c) ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT)

#define CPOLY_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
					| EVP_CIPH_FLAG_CUSTOM_CIPHER \
					| EVP_CIPH_ALWAYS_CALL_INIT \
					| EVP_CIPH_CTRL_INIT \
					| EVP_CIPH_CUSTOM_COPY \
					| EVP_CIPH_FLAG_AEAD_CIPHER \
					| EVP_CIPH_FLAG_PIPELINE)

typedef struct pal_cpoly_ctx {
	uint8_t key[32];
	int key_len;
  int tls_tag_len;
  int enc;
	uint8_t iv[12];
	int iv_len;
	uint8_t auth_tag[16];
	int auth_taglen;
	uint8_t aad[16];
	int aad_len;
	/* Below two members for tls1_2 */
	uint8_t seq_num[SSL_MAX_PIPELINES][8];
	int tls_aad_len;
	uint8_t dev_id;
	struct rte_crypto_sym_xform aead_xform;
	struct rte_cryptodev_sym_session *cry_session;
	struct rte_crypto_op *op;
	struct rte_mbuf *ibuf;
	struct rte_mbuf *obuf;
	/* Below members are for pipeline */
	int numpipes;
	uint8_t **input_buf;
	uint8_t **output_buf;
	size_t *input_len;
	struct rte_crypto_op *ops[SSL_MAX_PIPELINES];
	struct rte_mbuf *ibufs[SSL_MAX_PIPELINES];
	uint32_t aad_cnt;
	char aad_pipe[SSL_MAX_PIPELINES][TLS_HDR_SIZE];
	int hw_offload_pkt_sz_threshold;
  async_job async_cb;
}pal_cpoly_ctx_t;

int pal_create_cpoly_aead_session(pal_cpoly_ctx_t *pal_ctx,
					int aad_len, uint8_t reconfigure);
int pal_chacha20_poly1305_tls_cipher(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, void *wctx);
int pal_chacha20_poly1305_non_tls_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
	const unsigned char *in, size_t len, int sym_queue, unsigned char *buf);
int pal_chacha20_poly1305_tls_1_3_crypto(pal_cpoly_ctx_t *pal_ctx, unsigned char *out,
    const unsigned char *in, size_t len, int sym_queue, unsigned char *buf, void *wctx);
#endif // _PAL_CPOLY_H
