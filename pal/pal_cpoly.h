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
    struct rte_crypto_sym_xform aead_xform;
    struct rte_cryptodev_sym_session *cry_session;
    struct rte_crypto_op *op;
    struct rte_mbuf *ibuf;
    struct rte_mbuf *obuf;
    uint8_t **input_buf;
    uint8_t **output_buf;
    size_t *input_len;
    struct rte_crypto_op *ops[SSL_MAX_PIPELINES];
    struct rte_mbuf *ibufs[SSL_MAX_PIPELINES];
    uint8_t seq_num[SSL_MAX_PIPELINES][8];
    char aad_pipe[SSL_MAX_PIPELINES][TLS_HDR_SIZE];
    uint8_t key[32];
    uint8_t aad[16];
    uint8_t auth_tag[16];
    unsigned char buf[16]; /* Buffer of partial blocks processed via update calls */
    uint8_t iv[12];
    uint32_t aad_cnt;
    int key_len;
    int tls_tag_len;
    int enc;
    int iv_len;
    int auth_taglen;
    int aad_len;
    int tls_aad_len;
    int tls_aad_pad_sz;
    int numpipes;
    int hw_offload_pkt_sz_threshold;
    int queue;
    int dev_id;
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
