#ifndef __CBC_HMAC_SHA1__
#define __CBC_HMAC_SHA1__

#include "pal.h"
#include "pal_cbc.h"

#define SHA_DIGEST_LENGTH 20

/* Offset were the IV need to be copied */
#define PAL_AES_CBC_HMAC_SHA_IV_OFFSET    (sizeof(struct rte_crypto_op) + \
		sizeof(struct rte_crypto_sym_op) + 2 * \
		sizeof(struct rte_crypto_sym_xform))

/* Meta Data follows after the IV */
#define PAL_COP_METADATA_OFF_CBC_HMAC_SHA \
	(PAL_AES_CBC_HMAC_SHA_IV_OFFSET + PAL_AES_CBC_IV_LENGTH)

/* Invalid payload length */
#define PAL_AES_SHA1_NO_PAYLOAD_LENGTH       ((size_t)-1)

typedef int
(*cbc_iv_callback) (const unsigned char *key, size_t len, unsigned char *in,
        unsigned char *out, const unsigned char *iv, int enc);

typedef struct pal_aes_cbc_hmac_sha1_ctx {
	uint8_t key[PAL_AES256_CBC_KEY_LENGTH];
	uint8_t iv[PAL_AES_CBC_IV_LENGTH];
	int keylen;
	int enc;
	uint8_t dev_id; /*<cpt dev_id>*/
	struct rte_cryptodev_sym_session *cry_session;
	struct rte_crypto_op *op;
	struct rte_mbuf *ibuf;
	struct rte_mbuf *obuf;
	uint8_t tls_aad[SSL_MAX_PIPELINES][EVP_AEAD_TLS1_AAD_LEN];
	int tls_aad_len;
	unsigned int tls_ver;
	size_t payload_length;
	uint8_t hmac_key[SHA_DIGEST_LENGTH];
	int update_keys;

	/*Below members are for pipeline */
	uint8_t numpipes;
	uint32_t aad_cnt;
	uint8_t **input_buf;
	uint8_t **output_buf;
	long *input_len;
  cbc_iv_callback iv_cb;
  async_job async_cb;
} aes_cbc_hmac_sha1_ctx_t;

int pal_aes_cbc_hmac_sha1_cipher(aes_cbc_hmac_sha1_ctx_t *pal_ctx, unsigned char *out,
			                           const unsigned char *in, size_t inl,
                                 int sym_queue, int);

int pal_aes_cbc_hmac_sha1_create_session(aes_cbc_hmac_sha1_ctx_t *pal_ctx,
		const unsigned char *key, const unsigned char *iv,
		int enc, int key_len);

#endif // __CBC_HMAC_SHA1__
