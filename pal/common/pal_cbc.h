/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PAL_CBC_HH__
#define __PAL_CBC_HH__

#include "pal.h"

#define PAL_AES128_CBC_KEY_LENGTH 16
#define PAL_AES256_CBC_KEY_LENGTH 32

typedef struct pal_cbc_ctx {
    struct rte_cryptodev_sym_session *cry_session;
    /* Below members are for pipeline */
    uint8_t **input_buf;
    uint8_t **output_buf;
    long int *input_len;
    int hw_offload_pkt_sz_threshold;
    int sym_queue;
    int dev_id; /* cpt dev_id*/
    uint8_t numpipes;
    async_job async_cb;
}pal_cbc_ctx_t;

int pal_aes_cbc_cipher(pal_cbc_ctx_t *pal_ctx, unsigned char *out,
        const unsigned char *in, size_t inl, unsigned char *iv, int enc,
        int sym_queue, void *);
int pal_aes_cbc_cleanup(pal_cbc_ctx_t *pal_ctx);
int pal_aes_cbc_create_session(pal_cbc_ctx_t *pal_ctx, const unsigned char *key,
        const unsigned char *iv, int enc, int key_len);
#endif //__PAL_CBC_H__
