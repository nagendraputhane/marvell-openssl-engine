/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PAL_COMMON_CBC_H__
#define __PAL_COMMON_CBC_H__

#include "pal.h"
#include "defs.h"

#define PAL_AES128_CBC_KEY_LENGTH 16
#define PAL_AES256_CBC_KEY_LENGTH 32

int pal_aes_cbc_cipher(pal_cbc_ctx_t *pal_ctx, unsigned char *out,
        const unsigned char *in, size_t inl, unsigned char *iv, int enc,
        int sym_queue, void *);
int pal_aes_cbc_cleanup(pal_cbc_ctx_t *pal_ctx);
int pal_aes_cbc_create_session(pal_cbc_ctx_t *pal_ctx, const unsigned char *key,
        const unsigned char *iv, int enc, int key_len);
#endif //__PAL_CBC_H__
