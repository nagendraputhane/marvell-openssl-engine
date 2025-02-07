/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <assert.h>

/* For SSL3_VERSION */
#include <openssl/prov_ssl.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>
#include <openssl/core_dispatch.h>
#include <openssl/rand.h>
#include <internal/constant_time.h>
#include "prov.h"
#include "ciphercommon.h"

/*-
 * Generic cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *prov_cipher_generic_gettable_params(ossl_unused void *provctx)
{
    return cipher_known_gettable_params;
}

int prov_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags,
                                   size_t kbits, size_t blkbits, size_t ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(prov_cipher_generic)
{ OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, NULL, 0, OSSL_PARAM_UNMODIFIED },
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(prov_cipher_generic)

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(prov_cipher_generic)
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_USE_BITS, NULL),
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(prov_cipher_generic)

/*-
 * AEAD cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_aead_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *prov_cipher_aead_gettable_ctx_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return cipher_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM cipher_aead_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *prov_cipher_aead_settable_ctx_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return cipher_aead_known_settable_ctx_params;
}

/* Functions defined in ssl/tls_pad.c */
int ssl3_cbc_remove_padding_and_mac(size_t *reclen,
                                    size_t origreclen,
                                    unsigned char *recdata,
                                    unsigned char **mac,
                                    int *alloced,
                                    size_t block_size, size_t mac_size,
                                    OSSL_LIB_CTX *libctx);

int tls1_cbc_remove_padding_and_mac(size_t *reclen,
                                    size_t origreclen,
                                    unsigned char *recdata,
                                    unsigned char **mac,
                                    int *alloced,
                                    size_t block_size, size_t mac_size,
                                    int aead,
                                    OSSL_LIB_CTX *libctx);

/*
 * Fills a single block of buffered data from the input, and returns the amount
 * of data remaining in the input that is a multiple of the blocksize. The buffer
 * is only filled if it already has some data in it, isn't full already or we
 * don't have at least one block in the input.
 *
 * buf: a buffer of blocksize bytes
 * buflen: contains the amount of data already in buf on entry. Updated with the
 *         amount of data in buf at the end. On entry *buflen must always be
 *         less than the blocksize
 * blocksize: size of a block. Must be greater than 0 and a power of 2
 * in: pointer to a pointer containing the input data
 * inlen: amount of input data available
 *
 * On return buf is filled with as much data as possible up to a full block,
 * *buflen is updated containing the amount of data in buf. *in is updated to
 * the new location where input data should be read from, *inlen is updated with
 * the remaining amount of data in *in. Returns the largest value <= *inlen
 * which is a multiple of the blocksize.
 */
size_t prov_cipher_fillblock(unsigned char *buf, size_t *buflen,
                             size_t blocksize,
                             const unsigned char **in, size_t *inlen)
{
    size_t blockmask = ~(blocksize - 1);
    size_t bufremain = blocksize - *buflen;

    assert(*buflen <= blocksize);
    assert(blocksize > 0 && (blocksize & (blocksize - 1)) == 0);

    if (*inlen < bufremain)
        bufremain = *inlen;
    memcpy(buf + *buflen, *in, bufremain);
    *in += bufremain;
    *inlen -= bufremain;
    *buflen += bufremain;

    return *inlen & blockmask;
}

/*
 * Fills the buffer with trailing data from an encryption/decryption that didn't
 * fit into a full block.
 */
int prov_cipher_trailingdata(unsigned char *buf, size_t *buflen, size_t blocksize,
                             const unsigned char **in, size_t *inlen)
{
    if (*inlen == 0)
        return 1;

    if (*buflen + *inlen > blocksize) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(buf + *buflen, *in, *inlen);
    *buflen += *inlen;
    *inlen = 0;

    return 1;
}

/* Pad the final block for encryption */
void prov_cipher_padblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
    size_t i;
    unsigned char pad = (unsigned char)(blocksize - *buflen);

    for (i = *buflen; i < blocksize; i++)
        buf[i] = pad;
}

int prov_cipher_unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
    size_t pad, i;
    size_t len = *buflen;

    if(len != blocksize) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * The following assumes that the ciphertext has been authenticated.
     * Otherwise it provides a padding oracle.
     */
    pad = buf[blocksize - 1];
    if (pad == 0 || pad > blocksize) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
        return 0;
    }
    for (i = 0; i < pad; i++) {
        if (buf[--len] != pad) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            return 0;
        }
    }
    *buflen = len;
    return 1;
}

/*-
 * prov_cipher_tlsunpadblock removes the CBC padding from the decrypted, TLS, CBC
 * record in constant time. Also removes the MAC from the record in constant
 * time.
 *
 * libctx: Our library context
 * tlsversion: The TLS version in use, e.g. SSL3_VERSION, TLS1_VERSION, etc
 * buf: The decrypted TLS record data
 * buflen: The length of the decrypted TLS record data. Updated with the new
 *         length after the padding is removed
 * block_size: the block size of the cipher used to encrypt the record.
 * mac: Location to store the pointer to the MAC
 * alloced: Whether the MAC is stored in a newly allocated buffer, or whether
 *          *mac points into *buf
 * macsize: the size of the MAC inside the record (or 0 if there isn't one)
 * aead: whether this is an aead cipher
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: (in constant time) Record is publicly valid. If padding is invalid then
 *      the mac is random
 */
int prov_cipher_tlsunpadblock(OSSL_LIB_CTX *libctx, unsigned int tlsversion,
                              unsigned char *buf, size_t *buflen,
                              size_t blocksize,
                              unsigned char **mac, int *alloced, size_t macsize,
                              int aead)
{
    int ret;

    switch (tlsversion) {
    case SSL3_VERSION:
        return ssl3_cbc_remove_padding_and_mac(buflen, *buflen, buf, mac,
                                               alloced, blocksize, macsize,
                                               libctx);

    case TLS1_2_VERSION:
    case DTLS1_2_VERSION:
    case TLS1_1_VERSION:
    case DTLS1_VERSION:
    case DTLS1_BAD_VER:
        /* Remove the explicit IV */
        buf += blocksize;
        *buflen -= blocksize;
        /* Fall through */
    case TLS1_VERSION:
        ret = tls1_cbc_remove_padding_and_mac(buflen, *buflen, buf, mac,
                                              alloced, blocksize, macsize,
                                              aead, libctx);
        return ret;

    default:
        return 0;
    }
}
