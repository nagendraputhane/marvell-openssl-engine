/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include "pal.h"

#include <openssl/objects.h>

#include "pal_ecdsa.h"

#define MAX_DEQUEUE_OPS 32

extern int cpt_num_asym_requests_in_flight;

static int ecdsa_sess_create(struct rte_crypto_asym_xform *ecdsa_xform,
				struct rte_cryptodev_asym_session **sess, int devid)
{
    return 1;
}

static int ecdh_sess_create(struct rte_crypto_asym_xform *ecdh_xform,
				struct rte_cryptodev_asym_session **sess,
				int devid)
{
	return 1;
}

/**
 * @returns 1 on success, 0 on auth failure, and -1 on error
 */

static int perform_crypto_op(struct rte_crypto_op *crypto_op, pal_ecdsa_ctx_t *pal_ctx)
{
	return 1;
}

/**
 * @returns 1 on success, 0 on failure
 * Conforms to OpenSSL's ECDSA_sign semantics
 */
int pal_ecdsa_sign(pal_ecdsa_ctx_t *pal_ctx)
{
	return 0;
}

/**
 * @returns 1 on successful verification, 0 on verification failure, -1 on error
 */
int pal_ecdsa_verify(pal_ecdsa_ctx_t *pal_ctx)
{
	return 0;
}

int pal_ecdsa_ec_point_multiplication( pal_ecdsa_ctx_t *pal_ctx)
{
	return 0;
}
