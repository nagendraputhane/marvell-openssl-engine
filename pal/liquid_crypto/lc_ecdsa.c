/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "pal.h"
#include <openssl/objects.h>
#include "pal_ecdsa.h"

#define MAX_DEQUEUE_OPS 32
extern int cpt_num_asym_requests_in_flight;

/**
 * @returns 1 on success, 0 on failure
 * Conforms to OpenSSL's ECDSA_sign semantics
 */
int pal_ecdsa_sign(pal_ecdsa_ctx_t *pal_ctx)
{
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = (uint64_t)(uintptr_t)pal_ctx;
	uint8_t rs_output[PCURVES_MAX_DER_SIG_LEN * 2]; // Output buffer for R,S values
	struct dao_lc_res res;
	int ret, nb_rx = 0;

	// Initialize completion flags
	pal_ctx->is_completed = 0;
	pal_ctx->is_success = 0;

	// Clear result buffer
	memset(&res, 0, sizeof(res));

	// Enqueue ECDSA sign operation
	ret = dao_liquid_crypto_enq_op_ecdsa_sign(
		dev_id, qp_id, pal_ctx->curve_id,
		pal_ctx->secret_len, pal_ctx->pkey_len, pal_ctx->dlen,
		pal_ctx->secret, pal_ctx->pkey, (uint8_t *)pal_ctx->dgst,
		rs_output, op_cookie);

	if (unlikely(ret < 0)) {
		fprintf(stderr, "Could not enqueue ECDSA sign operation");
		return 0;
	}

	// Increment in-flight counter
	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);

	// If async callback is set, pause the job
	if (pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

	// Wait for operation to complete
	while (pal_ctx->is_completed == 0) {
		nb_rx = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);

		if (nb_rx == 0 && pal_ctx->async_cb) {
			pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
		} else if (nb_rx > 0) {
			pal_ecdsa_ctx_t *completed_ctx = (pal_ecdsa_ctx_t *)(uintptr_t)res.op_cookie;
			completed_ctx->is_completed = 1;
			completed_ctx->is_success = (res.res.cn9k.compcode == DAO_CPT_COMP_GOOD &&
										res.res.cn9k.uc_compcode == DAO_UC_SUCCESS);

			if (completed_ctx->is_success) {
				// Extract signature components (r,s) from result
				uint16_t prime_length = res.ecdsa.ecc_rs_out_len / 2;

				// Copy the signature components
				memcpy(completed_ctx->rdata, rs_output, prime_length);
				memcpy(completed_ctx->sdata, rs_output + prime_length, prime_length);

				// Update lengths
				completed_ctx->rlen = prime_length;
				completed_ctx->slen = prime_length;
			}
		}
	}

	// Decrement in-flight counter
	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	return pal_ctx->is_success;
}

/**
 * @returns 1 on successful verification, 0 on verification failure, -1 on error
 */
int pal_ecdsa_verify(pal_ecdsa_ctx_t *pal_ctx)
{
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	uint64_t op_cookie = (uint64_t)(uintptr_t)pal_ctx;
	struct dao_lc_res res;
	int ret, nb_rx = 0;

	// Initialize completion flags
	pal_ctx->is_completed = 0;
	pal_ctx->is_success = 0;

	memset(&res, 0, sizeof(res));

	// Enqueue ECDSA verify operation
	ret = dao_liquid_crypto_enq_op_ecdsa_verify(
		dev_id, qp_id, pal_ctx->curve_id,
		pal_ctx->rlen, pal_ctx->slen, pal_ctx->dlen,
		pal_ctx->x_data_len, pal_ctx->y_data_len,
		pal_ctx->rdata, pal_ctx->sdata, (uint8_t*)pal_ctx->dgst,
		pal_ctx->x_data, pal_ctx->y_data, op_cookie);

	if (unlikely(ret < 0)) {
		fprintf(stderr, "Could not enqueue ECDSA verify operation");
		return -1;
	}

	// Increment in-flight counter
	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);

	// If async callback is set, pause the job
	if (pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

	// Wait for operation to complete
	while (pal_ctx->is_completed == 0) {
		nb_rx = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);

		if (nb_rx == 0 && pal_ctx->async_cb) {
			pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
		} else if (nb_rx > 0) {
			pal_ecdsa_ctx_t *completed_ctx = (pal_ecdsa_ctx_t *)(uintptr_t)res.op_cookie;
			completed_ctx->is_completed = 1;

			int compcode = (res.res.cn9k.compcode == DAO_CPT_COMP_GOOD);
			int uc_compcode = (res.res.cn9k.uc_compcode == DAO_UC_SUCCESS);
			/* Determine is_success:
			 * compcode == 0                => -1 (error)
			 * compcode == 1 && uc==0       => 0 (verification failed)
			 * compcode == 1 && uc==1       => 1 (verification succeeded)
			 */
			completed_ctx->is_success = (compcode & uc_compcode) + compcode - 1;
		}
	}

	// Decrement in-flight counter
	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	return pal_ctx->is_success;
}

int pal_ecdsa_ec_point_multiplication(pal_ecdsa_ctx_t *pal_ctx)
{
	(void)pal_ctx; /* Unused for now */
	fprintf(stderr, "pal_ecdsa_ec_point_multiplication: not supported yet\n");
	return 0;
}
