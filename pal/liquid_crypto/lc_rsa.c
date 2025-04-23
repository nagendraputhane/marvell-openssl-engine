/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */


#define _GNU_SOURCE
#include <errno.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <dao_liquid_crypto.h>
#include <hw/cpt.h>
#include "pal_rsa.h"
#include  "defs.h"


extern  int cpt_num_asym_requests_in_flight ;

int pal_rsa_capability_check_modlen(int16_t modlen)
{
	return 0;
}


int pal_rsa_priv_enc(pal_rsa_ctx_t *pal_ctx, int flen,const unsigned char *from, unsigned char *to)
{
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res res;
	int ret ,nb_rx=0;
	uint64_t op_cookie = (uint64_t)(uintptr_t)pal_ctx;
	pal_ctx->is_completed = 0;

	memset(&res, 0, sizeof(res));

	if(pal_ctx->use_crt_method){
	ret = dao_liquid_crypto_enq_op_pkcs1v15enc_crt(dev_id, qp_id,(uint16_t)pal_ctx->rsa_n_len,flen,pal_ctx->rsa_qt_q_data,pal_ctx->rsa_qt_dQ_data,
							pal_ctx->rsa_qt_p_data,pal_ctx->rsa_qt_dP_data,pal_ctx->rsa_qt_qInv_data,(uint8_t*)from,(uint8_t*)to,op_cookie);
    }
    else {
    ret = dao_liquid_crypto_enq_op_pkcs1v15enc(dev_id, qp_id,DAO_LC_RSA_KEY_TYPE_PRIVATE,
							(uint16_t)pal_ctx->rsa_n_len,(uint16_t)pal_ctx->rsa_d_len,flen,
							pal_ctx->rsa_n_data,pal_ctx->rsa_d_data,(uint8_t*)from,(uint8_t*)to,op_cookie);
	}

	if (ret < 0) {
		fprintf(stderr, "Could not enqueue RSA sign operation ");
		return -1;
	}

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);

	while(pal_ctx->is_completed == 0)
	{
		nb_rx=dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);

		if (nb_rx == 0 && pal_ctx->async_cb){
			pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
		}
		else if (nb_rx > 0) {
			pal_rsa_ctx_t *completed_ctx = (pal_rsa_ctx_t *)(uintptr_t)res.op_cookie;
			completed_ctx->is_completed = 1;
			completed_ctx->is_success = !res.res.cn10k.uc_compcode;
			completed_ctx->out_len = (int)res.rsa.data_out_len;
		}
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->is_success)
	{
		return pal_ctx->out_len;
	}

	return -1;
}

int pal_rsa_pub_dec(pal_rsa_ctx_t *pal_ctx, int flen,const unsigned char *from, unsigned char *to)
{

	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res res;
	int ret,nb_rx=0;
	uint64_t op_cookie = (uint64_t)(uintptr_t)pal_ctx;
	pal_ctx->is_completed = 0;

	memset(&res, 0, sizeof(res));

	ret = dao_liquid_crypto_enq_op_pkcs1v15dec(dev_id, qp_id,DAO_LC_RSA_KEY_TYPE_PUBLIC,
		(uint16_t)pal_ctx->rsa_n_len,(uint16_t)pal_ctx->rsa_e_len,pal_ctx->rsa_n_data,
		pal_ctx->rsa_e_data,(uint8_t*)from,(uint8_t*)to,op_cookie);

	if (ret < 0) {
		fprintf(stderr, "Could not enqueue RSA verify operation");
		return -1;
	}

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);


	while(pal_ctx->is_completed == 0)
	{
		nb_rx=dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);

		if (nb_rx == 0 && pal_ctx->async_cb){
			pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
		}
		else if (nb_rx > 0) {
			pal_rsa_ctx_t *completed_ctx = (pal_rsa_ctx_t *)(uintptr_t)res.op_cookie;
			completed_ctx->is_completed = 1;
			completed_ctx->is_success = !res.res.cn10k.uc_compcode;
			completed_ctx->out_len = (int)res.rsa.data_out_len;
		}
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->is_success)
	{
		return pal_ctx->out_len;
	}

	return -1;

}

int pal_rsa_pub_enc(pal_rsa_ctx_t *pal_ctx, int flen,const unsigned char *from, unsigned char *to)
{

	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res res;
	int ret,nb_rx=0;
	uint64_t op_cookie = (uint64_t)(uintptr_t)pal_ctx;
	pal_ctx->is_completed = 0;

	memset(&res, 0, sizeof(res));

	ret = dao_liquid_crypto_enq_op_pkcs1v15enc(dev_id, qp_id,DAO_LC_RSA_KEY_TYPE_PUBLIC,
		(uint16_t)pal_ctx->rsa_n_len,(uint16_t)pal_ctx->rsa_e_len,(uint16_t)flen,
		pal_ctx->rsa_n_data,pal_ctx->rsa_e_data,(uint8_t*)from,(uint8_t*)to,op_cookie);


	if (ret < 0) {
		fprintf(stderr, "Could not enqueue RSA encrypt operation");
		return -1;
	}

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);


	while(pal_ctx->is_completed == 0)
	{
		nb_rx=dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);

		if (nb_rx == 0 && pal_ctx->async_cb){
			pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
		}
		else if (nb_rx > 0) {
			pal_rsa_ctx_t *completed_ctx = (pal_rsa_ctx_t *)(uintptr_t)res.op_cookie;
			completed_ctx->is_completed = 1;
			completed_ctx->is_success = !res.res.cn10k.uc_compcode;
			completed_ctx->out_len = (int)res.rsa.data_out_len;
		}
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->is_success)
	{
		return pal_ctx->out_len;
	}

	return -1;
}

int pal_rsa_priv_dec(pal_rsa_ctx_t *pal_ctx, int flen,const unsigned char *from, unsigned char *to)
{
	uint8_t dev_id = glb_params.dev_id;
	uint16_t qp_id = glb_params.qp_id;
	struct dao_lc_res res;
	int ret,nb_rx=0;
	uint64_t op_cookie = (uint64_t)(uintptr_t)pal_ctx;
	pal_ctx->is_completed = 0;

	memset(&res, 0, sizeof(res));

	if(pal_ctx->use_crt_method)
	{
		ret = dao_liquid_crypto_enq_op_pkcs1v15dec_crt(dev_id,qp_id,(uint16_t)pal_ctx->rsa_n_len,pal_ctx->rsa_qt_q_data,
		pal_ctx->rsa_qt_dQ_data,pal_ctx->rsa_qt_p_data,pal_ctx->rsa_qt_dP_data,
		pal_ctx->rsa_qt_qInv_data,(uint8_t*)from,(uint8_t*)to,op_cookie);
	}
	else
	{
		ret = dao_liquid_crypto_enq_op_pkcs1v15dec(dev_id, qp_id,DAO_LC_RSA_KEY_TYPE_PRIVATE,
		(uint16_t)pal_ctx->rsa_n_len,(uint16_t)pal_ctx->rsa_d_len,pal_ctx->rsa_n_data,
		pal_ctx->rsa_d_data,(uint8_t*)from,(uint8_t*)to,op_cookie);
	}

	if (ret < 0) {
		fprintf(stderr, "Could not enqueue RSA decrypt operation");
		return -1;
	}

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->async_cb)
		pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);


	while(pal_ctx->is_completed == 0)
	{
		nb_rx=dao_liquid_crypto_dequeue_burst(dev_id, qp_id, &res, 1);

		if (nb_rx == 0 && pal_ctx->async_cb){
			pal_ctx->async_cb(NULL, NULL, 0, NULL, NULL, ASYNC_JOB_PAUSE);
		}
		else if (nb_rx > 0) {
			pal_rsa_ctx_t *completed_ctx = (pal_rsa_ctx_t *)(uintptr_t)res.op_cookie;
			completed_ctx->is_completed = 1;
			completed_ctx->is_success = !res.res.cn10k.uc_compcode;
			completed_ctx->out_len = (int)res.rsa.data_out_len;
		}
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);

	if(pal_ctx->is_success)
	{
		return pal_ctx->out_len;
	}

	return -1;
}
