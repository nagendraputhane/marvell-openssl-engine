/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "pal.h"
#include "defs.h"
#ifdef OSSL_PMD
#include "prov_ossl.h"
#else
#include "prov_cnxk.h"
#endif

unsigned int dev_in_use = 0;
int asym_queues[PAL_MAX_THREADS];
int sym_queues[PAL_MAX_THREADS];
int asym_dev_id[PAL_MAX_THREADS];
int sym_dev_id[PAL_MAX_THREADS];
unsigned int queues_per_vf[PAL_MAX_CPT_DEVICES] = {0};
uint32_t cpt_provider_sessions = CPT_PROVIDER_DEFAULT_SESSIONS;
uint32_t cpt_provider_num_mbufs = CPT_PROVIDER_DEFAULT_MBUFS;
uint32_t cpt_provider_num_sym_ops = CPT_PROVIDER_DEFAULT_SYM_OPS;
uint32_t cpt_provider_num_asym_ops = CPT_PROVIDER_DEFAULT_ASYM_OPS;
uint16_t cpt_provider_pool_cache_size = CPT_PROVIDER_DEFAULT_POOL_CACHE_SIZE;
uint16_t cpt_provider_asym_qp_desc_count = CPT_PROVIDER_DEFAULT_ASYM_QP_DESC_COUNT;
uint16_t cpt_provider_sym_qp_desc_count = CPT_PROVIDER_DEFAULT_SYM_QP_DESC_COUNT;

int pal_plt_init()
{
    int lcoreid;
    int ret = 0;
    int i = 0;
    int thread_idid;
    int sym_dev_count = 0, asym_dev_count = 0;

    ret = provcpt_hw_init();
    if (ret < 0) {
        fprintf(stderr, "Failed in platform init\n");
}

    sym_dev_count = pal_crypto_get_num_devices();
    asym_dev_count = sym_dev_count;

    /* Setup default queues for thread_id 0 when cptvf_queues not configured */
    if (sym_dev_count > 0 && dev_in_use == 0) {
        for (thread_idid = 0; thread_idid < PAL_MAX_THREADS; thread_idid++) {
            sym_dev_id[thread_idid] = asym_dev_id[thread_idid] = -1;
            sym_queues[thread_idid] = asym_queues[thread_idid] = -1;
        }
        thread_idid = 0;
        queues_per_vf[thread_idid] = 2;
        sym_dev_id[thread_idid] = 0;
        sym_queues[thread_idid] = 0;
        asym_dev_id[thread_idid] = 0;
        asym_queues[thread_idid] = 1;
        dev_in_use = 1;
    }

    dev_in_use = MIN(sym_dev_count, (int)rte_lcore_count());

    pal_cryptodev_config_t config = {
        .q_per_dev = queues_per_vf,
        .asym_qs = asym_queues,
        .sym_qs = sym_queues,
        .sym_dev_ids = sym_dev_id,
        .asym_dev_ids = asym_dev_id,
        .dev_in_use = dev_in_use,
        .sym_qp_descs = cpt_provider_sym_qp_desc_count,
        .asym_qp_descs = cpt_provider_asym_qp_desc_count,
        .nb_mbufs = cpt_provider_num_mbufs,
 .nb_ops = cpt_provider_num_sym_ops,
        .nb_sessions = cpt_provider_sessions,
        .pool_cache_size = cpt_provider_pool_cache_size,
        .custom_mbuf_sz = CPT_PROVIDER_MBUF_CUSTOM_BUF_SIZE,
        .digest_len = PAL_CPT_DIGEST_LEN,
        .nb_asym_ops = cpt_provider_num_asym_ops,
        .nb_sym_ops = cpt_provider_num_sym_ops,
    };


    ret = pal_cryptodev_configuration(&config);
    if (ret < 0) {
        fprintf(stderr,"pal_cryptodev_configuration failed\n");
        return 0;
    }


    fprintf(stderr,"sym_dev_count:%d,dev_in_use: %d\n",sym_dev_count,dev_in_use);

    RTE_LOG(INFO, USER1, "CPT DEVICES AND LCORE MAP:\n");
    RTE_LOG(INFO, USER1, "==========================\n");
    i = 0;
    if (sym_dev_count > 0) {
        RTE_LCORE_FOREACH(lcoreid)
        {
            sym_dev_id[lcoreid] = pal_get_sym_valid_dev(sym_dev_id[lcoreid]);
            sym_queues[lcoreid] = 0;
            RTE_LOG(INFO, USER1, "lcoreid: %d, symid: %d\n",
                    lcoreid, sym_dev_id[lcoreid]);
            i++;
        }
    }

    i = 0;
    if (asym_dev_count > 0) {
        RTE_LCORE_FOREACH(lcoreid)
{
            asym_dev_id[lcoreid] = pal_get_sym_valid_dev(asym_dev_id[lcoreid]);
            asym_queues[lcoreid] = 1;
            RTE_LOG(INFO, USER1, "lcoreid: %d, asymid: %d\n",
                    lcoreid, asym_dev_id[lcoreid]);
            i++;
        }
    }

    RTE_LOG(INFO, USER1, "==========================\n");
    RTE_LOG(INFO, USER1, "C%d, mapped entries for given cores: %d\n",
            rte_lcore_id(), i);

    return 1;
}

int asym_get_valid_devid_qid(int *devid, int *queue)
{
	int thread_id = pal_get_thread_id();

	if(thread_id == -1 || asym_dev_id[thread_id] == -1) {
		fprintf(stderr, "Invalid thread_id %d\n", thread_id);
		return 0;
	}

	*devid = asym_dev_id[thread_id];
	*queue = asym_queues[thread_id];
	return 1;
}

int sym_get_valid_devid_qid(int *devid, int *queue)
{
	int thread_id = pal_get_thread_id();

	if(thread_id == -1 || sym_dev_id[thread_id] == -1) {
		fprintf(stderr, "Invalid thread_id %d\n", thread_id);
		return 0;
	}

	*devid = sym_dev_id[thread_id];
	*queue = sym_queues[thread_id];
	return 1;
}
