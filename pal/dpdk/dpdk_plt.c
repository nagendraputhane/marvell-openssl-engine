/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include "pal.h"
#include "defs.h"
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#define OSSL_PMD_MAX_ARGS 7
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

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
extern const char *crypto_name;

static inline int build_eal_params_for_ossl_pmd(char ***argv_out, int *argc_out)
{
	uint64_t feature_flags = 0;
	char idstr[10];
	int  idx = -1, ret = 0;
	char cpu[3] = {0};
	int max_args = OSSL_PMD_MAX_ARGS;

	snprintf(idstr, sizeof(idstr), "rte%d", getpid());
	snprintf(cpu, sizeof(cpu), "%2d", sched_getcpu());

	char **argv = malloc(max_args * sizeof(char *));
	if (!argv) {
		fprintf(stderr, "Failed to allocate memory for argv\n");
		return -1;
	}

	int i = 0;
	argv[i++] = strdup("DPDK");
	argv[i++] = strdup("--file-prefix");
	argv[i++] = strdup(idstr);
	argv[i++] = strdup("--socket-mem=500"); // 500MB per process
	argv[i++] = strdup("-l");
	argv[i++] = strdup(cpu);
	argv[i++] = strdup("-d");
	argv[i++] = strdup("librte_mempool_ring.so");

	*argv_out = argv;
	*argc_out = i;

	return 0;
}
static inline int build_eal_params_for_cnxk_pmd(char ***argv_out, int *argc_out)
{
	int cpuquot, cpurem;
	char devstr[20], idstr[10] , cpu[3] = {0};
	char *bus = getenv("OTX2_BUS");

	snprintf(idstr, sizeof(idstr), "rte%d", getpid());
	snprintf(cpu, sizeof(cpu), "%2d", sched_getcpu());

	cpuquot = (unsigned short)(sched_getcpu() + 1) / OTX2_NUM_PER_BUS;
	cpurem = (unsigned short)(sched_getcpu() + 1)  % OTX2_NUM_PER_BUS;

	if (!bus) {
		fprintf(stderr, " OTX2 BUS slot not defined. Using default\n");
		bus = OTX2_DEF_DEV_BUS;
	}
	/* Symmetric device */
	snprintf(devstr, sizeof(devstr), "%04d:%s:0%d.%d", OTX2_DEV_DOMAIN, bus, cpuquot, cpurem);
	char **argv = malloc(OTX2_NUM_ARGS * sizeof(char *));
	if (!argv) {
		fprintf(stderr, "Failed to allocate memory\n");
		return -1;
	}
	int i=0;
	argv[i++] = strdup("DPDK");
	argv[i++] = strdup("--file-prefix");
	argv[i++] = strdup(idstr);
	argv[i++] = strdup("--socket-mem=500"); /* 500MB per process */
	argv[i++] = strdup("-l");
	argv[i++] = strdup(cpu);
	argv[i++] = strdup("-d");
	argv[i++] = strdup("librte_mempool_ring.so");
	argv[i++] = strdup("-d");
	argv[i++] = strdup("librte_crypto_cnxk.so");
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
	argv[i++] = strdup("-a");
	argv[i++] = strdup(devstr);
#else
	argv[i++] = strdup("-w");
	argv[i++] = strdup(devstr);
#endif

while (i < OTX2_NUM_ARGS) {
	argv[i++] = NULL;
}

	*argv_out = argv;
	*argc_out = i;
	return 0;
}
static inline int cpt_hw_init(void)
{
	uint64_t feature_flags = 0;
	int argc, idx = -1, ret = 0;
	char **argv = NULL;

	crypto_name = getenv("CRYPTO_DRIVER");
	if(crypto_name && strcmp(crypto_name, "crypto_openssl")== 0 )
	{
		build_eal_params_for_ossl_pmd(&argv, &argc);
	}
	else{
		build_eal_params_for_cnxk_pmd(&argv, &argc);
	}

	ret = pal_crypto_init(argc, argv, 1, crypto_name);
	if (ret < 0) {
		engine_log(ENG_LOG_ERR, "Failed in pal_crypto_init\n");
		free(argv);
		return -1;
	}
	free(argv);
	return 0;
}

int pal_plt_init()
{
    int lcoreid;
    int ret = 0;
    int i = 0;
    int thread_idid;
    int sym_dev_count = 0, asym_dev_count = 0;

    ret = cpt_hw_init();
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
