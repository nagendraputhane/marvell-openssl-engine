/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include "cpt_engine.h"
#include "pal/pal.h"
#include "pal/pal_rsa.h"
#include "cpt_engine_ecdsa.h"
#include "cpt_engine_rsa.h"
#include "cpt_engine_malloc.h"
#include "pal/pal_common.h"

unsigned int dev_in_use = 0;
char *crypto_drv_name = NULL;
OSSL_ASYNC_FD zero_fd;

int dpdkcpt_cipher_nids[] = { NID_aes_128_cbc, NID_aes_256_cbc,
			NID_aes_128_gcm, NID_aes_256_gcm,
			NID_aes_128_cbc_hmac_sha1, NID_aes_256_cbc_hmac_sha1,
			NID_chacha20_poly1305, 0};

/* Engine Id and Name */
static const char *cpt_engine_id = "dpdk_engine";
static const char *cpt_engine_name = "OpenSSL Engine v1.0 using DPDK";

static ENGINE_CMD_DEFN cpt_engine_cmd_defns [] =
{
	{CPT_ENGINE_CTRL_CMD_EAL_PARAMS, "eal_params",
	 "Parameters for rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_EAL_INIT, "eal_init",
	 "Perform rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_EAL_PID_IN_FP, "eal_pid_in_fileprefix",
	 "Use PID in file-prefix for rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_EAL_CORE_BY_CPU, "eal_core_by_cpu",
	 "Specify current corenum in rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_EAL_CPTVF_BY_CPU, "eal_cptvf_by_cpu",
	 "Use current corenum to determine whitelisting of crypto VF BDF", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_CRYPTO_DRIVER, "crypto_driver",
	 "DPDK crypto PMD to use", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_CPTVF_QUEUES, "cptvf_queues",
	 "VF Queues to map for each thread_id ", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_ENGINE_ALG_SUPPORT, "engine_alg_support",
	 "Enable/disable asymmetric or symmetric support in openssl engine ", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_DPDK_QP_CONF_PARAMS, "dpdk_qp_conf_params",
	"DPDK Mempool and qp descriptor count config params for Symmetric & Asymmetric operations", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_HW_OFFLOAD_THRESH_PKTSZ, "hw_offload_pkt_sz_thresh",
	"Threshold pktsize value configured for HW offload", ENGINE_CMD_FLAG_NUMERIC},
	{CPT_ENGINE_CTRL_CMD_ENG_LOG_LEVEL, "engine_log_level",
	"DPDK Engine_level to use", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_ENG_LOG_FILE, "engine_log_file",
	"DPDK Engine_logs to be dumped", ENGINE_CMD_FLAG_STRING},
	{CPT_ENGINE_CTRL_CMD_POLL, "POLL",
	"Poll the queues for running thread_id", ENGINE_CMD_FLAG_NO_INPUT},
	{CPT_ENGINE_GET_NUM_REQUESTS_IN_FLIGHT, "GET_NUM_REQUESTS_IN_FLIGHT",
	"Get the number of in-flight requests", ENGINE_CMD_FLAG_NUMERIC},
	{0, NULL, NULL, 0}
};

#define CPT_ENGINE_MAX_EAL_PARAMS 64
#define CPT_ENGINE_MAX_EAL_ARGV 64

static char * cpt_engine_eal_params[CPT_ENGINE_MAX_EAL_PARAMS];
static char * cpt_engine_eal_argv[CPT_ENGINE_MAX_EAL_ARGV];
static int cpt_engine_eal_params_cnt = 0;
static int cpt_engine_eal_argc = 0;
static char * cpt_engine_queue_conf = NULL;
static uint8_t disable_eal_init = 0;
static uint8_t engine_level = 0;
static FILE* log_fp = NULL;
static char * cpt_engine_alg_params = NULL;
static uint16_t pool_cachesz[CPT_ENGINE_MAX_NUM_POOL];

int asym_queues[PAL_MAX_THREADS];
int sym_queues[PAL_MAX_THREADS];
int asym_dev_id[PAL_MAX_THREADS];
int sym_dev_id[PAL_MAX_THREADS];
unsigned int queues_per_vf[PAL_MAX_CPT_DEVICES] = {0};
uint32_t cpt_engine_sessions = CPT_ENGINE_DEFAULT_SESSIONS;
uint32_t cpt_engine_num_mbufs = CPT_ENGINE_DEFAULT_MBUFS;
uint32_t cpt_engine_num_sym_ops = CPT_ENGINE_DEFAULT_SYM_OPS;
uint32_t cpt_engine_num_asym_ops = CPT_ENGINE_DEFAULT_ASYM_OPS;
uint16_t cpt_engine_pool_cache_size = CPT_ENGINE_DEFAULT_POOL_CACHE_SIZE;
uint16_t cpt_engine_asym_qp_desc_count = CPT_ENGINE_DEFAULT_ASYM_QP_DESC_COUNT;
uint16_t cpt_engine_sym_qp_desc_count = CPT_ENGINE_DEFAULT_SYM_QP_DESC_COUNT;
uint16_t hw_offload_pktsz_thresh = HW_OFFLOAD_PKT_SZ_THRESHOLD_DEFAULT;

extern int cpt_num_asym_requests_in_flight;
extern int cpt_num_cipher_pipeline_requests_in_flight;

int cpt_num_kdf_requests_in_flight = 0;
/* Multi-buffer number of items in queue */
int cpt_num_asym_mb_items_in_queue = 0;
int cpt_num_kdf_mb_items_in_queue = 0;
int cpt_num_cipher_mb_items_in_queue = 0;

static inline int process_cpt_engine_queue_conf(char*, int);

/* RSA */
static RSA_METHOD *cpt_engine_rsa_method = NULL;
static EC_KEY_METHOD *cpt_engine_eckey_method = NULL;

/* Engine Lifetime functions */
static int cpt_engine_destroy(ENGINE *e);
static int cpt_engine_init(ENGINE *e);
static int cpt_engine_ctrl(ENGINE *e, int cmd, long numval, void * ptrval, void (*cb) (void));
static int cpt_engine_finish(ENGINE *e);

static int cpt_engine_cap_ciphers(const int **nids, ENGINE *e);

/* Setup ciphers */
static int cpt_engine_ciphers(ENGINE *, const EVP_CIPHER **, const int **, int);

static const EC_KEY_METHOD *default_eckey_meth = NULL;

int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
		     BIGNUM **rp) = NULL;
ECDSA_SIG *(*ecdsa_sign_sig)(const unsigned char *dgst, int dgst_len,
			  const BIGNUM *in_kinv, const BIGNUM *in_r,
			  EC_KEY *eckey) = NULL;
int (*ecdsa_verify_sig)(const unsigned char *dgst, int dgst_len,
		     const ECDSA_SIG *sig, EC_KEY *eckey) = NULL;

static int ec_key_set_group(EC_KEY *key, const EC_GROUP *grp)
{
       int nid = EC_GROUP_get_curve_name(grp);

       switch (nid) {
       case NID_X9_62_prime192v1:
       case NID_secp224r1:
       case NID_X9_62_prime256v1:
       case NID_secp384r1:
       case NID_secp521r1:
               break;
       default:
               /* Unsupported curve */
               return EC_KEY_set_method(key, default_eckey_meth);
       }

       return 1;
}

/*
* Parse core numbers from below format
* cptvf_queues = {{c1, c2, c2, c3...}, {c4, c4, c6, ...}, ...}
*/
static inline int process_cpt_engine_queue_conf(char* queue_conf, int sym_dev_count) {
	char * tok = NULL, *range_tok = NULL;
	int vf = -1;
	unsigned int parsing_done = 0, queue = 0;
	unsigned int thread_id = 0, thread_id_l = 0, thread_id_h = 0;

	for (thread_id = 0; thread_id < PAL_MAX_THREADS; thread_id++) {
		sym_dev_id[thread_id] = asym_dev_id[thread_id] = -1;
		sym_queues[thread_id] = asym_queues[thread_id] = -1;
	}
	tok = strpbrk(queue_conf, "{");
	if (tok == NULL || *tok == '\0') {
		engine_log(ENG_LOG_ERR, "%s: cptvf_queues: Invalid Format\n", __FUNCTION__);
		return -1;
	}
	tok = strpbrk(tok+1, "{");
	while (tok != NULL && *tok != '\0') {
		switch(*tok) {
			case '{':
			/* Start of one VF config */
			vf++;
			queue = 0;
			/* Only parse config for the devices available */
			if (vf >= sym_dev_count) {
				parsing_done = 1;
				break;
			}
			if (vf >= PAL_MAX_CPT_DEVICES) {
				engine_log(ENG_LOG_ERR,
					"%s: cptvf_queues: Too many VFs configured\n", __FUNCTION__);
				return -1;
			}
			/* Fall through */
			case ',':
			/* Expect core number after '{' and ',' */
			sscanf(tok+1, "%d", &thread_id_l);
			if (thread_id_l > PAL_MAX_THREADS) {
				engine_log(ENG_LOG_ERR, "%s: Core number exceeds PAL_MAX_THREADS\n", __FUNCTION__);
				return -1;
			}
			thread_id_h = thread_id_l;
			range_tok = strpbrk(tok+1, "-{},");
			/* If next token is -, the input is a thread_id range of format %d-%d */
			if (range_tok != NULL && *range_tok == '-') {
				tok = range_tok;
				sscanf(tok+1, "%d", &thread_id_h);
				if (thread_id_h > PAL_MAX_THREADS) {
					engine_log(ENG_LOG_ERR, "%s: Core number exceeds PAL_MAX_THREADS\n", __FUNCTION__);
					return -1;
				}
			}
			for (thread_id = thread_id_l; thread_id <= thread_id_h; thread_id++) {
				if (sym_queues[thread_id] == -1) {
					sym_queues[thread_id] = queue;
					sym_dev_id[thread_id] = vf;
					/* Setup same queue for asym operation as well,
					* will be overwritten when second queue is configuered for same core */
					asym_queues[thread_id] = queue;
					asym_dev_id[thread_id] = vf;
					queues_per_vf[vf]++;
				} else if (asym_dev_id[thread_id] == sym_dev_id[thread_id] &&
								asym_queues[thread_id] == sym_queues[thread_id]){
					asym_queues[thread_id] = queue;
					asym_dev_id[thread_id] = vf;
					queues_per_vf[vf]++;
				} else {
					engine_log(ENG_LOG_ERR,
						"%s: cptvf_queues: maximum only 2 queues per core\n", __FUNCTION__);
					return -1;
				}
				queue++;
			}
			break;

			case '}':
			/* End of one VF config */
			dev_in_use++;
			tok = strpbrk(tok+1, "{},");
			if (tok != NULL && *tok == '}') {
				/* }} marks the end of complete config */
				parsing_done = 1;
			} else if (tok == NULL || *tok != ',') {
				engine_log(ENG_LOG_ERR, "%s: cptvf_queues: Invalid Format\n", __FUNCTION__);
				return -1;
			}
			break;
		}
		if (parsing_done) break;
		if (tok == NULL) {
			engine_log(ENG_LOG_ERR, "%s: cptvf_queues: Invalid Format\n", __FUNCTION__);
			return -1;
		}
		tok = strpbrk(tok+1, "{},");
	}

	return 0;
}

/*
 * OSSL_CONF_INIT: use openssl.cnf file for configuring engine.
 * When using conf file, register engine lifecycle functions and cpt_engine_init will be called later while processing conf file.
 */
static int cpt_engine_basic_bind(ENGINE *e)
{
#ifdef OSSL_CONF_INIT
	if (!ENGINE_set_id(e, cpt_engine_id) ||
	    !ENGINE_set_name(e, cpt_engine_name) ||
	    !ENGINE_set_destroy_function(e, cpt_engine_destroy) ||
	    !ENGINE_set_init_function(e, cpt_engine_init) ||
	    !ENGINE_set_cmd_defns(e, cpt_engine_cmd_defns) ||
	    !ENGINE_set_ctrl_function(e, cpt_engine_ctrl) ||
	    !ENGINE_set_finish_function(e, cpt_engine_finish)) {
		return 0;
	}
#else
	SET_ENGINE_ALG_FLAGS(e, (ENGINE_get_flags(e)|ALL_ALG_SUPPORT_MASK));
	if (!cpt_engine_init(e)) {
		return 0;
	}
#endif
	return 1;
}

static int bind_cpt_engine(ENGINE *e)
{
	struct rte_cryptodev_config conf;
	int thread_idid;
	int sym_dev_count = 0;
	int ret = 0;
	int i = 0, q = 0;


	if ((ENGINE_get_flags(e)&ALL_ALG_SUPPORT_MASK))
		engine_log(ENG_LOG_ERR, "CPT HW Offload Configured!!!\n");

	if ((zero_fd = open("/dev/zero", 0)) < 0)
		return -1;

	ret = pal_crypto_init(cpt_engine_eal_argc, cpt_engine_eal_argv, !disable_eal_init, crypto_drv_name);
	if (ret < 0) {
		engine_log(ENG_LOG_ERR, "Failed in platform init\n");
		return 0;
	}

	sym_dev_count = pal_crypto_get_num_devices();
	if(cpt_engine_queue_conf != NULL &&
			process_cpt_engine_queue_conf(cpt_engine_queue_conf, sym_dev_count) < 0) {
		engine_log(ENG_LOG_ERR, "Failed processing cptvf_queues config\n");
		return 0;
	}

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

	pal_cryptodev_config_t config = {
		.q_per_dev = queues_per_vf,
		.asym_qs = asym_queues,
		.sym_qs = sym_queues,
		.sym_dev_ids = sym_dev_id,
		.asym_dev_ids = asym_dev_id,
		.dev_in_use = dev_in_use,
		.sym_qp_descs = cpt_engine_sym_qp_desc_count,
		.asym_qp_descs = cpt_engine_asym_qp_desc_count,
		.nb_mbufs = cpt_engine_num_mbufs,
		.nb_ops = cpt_engine_num_sym_ops,
		.nb_sessions = cpt_engine_sessions,
		.pool_cache_size = cpt_engine_pool_cache_size,
		.custom_mbuf_sz = CPT_ENGINE_RTE_MBUF_CUSTOM_BUF_SIZE,
    .digest_len = PAL_CPT_DIGEST_LEN,
    .nb_asym_ops = cpt_engine_num_asym_ops,
    .nb_sym_ops = cpt_engine_num_sym_ops,
	};

	ret = pal_cryptodev_configuration(&config);
	if (ret < 0) {
					engine_log(ENG_LOG_ERR,
									"Something went wrong in asym config\n");
					return 0;
	}

	if(dev_in_use > 0) {
		if (IS_ALG_ENABLED(e, EC)) {
			/* EC KEY method */
			default_eckey_meth = EC_KEY_get_default_method();
			cpt_engine_eckey_method = EC_KEY_METHOD_new(default_eckey_meth);

			EC_KEY_METHOD_set_init(cpt_engine_eckey_method, NULL, NULL, NULL,
					ec_key_set_group, NULL, NULL);
			EC_KEY_METHOD_get_sign(default_eckey_meth, NULL,
					&ecdsa_sign_setup, &ecdsa_sign_sig);
			EC_KEY_METHOD_set_sign(cpt_engine_eckey_method, ecdsa_sign,
					ecdsa_sign_setup, ecdsa_sign_sig);
			EC_KEY_METHOD_get_verify(default_eckey_meth, NULL,
					&ecdsa_verify_sig);
			EC_KEY_METHOD_set_verify(cpt_engine_eckey_method, ecdsa_verify,
					ecdsa_verify_sig);
			EC_KEY_METHOD_set_keygen(cpt_engine_eckey_method, ecdh_keygen);
			EC_KEY_METHOD_set_compute_key(cpt_engine_eckey_method, ecdh_compute_key);

			if (!ENGINE_set_EC(e, cpt_engine_eckey_method)) {
				engine_log(ENG_LOG_ERR, "Setting EC method failed");
				goto err;
			}
		}
		if (IS_ALG_ENABLED(e, RSA)) {
			/* RSA method */
			default_rsa_meth = RSA_get_default_method();
			if ((cpt_engine_rsa_method = RSA_meth_new("DPDK RSA method", 0)) ==
					NULL ||
					RSA_meth_set_pub_dec(cpt_engine_rsa_method, cpt_engine_rsa_pub_dec) ==
					0 ||
					RSA_meth_set_priv_enc(cpt_engine_rsa_method, cpt_engine_rsa_priv_enc) ==
					0 ||
					RSA_meth_set_pub_enc(cpt_engine_rsa_method, cpt_engine_rsa_pub_enc) ==
					0 ||
					RSA_meth_set_priv_dec(cpt_engine_rsa_method, cpt_engine_rsa_priv_dec) ==
					0) {
				engine_log(ENG_LOG_ERR, "Setting RSA operations failed");
				goto err;
			}
			/* Set ENGINE for RSA */
			if (!ENGINE_set_RSA(e, cpt_engine_rsa_method)) {
				engine_log(ENG_LOG_ERR, "Setting RSA method failed");
				goto err;
			}
		}
	}

	engine_log(ENG_LOG_INFO, "DPDK Pool Params: sessions=%d, mbufs=%d, sym_ops=%d, asym_ops=%d, asym_desc_cnt=%d, sym_desc_cnt=%d\n", cpt_engine_sessions, cpt_engine_num_mbufs, cpt_engine_num_sym_ops, cpt_engine_num_asym_ops, cpt_engine_asym_qp_desc_count, cpt_engine_sym_qp_desc_count);
	engine_log(ENG_LOG_INFO, "CPT DEVICES AND LCORE MAP:\n");
	engine_log(ENG_LOG_INFO, "==========================\n");
	for (thread_idid = 0; thread_idid < PAL_MAX_THREADS; thread_idid++) {
		if (sym_queues[thread_idid] != -1) {
			/* Till this point, sym_dev_id and asym_dev_id arrays
			 * contain VF index rather than actual VF id */
			sym_dev_id[thread_idid] = pal_get_sym_valid_dev(sym_dev_id[thread_idid]);
			asym_dev_id[thread_idid] = pal_get_sym_valid_dev(asym_dev_id[thread_idid]);
			if (IS_ALG_ENABLED(e, GCM) || IS_ALG_ENABLED(e, CBC) || (IS_ALG_ENABLED(e, CPOLY)))
			  engine_log(ENG_LOG_INFO, "thread_idid: %d, symid: %d sym_queue: %d\n",
				  thread_idid, sym_dev_id[thread_idid], sym_queues[thread_idid]);
			if (IS_ALG_ENABLED(e, RSA) || IS_ALG_ENABLED(e, EC))
			  engine_log(ENG_LOG_INFO, "thread_idid: %d, asymid: %d asym_queue: %d\n",
				  thread_idid, asym_dev_id[thread_idid], asym_queues[thread_idid]);
		}
	}
	engine_log(ENG_LOG_INFO, "==========================\n");

	if (!ENGINE_set_id(e, cpt_engine_id) ||
	    !ENGINE_set_name(e, cpt_engine_name) ||
	    !ENGINE_set_ciphers(e, cpt_engine_ciphers) ||
	    !ENGINE_set_destroy_function(e, cpt_engine_destroy) ||
	    !ENGINE_set_finish_function(e, cpt_engine_finish)) {
		engine_log(ENG_LOG_ERR, "CPT_ENGINE Engine set failed");
		goto err;
	}
	return 1;

err:
	pal_crypto_uninit();
	return 0;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
	if (id && (strcmp(id, cpt_engine_id) != 0))
		return 0;
	if (!cpt_engine_basic_bind(e)) {
		engine_log(ENG_LOG_ERR, "Failed to set basic ENGINE_set_xxx properties\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

void ENGINE_load_cpt_engine(void)
{
	ENGINE *e = ENGINE_new();
	if (e == NULL)
		return;
	if (!cpt_engine_basic_bind(e)) {
		ENGINE_free(e);
		engine_log(ENG_LOG_ERR, "Failed to set basic ENGINE_set_xxx properties\n");
		return;
	}
	ENGINE_add(e);
	ENGINE_free(e);
	ERR_clear_error();
}

static int cpt_engine_init(ENGINE *e)
{
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "Engine init filure\n");
		return 0;
	}
	if (!bind_cpt_engine(e)) {
		return 0;
	}
#ifdef CPT_ENGINE_MEM_FUNC
	CRYPTO_set_mem_functions(cpt_engine_malloc, cpt_engine_realloc, cpt_engine_free);
#endif
	return 1;
}

static int cpt_engine_finish(ENGINE *e)
{
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "Engine finish failure\n");
		return 0;
	}
	return 1;
}

static int cpt_engine_ctrl(ENGINE *e, int cmd, long numval, void * ptrval, void (*cb) (void))
{
	char * sp = NULL, *alg = NULL, *value = NULL;
	int engine_flags = 0;
	uint32_t user_val = 0;
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "%s: Invalid Engine\n", __FUNCTION__);
		return 0;
	}
	switch(cmd) {
	case CPT_ENGINE_CTRL_CMD_EAL_PARAMS:
		engine_log(ENG_LOG_ERR, "eal params: '%s'\n", (char *)ptrval);

		/* This is freed implicitly on process exit */
		cpt_engine_eal_params[cpt_engine_eal_params_cnt] = OPENSSL_strdup(ptrval);
		cpt_engine_eal_argv[cpt_engine_eal_argc] =
			strtok_r(cpt_engine_eal_params[cpt_engine_eal_params_cnt], " ", &sp);
		while(cpt_engine_eal_argv[cpt_engine_eal_argc])
		{
			cpt_engine_eal_argc++;
			cpt_engine_eal_argv[cpt_engine_eal_argc] = strtok_r(NULL, " ", &sp);
		}
		cpt_engine_eal_params_cnt++;
		break;
	case CPT_ENGINE_CTRL_CMD_EAL_INIT:
		if (strcmp(ptrval, "no") == 0)
		{
			disable_eal_init = 1;
		}
		break;
	case CPT_ENGINE_CTRL_CMD_EAL_PID_IN_FP:
		if (strcmp(ptrval, "yes") == 0)
		{
			char idstr[50] = {0};
			snprintf(idstr, sizeof(idstr), "--file-prefix=e_cpt_engine%d", getpid());
			engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)idstr);

			/* This is freed implicitly on process exit */
			cpt_engine_eal_argv[cpt_engine_eal_argc++] = OPENSSL_strdup(idstr);
			cpt_engine_eal_argv[cpt_engine_eal_argc] = NULL;
		}
		break;
	case CPT_ENGINE_CTRL_CMD_EAL_CORE_BY_CPU:
		if (strcmp(ptrval, "yes") == 0)
		{
			char cpu[15] = {0};
			snprintf(cpu, sizeof(cpu), "--lcores=0@%2d", sched_getcpu());
			engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)cpu);

			/* This is freed implicitly on process exit */
			cpt_engine_eal_argv[cpt_engine_eal_argc++] = OPENSSL_strdup(cpu);
			cpt_engine_eal_argv[cpt_engine_eal_argc] = NULL;
		}
		break;
	case CPT_ENGINE_CTRL_CMD_EAL_CPTVF_BY_CPU:
		{
		char cptvf[20] = {0};

		/*
		 * cptvf DBDF will be of the form DDDD:BB:dd.f.
		 * DDDD:BB: comes from ptrval
		 * dd.f comes from sched_getcpu()
		 * -w is depcrecated, use -a (allow) for PCI
		 */
		snprintf(cptvf, sizeof(cptvf), "-a%.8s%02d.%d", (char *)ptrval,
			((sched_getcpu() + 1) >> 3) & 0x7, (sched_getcpu() + 1) & 0x7);
		engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)cptvf);

		/* This is freed implicitly on process exit */
		cpt_engine_eal_argv[cpt_engine_eal_argc++] = OPENSSL_strdup(cptvf);
		cpt_engine_eal_argv[cpt_engine_eal_argc] = NULL;
		break;
		}
	case CPT_ENGINE_CTRL_CMD_CRYPTO_DRIVER:
		if (strncmp(ptrval, "crypto_openssl", 14) == 0)
		{
			char vdevstr[50] = {0};
			snprintf(vdevstr, sizeof(vdevstr),
						"--vdev=%s,max_nb_queue_pairs=64", (char *)ptrval);
			engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)vdevstr);

			/* This is freed implicitly on process exit */
			cpt_engine_eal_argv[cpt_engine_eal_argc++] = OPENSSL_strdup(vdevstr);
			cpt_engine_eal_argv[cpt_engine_eal_argc] = NULL;
		}
		crypto_drv_name = OPENSSL_strdup(ptrval);
		break;
	case CPT_ENGINE_CTRL_CMD_CPTVF_QUEUES:
		cpt_engine_queue_conf = OPENSSL_strdup(ptrval);
		break;
	case CPT_ENGINE_CTRL_CMD_ENG_LOG_LEVEL:
		if (strcmp(ptrval, "ENG_LOG_EMERG") == 0) {
			engine_level = 1;
		}
		else if (strcmp(ptrval, "ENG_LOG_ERR") == 0) {
			engine_level = 2;
		}
		else if (strcmp(ptrval, "ENG_LOG_INFO") == 0 ) {
			engine_level = 3;
		}
    pal_register_log_fp_and_level(NULL, engine_level);
		break;
	case CPT_ENGINE_CTRL_CMD_ENG_LOG_FILE:
		log_fp = fopen(ptrval, "a");
			if(!log_fp) {
				engine_log(ENG_LOG_ERR, "Can't open file with Error Number", errno);
			}
		break;
	case CPT_ENGINE_CTRL_CMD_ENGINE_ALG_SUPPORT:
		engine_flags =  ENGINE_get_flags(e);
		cpt_engine_alg_params =  OPENSSL_strdup(ptrval);
		alg = strtok_r(cpt_engine_alg_params, ":", &sp);
		engine_log(ENG_LOG_ERR, "Enabled ");
		while (alg != NULL) {
			if (strcmp(alg, "NONE") == 0) {
				engine_log(ENG_LOG_ERR, "None of the operations ");
			} else if (strcmp(alg, "ALL") == 0) {
				engine_log(ENG_LOG_ERR, "Both Asymmetric and Symmetric Operations ");
				engine_flags|=ALL_ALG_SUPPORT_MASK;
			} else if (strcmp(alg, "ASYM") == 0) {
				engine_log(ENG_LOG_ERR, "Asymmetric Operations Only ");
				engine_flags|=ASYM_ALG_SUPPORT_MASK;
			} else if (strcmp(alg, "SYM") == 0) {
				engine_log(ENG_LOG_ERR, "Symmetric Operations Only ");
				engine_flags|=SYM_ALG_SUPPORT_MASK;
			} else if (strcmp(alg, "RSA") == 0) {
				engine_log(ENG_LOG_ERR, "RSA ");
				engine_flags|=ALG_MASK(RSA);
			} else if (strcmp(alg, "EC") == 0) {
				engine_log(ENG_LOG_ERR, "ECDSA ECDH ");
				engine_flags|=ALG_MASK(EC);
			} else if (strcmp(alg, "GCM") == 0) {
				engine_log(ENG_LOG_ERR, "AES-GCM ");
				engine_flags|=ALG_MASK(GCM);
			} else if (strcmp(alg, "CBC") == 0) {
				engine_log(ENG_LOG_ERR, "AES-CBC ");
				engine_flags|=ALG_MASK(CBC);
			} else if (strcmp(alg, "CPOLY") == 0) {
				engine_log(ENG_LOG_ERR, "CHACHA20-POLY1305 ");
				engine_flags|=ALG_MASK(CPOLY);
			} else {
				engine_log(ENG_LOG_ERR, "ALL operations since value configured is invalid ");
				engine_flags|=ALL_ALG_SUPPORT_MASK;
			}
			alg = strtok_r(NULL, ":", &sp);
		}
		//printf("in engine !!!\n");
		SET_ENGINE_ALG_FLAGS(e, engine_flags);
		break;
	case CPT_ENGINE_CTRL_CMD_DPDK_QP_CONF_PARAMS:
		if ((value = strstr(ptrval, "pool_cachesz=")) !=NULL) {
			cpt_engine_pool_cache_size =
				atoi(value+strlen("pool_cachesz="));
			user_val = cpt_engine_pool_cache_size;
			cpt_engine_pool_cache_size =
				CHECK_LIMIT_AND_ASSIGN(cpt_engine_pool_cache_size,
						CPT_ENGINE_MAX_POOL_CACHE_SIZE,
						CPT_ENGINE_MIN_POOL_CACHE_SIZE);
			if (user_val != cpt_engine_pool_cache_size)
				engine_log(ENG_LOG_ERR, "Configured pool cachesz value "
						"is outside range limit. "
						"Setting value as %d\n",
						cpt_engine_pool_cache_size);
		}
		if ((value = strstr(ptrval, "sessions=")) != NULL) {
			cpt_engine_sessions = atoi(value+strlen("sessions="));
			user_val = cpt_engine_sessions;
			cpt_engine_sessions =
				CHECK_LIMIT_AND_ASSIGN(cpt_engine_sessions,
							CPT_ENGINE_MAX_SESSIONS,
							CPT_ENGINE_MIN_SESSIONS);
			if (user_val != cpt_engine_sessions)
				engine_log(ENG_LOG_ERR,"Configured sessions value is "
					       "outside range limit. Setting "
					       " value as %d\n",
					       cpt_engine_sessions);
		}
		if ((value = strstr(ptrval, "mbufs=")) !=NULL) {
			cpt_engine_num_mbufs = atoi(value+strlen("mbufs="));
			user_val = cpt_engine_num_mbufs;
			cpt_engine_num_mbufs =
				CHECK_LIMIT_AND_ASSIGN(cpt_engine_num_mbufs,
							CPT_ENGINE_MAX_MBUFS,
							CPT_ENGINE_MIN_MBUFS);
			if (user_val != cpt_engine_num_mbufs)
				engine_log(ENG_LOG_ERR, "Configured mbufs value is "
						"outside range limit. Setting"
						" value as %d\n",
						cpt_engine_num_mbufs);
		}
		if ((value = strstr(ptrval, "sym_ops=")) !=NULL) {
			cpt_engine_num_sym_ops = atoi(value+strlen("sym_ops="));
			user_val = cpt_engine_num_sym_ops;
			cpt_engine_num_sym_ops =
				CHECK_LIMIT_AND_ASSIGN(cpt_engine_num_sym_ops,
						       CPT_ENGINE_MAX_SYM_OPS,
						       CPT_ENGINE_MIN_SYM_OPS);
			if (user_val != cpt_engine_num_sym_ops)
				engine_log(ENG_LOG_ERR, "Configured sym_ops value is "
						"outside range limit. Setting "
						"value as %d\n",
						cpt_engine_num_sym_ops);
		}
		if ((value = strstr(ptrval, "asym_ops=")) !=NULL) {
			cpt_engine_num_asym_ops = atoi(value+strlen("asym_ops="));
			user_val = cpt_engine_num_asym_ops;
			cpt_engine_num_asym_ops =
				CHECK_LIMIT_AND_ASSIGN(cpt_engine_num_asym_ops,
						       CPT_ENGINE_MAX_ASYM_OPS,
						       CPT_ENGINE_MIN_ASYM_OPS);
			if (user_val != cpt_engine_num_asym_ops)
				engine_log(ENG_LOG_ERR, "Configured asym ops value is "
						"outside range limit. Setting"
						" value as %d\n",
						cpt_engine_num_asym_ops);
		}
		if ((value = strstr(ptrval, "asym_desc_cnt=")) !=NULL) {
			cpt_engine_asym_qp_desc_count =
				atoi(value+strlen("asym_desc_cnt="));
			user_val = cpt_engine_asym_qp_desc_count;
			cpt_engine_asym_qp_desc_count =
				CHECK_LIMIT_AND_ASSIGN(cpt_engine_asym_qp_desc_count,
						CPT_ENGINE_MAX_ASYM_QP_DESC_COUNT,
						CPT_ENGINE_MIN_ASYM_QP_DESC_COUNT);
			if (user_val != cpt_engine_asym_qp_desc_count)
				engine_log(ENG_LOG_ERR, "Configured asym qp desc count "
						"is outside range limit. "
						"Setting value as %d\n",
						cpt_engine_asym_qp_desc_count);
		}
		if ((value = strstr(ptrval, " sym_desc_cnt=")) !=NULL) {
			cpt_engine_sym_qp_desc_count =
				atoi(value+strlen(" sym_desc_cnt="));
			user_val = cpt_engine_sym_qp_desc_count;
			cpt_engine_sym_qp_desc_count =
				CHECK_LIMIT_AND_ASSIGN(cpt_engine_sym_qp_desc_count,
						CPT_ENGINE_MAX_SYM_QP_DESC_COUNT,
						CPT_ENGINE_MIN_SYM_QP_DESC_COUNT);
			if (user_val != cpt_engine_sym_qp_desc_count)
				engine_log(ENG_LOG_ERR, "Configured sym qp desc count "
						"is outside range limit. "
						"Setting value as %d\n",
						cpt_engine_sym_qp_desc_count);
		}
		break;
	case CPT_ENGINE_CTRL_CMD_HW_OFFLOAD_THRESH_PKTSZ:
		hw_offload_pktsz_thresh = (int)numval;
		hw_offload_pktsz_thresh =
			CHECK_LIMIT_AND_ASSIGN(hw_offload_pktsz_thresh,
						HW_OFFLOAD_PKT_SZ_THRESHOLD_MAX,
						HW_OFFLOAD_PKT_SZ_THRESHOLD_MIN);
		engine_log(ENG_LOG_ERR, "HW Offload threshold pktsz: %d\n",
				hw_offload_pktsz_thresh);
		break;
	case CPT_ENGINE_CTRL_CMD_POLL:
    {
      unsigned int thread_idid = pal_get_thread_id();
      pal_asym_poll(asym_dev_id[thread_idid], asym_queues[thread_idid], ossl_handle_async_asym_job);
      pal_sym_poll(sym_dev_id[thread_idid], sym_queues[thread_idid], ossl_handle_async_job);
      break;
    }
	case CPT_ENGINE_GET_NUM_REQUESTS_IN_FLIGHT:
		if (numval == GET_NUM_ASYM_REQUESTS_IN_FLIGHT) {
			*(int **)ptrval = &cpt_num_asym_requests_in_flight;
		} else if (numval == GET_NUM_KDF_REQUESTS_IN_FLIGHT) {
			*(int **)ptrval = &cpt_num_kdf_requests_in_flight;
		} else if (numval == GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT) {
			*(int **)ptrval = &cpt_num_cipher_pipeline_requests_in_flight;
		} else if (numval == GET_NUM_ASYM_MB_ITEMS_IN_QUEUE) {
			*(int **)ptrval = &cpt_num_asym_mb_items_in_queue;
		} else if (numval == GET_NUM_KDF_MB_ITEMS_IN_QUEUE) {
			*(int **)ptrval = &cpt_num_kdf_mb_items_in_queue;
		} else if (numval == GET_NUM_SYM_MB_ITEMS_IN_QUEUE) {
			*(int **)ptrval = &cpt_num_cipher_mb_items_in_queue;
		} else
			engine_log(ENG_LOG_ERR, "Invalid GET_NUM_REQUESTS_IN_FLIGHT parameter\n");
        break;
	default:
		break;
	}
	return 1;
}

static int cpt_engine_destroy(ENGINE *e)
{
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "Engine destroy failure\n");
		fclose(log_fp);
		return 0;
	}
	pal_crypto_uninit();
	return 1;
}

static int cpt_engine_cap_ciphers(const int **nids, ENGINE *e)
{
  int *cipher_nids, num, i = 0;

  num = (sizeof(dpdkcpt_cipher_nids) -1) /
    sizeof(dpdkcpt_cipher_nids[0]);
  cipher_nids = calloc(1, sizeof(int) * num);

  if (IS_ALG_ENABLED(e, CPOLY)) {
    if(pal_is_hw_sym_algos_supported(PAL_CRYPTO_AEAD_CHACHA20_POLY1305)) {
      cipher_nids[i++] = NID_chacha20_poly1305;
    }
  }

  if (IS_ALG_ENABLED(e, GCM)) {
    if(pal_is_hw_sym_algos_supported(PAL_CRYPTO_CIPHER_AES_GCM)) {
      cipher_nids[i++] = NID_aes_128_gcm;
      cipher_nids[i++] = NID_aes_256_gcm;
    }
  }

  if (IS_ALG_ENABLED(e, CBC)) {
    if(pal_is_hw_sym_algos_supported(PAL_CRYPTO_CIPHER_AES_CBC)) {
      cipher_nids[i++] = NID_aes_128_cbc;
      cipher_nids[i++] = NID_aes_256_cbc;

      if(pal_is_hw_sym_algos_supported(PAL_CRYPTO_CIPHER_AES_CBC_HMAC_SHA1)) {
        cipher_nids[i++] = NID_aes_128_cbc_hmac_sha1;
        cipher_nids[i++] = NID_aes_256_cbc_hmac_sha1;
      }
    }
  }

  cipher_nids[i] = 0;
  *nids = cipher_nids;
  return i;
}

static int cpt_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
			   const int **nids, int nid)
{

	int ok = 1, num = 0;
	(void)e;

	if (cipher == NULL) {
		/* We are returning a list of supported nids */
		num = cpt_engine_cap_ciphers(nids, e);
		return num;
	}

	/* We are being asked for a specific cipher */
	switch (nid) {
	case NID_aes_128_cbc:
		*cipher = cpt_engine_aes_128_cbc();
		break;
	case NID_aes_256_cbc:
		*cipher = cpt_engine_aes_256_cbc();
		break;
	case NID_aes_128_gcm:
		*cipher = cpt_engine_aes_128_gcm();
		break;
	case NID_aes_256_gcm:
		*cipher = cpt_engine_aes_256_gcm();
		break;
	case NID_aes_128_cbc_hmac_sha1:
		*cipher = cpt_engine_aes_128_cbc_hmac_sha1();
		break;
	case NID_aes_256_cbc_hmac_sha1:
		*cipher = cpt_engine_aes_256_cbc_hmac_sha1();
		break;
	case NID_chacha20_poly1305:
		*cipher = cpt_engine_chacha20_poly1305();
		break;
	default:
		ok = 0;
		*cipher = NULL;
		break;
	}
	return ok;
}


