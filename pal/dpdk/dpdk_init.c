/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#include "pal.h"

uint8_t cptdevs[PAL_MAX_CPT_DEVICES];
int sym_valid_dev[PAL_MAX_CPT_SYM_DEVICES];
int asym_valid_dev[PAL_MAX_CPT_ASYM_DEVICES];

int cpt_num_asym_requests_in_flight = 0;
int cpt_num_cipher_pipeline_requests_in_flight = 0;
dpdk_pools_t *pools = NULL;

int sym_dev_count = 0, asym_dev_count = 0;

static uint8_t engine_level = 0;
static FILE* log_fp = NULL;

extern const struct rte_cryptodev_asymmetric_xform_capability *asym_rsa_xform_cap;
static inline void free_all_mempools();

static inline uint64_t
get_next_crypto_dev(int *dev_id, int nb_devs, int cdev_id)
{
	struct rte_cryptodev_info info;

	while ((++(*dev_id)) < nb_devs) {
		rte_cryptodev_info_get(cptdevs[*dev_id], &info);
		/* Check if device belongs to respective driver,
		 * if not proceed with new device, though this
		 * shouldn't happen
		 */
		if (info.driver_id == cdev_id)
			return info.feature_flags;
	}
	return 0ULL;
}

/**
 * @brief Registers the log file pointer and log level for the engine.
 */

void pal_register_log_fp_and_level(FILE* fp, uint32_t level)
{
	log_fp = fp;
	engine_level = level;

	rte_openlog_stream(fp);
}

/**
 * @brief Logs the message to the specified file pointer if the log
 * level is greater than or equal to the engine level.
 */

int engine_log(uint32_t level, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);

	if(engine_level >= level) {
		if(!log_fp)
			vfprintf(stderr, fmt, args);
		else
			vfprintf(log_fp, fmt, args);
	}
	va_end(args);
}
/**
 * @brief Initializes the DPDK environment and the specified cryptographic driver.
 *
 * This function sets up the DPDK environment using the provided command-line arguments
 * and initializes the specified cryptographic driver. It is designed to be called from
 * both the OpenSSL engine and provider contexts.
 *
 * @param argc The number of command-line arguments for DPDK initialization.
 * @param argv An array of strings representing the command-line arguments for DPDK initialization.
 *
 * @return Returns 0 on successful initialization, or a negative value on failure.
 *         Possible error codes include:
 *         - -1: Failed to initialize the DPDK environment.
 *         - -2: Failed to initialize the specified cryptographic driver.
 */

int pal_crypto_init(int argc, char *argv[], bool eal_init, char *driver_name)
{
	int ret = 0;
	int cdev_id, nb_devs, idx= -1;
  uint64_t feature_flags;
	char crypto_driver_name[PAL_MAX_DRIVER_NAME_LEN];
  char *driver = driver_name? driver_name: crypto_driver_name;

	if(eal_init)
	{
		/**
		 * If no RTE EAL arguments are passed then initialize DPDK with hardware specific
		 * default parameters.
		 */

		if(!argc) {
			argv = pal_get_hw_init_params(&argc, crypto_driver_name);
			if(!argv) {
				engine_log(ENG_LOG_ERR, "Failed to get DPDK HW init params\n");
				return -1;
			}
		}
		ret = rte_eal_init(argc, argv);
		if (ret < 0 && (rte_errno !=  EALREADY)) {
			engine_log(ENG_LOG_ERR, "Invalid EAL arguments\n");
			return -1;
		}
	}

  if(!pools) {
    pools = rte_zmalloc("dpdk_pools", sizeof(dpdk_pools_t), 0);
    if (!pools) {
      engine_log(ENG_LOG_ERR, "Failed to allocate memory for dpdk_pools\n");
      return -1;
    }
  }

	/* Get driver id */
	cdev_id = rte_cryptodev_driver_id_get(driver);
	if (cdev_id == -1) {
			engine_log(ENG_LOG_ERR,"CPT PMD must be loaded. Check if "
			"%s is enabled.\n",
			"CONFIG_RTE_LIBRTE_PMD_OCTEONTX2_CRYPTO");
		return -2;
	}

	/* Gets the number of attached crypto devices for particular driver */
	nb_devs = rte_cryptodev_devices_get(driver, cptdevs,
				PAL_MAX_CPT_DEVICES);
	if (!nb_devs) {
		engine_log(ENG_LOG_ERR,"No crypto device found\n");
		return -2;
	}
	feature_flags = get_next_crypto_dev(&idx, nb_devs, cdev_id);

	while (1) {
		if ((feature_flags & RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO) &&
		    (sym_dev_count < PAL_MAX_CPT_SYM_DEVICES)) {
			sym_valid_dev[sym_dev_count++] = cptdevs[idx];
			feature_flags = get_next_crypto_dev(&idx, nb_devs, cdev_id);
			if (!feature_flags)
				break;
		}
	}

	return 0;

}

/* Configure one symmetric device */
static int config_sym_devs(int sym_dev_count, pal_cryptodev_config_t *config)
{
	struct rte_cryptodev_qp_conf qp_conf = {0};
	uint8_t socket_id = rte_socket_id();
	unsigned int lcore;
	int session_size, calc_cachesz = 0;

	/* Configure the queue pair */
	qp_conf.nb_descriptors = config->sym_qp_descs;

	calc_cachesz = MIN(config->pool_cache_size , CACHESZ_LIMIT(config->nb_mbufs * sym_dev_count));

	/* Create the mbuf pool. */
	pools->mbuf_pool = rte_pktmbuf_pool_create(
		"cpt_mbuf_pool", config->nb_mbufs * sym_dev_count,
		calc_cachesz, 0,
		RTE_PKTMBUF_HEADROOM + config->custom_mbuf_sz + config->digest_len,
		socket_id);

	if (!pools->mbuf_pool) {
		engine_log(ENG_LOG_ERR, "Failed to create cpt_mbuf pool\n");
		goto err;
	}

	calc_cachesz = MIN(config->pool_cache_size, CACHESZ_LIMIT(config->nb_sym_ops * sym_dev_count));

	/* Create symmetric op pool */
	pools->sym_op_pool = rte_crypto_op_pool_create(
		"crypto_sym_op_pool", RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		config->nb_sym_ops * sym_dev_count, calc_cachesz,
		PAL_AES_CBC_IV_LENGTH + sizeof(pal_cry_op_status_t),
		socket_id);
	if (!pools->sym_op_pool) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_sym_op pool\n");
		goto err;
	}

	/* Get private session data size. */
	session_size =
		rte_cryptodev_sym_get_private_session_size(sym_valid_dev[0]);

	/* Create session mempool for the session header, with one object
	 * per session.*/
	calc_cachesz = MIN(config->pool_cache_size,
				CACHESZ_LIMIT(config->nb_sessions * sym_dev_count));
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	 pools->sym_ses_pool = rte_cryptodev_sym_session_pool_create(
			"session_pool", config->nb_sessions * sym_dev_count,
			session_size, calc_cachesz, 0, socket_id);
#else
	pools->sym_ses_pool = rte_cryptodev_sym_session_pool_create(
			"session_pool", config->nb_sessions * sym_dev_count, 0,
			calc_cachesz, 0, socket_id);
#endif
	if (!pools->sym_ses_pool) {
		engine_log(ENG_LOG_ERR, "Failed to create session pool\n");
		goto err;
	}

#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
	/* Create private session mempool for the private session data,
	 * with one object per session.*/
	pools->sym_sess_priv_pool =
		rte_mempool_create("session_private_pool",
		config->nb_sessions * sym_dev_count,
		session_size, calc_cachesz, 0,
		NULL, NULL, NULL, NULL, socket_id, 0);
	if (!pools->sym_sess_priv_pool) {
		engine_log(ENG_LOG_ERR, "Failed to create session private pool\n");
		goto err;
	}

	qp_conf.mp_session_private = pools->sym_sess_priv_pool;
#endif
	qp_conf.mp_session = pools->sym_ses_pool;

	/* Multiple lcores sharing same queue is not supported
	 * Thus, sym_queues[lcore] has unique queues */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		if (config->sym_qs[lcore] != -1) {
			if (rte_cryptodev_queue_pair_setup(sym_valid_dev[config->sym_dev_ids[lcore]],
					config->sym_qs[lcore], &qp_conf, socket_id) < 0)
				goto err;
		}
	}
	return 0;

err:
	free_all_mempools();
	return -1;
}

/* Configure one asymmetric device */
static int config_asym_devs(int *asym_valid_dev, int asym_dev_count,
                            pal_cryptodev_config_t *config)
{
	unsigned int lcore;
	uint8_t socket_id = rte_socket_id();
	struct rte_cryptodev_qp_conf asym_qp_conf;
	struct rte_cryptodev_asym_capability_idx idx;
	int asym_session_size, shared_queue, calc_cachesz = 0;

	/* Configure queue pair*/
	asym_qp_conf.nb_descriptors = config->asym_qp_descs;

	/* Get asym dev capability */
	idx.type = RTE_CRYPTO_ASYM_XFORM_RSA;
	asym_rsa_xform_cap = rte_cryptodev_asym_capability_get(asym_valid_dev[0], &idx);
	calc_cachesz = MIN(config->pool_cache_size, CACHESZ_LIMIT(config->nb_asym_ops * asym_dev_count));

	/* Create asymmetric op pool */
	pools->asym_op_pool = rte_crypto_op_pool_create(
		"CRYPTO_ASYM_OP_POOL", RTE_CRYPTO_OP_TYPE_ASYMMETRIC,
		config->nb_asym_ops * asym_dev_count, calc_cachesz,
		/* extra sizeof(void *) to store async job ctx. */
		sizeof(struct rte_crypto_asym_xform) + sizeof(void *),
		socket_id);
	if (pools->asym_op_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_asym_op pool\n");
		goto err;
	}

	/* Get private session data size. */
	asym_session_size = RTE_MAX(
		rte_cryptodev_asym_get_private_session_size(asym_valid_dev[0]),
		rte_cryptodev_asym_get_header_session_size());

	/* Create session mempool, with two objects per session,
	 * one for the session header and another one for the
	 * private session data for the crypto device.*/
	calc_cachesz = MIN(config->pool_cache_size, CACHESZ_LIMIT(config->nb_sessions * 2 * asym_dev_count));
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	pools->asym_sess_pool =
		rte_cryptodev_asym_session_pool_create("asym_session_pool",
				config->nb_sessions * 2 * asym_dev_count,
				calc_cachesz, 0, socket_id);
#else
	pools->asym_sess_pool = rte_mempool_create("asym_session_pool",
			    config->nb_sessions * 2 * asym_dev_count,
			    asym_session_size, calc_cachesz,
			    0, NULL, NULL, NULL, NULL, socket_id, 0);
#endif
	if (pools->asym_sess_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create asym_session pool\n");
		goto err;
	}

  asym_qp_conf.mp_session = pools->asym_sess_pool;
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
	asym_qp_conf.mp_session_private = pools->asym_sess_pool;
#endif

	/* Same queue can be shared for sym and asym operations
	 * Thus, skip queues that are already configured for sym */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		shared_queue = (config->asym_dev_ids[lcore] == config->sym_dev_ids[lcore] &&
				config->asym_qs[lcore] == config->sym_qs[lcore]);
		if (config->asym_qs[lcore] != -1 && !shared_queue) {
			if (rte_cryptodev_queue_pair_setup(sym_valid_dev[config->asym_dev_ids[lcore]],
					config->asym_qs[lcore], &asym_qp_conf, socket_id) < 0)
				goto err;
		}
	}

	return 1;

err:
	free_all_mempools();
	return -1;
}

static inline void free_all_mempools()
{
	rte_mempool_free(pools->mbuf_pool);
	rte_mempool_free(pools->sym_ses_pool);
	rte_mempool_free(pools->sym_op_pool);
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
	rte_mempool_free(pools->sym_sess_priv_pool);
#endif
	rte_mempool_free(pools->asym_op_pool);
	rte_mempool_free(pools->asym_sess_pool);

  memset(pools, 0, sizeof(dpdk_pools_t));
	return;
}

int pal_cryptodev_configuration(pal_cryptodev_config_t *config)
{
	int i, ret;
	struct rte_cryptodev_config conf;

	sym_dev_count = asym_dev_count = MIN(sym_dev_count, config->dev_in_use);

	for (i = 0; i < sym_dev_count; i++) {
		conf.nb_queue_pairs = config->q_per_dev[i];
		conf.socket_id = rte_socket_id();
		conf.ff_disable = 0;
		if (rte_cryptodev_configure(sym_valid_dev[i], &conf) < 0)
			goto err;
	}

	ret = config_sym_devs(sym_dev_count, config);
	if (ret < 0)
	{
		engine_log(ENG_LOG_ERR, "Failed to configure symmetric devices\n");
		goto err;
	}
	ret = config_asym_devs(sym_valid_dev, sym_dev_count, config);
	if (ret < 0)
	{
		engine_log(ENG_LOG_ERR, "Failed to configure asymmetric devices\n");
		goto err;
	}


  engine_log(ENG_LOG_ERR, "mbuf_pool %p sym_ses_pool %p sym_op_pool %p asym_op_pool %p asym_sess_pool %p\n", pools->mbuf_pool, pools->sym_ses_pool, pools->sym_op_pool, pools->asym_op_pool, pools->asym_sess_pool);
	for (i = 0; i < sym_dev_count; i++) {
		if (rte_cryptodev_start(sym_valid_dev[i]) < 0)
				goto err;
	}

	return 0;

err:
	free_all_mempools();
	return -1;
}

void pal_crypto_uninit()
{

	free_all_mempools();
  rte_eal_cleanup();

}

int pal_crypto_get_num_devices(void)
{
	return sym_dev_count;
}

int pal_get_sym_valid_dev(int index)
{
	if(index >= sym_dev_count)
		return -1;

	return sym_valid_dev[index];
}

void pal_get_prop_name_and_desc(char *name,int len, char *rsa_desc,int rsa_desc_len, char *ec_desc, int desc_len)
{
    strncpy(name,"provider=dpdk_provider",len-1);
    name[len-1]='\0';

	strncpy(rsa_desc, "DPDK RSA implementation", rsa_desc_len - 1);
	rsa_desc[rsa_desc_len - 1] = '\0';
	strncpy(ec_desc, "DPDK EC implementation", desc_len - 1);
	ec_desc[desc_len - 1] = '\0';

}

void pal_get_provider_name(char *name, int len)
{
	strncpy(name, "OPENSSL DPDK PROVIDER", len - 1);
	name[len - 1] = '\0';
}
