/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <rte_eal.h>
#include "pal.h"
#include "defs.h"


#define TEST_LC_MAX_OUTPUT_LEN 5120
struct global_params glb_params;
int cpt_num_asym_requests_in_flight = 0;
int cpt_num_cipher_pipeline_requests_in_flight = 0;
static uint8_t log_level = 0;
static FILE* ossl_log_fp = NULL;

static uint8_t engine_level = 0;
static FILE* log_fp = NULL;

int pal_crypto_init(int argc, char *argv[], bool eal_init, char *driver_name)
{

	struct dao_lc_dev_conf dev_conf;
	struct dao_lc_qp_conf qp_conf;
	struct dao_lc_info *info;
	uint16_t qp_id;
	uint8_t dev_id;
	int ret, i;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		fprintf(stderr, "Could not initialize EAL");
		return ret;
	}

	argc += ret;
	argv += ret;

	ret = dao_liquid_crypto_init();
	if (ret < 0) {
		fprintf(stderr, "Could not initialize liquid crypto");
		goto eal_cleanup;
	}


	info = &glb_params.info;
	memset(info, 0, sizeof(*info));

	ret = dao_liquid_crypto_info_get(info);
	if (ret < 0) {
		fprintf(stderr, "Could not get liquid crypto information");
		goto fini;
	}

	if (info->nb_dev == 0) {
		fprintf(stderr, "No liquid crypto devices found");
		ret = -1;
		goto fini;
	}

	for (i = 0; i < info->nb_dev; i++) {
		if (info->nb_qp[i] != 0)
			break;
	}

	if (i == info->nb_dev) {
		fprintf(stderr, "No queue pairs found for any device");
		ret = -ENODEV;
		goto fini;
	}


	glb_params.dev_id = i;
	glb_params.qp_id = 1;

	for (dev_id = 0; dev_id < info->nb_dev; dev_id++) {
		fprintf(stdout,"Number of queue pairs for device %u: %u", dev_id, info->nb_qp[i]);

		if (info->nb_qp[dev_id] == 0)
			continue;

		memset(&dev_conf, 0, sizeof(dev_conf));
		dev_conf.dev_id = dev_id;
		dev_conf.nb_qp = info->nb_qp[dev_id];

		ret = dao_liquid_crypto_dev_create(&dev_conf);
		if (ret < 0) {
			fprintf(stderr, "Could not create liquid crypto device for device %u", dev_id);
			goto fini;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));

		qp_conf.nb_desc = 2048;
		qp_conf.out_of_order_delivery_en = false;
		qp_conf.max_seg_size = TEST_LC_MAX_OUTPUT_LEN;

		for (qp_id = 0; qp_id < info->nb_qp[dev_id]; qp_id++) {
			ret = dao_liquid_crypto_qp_configure(dev_id, qp_id, &qp_conf);
			if (ret < 0) {
				fprintf(stderr, "Could not configure liquid crypto queue pair for device \n");
				info->nb_qp[dev_id] = dev_id;
				goto dev_destroy;
			}
		}

		ret = dao_liquid_crypto_dev_start(dev_id);
		if (ret < 0) {
			fprintf(stderr,"Could not start liquid crypto device\n");
			info->nb_qp[dev_id] = dev_id;
			goto dev_destroy;
		}
	}

	return 0;
dev_destroy:
	for (dev_id = 0; dev_id < info->nb_dev; dev_id++) {
		if (info->nb_qp[dev_id] == 0)
			continue;
		dao_liquid_crypto_dev_destroy(dev_id);

	}

fini:
	dao_liquid_crypto_fini();

eal_cleanup:
	rte_eal_cleanup();

	return ret;
}

int
op_dequeue(uint8_t dev_id, uint16_t qp_id, struct dao_lc_res *res)
{
	uint64_t timeout;
	int ret;

	/* Set a timeout of TEST_LC_TIMEOUT second. */
	timeout = rte_get_timer_cycles() + rte_get_timer_hz() * TEST_LC_TIMEOUT;

	do {
		ret = dao_liquid_crypto_dequeue_burst(dev_id, qp_id, res, 1);
		if (ret == 1)
		break;

		if (rte_get_timer_cycles() > timeout) {
			fprintf(stderr,"Operation timed out\n");
			break;
		}
	}while (ret == 0);

	if (ret != 1) {
		fprintf(stderr,"Could not dequeue operation");
		return -1;
	}

	return 0;
}
int ossl_log(uint32_t level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	if(log_level >= level) {
		if(!ossl_log_fp)
			vfprintf(stderr, fmt, args);
		else
			vfprintf(log_fp, fmt, args);
	}
	va_end(args);
}

/*Added to support provider logging , as we are using engine_log in provider*/
int engine_log(uint32_t level, const char *fmt, ...)
{
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

void pal_get_prop_name_and_desc(char *name,int len, char *rsa_desc,int rsa_desc_len, char *ec_desc, int desc_len)
{
	strncpy(name,"provider=lc_provider",len-1);
	name[len-1]='\0';

	strncpy(rsa_desc, "LC RSA implementation", rsa_desc_len - 1);
	rsa_desc[rsa_desc_len - 1] = '\0';
	strncpy(ec_desc, "LC EC implementation", desc_len - 1);
	ec_desc[desc_len - 1] = '\0';

}

void pal_get_provider_name(char *name, int len)
{
	strncpy(name, "OPENSSL LC PROVIDER", len - 1);
	name[len - 1] = '\0';
}

void pal_crypto_uninit()
{
	struct dao_lc_info *info;
	uint8_t dev_id;

	info = &glb_params.info;

	for (dev_id = 0; dev_id < info->nb_dev; dev_id++) {
		if (info->nb_qp[dev_id] == 0)
			continue;
		dao_liquid_crypto_dev_stop(dev_id);
	}

	for (dev_id = 0; dev_id < info->nb_dev; dev_id++) {
		if (info->nb_qp[dev_id] == 0)
			continue;
		dao_liquid_crypto_dev_destroy(dev_id);
	}

	dao_liquid_crypto_fini();
	rte_eal_cleanup();
}
