/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "pal.h"
#include "pal_common.h"
#include "defs.h"
extern dpdk_pools_t *pools;

struct rte_cryptodev_sym_session *
pal_sym_create_session(uint16_t dev_id,
			struct rte_crypto_sym_xform *xform,
			uint8_t reconfigure,
			struct rte_cryptodev_sym_session *ses)
{
	return NULL;
}

bool pal_is_hw_sym_algos_supported(int algo)
{
	return true;
}

int pal_sym_session_cleanup(struct rte_cryptodev_sym_session *session, int dev_id)
{
	return 1;
}

int pal_asym_create_session(uint16_t dev_id, struct rte_crypto_asym_xform *xform,
			struct rte_cryptodev_asym_session **sess)
{
	return 1;
}

int pal_sym_poll(uint8_t dev_id, uint16_t qp_id, async_job async_cb)
{

	return 0;
}

int pal_asym_poll(uint8_t dev_id, uint16_t qp_id, user_callback_fn callback)
{
	return 0;
}

int pal_get_thread_id()
{
	unsigned int lcore = rte_lcore_id();

	if (lcore == LCORE_ID_ANY) {
		ossl_log(OSSL_LOG_ERR, "%s: lcore :%d\n", __FUNCTION__, lcore);
		return -1;
	}

	return lcore;
}
