/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "cpt_engine.h"
#include <rte_lcore.h>
#include <rte_errno.h>
#include "cpt_engine_usr.h"

int dpdk_rte_thread_register(void)
{
	int ret = rte_thread_register ();
	if (ret < 0)
		engine_log(ENG_LOG_ERR, "Warning: could not register new thread, reason %s",
				rte_strerror (rte_errno));
	return ret;
}
