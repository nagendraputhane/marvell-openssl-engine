/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include "pal.h"
#include "defs.h"
#ifdef OSSL_PMD
#include "prov_ossl.h"
#else
#include "prov_cnxk.h"
#endif


#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

int pal_plt_init(void)
{
	uint64_t feature_flags = 0;
	char idstr[10];
	int argc, idx = -1, ret = 0;
	char cpu[3] = {0};

	snprintf(idstr,sizeof(idstr), "rte%d", getpid());
	snprintf(cpu,sizeof(cpu), "%2d", sched_getcpu());

	char *argv[] = {
				"DPDK", "--file-prefix",
				idstr,  "--socket-mem=500", /* 500MB per process */
				"-l",   cpu,
				"-d",   "librte_mempool_ring.so",
	};

	argc = sizeof(argv)/sizeof(char *);

	ret = pal_crypto_init(argc, argv, 1, crypto_name);

	if (ret < 0) {
		ossl_log(OSSL_LOG_ERR, "Failed in pal_crypto_init\n");
		return -1;
	}

	return 0;
}
