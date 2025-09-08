/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include "pal.h"
#include "defs.h"

#define MAX_LC_DEVS	8

unsigned int dev_in_use = 0;
int asym_queues[RTE_MAX_LCORE];
int sym_queues[RTE_MAX_LCORE];
int asym_dev_id[RTE_MAX_LCORE];
int sym_dev_id[RTE_MAX_LCORE];

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

int pal_plt_init(void)
{
	uint64_t feature_flags = 0;
	char idstr[10], devstr[20];
	int argc, idx = -1, ret = 0;
	char cpu[3] = {0};
	int cpurem;
	const char *sdp_vf_base = getenv("SDP_VF_BASE");
	if (!sdp_vf_base) {
		ossl_log(OSSL_LOG_ERR, "SDP_VF_BASE not set\n");
		return -1;
	}

	/* Parse PCI BDF (domain:bus:device.function) from SDP_VF_BASE */
	unsigned int dev_domain = 0, dev_bus = 0, dev_slot = 0, dev_func = 0;
	if (sscanf(sdp_vf_base, "%4x:%2x:%2x.%1x",
			&dev_domain, &dev_bus, &dev_slot, &dev_func) != 4) {
		ossl_log(OSSL_LOG_ERR, "Invalid SDP_VF_BASE format: %s\n", sdp_vf_base);
		return -1;
	}

	snprintf(idstr, sizeof(idstr), "rte%d", getpid());
	snprintf(cpu, sizeof(cpu), "%2d", sched_getcpu());

	cpurem = (unsigned short)(sched_getcpu()) % MAX_LC_DEVS;

	snprintf(devstr, sizeof(devstr), "%04x:%02x:%02x.%1x", dev_domain, dev_bus, dev_slot, cpurem);
	char *argv[] = {
				"DPDK", "--file-prefix",
				idstr,  "--socket-mem=500", /* 500MB per process */
				"-a", devstr,
				"-l",   cpu,
				"-d",   "librte_mempool_ring.so",
	};

	argc = sizeof(argv)/sizeof(char *);

	ret = pal_crypto_init(argc, argv, 1, NULL);

	if (ret < 0) {
		ossl_log(OSSL_LOG_ERR, "Failed in pal_crypto_init\n");
		return -1;
	}

	return 0;
}
