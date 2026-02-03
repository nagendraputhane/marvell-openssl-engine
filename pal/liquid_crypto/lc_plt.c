/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include "pal.h"
#include "defs.h"

#define MAX_ARGV	10

unsigned int dev_in_use = 0;
int asym_queues[RTE_MAX_LCORE];
int sym_queues[RTE_MAX_LCORE];
int asym_dev_id[RTE_MAX_LCORE];
int sym_dev_id[RTE_MAX_LCORE];

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

int pal_plt_init(void)
{
	char idstr[10], devstr[20];
	char cpu[3] = {0};
	int cpurem;
	const char *sdp_vf_base = getenv("SDP_VF_BASE");
	const char *max_lc_devs_env = getenv("MAX_LC_DEVS");
	int max_lc_devs = 8;  /* Default value */
	int use_device = 0, argc = 0, ret = 0;
	char *argv[MAX_ARGV];

	/* Get MAX_LC_DEVS from environment or use default */
	if (max_lc_devs_env) {
		max_lc_devs = atoi(max_lc_devs_env);
		if (max_lc_devs <= 0) {
			ossl_log(OSSL_LOG_INFO, "Invalid MAX_LC_DEVS value, using default (8)\n");
			max_lc_devs = 8;
		}
	}

	snprintf(idstr, sizeof(idstr), "rte%d", getpid());
	snprintf(cpu, sizeof(cpu), "%2d", sched_getcpu());

	/* Check if SDP_VF_BASE is set and parse it */
	if (sdp_vf_base) {
		/* Parse PCI BDF (domain:bus:device.function) from SDP_VF_BASE */
		unsigned int dev_domain = 0, dev_bus = 0, dev_slot = 0, dev_func = 0;
		if (sscanf(sdp_vf_base, "%4x:%2x:%2x.%1x",
				&dev_domain, &dev_bus, &dev_slot, &dev_func) == 4) {
			cpurem = (unsigned short)(sched_getcpu()) % max_lc_devs;
			snprintf(devstr, sizeof(devstr), "%04x:%02x:%02x.%1x",
			         dev_domain, dev_bus, dev_slot, cpurem);
			use_device = 1;
		} else {
			ossl_log(OSSL_LOG_ERR, "Invalid SDP_VF_BASE format: %s\n", sdp_vf_base);
			return -1;
		}
	}

	/* Build argv array based on OS */
#ifdef __FreeBSD__
	argv[argc++] = "DPDK";
	argv[argc++] = "-m 500"; /* 500MB per process */
	if (use_device) {
		argv[argc++] = "-a";
		argv[argc++] = devstr;
	}
	argv[argc++] = "-l";
	argv[argc++] = cpu;
	argv[argc++] = "-d";
	argv[argc++] = "librte_mempool_ring.so";
#else
	argv[argc++] = "DPDK";
	argv[argc++] = "--file-prefix";
	argv[argc++] = idstr;
	argv[argc++] = "--socket-mem=500"; /* 500MB per process */
	if (use_device) {
		argv[argc++] = "-a";
		argv[argc++] = devstr;
	}
	argv[argc++] = "-l";
	argv[argc++] = cpu;
	argv[argc++] = "-d";
	argv[argc++] = "librte_mempool_ring.so";
#endif

	ret = pal_crypto_init(argc, argv, 1, NULL);

	if (ret < 0) {
		ossl_log(OSSL_LOG_ERR, "Failed in pal_crypto_init\n");
		return -1;
	}

	return 0;
}
