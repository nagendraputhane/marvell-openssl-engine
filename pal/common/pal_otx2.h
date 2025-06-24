/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __COMMON_PAL_OTX2_H__
#define __COMMON_PAL_OTX2_H__

#include <stdlib.h>
#include <rte_common.h>
#include <rte_version.h>

#define E_DEV_DOMAIN			2
#define PAL_DPDK_NUM_ARGS		10
#define PAL_DPDK_NUM_PER_BUSS		8
#define DEF_DEV_BUS			"10"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

static inline char ** pal_get_hw_init_params(int *argc, char *crypto_driver_name)
{
	char **argv;
	char cpu[5] = {0};
  char *crypto_name;
	int cpuquot, cpurem;
	char devstr[20], idstr[10];
	char *bus = getenv("OTX2_BUS");

	sprintf(idstr, "rte%d", getpid());
	sprintf(cpu, "0@%2d", sched_getcpu());

	cpuquot = (unsigned short)(sched_getcpu() + 1) / PAL_DPDK_NUM_PER_BUSS;
	cpurem = (unsigned short)(sched_getcpu() + 1)  % PAL_DPDK_NUM_PER_BUSS;

	if (!bus) {
		fprintf(stderr, " OTX2 BUS slot not defined. Using default\n");
		bus = DEF_DEV_BUS;
	}

	crypto_name = getenv("CRYPTO_DRIVER");
	if (!crypto_name) {
		fprintf(stderr, " CRYPTO DRIVER name not defined. Using default (crypto_cn10k)\n");
		crypto_name = "crypto_cn10k";
	}

	/* Symmetric engine */
	sprintf(devstr, "%04d:%s:0%d.%d", E_DEV_DOMAIN, bus, cpuquot, cpurem);

	argv = (char **)malloc(PAL_DPDK_NUM_ARGS * sizeof(char *));
	if (!argv) {
					fprintf(stderr, "Memory allocation failed\n");
					return NULL;
	}

	argv[0] = strdup("DPDK");
	argv[1] = strdup("--file-prefix");
	argv[2] = strdup(idstr);
	argv[3] = strdup("--socket-mem=500");
	argv[4] = strdup("--lcores");
	argv[5] = strdup(cpu);
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
	argv[6] = strdup("-a");
#else
	argv[6] = strdup("-w");
#endif
	argv[7] = strdup(devstr);
	argv[8] = strdup("-d");
	argv[9] = strdup("librte_mempool_ring.so");

	*argc = PAL_DPDK_NUM_ARGS;
  strcpy(crypto_driver_name, crypto_name);

	return argv;
}
#endif
