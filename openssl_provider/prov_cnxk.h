/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include "pal/pal.h"

#define OTX2_DEV_DOMAIN			2
#define OTX2_NUM_ARGS		12
#define OTX2_NUM_PER_BUS		8
#define OTX2_DEF_DEV_BUS			"10"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"


const char *crypto_name;

static inline int provcpt_hw_init(void)
{
	uint64_t feature_flags = 0;
	char devstr[20], idstr[10];
	int argc, idx = -1, ret = 0;
	char cpu[3] = {0};
	int cpuquot, cpurem;
	char *bus = getenv("OTX2_BUS");

	sprintf(idstr, "rte%d", getpid());
	sprintf(cpu, "%2d", sched_getcpu());

	cpuquot = (unsigned short)(sched_getcpu() + 1) / OTX2_NUM_PER_BUS;
	cpurem = (unsigned short)(sched_getcpu() + 1)  % OTX2_NUM_PER_BUS;

	if (!bus) {
		fprintf(stderr, " OTX2 BUS slot not defined. Using default\n");
		bus = OTX2_DEF_DEV_BUS;
	}

	crypto_name = getenv("CRYPTO_DRIVER");
	if (!crypto_name) {
		fprintf(stderr, " CRYPTO DRIVER name not defined. Using default (crypto_octeontx2)\n");
		crypto_name = "crypto_octeontx2";
	}

	/* Symmetric device */
	sprintf(devstr, "%04d:%s:0%d.%d", OTX2_DEV_DOMAIN, bus, cpuquot, cpurem);

	char *argv[OTX2_NUM_ARGS] = {
		"DPDK",	"--file-prefix",
		idstr,	"--socket-mem=500", /* 500MB per process */
		"-l",	cpu,
		"-d",	"librte_mempool_ring.so",
		"-d",	"librte_crypto_cnxk.so",
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
		"-a",	devstr
#else
		"-w",	devstr
#endif
	};

	argc = OTX2_NUM_ARGS;

        ret = pal_crypto_init(argc, argv, 1, crypto_name);
        if (ret < 0) {
                engine_log(ENG_LOG_ERR, "Failed in pal_crypto_init\n");
                return -1;
        }

	return 0;
}

