/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef __PAL_COMMON_A80X0_H
#define __PAL_COMMON_A80X0_H

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#define PAL_DPDK_NUM_ARGS		10

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define crypto_name "crypto_mvsam";

static inline char ** pal_get_hw_init_params(int *argc, char *crypto_driver_name)
{
				char idstr[10];
				char **argv;

				sprintf(idstr, "rte%d", getpid());
				argv = (char **)malloc(PAL_DPDK_NUM_ARGS * sizeof(char *));
				if (argv == NULL) {
								fprintf(stderr, "Memory allocation failed\n");
								return NULL;
				}

				argv[0] = strdup("DPDK");
				argv[1] = strdup("--file-prefix");
				argv[2] = strdup(idstr);
				argv[3] = strdup("--socket-mem=500");
				argv[4] = strdup("--vdev");
				argv[5] = strdup(crypto_name);
				argv[6] = strdup("-d");
				argv[7] = strdup("librte_mempool_ring.so");
				argv[8] = strdup("-d");
				argv[9] = strdup("librte_pmd_mvsam_crypto.so");

				*argc = PAL_DPDK_NUM_ARGS;
				strcpy(crypto_driver_name, crypto_name);

				return argv;
}
#endif
