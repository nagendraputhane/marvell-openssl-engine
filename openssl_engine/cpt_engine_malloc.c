/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "cpt_engine.h"
#include "pal/pal.h"
#include "cpt_engine_malloc.h"

void *cpt_engine_malloc(size_t len, const char *file, int line)
{
	struct rte_mbuf *mbuf_ptr = NULL;
	void *data_ptr = NULL;

	(void)file, (void)line;

  return pal_pktbuf_alloc(len, PAL_CPT_DIGEST_LEN);
}

void *cpt_engine_realloc(void *ptr, size_t len, const char *file, int line)
{
	struct rte_mbuf *mbuf_ptr = NULL;
	uint64_t *data_ptr = NULL;
	(void)file, (void)line;

  return pal_pktbuf_realloc(ptr, len, PAL_CPT_DIGEST_LEN);
}

void cpt_engine_free(void *ptr, const char *file, int line)
{
	struct rte_mbuf *mbuf_ptr = NULL;
	uint64_t *data_ptr = NULL;

	(void)file, (void)line;

  pal_pktbuf_free(ptr);
}
