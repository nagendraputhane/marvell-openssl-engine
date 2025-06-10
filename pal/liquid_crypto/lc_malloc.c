/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include "pal.h"
#include "defs.h"

void * pal_pktbuf_alloc( size_t len, size_t predata_len)
{}

void *pal_pktbuf_realloc( void *ptr, size_t len, size_t predata_len)
{}

void pal_pktbuf_free( void *ptr)
{}

void * pal_malloc(size_t len)
{
	return rte_malloc(NULL, len, 0);
}
void pal_free(void *ptr)
{
	if(ptr)
		rte_free(ptr);
}
