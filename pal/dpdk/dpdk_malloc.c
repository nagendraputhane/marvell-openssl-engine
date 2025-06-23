/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include "pal.h"

extern dpdk_pools_t *pools;
void * pal_pktbuf_alloc( size_t len, size_t predata_len)
{
  struct rte_mbuf *mbuf_ptr = NULL;
  void *data_ptr = NULL;

  mbuf_ptr = rte_pktmbuf_alloc(pools->mbuf_pool);
  if (mbuf_ptr == NULL) {
    engine_log(ENG_LOG_ERR,"Failed to allocate mbuf for size %d\n", len);
    return NULL;
  }
  data_ptr = rte_pktmbuf_append(mbuf_ptr, len + predata_len);
  if (data_ptr == NULL)
    return NULL;

  *((uint64_t *)data_ptr - 1) = 0xDEADBEEF;

  return data_ptr;
}

void *pal_pktbuf_realloc( void *ptr, size_t len, size_t predata_len)
{
  struct rte_mbuf *mbuf_ptr = NULL;
  uint64_t *data_ptr = NULL;

  if (ptr == NULL)
    return pal_pktbuf_alloc(len, predata_len);

  if (len == 0) {
    pal_free(ptr);
    return NULL;
  }
  data_ptr = (uint64_t *)ptr - 1;
  if (*data_ptr == 0xDEADBEEF) {
    mbuf_ptr = (struct rte_mbuf *)((char *)ptr - RTE_PKTMBUF_HEADROOM - sizeof(struct rte_mbuf));
    if (mbuf_ptr == NULL) {
      engine_log(ENG_LOG_ERR, "Failed to get mbuf pointer\n");
      return NULL;
    }
    if (rte_pktmbuf_append(mbuf_ptr, len) == NULL)
      return NULL;
    return rte_pktmbuf_mtod(mbuf_ptr, void *);
  } else {
    data_ptr = realloc(ptr, len);
    return data_ptr;
  }
}

void pal_pktbuf_free( void *ptr)
{
  struct rte_mbuf *mbuf_ptr = NULL;
  uint64_t *data_ptr = NULL;

  if (ptr != NULL) {
    data_ptr = (uint64_t *)ptr - 1;
    if (*data_ptr == 0xDEADBEEF) {
      mbuf_ptr = (struct rte_mbuf *)((char *)ptr - RTE_PKTMBUF_HEADROOM - sizeof(struct rte_mbuf));
      rte_pktmbuf_free(mbuf_ptr);
    } else {
      free(ptr);
    }
  }
}
void * pal_malloc(size_t len)
{
  return rte_malloc(NULL, len, 0);
}
void pal_free(void *ptr)
{
  if(ptr)
  rte_free(ptr);
}
