/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _CPT_ENGINE_MALLOC_H_
#define _CPT_ENGINE_MALLOC_H_

/* define CPT_ENGINE_MEM_FUNC to overload openssl's malloc, realloc, and free */
/* #define CPT_ENGINE_MEM_FUNC */

/* Engine Memory Function */
void *cpt_engine_malloc(size_t len, const char *file, int line);
void *cpt_engine_realloc(void *ptr, size_t len, const char *file, int line);
void cpt_engine_free(void *ptr, const char *file, int line);

#endif //_CPT_ENGINE_MALLOC_H_
