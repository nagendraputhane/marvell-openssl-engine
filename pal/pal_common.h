/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */
#ifndef __PAL_COMMON_HH__
#define __PAL_COMMON_HH__

#include "pal.h"

typedef void (*user_callback_fn)(void **wctx);
int pal_sym_poll(uint8_t dev_id, uint16_t qp_id, async_job async_cb);
int pal_asym_poll(uint8_t dev_id, uint16_t qp_id, user_callback_fn callback);


#endif // __PAL_COMMON_HH__
