/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <fcntl.h>

#include "prov.h"
#include "pal.h"


OSSL_ASYNC_FD zero_fd;

int provplt_setup()
{
    int ret = 0;

    if ((zero_fd = open("/dev/zero", 0)) < 0)
        return -1;

    ret = pal_plt_init();
    if (ret < 0) {
        fprintf(stderr, "Failed in platform init\n");
        return 0;
    }

    return 1;
}

