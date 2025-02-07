/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include "prov.h"
#include "ec_common.h"
#include "pal/pal.h"
#include "pal/pal_ecdsa.h"

/**
 * Assumes that all the to-be-initialized pointers were set to NULL on function
 * call. i.e xform needs to have been memset/explicitly initialized to 0s
 *
 * @returns 1 on success, 0 on failure
 */
int get_curve_id(const EC_GROUP *ecgroup)
{
  int curve_name = EC_GROUP_get_curve_name(ecgroup);
  pal_crypto_curve_id_t curve_id;

  switch (curve_name) {
    case NID_X9_62_prime192v1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP192R1;
      break;
    case NID_secp224r1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP224R1;
      break;
    case NID_X9_62_prime256v1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP256R1;
      break;
    case NID_secp384r1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP384R1;
      break;
    case NID_secp521r1:
      curve_id = PAL_CRYPTO_EC_GROUP_SECP521R1;
      break;
    default:
      /* Unsupported curve */
      return 0;
  }

  return curve_id;
}

