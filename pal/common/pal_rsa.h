/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _E_PAL_DPDK_RSA_H
#define _E_PAL_DPDK_RSA_H
#include "pal.h"
#define MBUF_TEST_SIZE 1024
#define PAL_RSA_PKCS1_PADDING 1
#define PAL_RSA_NO_PADDING 3

typedef enum pal_rsa_key_type {
  PAL_RSA_KEY_TYPE_EXP = RTE_RSA_KEY_TYPE_EXP,
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
  PAL_RSA_KEY_TYPE_QT = RTE_RSA_KEY_TYPE_QT
#else
  PAL_RSA_KEY_TYPE_QT = RTE_RSA_KET_TYPE_QT
#endif
} pal_rsa_key_type_t;

typedef struct pal_rsa_ctx {
  int dev_id;
  int qp_id;
  int pad_type;
  int rsa_key_type;
  uint8_t *rsa_n_data;
  int rsa_n_len;
  uint8_t *rsa_e_data;
  int rsa_e_len;
  uint8_t *rsa_d_data;
  int rsa_d_len;
  uint8_t *rsa_qt_p_data;
  int rsa_qt_p_len;
  uint8_t *rsa_qt_q_data;
  int rsa_qt_q_len;
  uint8_t *rsa_qt_dP_data;
  int rsa_qt_dP_len;
  uint8_t *rsa_qt_dQ_data;
  int rsa_qt_dQ_len;
  uint8_t *rsa_qt_qInv_data;
  int rsa_qt_qInv_len;
  int padding;
  int use_crt_method;
  async_job async_cb;
  uint8_t *wctx_p;
} pal_rsa_ctx_t;

int pal_rsa_pub_enc(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_rsa_pub_dec(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_rsa_priv_enc(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_rsa_priv_dec(pal_rsa_ctx_t *pal_ctx, int flen, const unsigned char *from, unsigned char *to);
int pal_asym_xform_capability_check_modlen(int16_t modlen);
#endif //_E_PAL_DPDK_RSA_H
