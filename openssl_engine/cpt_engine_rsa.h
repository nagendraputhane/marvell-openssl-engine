/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _CPT_ENGINE_RSA_H_
#define _CPT_ENGINE_RSA_H_

#define MBUF_TEST_SIZE 1024
extern RSA_METHOD * default_rsa_meth;

int cpt_engine_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding);
int cpt_engine_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding);
int cpt_engine_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding);
int cpt_engine_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding);
#endif //_CPT_ENGINE_RSA_H_
