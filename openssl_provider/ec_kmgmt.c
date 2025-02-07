/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define _GNU_SOURCE
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/proverr.h>
#include "crypto/bn.h"
#include "crypto/ec.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "internal/param_build_set.h"

#include "prov.h"
#include "ec_common.h"
#include "pal/pal_ecdsa.h"

static OSSL_FUNC_keymgmt_new_fn prov_ec_newdata;
static OSSL_FUNC_keymgmt_gen_init_fn prov_ec_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn prov_ec_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn prov_ec_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn prov_ec_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn prov_ec_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn prov_ec_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn prov_ec_load;
static OSSL_FUNC_keymgmt_has_fn prov_ec_has;
static OSSL_FUNC_keymgmt_import_types_fn prov_ec_import_types;
static OSSL_FUNC_keymgmt_import_fn prov_ec_import;
static OSSL_FUNC_keymgmt_free_fn prov_ec_freedata;
static OSSL_FUNC_keymgmt_query_operation_name_fn prov_ec_query_operation_name;

#define BN_num_words(a) ((BN_num_bits(a)+BN_BITS2-1)/BN_BITS2)

#define EC_DEFAULT_MD "SHA256"
#define EC_POSSIBLE_SELECTIONS                                                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

# define EC_IMEXPORTABLE_PUBLIC_KEY                                            \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define EC_IMEXPORTABLE_PRIVATE_KEY                                           \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM ec_private_key_types[] = {
    EC_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_public_key_types[] = {
    EC_IMEXPORTABLE_PUBLIC_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM ec_key_types[] = {
     EC_IMEXPORTABLE_PRIVATE_KEY,
     EC_IMEXPORTABLE_PUBLIC_KEY,
     OSSL_PARAM_END
};
 static const OSSL_PARAM *ec_types[] = {
     NULL,
     ec_private_key_types,
     ec_public_key_types,
     ec_key_types
 };

static
const char *prov_ec_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }
    return NULL;
}

static
void *prov_ec_newdata(void *provctx)
{
    if (!prov_is_running())
        return NULL;
    return EC_KEY_new_ex(PROV_LIBCTX_OF(provctx), NULL);
}

static
void prov_ec_freedata(void *keydata)
{
    EC_KEY_free(keydata);
}

static
int prov_ec_has(const void *keydata, int selection)
{
    const EC_KEY *ec = keydata;
    int ok = 1;

    if (!prov_is_running() || ec == NULL)
        return 0;
    if ((selection & EC_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (EC_KEY_get0_public_key(ec) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (EC_KEY_get0_private_key(ec) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (EC_KEY_get0_group(ec) != NULL);
    /*
     * We consider OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS to always be
     * available, so no extra check is needed other than the previous one
     * against EC_POSSIBLE_SELECTIONS.
     */
    return ok;
}


struct ec_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *group_name;
    char *encoding;
    char *pt_format;
    char *group_check;
    char *field_type;
    BIGNUM *p, *a, *b, *order, *cofactor;
    unsigned char *gen, *seed;
    size_t gen_len, seed_len;
    int selection;
    int ecdh_mode;
    EC_GROUP *gen_group;
};

static void *prov_ec_gen_init(void *provctx, int selection,
                         const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct ec_gen_ctx *gctx = NULL;

    if (!prov_is_running() || (selection & (EC_POSSIBLE_SELECTIONS)) == 0)
        return NULL;


    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->selection = selection;
        gctx->ecdh_mode = 0;
    }
    if (!prov_ec_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx);
        gctx = NULL;
    }
    return gctx;
}

static void prov_ec_gen_cleanup(void *genctx)
{
    struct ec_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;

    EC_GROUP_free(gctx->gen_group);
    BN_free(gctx->p);
    BN_free(gctx->a);
    BN_free(gctx->b);
    BN_free(gctx->order);
    BN_free(gctx->cofactor);
    OPENSSL_free(gctx->group_name);
    OPENSSL_free(gctx->field_type);
    OPENSSL_free(gctx->pt_format);
    OPENSSL_free(gctx->encoding);
    OPENSSL_free(gctx->seed);
    OPENSSL_free(gctx->gen);
    OPENSSL_free(gctx);
}

static void *prov_ec_load(const void *reference, size_t reference_sz)
{
    EC_KEY *ec = NULL;

    if (prov_is_running() && reference_sz == sizeof(ec)) {
        /* The contents of the reference is the address to our object */
        ec = *(EC_KEY **)reference;

        /* We grabbed, so we detach it */
        *(EC_KEY **)reference = NULL;
        return ec;
    }
    return NULL;
}

static int prov_ec_gen_set_group(void *genctx, const EC_GROUP *src)
{
    struct ec_gen_ctx *gctx = genctx;
    EC_GROUP *group;

    group = EC_GROUP_dup(src);
    if (group == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        return 0;
    }
    EC_GROUP_free(gctx->gen_group);
    gctx->gen_group = group;
    return 1;
}

static int prov_ec_gen_set_template(void *genctx, void *templ)
{
    struct ec_gen_ctx *gctx = genctx;
    EC_KEY *ec = templ;
    const EC_GROUP *ec_group;

    if (!prov_is_running() || gctx == NULL || ec == NULL)
        return 0;
    if ((ec_group = EC_KEY_get0_group(ec)) == NULL)
        return 0;
    return prov_ec_gen_set_group(gctx, ec_group);
}

#define COPY_INT_PARAM(params, key, val)                                       \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL && !OSSL_PARAM_get_int(p, &val))                                 \
    goto err;

#define COPY_UTF8_PARAM(params, key, val)                                      \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL) {                                                               \
    if (p->data_type != OSSL_PARAM_UTF8_STRING)                                \
        goto err;                                                              \
    OPENSSL_free(val);                                                         \
    val = OPENSSL_strdup(p->data);                                             \
    if (val == NULL)                                                           \
        goto err;                                                              \
}

#define COPY_OCTET_PARAM(params, key, val, len)                                \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL) {                                                               \
    if (p->data_type != OSSL_PARAM_OCTET_STRING)                               \
        goto err;                                                              \
    OPENSSL_free(val);                                                         \
    len = p->data_size;                                                        \
    val = OPENSSL_memdup(p->data, p->data_size);                               \
    if (val == NULL)                                                           \
        goto err;                                                              \
}

#define COPY_BN_PARAM(params, key, bn)                                         \
p = OSSL_PARAM_locate_const(params, key);                                      \
if (p != NULL) {                                                               \
    if (bn == NULL)                                                            \
        bn = BN_new();                                                         \
    if (bn == NULL || !OSSL_PARAM_get_BN(p, &bn))                              \
        goto err;                                                              \
}

static int prov_ec_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    int ret = 0;
    struct ec_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;
    EC_GROUP *group = NULL;

//    COPY_INT_PARAM(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, gctx->ecdh_mode);

    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_GROUP_NAME, gctx->group_name);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE, gctx->field_type);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_ENCODING, gctx->encoding);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, gctx->pt_format);
    COPY_UTF8_PARAM(params, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, gctx->group_check);

    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_P, gctx->p);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_A, gctx->a);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_B, gctx->b);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_ORDER, gctx->order);
    COPY_BN_PARAM(params, OSSL_PKEY_PARAM_EC_COFACTOR, gctx->cofactor);

    COPY_OCTET_PARAM(params, OSSL_PKEY_PARAM_EC_SEED, gctx->seed, gctx->seed_len);
    COPY_OCTET_PARAM(params, OSSL_PKEY_PARAM_EC_GENERATOR, gctx->gen,
                     gctx->gen_len);

    ret = 1;
err:
    EC_GROUP_free(group);
    return ret;
}

int ecdh_keygen(EC_KEY *eckey)
{
  int ok = 0;
  BIGNUM *rx, *ry;
  int prime_length;
  void *rxbuf = NULL;
  void *rybuf = NULL;
  const BIGNUM *order;
  const EC_GROUP *group;
  BIGNUM *priv_key = NULL;
  EC_POINT *pub_key = NULL;
  const EC_POINT *generator;
  const BIGNUM *const_priv_key;
  BIGNUM *px = BN_new();
  BIGNUM *py = BN_new();
  pal_ecdsa_ctx_t pal_ctx = {0};
  pal_crypto_curve_id_t curve_id;


  if(!prov_asym_get_valid_devid_qid(&pal_ctx.devid, &pal_ctx.queue))
     goto err;

  group = EC_KEY_get0_group((const EC_KEY*)eckey);
  const_priv_key = EC_KEY_get0_private_key((const EC_KEY*)eckey);
  generator = EC_GROUP_get0_generator(group);

  if (const_priv_key == NULL) {
    priv_key = BN_secure_new();
    if (priv_key == NULL)
      goto err;
  } else
    priv_key = BN_dup(const_priv_key);

  order = EC_GROUP_get0_order(group);
  if (order == NULL)
    goto err;

  do
    if (!BN_rand_range(priv_key, order))
      goto err;
  while (BN_is_zero(priv_key)) ;

  pub_key = EC_POINT_new(group);
  if (pub_key == NULL)
    goto err;

  rxbuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
  rybuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
  if (rxbuf == NULL || rybuf == NULL)
    goto err;

  memset(rxbuf, 0, PCURVES_MAX_PRIME_LEN);
  memset(rybuf, 0, PCURVES_MAX_PRIME_LEN);

  curve_id = get_curve_id(group);
  if (!curve_id) {
    ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_INVALID_CURVE);
  }

  EC_POINT_get_affine_coordinates_GFp(group, generator, px, py, NULL);


  pal_ctx.x_data = bn_to_crypto_param(px);
  pal_ctx.x_data_len  = BN_num_bytes(px);
  pal_ctx.y_data = bn_to_crypto_param(py);;
  pal_ctx.y_data_len  = BN_num_bytes(py);
  pal_ctx.scalar_data = bn_to_crypto_param(priv_key);
  pal_ctx.scalar_data_len  = BN_num_bytes(priv_key);
  pal_ctx.rxbuf = rxbuf;
  pal_ctx.rybuf = rybuf;
  pal_ctx.curve_id = curve_id;
  pal_ctx.xform_type = PAL_CRYPTO_ASYM_XFORM_ECPM;
  pal_ctx.rxbuf = rxbuf;
  pal_ctx.rybuf = rybuf;
  pal_ctx.async_cb = provider_ossl_handle_async_job;

  if ((prime_length = pal_ecdsa_ec_point_multiplication(&pal_ctx)) == 0) {
    ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_POINT_ARITHMETIC_FAILURE);
    goto err;
  }

  rx = BN_bin2bn(rxbuf, prime_length, NULL);
  ry = BN_bin2bn(rybuf, prime_length, NULL);
  EC_POINT_set_affine_coordinates_GFp(group, pub_key, rx, ry,
      NULL);
  EC_KEY_set_private_key(eckey, priv_key);
  EC_KEY_set_public_key(eckey, pub_key);
  ok = 1;

err:
  if (rybuf)
    OPENSSL_free(rybuf);
  if (rxbuf)
    OPENSSL_free(rxbuf);
  if (pub_key)
    EC_POINT_free(pub_key);
  if (priv_key)
    BN_free(priv_key);
  return ok;
}

static int ec_gen_set_group_from_params(struct ec_gen_ctx *gctx)
{
    int ret = 0;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    EC_GROUP *group = NULL;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    if (gctx->encoding != NULL
        && !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING,
                                            gctx->encoding, 0))
        goto err;

    if (gctx->pt_format != NULL
        && !OSSL_PARAM_BLD_push_utf8_string(bld,
                                            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                            gctx->pt_format, 0))
        goto err;

    if (gctx->group_name != NULL) {
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                             gctx->group_name, 0))
            goto err;
        /* Ignore any other parameters if there is a group name */
        goto build;
    } else if (gctx->field_type != NULL) {
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                                             gctx->field_type, 0))
            goto err;
    } else {
        goto err;
    }
    if (gctx->p == NULL
        || gctx->a == NULL
        || gctx->b == NULL
        || gctx->order == NULL
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_P, gctx->p)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_A, gctx->a)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_B, gctx->b)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_ORDER, gctx->order))
        goto err;

    if (gctx->cofactor != NULL
        && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_COFACTOR,
                                   gctx->cofactor))
        goto err;

    if (gctx->seed != NULL
        && !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED,
                                             gctx->seed, gctx->seed_len))
        goto err;

    if (gctx->gen == NULL
        || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_GENERATOR,
                                             gctx->gen, gctx->gen_len))
        goto err;
build:
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;
    group = EC_GROUP_new_from_params(params, gctx->libctx, NULL);
    if (group == NULL)
        goto err;

    EC_GROUP_free(gctx->gen_group);
    gctx->gen_group = group;

    ret = 1;
err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static const OSSL_PARAM *prov_ec_gen_settable_params(ossl_unused void *genctx,
                                                ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}

static int ec_gen_assign_group(EC_KEY *ec, EC_GROUP *group)
{
    if (group == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return 0;
    }
    return EC_KEY_set_group(ec, group) > 0;
}

static void *prov_ec_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct ec_gen_ctx *gctx = genctx;
    EC_KEY *ec = NULL;
    int ret = 0;

    if (!prov_is_running()
        || gctx == NULL
        || (ec = EC_KEY_new_ex(gctx->libctx, NULL)) == NULL)
        return NULL;

    if (gctx->gen_group == NULL) {
        if (!ec_gen_set_group_from_params(gctx))
            goto err;
    }

    /* We must always assign a group, no matter what */
    ret = ec_gen_assign_group(ec, gctx->gen_group);

    /* Whether you want it or not, you get a keypair, not just one half */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ret = ret && ecdh_keygen(ec);

    if (ret)
        return ec;
err:
    /* Something went wrong, throw the key away */
    EC_KEY_free(ec);
    return NULL;
}

 static const OSSL_PARAM *prov_ec_imexport_types(int selection)
 {
     int type_select = 0;
     if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
         type_select += 1;
     if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
         type_select += 2;
     return ec_types[type_select];
 }

static const OSSL_PARAM *prov_ec_import_types(int selection)
{
    return prov_ec_imexport_types(selection);
}

int prov_ec_key_fromdata(EC_KEY *ec, const OSSL_PARAM params[], int include_private)
{
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL;
    unsigned char *pub_key = NULL;
    size_t pub_key_len;
    const EC_GROUP *ecg = NULL;
    EC_POINT *pub_point = NULL;
    int ok = 0;

    // Get the EC group from the EC_KEY object
    ecg = EC_KEY_get0_group(ec);
    if (ecg == NULL)
        return 0;

    // Locate the public and private key parameters
    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (include_private)
        param_priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

    // Create a new BN_CTX structure
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;

    // Handle the public key parameter
    if (param_pub_key != NULL) {
        if (!OSSL_PARAM_get_octet_string(param_pub_key, (void **)&pub_key, 0, &pub_key_len)
            || (pub_point = EC_POINT_new(ecg)) == NULL
            || !EC_POINT_oct2point(ecg, pub_point, pub_key, pub_key_len, ctx))
            goto err;
    }

    // Handle the private key parameter
     if (param_priv_key != NULL && include_private) {
        int fixed_words;
        const BIGNUM *order;

     order = EC_GROUP_get0_order(ecg);
        if (order == NULL || BN_is_zero(order))
            goto err;

     fixed_words = (BN_num_bits(order) + BN_BITS2 - 1) / BN_BITS2 + 2;

         if ((priv_key = BN_secure_new()) == NULL)
             goto err;
         BIGNUM *new_bn = BN_new();
     if (new_bn == NULL)
        goto err;
    if (!BN_set_word(new_bn, 0) || !BN_set_bit(new_bn, fixed_words * BN_BITS2 - 1))
        goto err;
     if (!BN_copy(new_bn, priv_key))
         goto err;
     BN_free(priv_key);
     priv_key = new_bn;
         BN_set_flags(priv_key, BN_FLG_CONSTTIME);

         if (!OSSL_PARAM_get_BN(param_priv_key, &priv_key))
            goto err;
     }

    // Set the private key in the EC_KEY object
    if (priv_key != NULL && !EC_KEY_set_private_key(ec, priv_key))
        goto err;

    // Set the public key in the EC_KEY object
    if (pub_point != NULL && !EC_KEY_set_public_key(ec, pub_point))
        goto err;

    ok = 1;

err:
    // Free allocated resources
    BN_CTX_free(ctx);
    BN_clear_free(priv_key);
    OPENSSL_free(pub_key);
    EC_POINT_free(pub_point);
    return ok;
}

int prov_ec_group_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    int ok = 0;
    EC_GROUP *group = NULL;

    if (ec == NULL)
        return 0;

    // Create a new EC_GROUP from the provided parameters
    group = EC_GROUP_new_from_params(params, NULL, NULL);
    if (group == NULL)
        goto err;

    // Set the group in the EC_KEY object
    if (!EC_KEY_set_group(ec, group))
        goto err;

    ok = 1;

err:
    // Free the EC_GROUP if it was allocated
    EC_GROUP_free(group);
    return ok;
}
static int prov_ec_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    EC_KEY *ec = keydata;
    int ok = 1;

    if (!prov_is_running() || ec == NULL)
        return 0;

    ok = ok && prov_ec_group_fromdata(ec, params);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
         int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

   ok = ok && prov_ec_key_fromdata(ec, params, include_private);
     }
    return ok;

}
const OSSL_DISPATCH prov_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))prov_ec_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))prov_ec_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
      (void (*)(void))prov_ec_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))prov_ec_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))prov_ec_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))prov_ec_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))prov_ec_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))prov_ec_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))prov_ec_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))prov_ec_has },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))prov_ec_import_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))prov_ec_import },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))prov_ec_query_operation_name },
    { 0, NULL }
};

