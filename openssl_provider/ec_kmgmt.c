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
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/proverr.h>
#include "crypto/bn.h"
#include "crypto/ec.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "internal/param_build_set.h"

#include "prov.h"
#include "ec_common.h"
#include "pal_ecdsa.h"

static OSSL_FUNC_keymgmt_new_fn prov_ec_newdata;
static OSSL_FUNC_keymgmt_gen_init_fn prov_ec_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn prov_ec_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn prov_ec_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn prov_ec_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn prov_ec_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn prov_ec_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn prov_ec_load;
static OSSL_FUNC_keymgmt_has_fn prov_ec_has;
static OSSL_FUNC_keymgmt_gettable_params_fn prov_ec_settable_params;
static OSSL_FUNC_keymgmt_set_params_fn prov_ec_set_params;
static OSSL_FUNC_keymgmt_import_types_fn prov_ec_import_types;
static OSSL_FUNC_keymgmt_import_fn prov_ec_import;
static OSSL_FUNC_keymgmt_export_types_fn prov_ec_export_types;
static OSSL_FUNC_keymgmt_export_fn prov_ec_export;
static OSSL_FUNC_keymgmt_free_fn prov_ec_freedata;
static OSSL_FUNC_keymgmt_gettable_params_fn prov_ec_gettable_params;
static OSSL_FUNC_keymgmt_get_params_fn prov_ec_get_params;
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

 static const OSSL_ITEM encoding_nameid_map[] = {
    { OPENSSL_EC_EXPLICIT_CURVE, OSSL_PKEY_EC_ENCODING_EXPLICIT },
    { OPENSSL_EC_NAMED_CURVE, OSSL_PKEY_EC_ENCODING_GROUP },
};
static const OSSL_ITEM format_nameid_map[] = {
    { (int)POINT_CONVERSION_UNCOMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED },
    { (int)POINT_CONVERSION_COMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED },
    { (int)POINT_CONVERSION_HYBRID, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID },
};
static const OSSL_ITEM check_group_type_nameid_map[] = {
    { 0, OSSL_PKEY_EC_GROUP_CHECK_DEFAULT },
    { EC_FLAG_CHECK_NAMED_GROUP, OSSL_PKEY_EC_GROUP_CHECK_NAMED },
    { EC_FLAG_CHECK_NAMED_GROUP_NIST, OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST },
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

static const OSSL_PARAM *prov_ec_export_types(int selection)
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
char *ossl_ec_check_group_type_id2name(int id)
{
    size_t i, sz;

    for (i = 0, sz = OSSL_NELEM(check_group_type_nameid_map); i < sz; i++) {
        if (id == (int)check_group_type_nameid_map[i].id)
            return check_group_type_nameid_map[i].ptr;
    }
    return NULL;
}

static inline
int otherparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl,
                          OSSL_PARAM params[])
{
    int ecdh_cofactor_mode = 0, group_check = 0;
    const char *name = NULL;
    point_conversion_form_t format;

    if (ec == NULL)
        return 0;

    format = EC_KEY_get_conv_form(ec);
    name = ossl_ec_pt_format_id2name((int)format);
    if (name != NULL
        && !ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                             name))
        return 0;

    group_check = EC_KEY_get_flags(ec) & EC_FLAG_CHECK_NAMED_GROUP_MASK;
    name = ossl_ec_check_group_type_id2name(group_check);
    if (name != NULL
        && !ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
                                             name))
        return 0;

    if ((EC_KEY_get_enc_flags(ec) & EC_PKEY_NO_PUBKEY) != 0
            && !ossl_param_build_set_int(tmpl, params,
                                         OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0))
        return 0;

    ecdh_cofactor_mode =
        (EC_KEY_get_flags(ec) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
    return ossl_param_build_set_int(tmpl, params,
                                    OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                    ecdh_cofactor_mode);
}

static
void *ec_newdata(void *provctx)
{
    if (!prov_is_running())
        return NULL;
    return EC_KEY_new_ex(PROV_LIBCTX_OF(provctx), NULL);
}

static const OSSL_PARAM ec_known_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
    EC_IMEXPORTABLE_PUBLIC_KEY,
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
    EC_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};

static
const OSSL_PARAM *prov_ec_gettable_params(void *provctx)
{
    return ec_known_gettable_params;
}

int ossl_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                      const char *key,
                                      const unsigned char *data,
                                      size_t data_len)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_octet_string(p, data, data_len);
    return 1;
}

int ossl_param_build_set_int(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                             const char *key, int num)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_int(bld, key, num);
    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_int(p, num);
    return 1;
}


int ossl_param_build_set_bn(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                            const char *key, const BIGNUM *bn)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_BN(bld, key, bn);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_BN(p, bn) > 0;
    return 1;
}

int ossl_param_build_set_utf8_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                     const char *key, const char *buf)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, 0);
    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_utf8_string(p, buf);
    return 1;
}


int ossl_param_build_set_bn_pad(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                const char *key, const BIGNUM *bn,  size_t sz)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_BN_pad(bld, key, bn, sz);
    p = OSSL_PARAM_locate(p, key);
    if (p != NULL) {
        if (sz > p->data_size) {
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
            return 0;
        }
        p->data_size = sz;
        return OSSL_PARAM_set_BN(p, bn);
    }
    return 1;
}

static inline
int key_to_params(const EC_KEY *eckey, OSSL_PARAM_BLD *tmpl,
                  OSSL_PARAM params[], int include_private,
                  unsigned char **pub_key)
{
    BIGNUM *x = NULL, *y = NULL;
    const BIGNUM *priv_key = NULL;
    const EC_POINT *pub_point = NULL;
    const EC_GROUP *ecg = NULL;
    size_t pub_key_len = 0;
    int ret = 0;
    BN_CTX *bnctx = NULL;
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (eckey == NULL
        || (ecg = EC_KEY_get0_group(eckey)) == NULL)
        return 0;

    priv_key = EC_KEY_get0_private_key(eckey);
    pub_point = EC_KEY_get0_public_key(eckey);

    if (pub_point != NULL) {
        OSSL_PARAM *p = NULL, *px = NULL, *py = NULL;
        /*
         * EC_POINT_point2buf() can generate random numbers in some
         * implementations so we need to ensure we use the correct libctx.
         */
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);

        bnctx = BN_CTX_new_ex(libctx);
        if (bnctx == NULL)
            goto err;


        /* If we are doing a get then check first before decoding the point */
        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
            px = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_X);
            py = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_PUB_Y);
        }

        if (p != NULL || tmpl != NULL) {
            /* convert pub_point to a octet string according to the SECG standard */
            point_conversion_form_t format = EC_KEY_get_conv_form(eckey);

            if ((pub_key_len = EC_POINT_point2buf(ecg, pub_point,
                                                  format,
                                                  pub_key, bnctx)) == 0
                || !ossl_param_build_set_octet_string(tmpl, p,
                                                      OSSL_PKEY_PARAM_PUB_KEY,
                                                      *pub_key, pub_key_len))
                goto err;
        }
        if (px != NULL || py != NULL) {
            if (px != NULL) {
                x = BN_CTX_get(bnctx);
                if (x == NULL)
                    goto err;
            }
            if (py != NULL) {
                y = BN_CTX_get(bnctx);
                if (y == NULL)
                    goto err;
            }

            if (!EC_POINT_get_affine_coordinates(ecg, pub_point, x, y, bnctx))
                goto err;
            if (px != NULL
                && !ossl_param_build_set_bn(tmpl, px,
                                            OSSL_PKEY_PARAM_EC_PUB_X, x))
                goto err;
            if (py != NULL
                && !ossl_param_build_set_bn(tmpl, py,
                                            OSSL_PKEY_PARAM_EC_PUB_Y, y))
                goto err;
        }
    }

    if (priv_key != NULL && include_private) {
        size_t sz;
        int ecbits;

        ecbits = EC_GROUP_order_bits(ecg);
        if (ecbits <= 0)
            goto err;
        sz = (ecbits + 7) / 8;

        if (!ossl_param_build_set_bn_pad(tmpl, params,
                                         OSSL_PKEY_PARAM_PRIV_KEY,
                                         priv_key, sz))
            goto err;
    }
    ret = 1;
 err:
    BN_CTX_free(bnctx);
    return ret;
}
static int ec_get_ecm_params(const EC_GROUP *group, OSSL_PARAM params[])
{
    return 1;
}
char *ossl_ec_pt_format_id2name(int id)
{
    size_t i, sz;

    for (i = 0, sz = OSSL_NELEM(format_nameid_map); i < sz; i++) {
        if (id == (int)format_nameid_map[i].id)
            return format_nameid_map[i].ptr;
    }
    return NULL;
}
static int ec_group_explicit_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                                    OSSL_PARAM params[], BN_CTX *bnctx,
                                    unsigned char **genbuf)
{
    int ret = 0, fid;
    const char *field_type;
    const OSSL_PARAM *param = NULL;
    const OSSL_PARAM *param_p = NULL;
    const OSSL_PARAM *param_a = NULL;
    const OSSL_PARAM *param_b = NULL;

    fid = EC_GROUP_get_field_type(group);

    if (fid == NID_X9_62_prime_field) {
        field_type = SN_X9_62_prime_field;
    } else if (fid == NID_X9_62_characteristic_two_field) {
#ifdef OPENSSL_NO_EC2M
        ERR_raise(ERR_LIB_EC, EC_R_GF2M_NOT_SUPPORTED);
        goto err;
#else
        field_type = SN_X9_62_characteristic_two_field;
#endif
    } else {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FIELD);
        return 0;
    }

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_P);
    param_a = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_A);
    param_b = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_B);
    if (tmpl != NULL || param_p != NULL || param_a != NULL || param_b != NULL)
    {
        BIGNUM *p = BN_CTX_get(bnctx);
        BIGNUM *a = BN_CTX_get(bnctx);
        BIGNUM *b = BN_CTX_get(bnctx);

        if (b == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto err;
        }

        if (!EC_GROUP_get_curve(group, p, a, b, bnctx)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            goto err;
        }
        if (!ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_P, p)
            || !ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_A, a)
            || !ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_B, b)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ORDER);
    if (tmpl != NULL || param != NULL) {
        const BIGNUM *order = EC_GROUP_get0_order(group);

        if (order == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
            goto err;
        }
        if (!ossl_param_build_set_bn(tmpl, params, OSSL_PKEY_PARAM_EC_ORDER,
                                    order)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE);
    if (tmpl != NULL || param != NULL) {
        if (!ossl_param_build_set_utf8_string(tmpl, params,
                                              OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                                              field_type)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_GENERATOR);
    if (tmpl != NULL || param != NULL) {
        size_t genbuf_len;
        const EC_POINT *genpt = EC_GROUP_get0_generator(group);
        point_conversion_form_t genform = EC_GROUP_get_point_conversion_form(group);

        if (genpt == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
            goto err;
        }
        genbuf_len = EC_POINT_point2buf(group, genpt, genform, genbuf, bnctx);
        if (genbuf_len == 0) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_GENERATOR);
            goto err;
        }
        if (!ossl_param_build_set_octet_string(tmpl, params,
                                               OSSL_PKEY_PARAM_EC_GENERATOR,
                                               *genbuf, genbuf_len)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_COFACTOR);
    if (tmpl != NULL || param != NULL) {
        const BIGNUM *cofactor = EC_GROUP_get0_cofactor(group);

        if (cofactor != NULL
            && !ossl_param_build_set_bn(tmpl, params,
                                        OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_SEED);
    if (tmpl != NULL || param != NULL) {
        unsigned char *seed = EC_GROUP_get0_seed(group);
        size_t seed_len = EC_GROUP_get_seed_len(group);

        if (seed != NULL
            && seed_len > 0
            && !ossl_param_build_set_octet_string(tmpl, params,
                                                  OSSL_PKEY_PARAM_EC_SEED,
                                                  seed, seed_len)) {
            ERR_raise(ERR_LIB_EC, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }
    ret = 1;
err:
    return ret;
}
static char *ec_param_encoding_id2name(int id)
{
    size_t i, sz;

    for (i = 0, sz = OSSL_NELEM(encoding_nameid_map); i < sz; i++) {
        if (id == (int)encoding_nameid_map[i].id)
            return encoding_nameid_map[i].ptr;
    }
    return NULL;
}


int ossl_ec_group_todata(const EC_GROUP *group, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], OSSL_LIB_CTX *libctx,
                         const char *propq,
                         BN_CTX *bnctx, unsigned char **genbuf)
{
    int ret = 0, curve_nid, encoding_flag;
    const char *encoding_name, *pt_form_name;
    point_conversion_form_t genform;

    if (group == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    genform = EC_GROUP_get_point_conversion_form(group);
    pt_form_name = ossl_ec_pt_format_id2name(genform);
    if (pt_form_name == NULL
        || !ossl_param_build_set_utf8_string(
                tmpl, params,
                OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, pt_form_name)) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_FORM);
        return 0;
    }
    encoding_flag = EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE;
    encoding_name = ec_param_encoding_id2name(encoding_flag);
    if (encoding_name == NULL
        || !ossl_param_build_set_utf8_string(tmpl, params,
                                             OSSL_PKEY_PARAM_EC_ENCODING,
                                             encoding_name)) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_ENCODING);
        return 0;
    }

    if (!ossl_param_build_set_int(tmpl, params,
                                  OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
                                  0))
        return 0;

    curve_nid = EC_GROUP_get_curve_name(group);

    /*
     * Get the explicit parameters in these two cases:
     * - We do not have a template, i.e. specific parameters are requested
     * - The curve is not a named curve
     */
    if (tmpl == NULL || curve_nid == NID_undef)
        if (!ec_group_explicit_todata(group, tmpl, params, bnctx, genbuf))
            goto err;

    if (curve_nid != NID_undef) {
        /* Named curve */
        const char *curve_name = OSSL_EC_curve_nid2name(curve_nid);

        if (curve_name == NULL
            || !ossl_param_build_set_utf8_string(tmpl, params,
                                                 OSSL_PKEY_PARAM_GROUP_NAME,
                                                 curve_name)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_CURVE);
            goto err;
        }
    }
    ret = 1;
err:
    return ret;
}

static
int common_get_params(void *key, OSSL_PARAM params[])
{
    int ret = 0;
    EC_KEY *eck = key;
    const EC_GROUP *ecg = NULL;
    OSSL_PARAM *p;
    unsigned char *pub_key = NULL, *genbuf = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = "";
    BN_CTX *bnctx = NULL;

    ecg = EC_KEY_get0_group(eck);
    if (ecg == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET);
        return 0;
    }

   EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        return 0;
    BN_CTX_start(bnctx);

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, ECDSA_size(eck)))
        goto err;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, EC_GROUP_order_bits(ecg)))
        goto err;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL) {
        int ecbits, sec_bits;

        ecbits = EC_GROUP_order_bits(ecg);

        if (ecbits >= 512)
            sec_bits = 256;
        else if (ecbits >= 384)
            sec_bits = 192;
        else if (ecbits >= 256)
            sec_bits = 128;
        else if (ecbits >= 224)
            sec_bits = 112;
        else if (ecbits >= 160)
            sec_bits = 80;
        else
            sec_bits = ecbits / 2;

        if (!OSSL_PARAM_set_int(p, sec_bits))
            goto err;
    }

    if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS))
            != NULL) {
        int explicitparams = EC_KEY_decoded_from_explicit_params(eck);

        if (explicitparams < 0
             || !OSSL_PARAM_set_int(p, explicitparams))
            goto err;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
                && !OSSL_PARAM_set_utf8_string(p, EC_DEFAULT_MD))
            goto err;

     p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
        if (p != NULL) {
            int ecdh_cofactor_mode = 0;

            ecdh_cofactor_mode =
                (EC_KEY_get_flags(eck) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
        }
     if ((p = OSSL_PARAM_locate(params,
                               OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        const EC_POINT *ecp = EC_KEY_get0_public_key(key);

        if (ecp == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
            goto err;
        }
        p->return_size = EC_POINT_point2oct(ecg, ecp,
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            p->data, p->data_size, bnctx);
        if (p->return_size == 0)
            goto err;
    }

    ret = ec_get_ecm_params(ecg, params)
          && ossl_ec_group_todata(ecg, NULL, params, libctx, propq, bnctx,
                                  &genbuf)
          && key_to_params(eck, NULL, params, 1, &pub_key)
          && otherparams_to_params(eck, NULL, params);
err:
    OPENSSL_free(genbuf);
    OPENSSL_free(pub_key);
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ret;
}


int prov_ec_get_params(void *key, OSSL_PARAM params[])
{
    return common_get_params(key, params);
}

static
int prov_ec_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
              void *cbarg)
{
     EC_KEY *ec = keydata;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    unsigned char *pub_key = NULL, *genbuf = NULL;
    BN_CTX *bnctx = NULL;
    int ok = 1;
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = "";

    if(!prov_is_running() || ec == NULL)
        return 0;

     if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        bnctx = BN_CTX_new();
        if (bnctx == NULL) {
            ok=0;
            goto end;
        }
        BN_CTX_start(bnctx);
         ok = ok && ossl_ec_group_todata(EC_KEY_get0_group(ec),tmpl, NULL, libctx, propq, bnctx, &genbuf);

         if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && key_to_params(ec, tmpl, NULL, include_private, &pub_key);
    }
     if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && otherparams_to_params(ec, tmpl, NULL);

     if (!ok || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        ok = 0;
        goto end;
    }

    ok = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
end:
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_free(pub_key);
    OPENSSL_free(genbuf);
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);
    return ok;
    }
}
static const OSSL_PARAM ec_known_settable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, NULL, 0),
    OSSL_PARAM_END
};

int ossl_ec_encoding_name2id(const char *name)
{
    size_t i, sz;

    /* Return the default value if there is no name */
    if (name == NULL)
        return OPENSSL_EC_NAMED_CURVE;

    for (i = 0, sz = OSSL_NELEM(encoding_nameid_map); i < sz; i++) {
        if (OPENSSL_strcasecmp(name, encoding_nameid_map[i].ptr) == 0)
            return encoding_nameid_map[i].id;
    }
    return -1;
}

int ossl_ec_encoding_param2id(const OSSL_PARAM *p, int *id)
{
    const char *name = NULL;
    int status = 0;

    switch (p->data_type) {
    case OSSL_PARAM_UTF8_STRING:
        /* The OSSL_PARAM functions have no support for this */
        name = p->data;
        status = (name != NULL);
        break;
    case OSSL_PARAM_UTF8_PTR:
        status = OSSL_PARAM_get_utf8_ptr(p, &name);
        break;
    }
    if (status) {
        int i = ossl_ec_encoding_name2id(name);

        if (i >= 0) {
            *id = i;
            return 1;
        }
    }
    return 0;
}

int ossl_ec_group_set_params(EC_GROUP *group, const OSSL_PARAM params[])
{
    int encoding_flag = -1, format = -1;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if (p != NULL) {
        if (!ossl_ec_pt_format_param2id(p, &format)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_FORM);
            return 0;
        }
        EC_GROUP_set_point_conversion_form(group, format);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING);
    if (p != NULL) {
        if (!ossl_ec_encoding_param2id(p, &encoding_flag)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_FORM);
            return 0;
        }
        EC_GROUP_set_asn1_flag(group, encoding_flag);
    }
    /* Optional seed */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_SEED);
    if (p != NULL) {
        /* The seed is allowed to be NULL */
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || !EC_GROUP_set_seed(group, p->data, p->data_size)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_SEED);
            return 0;
        }
    }
    return 1;
}


static int ec_check_group_type_name2id(const char *name)
{
    size_t i, sz;

    /* Return the default value if there is no name */
    if (name == NULL)
        return 0;

    for (i = 0, sz = OSSL_NELEM(check_group_type_nameid_map); i < sz; i++) {
        if (OPENSSL_strcasecmp(name, check_group_type_nameid_map[i].ptr) == 0)
            return check_group_type_nameid_map[i].id;
    }
    return -1;
}

int ossl_ec_set_check_group_type_from_name(EC_KEY *ec, const char *name)
{
    int flags = ec_check_group_type_name2id(name);

    if (flags == -1)
        return 0;
    EC_KEY_clear_flags(ec, EC_FLAG_CHECK_NAMED_GROUP_MASK);
    EC_KEY_set_flags(ec, flags);
    return 1;
}

static int ec_set_check_group_type_from_param(EC_KEY *ec, const OSSL_PARAM *p)
{
    const char *name = NULL;
    int status = 0;

    switch (p->data_type) {
    case OSSL_PARAM_UTF8_STRING:
        name = p->data;
        status = (name != NULL);
        break;
    case OSSL_PARAM_UTF8_PTR:
        status = OSSL_PARAM_get_utf8_ptr(p, &name);
        break;
    }
    if (status)
        return ossl_ec_set_check_group_type_from_name(ec, name);
    return 0;
}

static int ec_key_group_check_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE);
    if (p != NULL)
        return ec_set_check_group_type_from_param(ec, p);
    return 1;
}

int ossl_ec_pt_format_name2id(const char *name)
{
    size_t i, sz;

    /* Return the default value if there is no name */
    if (name == NULL)
        return (int)POINT_CONVERSION_UNCOMPRESSED;

    for (i = 0, sz = OSSL_NELEM(format_nameid_map); i < sz; i++) {
        if (OPENSSL_strcasecmp(name, format_nameid_map[i].ptr) == 0)
            return format_nameid_map[i].id;
    }
    return -1;
}

int ossl_ec_pt_format_param2id(const OSSL_PARAM *p, int *id)
{
    const char *name = NULL;
    int status = 0;

    switch (p->data_type) {
    case OSSL_PARAM_UTF8_STRING:
        /* The OSSL_PARAM functions have no support for this */
        name = p->data;
        status = (name != NULL);
        break;
    case OSSL_PARAM_UTF8_PTR:
        status = OSSL_PARAM_get_utf8_ptr(p, &name);
        break;
    }
    if (status) {
        int i = ossl_ec_pt_format_name2id(name);

        if (i >= 0) {
            *id = i;
            return 1;
        }
    }
    return 0;
}

static int ec_set_include_public(EC_KEY *ec, int include)
{
    int flags = EC_KEY_get_enc_flags(ec);

    if (!include)
        flags |= EC_PKEY_NO_PUBKEY;
    else
        flags &= ~EC_PKEY_NO_PUBKEY;
    EC_KEY_set_enc_flags(ec, flags);
    return 1;
}

int ossl_ec_set_ecdh_cofactor_mode(EC_KEY *ec, int mode)
{
    const EC_GROUP *ecg = EC_KEY_get0_group(ec);
    const BIGNUM *cofactor;
    /*
     * mode can be only 0 for disable, or 1 for enable here.
     *
     * This is in contrast with the same parameter on an ECDH EVP_PKEY_CTX that
     * also supports mode == -1 with the meaning of "reset to the default for
     * the associated key".
     */
    if (mode < 0 || mode > 1)
        return 0;

    if ((cofactor = EC_GROUP_get0_cofactor(ecg)) == NULL )
        return 0;

    /* ECDH cofactor mode has no effect if cofactor is 1 */
    if (BN_is_one(cofactor))
        return 1;

    if (mode == 1)
        EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
    else if (mode == 0)
        EC_KEY_clear_flags(ec, EC_FLAG_COFACTOR_ECDH);

    return 1;
}

static
const OSSL_PARAM *prov_ec_settable_params(void *provctx)
{
    return ec_known_settable_params;
}

static int ec_key_point_format_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    int format = -1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if (p != NULL) {
        if (!ossl_ec_pt_format_param2id(p, &format)) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_FORM);
            return 0;
        }
        EC_KEY_set_conv_form(ec, format);
    }
    return 1;
}

int ossl_ec_key_otherparams_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (ec == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL) {
        int mode;

        if (!OSSL_PARAM_get_int(p, &mode)
            || !ossl_ec_set_ecdh_cofactor_mode(ec, mode))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC);
    if (p != NULL) {
        int include = 1;

        if (!OSSL_PARAM_get_int(p, &include)
            || !ec_set_include_public(ec, include))
            return 0;
    }
    if (!ec_key_point_format_fromdata(ec, params))
        return 0;
    if (!ec_key_group_check_fromdata(ec, params))
        return 0;
    return 1;
}


static
int prov_ec_set_params(void *key, const OSSL_PARAM params[])
{
    EC_KEY *eck = key;
    const OSSL_PARAM *p;

    BN_CTX *ctx = NULL;
    if (key == NULL)
        return 0;
    if (params == NULL)
        return 1;


    if (!ossl_ec_group_set_params((EC_GROUP *)EC_KEY_get0_group(key), params))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {

        ctx = BN_CTX_new();
        int ret = 1;

        if (ctx == NULL
                || p->data_type != OSSL_PARAM_OCTET_STRING
                || !EC_KEY_oct2key(key, p->data, p->data_size, ctx))
            ret = 0;
        BN_CTX_free(ctx);
        if (!ret)
            return 0;
    }

    return ossl_ec_key_otherparams_fromdata(eck, params);
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
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))prov_ec_export_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))prov_ec_export },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))prov_ec_settable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))prov_ec_set_params },

    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))prov_ec_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))prov_ec_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))prov_ec_query_operation_name },
    { 0, NULL }
};
