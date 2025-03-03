#include <openssl/bn.h> // For BIGNUM(bn)

/*  Our provider side key object data type */
typedef struct {
    uint8_t *n_data;
    int n_len;
    uint8_t *d_data;
    int d_len;
    uint8_t *e_data;
    int e_len;
    uint8_t *qt_p_data;
    int qt_p_len;
    uint8_t *qt_q_data;
    int qt_q_len;
    uint8_t *qt_dP_data;
    int qt_dP_len;
    uint8_t *qt_dQ_data;
    int qt_dQ_len;
    uint8_t *qt_qInv_data;
    int qt_qInv_len;
    void *base_ptr; // Base pointer to free the memory allocated for xform members
    void *provctx;
    int use_crt;
    int refcnt;
} prov_rsa_key_data;

void __prov_rsa_freedata(void *keydata);

static inline int
prov_rsa_key_len(prov_rsa_key_data *keydata)
{
	return keydata->n_len;
}
