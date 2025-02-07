#include <openssl/bn.h> // For BIGNUM(bn)

/*  Our provider side key object data type */
typedef struct {
    void *provctx;
    BIGNUM *n;  // Modulus
    BIGNUM *e;  // Public exponent
    BIGNUM *d;  // Private exponent
#if 0
    BIGNUM *p;  // Prime 1
    BIGNUM *q;  // Prime 2
    BIGNUM *dP; // d mod (p-1)
    BIGNUM *dQ; // d mod (q-1)
    BIGNUM *qinv; // q^(-1) mod p
#endif
    int refcnt;
} prov_rsa_key_data;

void __prov_rsa_freedata(void *keydata);

static inline int
prov_rsa_key_len(prov_rsa_key_data *keydata)
{
	return BN_num_bytes(keydata->n);
}
