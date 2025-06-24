/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#define ASN1_SEQUENCE 0x30
#define ASN1_OCTET_STRING 0x04
#define ASN1_NULL 0x05
#define ASN1_OID 0x06

#define SHA224_DIGEST_LENGTH    28
#define SHA256_DIGEST_LENGTH    32
#define SHA384_DIGEST_LENGTH    48
#define SHA512_DIGEST_LENGTH    64

/* SHA OIDs are of the form: (2 16 840 1 101 3 4 2 |n|) */
#define ENCODE_DIGESTINFO_SHA(name, n, sz)                                     \
static const unsigned char digestinfo_##name##_der[] = {                       \
    ASN1_SEQUENCE, 0x11 + sz,                                                  \
      ASN1_SEQUENCE, 0x0d,                                                     \
        ASN1_OID, 0x09, 2 * 40 + 16, 0x86, 0x48, 1, 101, 3, 4, 2, n,           \
        ASN1_NULL, 0x00,                                                       \
      ASN1_OCTET_STRING, sz                                                    \
};

ENCODE_DIGESTINFO_SHA(sha256, 0x01, SHA256_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha384, 0x02, SHA384_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha512, 0x03, SHA512_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha224, 0x04, SHA224_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha512_224, 0x05, SHA224_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha512_256, 0x06, SHA256_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha3_224, 0x07, SHA224_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha3_256, 0x08, SHA256_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha3_384, 0x09, SHA384_DIGEST_LENGTH)
    ENCODE_DIGESTINFO_SHA(sha3_512, 0x0a, SHA512_DIGEST_LENGTH)
#define MD_CASE(name)                                                          \
    case NID_##name:                                                           \
        *len = sizeof(digestinfo_##name##_der);                                \
        return digestinfo_##name##_der;
const unsigned char *ossl_rsa_digestinfo_encoding(int md_nid, size_t *len)
{
    switch (md_nid) {
	MD_CASE(sha224)
	    MD_CASE(sha256)
	    MD_CASE(sha384)
	    MD_CASE(sha512)
	    MD_CASE(sha512_224)
	    MD_CASE(sha512_256)
	    MD_CASE(sha3_224)
	    MD_CASE(sha3_256)
	    MD_CASE(sha3_384)
	    MD_CASE(sha3_512)
    default:
	fprintf(stderr, "%s:%d:%s() Unsupported md algo type %u\n",
		__FILE__, __LINE__, __func__, md_nid);
	return NULL;
    }
}

/*
 * Encodes a DigestInfo prefix of hash |type| and digest |m|, as
 * described in EMSA-PKCS1-v1_5-ENCODE, RFC 3447 section 9.2 step 2. This
 * encodes the DigestInfo (T and tLen) but does not add the padding.
 *
 * On success, it returns one and sets |*out| to a newly allocated buffer
 * containing the result and |*out_len| to its length. The caller must free
 * |*out| with OPENSSL_free(). Otherwise, it returns zero.
 */
static int encode_pkcs1(unsigned char **out, size_t *out_len, int type,
			const unsigned char *m, size_t m_len)
{
    size_t di_prefix_len, dig_info_len;
    const unsigned char *di_prefix;
    unsigned char *dig_info;

    di_prefix = ossl_rsa_digestinfo_encoding(type, &di_prefix_len);
    if (unlikely(di_prefix == NULL)) {
	fprintf(stderr,
		"%s:%d:%s() ASN1 object identifier is not known for this md\n",
		__FILE__, __LINE__, __func__);
	return 0;
    }
    dig_info_len = di_prefix_len + m_len;
    dig_info = OPENSSL_malloc(dig_info_len);
    if (unlikely(dig_info == NULL)) {
	fprintf(stderr, "%s:%d:%s() OPENSSL_malloc failure\n",__FILE__, __LINE__, __func__);
	return 0;
    }
    memcpy(dig_info, di_prefix, di_prefix_len);
    memcpy(dig_info + di_prefix_len, m, m_len);

    *out = dig_info;
    *out_len = dig_info_len;
    return 1;
}
