#include "system.h"

#include <openssl/evp.h>
#if OPENSSL_VERSION_MAJOR >= 3
# include <openssl/params.h>
#endif
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

#include <rpm/rpmcrypto.h>
#include "rpmpgp_internal.h"

static const EVP_MD *getEVPMD(int hashalgo)
{
    switch (hashalgo) {

    case RPM_HASH_MD5:
        return EVP_md5();

    case RPM_HASH_SHA1:
        return EVP_sha1();

    case RPM_HASH_SHA256:
        return EVP_sha256();

    case RPM_HASH_SHA384:
        return EVP_sha384();

    case RPM_HASH_SHA512:
        return EVP_sha512();

    case RPM_HASH_SHA224:
        return EVP_sha224();

    default:
        return EVP_md_null();
    }
}


/*********************** pkey construction *******************************/

#if OPENSSL_VERSION_MAJOR >= 3

static EVP_PKEY *
construct_pkey_from_param(int id, OSSL_PARAM *params)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	pkey = NULL;
    if (ctx)
	EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static OSSL_PARAM 
create_bn_param(char *key, BIGNUM *bn)
{
    int sz = bn ? BN_num_bytes(bn) : -1;
    if (sz < 0 || BN_is_negative(bn)) {
	OSSL_PARAM param = OSSL_PARAM_END;
	return param;
    }
    if (sz == 0)
	sz = 1;
    unsigned char *buf = xmalloc(sz);
    BN_bn2nativepad(bn, buf, sz);
    OSSL_PARAM param = OSSL_PARAM_BN(key, buf, sz);
    return param;
}

static void
free_bn_param(OSSL_PARAM *param)
{
    free(param->data);
}

#endif

/****************************** RSA **************************************/

/* Key */

struct pgpDigKeyRSA_s {
    size_t nbytes; /* Size of modulus */

    BIGNUM *n; /* Common Modulus */
    BIGNUM *e; /* Public Exponent */
    EVP_PKEY *evp_pkey; /* Fully constructed key */
};

static int constructRSASigningKey(struct pgpDigKeyRSA_s *key)
{
    if (key->evp_pkey)
        return 1;	/* We've already constructed it, so just reuse it */

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_PARAM params[] = {
	create_bn_param("n", key->n),
	create_bn_param("e", key->e),
	OSSL_PARAM_END
    };
    key->evp_pkey = construct_pkey_from_param(EVP_PKEY_RSA, params);
    free_bn_param(params + 0);
    free_bn_param(params + 1);
    return key->evp_pkey ? 1 : 0;
#else
    /* Create the RSA key */
    RSA *rsa = RSA_new();
    if (!rsa) return 0;

    if (RSA_set0_key(rsa, key->n, key->e, NULL) != 1)
	goto exit;
    key->n = key->e = NULL;

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the RSA key to the EVP_PKEY structure.
       This will take over memory management of the key */
    if (EVP_PKEY_assign_RSA(key->evp_pkey, rsa) != 1) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }

    return 1;
exit:
    RSA_free(rsa);
    return 0;
#endif
}

static rpmpgpRC pgpSetKeyMpiRSA(pgpDigAlg pgpkey, int num, const uint8_t *p, int mlen)
{
    rpmpgpRC rc = RPMPGP_ERROR_BAD_PUBKEY;	/* assume failure */
    struct pgpDigKeyRSA_s *key = pgpkey->data;

    if (!key)
        key = pgpkey->data = xcalloc(1, sizeof(*key));

    if (key->evp_pkey)
	return rc;

    switch (num) {
    case 0:
        /* Modulus */
        if (key->n)
            return 1;	/* This should only ever happen once per key */
	key->nbytes = mlen - 2;
        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGP */
        key->n = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (key->n)
	    rc = RPMPGP_OK;
        break;

    case 1:
        /* Exponent */
        if (key->e)
            return 1;	/* This should only ever happen once per key */
        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGP */
        key->e = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (key->e)
	    rc = RPMPGP_OK;
        break;
    }

    return rc;
}

static void pgpFreeKeyRSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    if (key) {
        if (key->evp_pkey) {
            EVP_PKEY_free(key->evp_pkey);
        } else {
            /* If key->evp_pkey was constructed,
             * the memory management of these BNs
             * are freed with it. */
            BN_clear_free(key->n);
            BN_clear_free(key->e);
        }

        free(key);
    }
}

/* Signature */

struct pgpDigSigRSA_s {
    BIGNUM *bn;
};

static rpmpgpRC pgpSetSigMpiRSA(pgpDigAlg pgpsig, int num, const uint8_t *p, int mlen)
{
    rpmpgpRC rc = RPMPGP_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgpDigSigRSA_s *sig = pgpsig->data;

    if (!sig)
        sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
        if (sig->bn)
            return rc;	/* This should only ever happen once per signature */
        /* Create a BIGNUM from the signature pointer.
           Note: this assumes big-endian data as required
           by the PGP multiprecision integer format
           (RFC4880, Section 3.2)
           This will be useful later, as we can
           retrieve this value with appropriate
           padding. */
        sig->bn = BN_bin2bn(p + 2, mlen - 2, NULL);
        if (sig->bn)
	    rc = RPMPGP_OK;
        break;
    }
    return rc;
}

static void pgpFreeSigRSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    if (sig) {
        BN_clear_free(sig->bn);
        free(pgpsig->data);
    }
}

static rpmpgpRC pgpVerifySigRSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                           uint8_t *hash, size_t hashlen, int hash_algo)
{
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    void *padded_sig = NULL;

    if (!constructRSASigningKey(key)) {
        rc = RPMPGP_ERROR_BAD_PUBKEY;
        goto done;
    }

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
        goto done;

    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
        goto done;

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, getEVPMD(hash_algo)) <= 0)
        goto done;

    int pkey_len = EVP_PKEY_size(key->evp_pkey);
    padded_sig = xcalloc(1, pkey_len);
    if (BN_bn2binpad(sig->bn, padded_sig, pkey_len) <= 0)
        goto done;

    if (EVP_PKEY_verify(pkey_ctx, padded_sig, pkey_len, hash, hashlen) == 1)
        rc = RPMPGP_OK;		/* Success */

done:
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(padded_sig);
    return rc;
}

/****************************** DSA ***************************************/
/* Key */

struct pgpDigKeyDSA_s {
    BIGNUM *p; /* Prime */
    BIGNUM *q; /* Subprime */
    BIGNUM *g; /* Base */
    BIGNUM *y; /* Public Key */

    EVP_PKEY *evp_pkey; /* Fully constructed key */
};

static int constructDSASigningKey(struct pgpDigKeyDSA_s *key)
{
    if (key->evp_pkey)
        return 1;	/* We've already constructed it, so just reuse it */

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_PARAM params[] = {
	create_bn_param("p", key->p),
	create_bn_param("q", key->q),
	create_bn_param("g", key->g),
	create_bn_param("pub", key->y),
	OSSL_PARAM_END
    };
    key->evp_pkey = construct_pkey_from_param(EVP_PKEY_DSA, params);
    free_bn_param(params + 0);
    free_bn_param(params + 1);
    free_bn_param(params + 2);
    free_bn_param(params + 3);
    return key->evp_pkey ? 1 : 0;
#else
    /* Create the DSA key */
    DSA *dsa = DSA_new();
    if (!dsa) return 0;

    if (DSA_set0_pqg(dsa, key->p, key->q, key->g) != 1)
        goto exit;
    key->p = key->q = key->g = NULL;
    if (DSA_set0_key(dsa, key->y, NULL) != 1)
        goto exit;
    key->y = NULL;

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the DSA key to the EVP_PKEY structure.
       This will take over memory management of the key */
    if (EVP_PKEY_assign_DSA(key->evp_pkey, dsa) != 1) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }
    return 1;

exit:
    DSA_free(dsa);
    return 0;
#endif
}


static rpmpgpRC pgpSetKeyMpiDSA(pgpDigAlg pgpkey, int num, const uint8_t *p, int mlen)
{
    rpmpgpRC rc = RPMPGP_ERROR_BAD_PUBKEY;	/* assume failure */
    struct pgpDigKeyDSA_s *key = pgpkey->data;

    if (!key)
        key = pgpkey->data = xcalloc(1, sizeof(*key));

    switch (num) {
    case 0:
        /* Prime */
        if (key->p)
            return rc;	/* This should only ever happen once per key */
        key->p = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->p)
	    rc = RPMPGP_OK;
        break;
    case 1:
        /* Subprime */
        if (key->q)
            return rc;	/* This should only ever happen once per key */
        key->q = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->q)
	    rc = RPMPGP_OK;
        break;
    case 2:
        /* Base */
        if (key->g)
            return rc;	/* This should only ever happen once per key */
        key->g = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->g)
	    rc = RPMPGP_OK;
        break;
    case 3:
        /* Public */
        if (key->y)
            return rc;	/* This should only ever happen once per key */
        key->y = BN_bin2bn(p + 2, mlen - 2, NULL);
	if (key->y)
	    rc = RPMPGP_OK;
        break;
    }
    return rc;
}

static void pgpFreeKeyDSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    if (key) {
        if (key->evp_pkey) {
            EVP_PKEY_free(key->evp_pkey);
        } else {
            /* If key->evp_pkey was constructed,
             * the memory management of these BNs
             * are freed with it. */
            BN_clear_free(key->p);
            BN_clear_free(key->q);
            BN_clear_free(key->g);
            BN_clear_free(key->y);
        }
        free(key);
    }
}

/* Signature */

struct pgpDigSigDSA_s {
    unsigned char *r;
    int rlen;
    unsigned char *s;
    int slen;
};

static void add_asn1_tag(unsigned char *p, int tag, int len)
{
    *p++ = tag;
    if (len >= 256) {
	*p++ = 130;
	*p++ = len >> 8;
    } else if (len > 128) {
	*p++ = 129;
    }
    *p++ = len;
}

/* create the DER encoding of the SEQUENCE of two INTEGERs r and s */
/* used by DSA and ECDSA */
static unsigned char *constructDSASignature(unsigned char *r, int rlen, unsigned char *s, int slen, size_t *siglenp)
{
    int len1 = rlen + (!rlen || (*r & 0x80) != 0 ? 1 : 0), hlen1 = len1 < 128 ? 2 : len1 < 256 ? 3 : 4;
    int len2 = slen + (!slen || (*s & 0x80) != 0 ? 1 : 0), hlen2 = len2 < 128 ? 2 : len2 < 256 ? 3 : 4;
    int len3 = hlen1 + len1 + hlen2 + len2, hlen3 = len3 < 128 ? 2 : len3 < 256 ? 3 : 4;
    unsigned char *buf;
    if (rlen < 0 || rlen >= 65534 || slen < 0 || slen >= 65534 || len3 > 65535)
	return 0;	/* should never happen as pgp's MPIs have a length < 8192 */
    buf = xmalloc(hlen3 + len3);
    add_asn1_tag(buf, 0x30, len3);
    add_asn1_tag(buf + hlen3, 0x02, len1);
    buf[hlen3 + hlen1] = 0;		/* zero first byte of the integer */
    memcpy(buf + hlen3 + hlen1 + len1 - rlen, r, rlen);
    add_asn1_tag(buf + hlen3 + hlen1 + len1, 0x02, len2);
    buf[hlen3 + len3 - len2] = 0;	/* zero first byte of the integer */
    memcpy(buf + hlen3 + len3 - slen, s, slen);
    *siglenp = hlen3 + len3;
    return buf;
}

static rpmpgpRC pgpSetSigMpiDSA(pgpDigAlg pgpsig, int num, const uint8_t *p, int mlen)
{
    rpmpgpRC rc = RPMPGP_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgpDigSigDSA_s *sig = pgpsig->data;

    if (!sig)
        sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
        if (sig->r)
            return rc;	/* This should only ever happen once per signature */
        sig->rlen = mlen - 2;
        sig->r = memcpy(xmalloc(mlen - 2), p + 2, mlen - 2);
        rc = RPMPGP_OK;
        break;
    case 1:
        if (sig->s)
            return rc;	/* This should only ever happen once per signature */
        sig->slen = mlen - 2;
        sig->s = memcpy(xmalloc(mlen - 2), p + 2, mlen - 2);
        rc = RPMPGP_OK;
        break;
    }

    return rc;
}

static void pgpFreeSigDSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    if (sig) {
	free(sig->r);
	free(sig->s);
    }
    free(pgpsig->data);
}

static rpmpgpRC pgpVerifySigDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                           uint8_t *hash, size_t hashlen, int hash_algo)
{
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    unsigned char *xsig = NULL;		/* signature encoded for X509 */
    size_t xsig_len = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (!constructDSASigningKey(key)) {
        rc = RPMPGP_ERROR_BAD_PUBKEY;
        goto done;
    }

    xsig = constructDSASignature(sig->r, sig->rlen, sig->s, sig->slen, &xsig_len);
    if (!xsig)
        goto done;

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
        goto done;

    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
        goto done;

    if (EVP_PKEY_verify(pkey_ctx, xsig, xsig_len, hash, hashlen) == 1)
        rc = RPMPGP_OK;		/* Success */

done:
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(xsig);
    return rc;
}

/****************************** ECDSA ***************************************/

struct pgpDigKeyECDSA_s {
    EVP_PKEY *evp_pkey; /* Fully constructed key */
    unsigned char *q;	/* compressed point */
    int qlen;
};

static int constructECDSASigningKey(struct pgpDigKeyECDSA_s *key, int curve)
{
    if (key->evp_pkey)
	return 1;	/* We've already constructed it, so just reuse it */

#if OPENSSL_VERSION_MAJOR >= 3
    if (curve == PGPCURVE_NIST_P_256) {
	OSSL_PARAM params[] = {
	    OSSL_PARAM_utf8_string("group", "P-256", 5),
	    OSSL_PARAM_octet_string("pub", key->q, key->qlen),
	    OSSL_PARAM_END
	};
	key->evp_pkey = construct_pkey_from_param(EVP_PKEY_EC, params);
    } else if (curve == PGPCURVE_NIST_P_384) {
	OSSL_PARAM params[] = {
	    OSSL_PARAM_utf8_string("group", "P-384", 5),
	    OSSL_PARAM_octet_string("pub", key->q, key->qlen),
	    OSSL_PARAM_END
	};
	key->evp_pkey = construct_pkey_from_param(EVP_PKEY_EC, params);
    } else if (curve == PGPCURVE_NIST_P_521) {
	OSSL_PARAM params[] = {
	    OSSL_PARAM_utf8_string("group", "P-521", 5),
	    OSSL_PARAM_octet_string("pub", key->q, key->qlen),
	    OSSL_PARAM_END
	};
	key->evp_pkey = construct_pkey_from_param(EVP_PKEY_EC, params);
    }
    return key->evp_pkey ? 1 : 0;
#else
    /* Create the EC key */
    EC_KEY *ec = NULL;
    if (curve == PGPCURVE_NIST_P_256)
	ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    else if (curve == PGPCURVE_NIST_P_384)
	ec = EC_KEY_new_by_curve_name(NID_secp384r1);
    else if (curve == PGPCURVE_NIST_P_521)
	ec = EC_KEY_new_by_curve_name(NID_secp521r1);
    if (!ec)
	return 0;

    if (EC_KEY_oct2key(ec, key->q, key->qlen, NULL) != 1)
        goto exit;

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the EC key to the EVP_PKEY structure.
       This will take over memory management of the key */
    if (EVP_PKEY_assign_EC_KEY(key->evp_pkey, ec) != 1) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }
    return 1;

exit:
    EC_KEY_free(ec);
    return 0;
#endif
}

static rpmpgpRC pgpSetKeyMpiECDSA(pgpDigAlg pgpkey, int num, const uint8_t *p, int mlen)
{
    struct pgpDigKeyECDSA_s *key = pgpkey->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_PUBKEY;	/* assume failure */

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));
    if (num == 0 && !key->q && mlen > 3 && p[2] == 0x04) {
	key->qlen = mlen - 2;
	key->q = memcpy(xmalloc(mlen - 2), p + 2, mlen - 2);
	rc = RPMPGP_OK;
    }
    return rc;
}

static void pgpFreeKeyECDSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyECDSA_s *key = pgpkey->data;
    if (key) {
	if (key->q)
	    free(key->q);
	if (key->evp_pkey)
	    EVP_PKEY_free(key->evp_pkey);
	free(key);
    }
}

struct pgpDigSigECDSA_s {
    unsigned char *r;
    int rlen;
    unsigned char *s;
    int slen;
};

static rpmpgpRC pgpSetSigMpiECDSA(pgpDigAlg pgpsig, int num, const uint8_t *p, int mlen)
{
    rpmpgpRC rc = RPMPGP_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgpDigSigECDSA_s *sig = pgpsig->data;

    if (!sig)
        sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
        if (sig->r)
            return rc;	/* This should only ever happen once per signature */
	sig->rlen = mlen - 2;
        sig->r = memcpy(xmalloc(mlen), p + 2, mlen - 2);
        rc = RPMPGP_OK;
        break;
    case 1:
        if (sig->s)
            return 1;	/* This should only ever happen once per signature */
	sig->slen = mlen - 2;
        sig->s = memcpy(xmalloc(mlen), p + 2, mlen - 2);
        rc = RPMPGP_OK;
        break;
    }

    return rc;
}

static void pgpFreeSigECDSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigECDSA_s *sig = pgpsig->data;
    if (sig) {
	free(sig->r);
	free(sig->s);
    }
    free(pgpsig->data);
}

static rpmpgpRC pgpVerifySigECDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                           uint8_t *hash, size_t hashlen, int hash_algo)
{
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgpDigSigECDSA_s *sig = pgpsig->data;
    struct pgpDigKeyECDSA_s *key = pgpkey->data;
    unsigned char *xsig = NULL;		/* signature encoded for X509 */
    size_t xsig_len = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (!constructECDSASigningKey(key, pgpkey->curve)) {
	rc = RPMPGP_ERROR_BAD_PUBKEY;
        goto done;
    }

    xsig = constructDSASignature(sig->r, sig->rlen, sig->s, sig->slen, &xsig_len);
    if (!xsig)
        goto done;

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
        goto done;

    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
        goto done;

    if (EVP_PKEY_verify(pkey_ctx, xsig, xsig_len, hash, hashlen) == 1)
        rc = RPMPGP_OK;		/* Success */

done:
    if (pkey_ctx)
	EVP_PKEY_CTX_free(pkey_ctx);
    free(xsig);
    return rc;
}

/****************************** EDDSA ***************************************/

#ifdef EVP_PKEY_ED25519

struct pgpDigKeyEDDSA_s {
    EVP_PKEY *evp_pkey; /* Fully constructed key */
    unsigned char *q;	/* compressed point */
    int qlen;
};

static int constructEDDSASigningKey(struct pgpDigKeyEDDSA_s *key, int curve)
{
    if (key->evp_pkey)
	return 1;	/* We've already constructed it, so just reuse it */
    if (curve == PGPCURVE_ED25519)
	key->evp_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key->q, key->qlen);
    return key->evp_pkey ? 1 : 0;
}

static rpmpgpRC pgpSetKeyMpiEDDSA(pgpDigAlg pgpkey, int num, const uint8_t *p, int mlen)
{
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));
    if (num == 0 && !key->q && mlen > 3 && p[2] == 0x40) {
	key->qlen = mlen - 3;
	key->q = memcpy(xmalloc(key->qlen), p + 3, key->qlen);		/* we do not copy the leading 0x40 */
	rc = RPMPGP_OK;
    }
    return rc;
}

static void pgpFreeKeyEDDSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    if (key) {
	if (key->q)
	    free(key->q);
	if (key->evp_pkey)
	    EVP_PKEY_free(key->evp_pkey);
	free(key);
    }
}

struct pgpDigSigEDDSA_s {
    unsigned char sig[32 + 32];
};

static rpmpgpRC pgpSetSigMpiEDDSA(pgpDigAlg pgpsig, int num, const uint8_t *p, int mlen)
{
    rpmpgpRC rc = RPMPGP_ERROR_BAD_SIGNATURE;	/* assume failure */
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));
    mlen -= 2;	/* skip mpi len */
    if (mlen <= 0 || mlen > 32 || (num != 0 && num != 1))
	return rc;
    memcpy(sig->sig + 32 * num + 32 - mlen, p + 2, mlen);
    return RPMPGP_OK;
}

static void pgpFreeSigEDDSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    if (sig) {
	free(pgpsig->data);
    }
}

static rpmpgpRC pgpVerifySigEDDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                           uint8_t *hash, size_t hashlen, int hash_algo)
{
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION;	/* assume failure */
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    EVP_MD_CTX *md_ctx = NULL;

    if (!constructEDDSASigningKey(key, pgpkey->curve)) {
	rc = RPMPGP_ERROR_BAD_PUBKEY;
	goto done;
    }
    md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_md_null(), NULL, key->evp_pkey) != 1)
	goto done;
    if (EVP_DigestVerify(md_ctx, sig->sig, 64, hash, hashlen) == 1)
	rc = RPMPGP_OK;		/* Success */
done:
    if (md_ctx)
	EVP_MD_CTX_free(md_ctx);
    return rc;
}

#endif



/****************************** PGP **************************************/

static int pgpSupportedCurve(int algo, int curve)
{
#ifdef EVP_PKEY_ED25519
    if (algo == PGPPUBKEYALGO_EDDSA && curve == PGPCURVE_ED25519)
	return 1;
#endif
    if (algo == PGPPUBKEYALGO_ECDSA && curve == PGPCURVE_NIST_P_256)
	return 1;
    if (algo == PGPPUBKEYALGO_ECDSA && curve == PGPCURVE_NIST_P_384)
	return 1;
    if (algo == PGPPUBKEYALGO_ECDSA && curve == PGPCURVE_NIST_P_521)
	return 1;
    return 0;
}

void pgpDigAlgInitPubkey(pgpDigAlg ka, int algo, int curve)
{
    switch (algo) {
    case PGPPUBKEYALGO_RSA:
        ka->setmpi = pgpSetKeyMpiRSA;
        ka->free = pgpFreeKeyRSA;
        ka->mpis = 2;
        break;
    case PGPPUBKEYALGO_DSA:
        ka->setmpi = pgpSetKeyMpiDSA;
        ka->free = pgpFreeKeyDSA;
        ka->mpis = 4;
        break;
    case PGPPUBKEYALGO_ECDSA:
	if (!pgpSupportedCurve(algo, curve))
	    break;
        ka->setmpi = pgpSetKeyMpiECDSA;
        ka->free = pgpFreeKeyECDSA;
        ka->mpis = 1;
        ka->curve = curve;
	break;
#ifdef EVP_PKEY_ED25519
    case PGPPUBKEYALGO_EDDSA:
	if (!pgpSupportedCurve(algo, curve))
	    break;
        ka->setmpi = pgpSetKeyMpiEDDSA;
        ka->free = pgpFreeKeyEDDSA;
        ka->mpis = 1;
        ka->curve = curve;
        break;
#endif
    default:
        break;
    }
}

void pgpDigAlgInitSignature(pgpDigAlg sa, int algo)
{
    switch (algo) {
    case PGPPUBKEYALGO_RSA:
        sa->setmpi = pgpSetSigMpiRSA;
        sa->free = pgpFreeSigRSA;
        sa->verify = pgpVerifySigRSA;
        sa->mpis = 1;
        break;
    case PGPPUBKEYALGO_DSA:
        sa->setmpi = pgpSetSigMpiDSA;
        sa->free = pgpFreeSigDSA;
        sa->verify = pgpVerifySigDSA;
        sa->mpis = 2;
        break;
    case PGPPUBKEYALGO_ECDSA:
        sa->setmpi = pgpSetSigMpiECDSA;
        sa->free = pgpFreeSigECDSA;
        sa->verify = pgpVerifySigECDSA;
        sa->mpis = 2;
        break;
#ifdef EVP_PKEY_ED25519
    case PGPPUBKEYALGO_EDDSA:
        sa->setmpi = pgpSetSigMpiEDDSA;
        sa->free = pgpFreeSigEDDSA;
        sa->verify = pgpVerifySigEDDSA;
        sa->mpis = 2;
        break;
#endif
    default:
        break;
    }
}
