#include "system.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
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

    /* Create the RSA key */
    RSA *rsa = RSA_new();
    if (!rsa) return 0;

    if (RSA_set0_key(rsa, key->n, key->e, NULL) <= 0)
	goto exit;
    key->n = key->e = NULL;

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the RSA key to the EVP_PKEY structure.
       This will take over memory management of the RSA key */
    if (!EVP_PKEY_assign_RSA(key->evp_pkey, rsa)) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }

    return 1;
exit:
    RSA_free(rsa);
    return 0;
}

static int pgpSetKeyMpiRSA(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    size_t mlen = pgpMpiLen(p) - 2;
    struct pgpDigKeyRSA_s *key = pgpkey->data;

    if (!key)
        key = pgpkey->data = xcalloc(1, sizeof(*key));
    else if (key->evp_pkey)
	return 1;

    switch (num) {
    case 0:
        /* Modulus */
        if (key->n) {
            /* This should only ever happen once per key */
            return 1;
        }

	key->nbytes = mlen;
        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGP */
        key->n = BN_bin2bn(p+2, mlen, NULL);
        if (!key->n) return 1;
        break;

    case 1:
        /* Exponent */
        if (key->e) {
            /* This should only ever happen once per key */
            return 1;
        }

        /* Create a BIGNUM from the pointer.
           Note: this assumes big-endian data as required by PGP */
        key->e = BN_bin2bn(p+2, mlen, NULL);
        if (!key->e) return 1;
        break;
    }

    return 0;
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
    size_t len;
};

static int pgpSetSigMpiRSA(pgpDigAlg pgpsig, int num, const uint8_t *p)
{
    BIGNUM *bn = NULL;

    int mlen = pgpMpiLen(p) - 2;
    int rc = 1;

    struct pgpDigSigRSA_s *sig = pgpsig->data;
    if (!sig) {
        sig = xcalloc(1, sizeof(*sig));
    }

    switch (num) {
    case 0:
        if (sig->bn) {
            /* This should only ever happen once per signature */
            return 1;
        }

        bn = sig->bn = BN_new();
        if (!bn) return 1;

        /* Create a BIGNUM from the signature pointer.
           Note: this assumes big-endian data as required
           by the PGP multiprecision integer format
           (RFC4880, Section 3.2)
           This will be useful later, as we can
           retrieve this value with appropriate
           padding. */
        bn = BN_bin2bn(p+2, mlen, bn);
        if (!bn) return 1;

        sig->bn = bn;
        sig->len = mlen;

        pgpsig->data = sig;
        rc = 0;
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

static int pgpVerifySigRSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                           uint8_t *hash, size_t hashlen, int hash_algo)
{
    int rc = 1; /* assume failure */
    EVP_PKEY_CTX *pkey_ctx = NULL;
    struct pgpDigSigRSA_s *sig = pgpsig->data;

    void *padded_sig = NULL;

    struct pgpDigKeyRSA_s *key = pgpkey->data;

    if (!constructRSASigningKey(key))
        goto done;

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
    {
        /* Success */
        rc = 0;
    }

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

    /* Create the DSA key */
    DSA *dsa = DSA_new();
    if (!dsa) return 0;

    if (!DSA_set0_pqg(dsa, key->p, key->q, key->g)) {
        goto exit;
    }
    if (!DSA_set0_key(dsa, key->y, NULL)) {
        goto exit;
    }

    /* Create an EVP_PKEY container to abstract the key-type. */
    if (!(key->evp_pkey = EVP_PKEY_new()))
	goto exit;

    /* Assign the DSA key to the EVP_PKEY structure.
       This will take over memory management of the RSA key */
    if (!EVP_PKEY_assign_DSA(key->evp_pkey, dsa)) {
        EVP_PKEY_free(key->evp_pkey);
        key->evp_pkey = NULL;
	goto exit;
    }
    return 1;

exit:
    DSA_free(dsa);
    return 0;
}


static int pgpSetKeyMpiDSA(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    BIGNUM *bn;
    size_t mlen = pgpMpiLen(p) - 2;
    struct pgpDigKeyDSA_s *key = pgpkey->data;

    if (!key) {
        key = pgpkey->data = xcalloc(1, sizeof(*key));
    }

    /* Create a BIGNUM from the key pointer.
       Note: this assumes big-endian data as required
       by the PGP multiprecision integer format
       (RFC4880, Section 3.2) */
    bn = BN_bin2bn(p+2, mlen, NULL);
    if (!bn) return 1;

    switch (num) {
    case 0:
        /* Prime */
        if (key->p) {
            /* This should only ever happen once per key */
            return 1;
        }
        key->p = bn;
        break;

    case 1:
        /* Subprime */
        if (key->q) {
            /* This should only ever happen once per key */
            return 1;
        }
        key->q = bn;
        break;
    case 2:
        /* Base */
        if (key->g) {
            /* This should only ever happen once per key */
            return 1;
        }
        key->g = bn;
        break;
    case 3:
        /* Public */
        if (key->y) {
            /* This should only ever happen once per key */
            return 1;
        }
        key->y = bn;
        break;
    }

    return 0;
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

static int pgpSetSigMpiDSA(pgpDigAlg pgpsig, int num, const uint8_t *p)
{
    int mlen = pgpMpiLen(p) - 2;
    int rc = 1;

    struct pgpDigSigDSA_s *sig = pgpsig->data;
    if (!sig) {
        sig = xcalloc(1, sizeof(*sig));
	pgpsig->data = sig;
    }

    switch (num) {
    case 0:
        if (sig->r)
            return 1;	/* This should only ever happen once per signature */
	sig->rlen = mlen;
        sig->r = memcpy(xmalloc(mlen), p + 2, mlen);
        rc = 0;
        break;
    case 1:
        if (sig->s)
            return 1;	/* This should only ever happen once per signature */
	sig->slen = mlen;
        sig->s = memcpy(xmalloc(mlen), p + 2, mlen);
        rc = 0;
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

static int pgpVerifySigDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                           uint8_t *hash, size_t hashlen, int hash_algo)
{
    int rc = 1; /* assume failure */
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    unsigned char *xsig = NULL;		/* signature encoded for X509 */
    size_t xsig_len = 0;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (!constructDSASigningKey(key))
        goto done;

    xsig = constructDSASignature(sig->r, sig->rlen, sig->s, sig->slen, &xsig_len);
    if (!xsig)
        goto done;

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (!pkey_ctx)
        goto done;

    if (EVP_PKEY_verify_init(pkey_ctx) != 1)
        goto done;

    if (EVP_PKEY_verify(pkey_ctx, xsig, xsig_len, hash, hashlen) == 1)
    {
        /* Success */
        rc = 0;
    }

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

static int pgpSetKeyMpiEDDSA(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    size_t mlen = pgpMpiLen(p) - 2;
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    int rc = 1;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));
    if (num == 0 && !key->q && mlen > 1 && p[2] == 0x40) {
	key->qlen = mlen - 1;
	key->q = xmalloc(key->qlen);
	memcpy(key->q, p + 3, key->qlen),
	rc = 0;
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

static int pgpSetSigMpiEDDSA(pgpDigAlg pgpsig, int num, const uint8_t *p)
{
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    int mlen = pgpMpiLen(p) - 2;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));
    if (!mlen || mlen > 32 || (num != 0 && num != 1))
	return 1;
    memcpy(sig->sig + 32 * num + 32 - mlen, p + 2, mlen);
    return 0;
}

static void pgpFreeSigEDDSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    if (sig) {
	free(pgpsig->data);
    }
}

static int pgpVerifySigEDDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                           uint8_t *hash, size_t hashlen, int hash_algo)
{
    int rc = 1;		/* assume failure */
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    EVP_MD_CTX *md_ctx = NULL;

    if (!constructEDDSASigningKey(key, pgpkey->curve))
	goto done;
    md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_md_null(), NULL, key->evp_pkey) != 1)
	goto done;
    if (EVP_DigestVerify(md_ctx, sig->sig, 64, hash, hashlen) == 1)
	rc = 0;		/* Success */
done:
    if (md_ctx)
	EVP_MD_CTX_free(md_ctx);
    return rc;
}

#endif


/****************************** NULL **************************************/

static int pgpSetMpiNULL(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    return 1;
}

static int pgpVerifyNULL(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                         uint8_t *hash, size_t hashlen, int hash_algo)
{
    return 1;
}

/****************************** PGP **************************************/
pgpDigAlg pgpDigAlgNewPubkey(int algo, int curve)
{
    pgpDigAlg ka = xcalloc(1, sizeof(*ka));;

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
#ifdef EVP_PKEY_ED25519
    case PGPPUBKEYALGO_EDDSA:
	if (curve != PGPCURVE_ED25519) {
	    ka->setmpi = pgpSetMpiNULL;	/* unsupported curve */
	    ka->mpis = -1;
	    break;
	}
        ka->setmpi = pgpSetKeyMpiEDDSA;
        ka->free = pgpFreeKeyEDDSA;
        ka->mpis = 1;
        ka->curve = curve;
        break;
#endif
    default:
        ka->setmpi = pgpSetMpiNULL;
        ka->mpis = -1;
        break;
    }

    ka->verify = pgpVerifyNULL; /* keys can't be verified */

    return ka;
}

pgpDigAlg pgpDigAlgNewSignature(int algo)
{
    pgpDigAlg sa = xcalloc(1, sizeof(*sa));

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
#ifdef EVP_PKEY_ED25519
    case PGPPUBKEYALGO_EDDSA:
        sa->setmpi = pgpSetSigMpiEDDSA;
        sa->free = pgpFreeSigEDDSA;
        sa->verify = pgpVerifySigEDDSA;
        sa->mpis = 2;
        break;
#endif
    default:
        sa->setmpi = pgpSetMpiNULL;
        sa->verify = pgpVerifyNULL;
        sa->mpis = -1;
        break;
    }
    return sa;
}
