#include "system.h"

#include <gcrypt.h>

#include <rpm/rpmcrypto.h>
#include "rpmpgp_internal.h"
#include "debug.h"

static int hashalgo2gcryalgo(int hashalgo)
{
    switch (hashalgo) {
    case RPM_HASH_MD5:
	return GCRY_MD_MD5;
    case RPM_HASH_SHA1:
	return GCRY_MD_SHA1;
    case RPM_HASH_SHA224:
	return GCRY_MD_SHA224;
    case RPM_HASH_SHA256:
	return GCRY_MD_SHA256;
    case RPM_HASH_SHA384:
	return GCRY_MD_SHA384;
    case RPM_HASH_SHA512:
	return GCRY_MD_SHA512;
    default:
	return 0;
    }
}

/****************************** RSA **************************************/

struct pgpDigSigRSA_s {
    gcry_mpi_t s;
};

struct pgpDigKeyRSA_s {
    gcry_mpi_t n;
    gcry_mpi_t e;
};

static rpmpgpRC pgpSetSigMpiRSA(pgpDigAlg pgpsig, int num, const uint8_t *p, int mlen)
{
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_SIGNATURE;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    }
    return rc;
}

static rpmpgpRC pgpSetKeyMpiRSA(pgpDigAlg pgpkey, int num, const uint8_t *p, int mlen)
{
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->n, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&key->e, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    }
    return rc;
}

static rpmpgpRC pgpVerifySigRSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig, uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    int gcry_hash_algo = hashalgo2gcryalgo(hash_algo);
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION;

    if (!sig || !key || !gcry_hash_algo)
	return rc;

    gcry_sexp_build(&sexp_sig, NULL, "(sig-val (rsa (s %M)))", sig->s);
    gcry_sexp_build(&sexp_data, NULL, "(data (flags pkcs1) (hash %s %b))", gcry_md_algo_name(gcry_hash_algo), (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (rsa (n %M) (e %M)))", key->n, key->e);
    if (sexp_sig && sexp_data && sexp_pkey)
	if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
	    rc = RPMPGP_OK;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgpFreeSigRSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    if (sig) {
        gcry_mpi_release(sig->s);
	pgpsig->data = _free(sig);
    }
}

static void pgpFreeKeyRSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    if (key) {
        gcry_mpi_release(key->n);
        gcry_mpi_release(key->e);
	pgpkey->data = _free(key);
    }
}


/****************************** DSA **************************************/

struct pgpDigSigDSA_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgpDigKeyDSA_s {
    gcry_mpi_t p;
    gcry_mpi_t q;
    gcry_mpi_t g;
    gcry_mpi_t y;
};

static rpmpgpRC pgpSetSigMpiDSA(pgpDigAlg pgpsig, int num, const uint8_t *p, int mlen)
{
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_SIGNATURE;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->r, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    }
    return rc;
}

static rpmpgpRC pgpSetKeyMpiDSA(pgpDigAlg pgpkey, int num, const uint8_t *p, int mlen)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->p, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&key->q, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    case 2:
	if (!gcry_mpi_scan(&key->g, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    case 3:
	if (!gcry_mpi_scan(&key->y, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    }
    return rc;
}

static rpmpgpRC pgpVerifySigDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig, uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION;
    size_t qlen;

    if (!sig || !key)
	return rc;

    qlen = (mpi_get_nbits(key->q) + 7) / 8;
    if (qlen < 20)
	qlen = 20;		/* sanity */
    if (hashlen > qlen)
	hashlen = qlen;		/* dsa2: truncate hash to qlen */
    gcry_sexp_build(&sexp_sig, NULL, "(sig-val (dsa (r %M) (s %M)))", sig->r, sig->s);
    gcry_sexp_build(&sexp_data, NULL, "(data (flags raw) (value %b))", (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", key->p, key->q, key->g, key->y);
    if (sexp_sig && sexp_data && sexp_pkey)
	if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
	    rc = RPMPGP_OK;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgpFreeSigDSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    if (sig) {
        gcry_mpi_release(sig->r);
        gcry_mpi_release(sig->s);
	pgpsig->data = _free(sig);
    }
}

static void pgpFreeKeyDSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    if (key) {
        gcry_mpi_release(key->p);
        gcry_mpi_release(key->q);
        gcry_mpi_release(key->g);
        gcry_mpi_release(key->y);
	pgpkey->data = _free(key);
    }
}


/****************************** ECC **************************************/

struct pgpDigSigECC_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgpDigKeyECC_s {
    gcry_mpi_t q;
};

static rpmpgpRC pgpSetSigMpiECC(pgpDigAlg pgpsig, int num, const uint8_t *p, int mlen)
{
    struct pgpDigSigECC_s *sig = pgpsig->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_SIGNATURE;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->r, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    case 1:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    }
    return rc;
}

static rpmpgpRC pgpSetKeyMpiECC(pgpDigAlg pgpkey, int num, const uint8_t *p, int mlen)
{
    struct pgpDigKeyECC_s *key = pgpkey->data;
    rpmpgpRC rc = RPMPGP_ERROR_BAD_PUBKEY;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->q, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = RPMPGP_OK;
	break;
    }
    return rc;
}

static int
ed25519_zero_extend(gcry_mpi_t x, unsigned char *buf, int bufl)
{
    int n = (gcry_mpi_get_nbits(x) + 7) / 8;
    if (n == 0 || n > bufl)
	return 1;
    n = bufl - n;
    if (n)
	memset(buf, 0, n);
    gcry_mpi_print(GCRYMPI_FMT_USG, buf + n, bufl - n, NULL, x);
    return 0;
}

static rpmpgpRC pgpVerifySigECC(pgpDigAlg pgpkey, pgpDigAlg pgpsig, uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyECC_s *key = pgpkey->data;
    struct pgpDigSigECC_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION;
    unsigned char buf_r[32], buf_s[32];

    if (!sig || !key)
	return rc;
    if (pgpkey->curve == PGPCURVE_ED25519) {
	if (ed25519_zero_extend(sig->r, buf_r, 32) || ed25519_zero_extend(sig->s, buf_s, 32))
	    return rc;
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (eddsa (r %b) (s %b)))", 32, (const char *)buf_r, 32, (const char *)buf_s, 32);
	gcry_sexp_build(&sexp_data, NULL, "(data (flags eddsa) (hash-algo sha512) (value %b))", (int)hashlen, (const char *)hash);
	gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"Ed25519\") (flags eddsa) (q %M)))", key->q);
	if (sexp_sig && sexp_data && sexp_pkey)
	    if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
		rc = RPMPGP_OK;
	gcry_sexp_release(sexp_sig);
	gcry_sexp_release(sexp_data);
	gcry_sexp_release(sexp_pkey);
	return rc;
    }
    if (pgpkey->curve == PGPCURVE_NIST_P_256 || pgpkey->curve == PGPCURVE_NIST_P_384 || pgpkey->curve == PGPCURVE_NIST_P_521) {
	gcry_sexp_build(&sexp_sig, NULL, "(sig-val (ecdsa (r %M) (s %M)))", sig->r, sig->s);
	gcry_sexp_build(&sexp_data, NULL, "(data (value %b))", (int)hashlen, (const char *)hash);
	if (pgpkey->curve == PGPCURVE_NIST_P_256)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-256\") (q %M)))", key->q);
	else if (pgpkey->curve == PGPCURVE_NIST_P_384)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-384\") (q %M)))", key->q);
	else if (pgpkey->curve == PGPCURVE_NIST_P_521)
	    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"NIST P-521\") (q %M)))", key->q);
	if (sexp_sig && sexp_data && sexp_pkey)
	    if (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0)
		rc = RPMPGP_OK;
	gcry_sexp_release(sexp_sig);
	gcry_sexp_release(sexp_data);
	gcry_sexp_release(sexp_pkey);
	return rc;
    }
    return rc;
}

static void pgpFreeSigECC(pgpDigAlg pgpsig)
{
    struct pgpDigSigECC_s *sig = pgpsig->data;
    if (sig) {
	gcry_mpi_release(sig->r);
	gcry_mpi_release(sig->s);
	pgpsig->data = _free(sig);
    }
}

static void pgpFreeKeyECC(pgpDigAlg pgpkey)
{
    struct pgpDigKeyECC_s *key = pgpkey->data;
    if (key) {
	gcry_mpi_release(key->q);
	pgpkey->data = _free(key);
    }
}


static int pgpSupportedCurve(int algo, int curve)
{
    if (algo == PGPPUBKEYALGO_EDDSA && curve == PGPCURVE_ED25519) {
	static int supported_ed25519;
	if (!supported_ed25519) {
	    gcry_sexp_t sexp = NULL;
	    unsigned int nbits;
	    gcry_sexp_build(&sexp, NULL, "(public-key (ecc (curve \"Ed25519\")))");
	    nbits = gcry_pk_get_nbits(sexp);
	    gcry_sexp_release(sexp);
	    supported_ed25519 = nbits > 0 ? 1 : -1;
	}
	return supported_ed25519 > 0;
    }
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
    case PGPPUBKEYALGO_EDDSA:
	if (!pgpSupportedCurve(algo, curve))
	    break;
        ka->setmpi = pgpSetKeyMpiECC;
        ka->free = pgpFreeKeyECC;
        ka->mpis = 1;
        ka->curve = curve;
        break;
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
    case PGPPUBKEYALGO_EDDSA:
        sa->setmpi = pgpSetSigMpiECC;
        sa->free = pgpFreeSigECC;
        sa->verify = pgpVerifySigECC;
        sa->mpis = 2;
        break;
    default:
        break;
    }
}
