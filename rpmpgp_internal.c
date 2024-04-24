/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal.c
 * Routines to handle RFC-2440 detached signatures.
 */

#include "system.h"

#include <time.h>
#include <netinet/in.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>

#include "rpmpgpval.h"
#include "rpmpgp_internal.h"

#include "debug.h"

typedef uint8_t pgpTime_t[4];

typedef struct pgpPktKeyV4_s {
    uint8_t version;	/*!< version number (4). */
    pgpTime_t time;	/*!< time that the key was created. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
} * pgpPktKeyV4;

typedef struct pgpPktSigV3_s {
    uint8_t version;	/*!< version number (3). */
    uint8_t hashlen;	/*!< length of following hashed material. MUST be 5. */
    uint8_t sigtype;	/*!< signature type. */
    pgpTime_t time;	/*!< 4 byte creation time. */
    pgpKeyID_t signid;	/*!< key ID of signer. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t signhash16[2];	/*!< left 16 bits of signed hash value. */
} * pgpPktSigV3;

typedef struct pgpPktSigV4_s {
    uint8_t version;	/*!< version number (4). */
    uint8_t sigtype;	/*!< signature type. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t hashlen[2];	/*!< length of following hashed material. */
} * pgpPktSigV4;

static rpmpgpRC getKeyID(const uint8_t *h, size_t hlen, pgpKeyID_t keyid);

static inline unsigned int pgpGrab2(const uint8_t *s)
{
    return s[0] << 8 | s[1];
}

static inline unsigned int pgpGrab4(const uint8_t *s)
{
    return s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3];
}

/** \ingroup rpmpgp
 * Decode length in old format packet headers.
 * @param s		pointer to packet (including tag)
 * @param slen		buffer size
 * @param[out] *lenp	decoded length
 * @return		packet header length, 0 on error
 */
static inline size_t pgpOldLen(const uint8_t *s, size_t slen, size_t * lenp)
{
    size_t dlen, lenlen;

    if (slen < 2)
	return 0;
    lenlen = 1 << (s[0] & 0x3);
    /* Reject indefinite length packets and check bounds */
    if (lenlen == 8 || slen < lenlen + 1)
	return 0;
    if (lenlen == 1)
	dlen = s[1];
    else if (lenlen == 2)
	dlen = s[1] << 8 | s[2];
    else if (lenlen == 4 && s[1] == 0)
	dlen = s[2] << 16 | s[3] << 8 | s[4];
    else
	return 0;
    if (slen - (1 + lenlen) < dlen)
	return 0;
    *lenp = dlen;
    return lenlen + 1;
}

/** \ingroup rpmpgp
 * Decode length from 1, 2, or 5 octet body length encoding, used in
 * new format packet headers.
 * Partial body lengths are (intentionally) not supported.
 * @param s		pointer to packet (including tag)
 * @param slen		buffer size
 * @param[out] *lenp	decoded length
 * @return		packet header length, 0 on error
 */
static inline size_t pgpNewLen(const uint8_t *s, size_t slen, size_t * lenp)
{
    size_t dlen, hlen;

    if (s[1] < 192 && slen > 1) {
	hlen = 2;
	dlen = s[1];
    } else if (s[1] < 224 && slen > 3) {
	hlen = 3;
	dlen = (((s[1]) - 192) << 8) + s[2] + 192;
    } else if (s[1] == 255 && slen > 6 && s[2] == 0) {
	hlen = 6;
	dlen = s[3] << 16 | s[4] << 8 | s[5];
    } else {
	return 0;
    }
    if (slen - hlen < dlen)
	return 0;
    *lenp = dlen;
    return hlen;
}

/** \ingroup rpmpgp
 * Decode length from 1, 2, or 5 octet body length encoding, used in
 * V4 signature subpackets. Note that this is slightly different from
 * the pgpNewLen function.
 * @param s		pointer to subpacket (including tag)
 * @param slen		buffer size
 * @param[out] *lenp	decoded length
 * @return		subpacket header length (excluding type), 0 on error
 */
static inline size_t pgpSubPktLen(const uint8_t *s, size_t slen, size_t * lenp)
{
    size_t dlen, lenlen;

    if (*s < 192) {
	lenlen = 1;
	dlen = *s;
    } else if (*s < 255 && slen > 2) {
	lenlen = 2;
	dlen = (((s[0]) - 192) << 8) + s[1] + 192;
    } else if (*s == 255 && slen > 5 && s[1] == 0) {
	lenlen = 5;
	dlen = s[2] << 16 | s[3] << 8 | s[4];
    } else {
	return 0;
    }
    if (slen - lenlen < dlen)
	return 0;
    *lenp = dlen;
    return lenlen;
}

struct pgpPkt {
    uint8_t tag;		/* decoded PGP tag */
    const uint8_t *head;	/* pointer to start of packet (header) */
    const uint8_t *body;	/* pointer to packet body */
    size_t blen;		/* length of body in bytes */
};

static rpmpgpRC pgpDecodePkt(const uint8_t *p, size_t plen, struct pgpPkt *pkt)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET; /* assume failure */

    /* Valid PGP packet header must always have two or more bytes in it */
    if (p && plen >= 2 && p[0] & 0x80) {
	size_t hlen;

	if (p[0] & 0x40) {
	    /* New format packet, body length encoding in second byte */
	    hlen = pgpNewLen(p, plen, &pkt->blen);
	    pkt->tag = (p[0] & 0x3f);
	} else {
	    /* Old format packet */
	    hlen = pgpOldLen(p, plen, &pkt->blen);
	    pkt->tag = (p[0] >> 2) & 0xf;
	}

	/* Does the packet header and its body fit in our boundaries? */
	if (hlen && (hlen + pkt->blen <= plen)) {
	    pkt->head = p;
	    pkt->body = pkt->head + hlen;
	    rc = RPMPGP_OK;
	}
    }
    return rc;
}

static rpmpgpRC pgpVersion(const uint8_t *h, size_t hlen, uint8_t *version)
{
    if (hlen < 1)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    *version = h[0];
    return RPMPGP_OK;
}

static rpmpgpRC pgpPrtSubType(const uint8_t *h, size_t hlen, pgpDigParams _digp, int hashed)
{
    const uint8_t *p = h;

    while (hlen > 0) {
	size_t plen = 0, lenlen;
	int impl = 0;
	lenlen = pgpSubPktLen(p, hlen, &plen);
	if (lenlen == 0 || plen < 1 || lenlen + plen > hlen)
	    break;
	p += lenlen;
	hlen -= lenlen;

	switch (*p & ~PGPSUBTYPE_CRITICAL) {
	case PGPSUBTYPE_SIG_CREATE_TIME:
	    if (!hashed)
		break; /* RFC 4880 §5.2.3.4 creation time MUST be hashed */
	    if (plen - 1 != 4)
		break; /* other lengths not understood */
	    if (_digp->saved & PGPDIG_SAVED_TIME)
		return RPMPGP_ERROR_DUPLICATE_DATA;
	    impl = *p;
	    _digp->time = pgpGrab4(p + 1);
	    _digp->saved |= PGPDIG_SAVED_TIME;
	    break;

	case PGPSUBTYPE_ISSUER_KEYID:
	    if (plen - 1 != sizeof(_digp->signid))
		break; /* other lengths not understood */
	    impl = *p;
	    if (!(_digp->saved & PGPDIG_SAVED_ID)) {
		memcpy(_digp->signid, p+1, sizeof(_digp->signid));
		_digp->saved |= PGPDIG_SAVED_ID;
	    }
	    break;

	case PGPSUBTYPE_KEY_FLAGS:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (_digp->saved & PGPDIG_SAVED_KEY_FLAGS)
		return RPMPGP_ERROR_DUPLICATE_DATA;
	    impl = *p;
	    _digp->key_flags = plen >= 2 ? p[1] : 0;
	    _digp->saved |= PGPDIG_SAVED_KEY_FLAGS;
	    break;

	case PGPSUBTYPE_KEY_EXPIRE_TIME:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (plen - 1 != 4)
		break; /* other lengths not understood */
	    if (_digp->saved & PGPDIG_SAVED_KEY_EXPIRE)
		return RPMPGP_ERROR_DUPLICATE_DATA;
	    impl = *p;
	    _digp->key_expire = pgpGrab4(p + 1);
	    _digp->saved |= PGPDIG_SAVED_KEY_EXPIRE;
	    break;

	case PGPSUBTYPE_SIG_EXPIRE_TIME:
	    if (!hashed)
		break; /* RFC 4880 §5.2.3.4 creation time MUST be hashed */
	    if (plen - 1 != 4)
		break; /* other lengths not understood */
	    if (_digp->saved & PGPDIG_SAVED_SIG_EXPIRE)
		return RPMPGP_ERROR_DUPLICATE_DATA;
	    impl = *p;
	    _digp->sig_expire = pgpGrab4(p + 1);
	    _digp->saved |= PGPDIG_SAVED_SIG_EXPIRE;
	    break;

	case PGPSUBTYPE_EMBEDDED_SIG:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (_digp->sigtype != PGPSIGTYPE_SUBKEY_BINDING)
		break;	/* do not bother for other types */
	    if (plen - 1 < 6)
		break;	/* obviously not a signature */
	    if (_digp->embedded_sig)
		break;	/* just store the first one. we may need to changed this to select the most recent. */
	    impl = *p;
	    _digp->embedded_sig_len = plen - 1;
	    _digp->embedded_sig = memcpy(xmalloc(plen - 1), p + 1, plen - 1);
	    break;

	case PGPSUBTYPE_PRIMARY_USERID:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (plen - 1 != 1)
		break; /* other lengths not understood */
	    impl = *p;
	    if (p[1])
		_digp->saved |= PGPDIG_SAVED_PRIMARY;
	    break;

	default:
	    break;
	}

	if (!impl && (p[0] & PGPSUBTYPE_CRITICAL))
	    return RPMPGP_ERROR_UNKNOWN_CRITICAL_PKT;

	p += plen;
	hlen -= plen;
    }

    if (hlen != 0)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    return RPMPGP_OK;
}

static inline int pgpMpiLen(const uint8_t *p)
{
    int mpi_bits = (p[0] << 8) | p[1];
    return 2 + ((mpi_bits + 7) >> 3);
}

pgpDigAlg pgpDigAlgFree(pgpDigAlg alg)
{
    if (alg) {
        if (alg->free)
            alg->free(alg);
        free(alg);
    }
    return NULL;
}

static rpmpgpRC processMpis(const int mpis, pgpDigAlg alg,
		       const uint8_t *p, const uint8_t *const pend)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    int i = 0;
    for (; i < mpis && pend - p >= 2; i++) {
	int mpil = pgpMpiLen(p);
	if (mpil < 2 || pend - p < mpil)
	    return rc;
	if (alg && alg->setmpi(alg, i, p, mpil))
	    return rc;
	p += mpil;
    }

    /* Does the size and number of MPI's match our expectations? */
    if (p == pend && i == mpis)
	rc = RPMPGP_OK;
    return rc;
}

static rpmpgpRC pgpPrtSigParams(pgpTag tag, const uint8_t *h, size_t hlen,
		pgpDigParams sigp)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    /* We can't handle more than one sig at a time */
    if (sigp->alg || !sigp->mpi_offset || sigp->mpi_offset > hlen || sigp->tag != PGPTAG_SIGNATURE)
	return RPMPGP_ERROR_INTERNAL;
    pgpDigAlg alg = pgpDigAlgNewSignature(sigp->pubkey_algo);
    if (alg->mpis < 0)
	rc = RPMPGP_ERROR_UNSUPPORTED_ALGORITHM;
    else
	rc = processMpis(alg->mpis, alg, h + sigp->mpi_offset, h + hlen);
    if (rc == RPMPGP_OK)
	sigp->alg = alg;
    else
	pgpDigAlgFree(alg);
    return rc;
}

static rpmpgpRC pgpPrtSigNoParams(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    const uint8_t * p;
    size_t plen;

    if (_digp->version || _digp->saved || _digp->tag != PGPTAG_SIGNATURE)
	return RPMPGP_ERROR_INTERNAL;

    if (pgpVersion(h, hlen, &_digp->version))
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;

    switch (_digp->version) {
    case 3:
    {   pgpPktSigV3 v = (pgpPktSigV3)h;

	if (hlen <= sizeof(*v) || v->hashlen != 5)
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	_digp->hashlen = v->hashlen;
	_digp->sigtype = v->sigtype;
	_digp->hash = memcpy(xmalloc(v->hashlen), &v->sigtype, v->hashlen);
	_digp->time = pgpGrab4(v->time);
	memcpy(_digp->signid, v->signid, sizeof(_digp->signid));
	_digp->saved = PGPDIG_SAVED_TIME | PGPDIG_SAVED_ID;
	_digp->pubkey_algo = v->pubkey_algo;
	_digp->hash_algo = v->hash_algo;
	memcpy(_digp->signhash16, v->signhash16, sizeof(_digp->signhash16));
	_digp->mpi_offset = sizeof(*v);
	rc = RPMPGP_OK;
    }	break;
    case 4:
    {   pgpPktSigV4 v = (pgpPktSigV4)h;
	const uint8_t *const hend = h + hlen;
	int hashed;

	if (hlen <= sizeof(*v))
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	_digp->sigtype = v->sigtype;
	_digp->pubkey_algo = v->pubkey_algo;
	_digp->hash_algo = v->hash_algo;

	/* parse both the hashed and unhashed subpackets */
	p = &v->hashlen[0];
	for (hashed = 1; hashed >= 0; hashed--) {
	    if (p > hend || hend - p < 2)
		return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	    plen = pgpGrab2(p);
	    p += 2;
	    if (hend - p < plen)
		return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	    if (hashed) {
		_digp->hashlen = sizeof(*v) + plen;
		_digp->hash = memcpy(xmalloc(_digp->hashlen), v, _digp->hashlen);
	    }
	    rc = pgpPrtSubType(p, plen, _digp, hashed);
	    if (rc != RPMPGP_OK)
		return rc;
	    p += plen;
	}

	if (!(_digp->saved & PGPDIG_SAVED_TIME))
	    return RPMPGP_ERROR_NO_CREATION_TIME;	/* RFC 4880 §5.2.3.4 creation time MUST be present */

	if (p > hend || hend - p < 2)
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	memcpy(_digp->signhash16, p, sizeof(_digp->signhash16));
	p += 2;

	if (p > hend)
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	_digp->mpi_offset = p - h;
	rc = RPMPGP_OK;
    }	break;
    default:
	rc = RPMPGP_ERROR_UNSUPPORTED_VERSION;
	break;
    }
    return rc;
}

static rpmpgpRC pgpPrtSig(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    rpmpgpRC rc = pgpPrtSigNoParams(tag, h, hlen, _digp);
    if (rc == RPMPGP_OK)
	rc = pgpPrtSigParams(tag, h, hlen, _digp);
    return rc;
}

static uint8_t curve_oids[] = {
    PGPCURVE_NIST_P_256,	0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    PGPCURVE_NIST_P_384,	0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    PGPCURVE_NIST_P_521,	0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
    PGPCURVE_BRAINPOOL_P256R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
    PGPCURVE_BRAINPOOL_P512R1,	0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
    PGPCURVE_ED25519,		0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
    PGPCURVE_CURVE25519,	0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
    0,
};

static int pgpCurveByOid(const uint8_t *p, int l)
{
    uint8_t *curve;
    for (curve = curve_oids; *curve; curve += 2 + curve[1])
        if (l == (int)curve[1] && !memcmp(p, curve + 2, l))
            return (int)curve[0];
    return 0;
}

static rpmpgpRC pgpPrtKeyParams(pgpTag tag, const uint8_t *h, size_t hlen,
		pgpDigParams keyp)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    const uint8_t *p;
    int curve = 0;
    /* We can't handle more than one key at a time */
    if (keyp->alg || !keyp->mpi_offset || keyp->mpi_offset > hlen)
	return  RPMPGP_ERROR_INTERNAL;
    p = h + keyp->mpi_offset;
    if (keyp->pubkey_algo == PGPPUBKEYALGO_EDDSA || keyp->pubkey_algo == PGPPUBKEYALGO_ECDSA) {
	int len = (hlen > 1) ? p[0] : 0;
	if (len == 0 || len == 0xff || len >= hlen)
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	curve = pgpCurveByOid(p + 1, len);
	if (!curve)
	    return RPMPGP_ERROR_UNSUPPORTED_CURVE;
	p += len + 1;
    }
    pgpDigAlg alg = pgpDigAlgNewPubkey(keyp->pubkey_algo, curve);
    if (alg->mpis < 0)
	rc = RPMPGP_ERROR_UNSUPPORTED_ALGORITHM;
    else
	rc = processMpis(alg->mpis, alg, p, h + hlen);
    if (rc == RPMPGP_OK)
	keyp->alg = alg;
    else
	pgpDigAlgFree(alg);
    return rc;
}

/* validate that the mpi data matches our expectations */
static rpmpgpRC pgpValidateKeyParamsSize(int pubkey_algo, const uint8_t *p, size_t plen) {
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    int nmpis = -1;

    switch (pubkey_algo) {
	case PGPPUBKEYALGO_ECDSA:
	case PGPPUBKEYALGO_EDDSA:
	    if (!plen || p[0] == 0x00 || p[0] == 0xff || plen < 1 + p[0])
		return rc;
	    plen -= 1 + p[0];
	    p += 1 + p[0];
	    nmpis = 1;
	    break;
	case PGPPUBKEYALGO_RSA:
	    nmpis = 2;
	    break;
	case PGPPUBKEYALGO_DSA:
	    nmpis = 4;
	    break;
	default:
	    break;
    }
    if (nmpis < 0)
	return rc;
    return processMpis(nmpis, NULL, p, p + plen);
}

static rpmpgpRC pgpPrtKey(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */

    if (_digp->version || _digp->saved)
	return RPMPGP_ERROR_INTERNAL;
    if  (_digp->tag != PGPTAG_PUBLIC_KEY && _digp->tag != PGPTAG_PUBLIC_SUBKEY)
	return RPMPGP_ERROR_INTERNAL;

    if (pgpVersion(h, hlen, &_digp->version))
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;

    /* We only permit V4 keys, V3 keys are long long since deprecated */
    switch (_digp->version) {
    case 4:
    {   pgpPktKeyV4 v = (pgpPktKeyV4)h;

	if (hlen <= sizeof(*v))
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	_digp->time = pgpGrab4(v->time);
	_digp->saved |= PGPDIG_SAVED_TIME;
	_digp->pubkey_algo = v->pubkey_algo;
	_digp->mpi_offset = sizeof(*v);
	rc = RPMPGP_OK;
    }	break;
    default:
	rc = RPMPGP_ERROR_UNSUPPORTED_VERSION;
	break;
    }

    /* read mpi data if there was no error */
    if (rc == RPMPGP_OK)
	rc = pgpPrtKeyParams(tag, h, hlen, _digp);
    /* calculate the key id if we could parse the key */
    if (rc == RPMPGP_OK) {
	if ((rc = getKeyID(h, hlen, _digp->signid)) == RPMPGP_OK)
	    _digp->saved |= PGPDIG_SAVED_ID;
    }
    return rc;
}

static rpmpgpRC pgpPrtUserID(pgpTag tag, const uint8_t *h, size_t hlen,
			pgpDigParams _digp)
{
    free(_digp->userid);
    _digp->userid = memcpy(xmalloc(hlen+1), h, hlen);
    _digp->userid[hlen] = '\0';
    return RPMPGP_OK;
}

static rpmpgpRC getPubkeyFingerprint(const uint8_t *h, size_t hlen,
			  uint8_t **fp, size_t *fplen)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    uint8_t version = 0;

    if (pgpVersion(h, hlen, &version))
	return rc;

    /* We only permit V4 keys, V3 keys are long long since deprecated */
    switch (version) {
    case 4:
      {	pgpPktKeyV4 v = (pgpPktKeyV4)h;
	if (hlen < sizeof(*v))
	    return rc;
	/* Does the size and number of MPI's match our expectations? */
	if (pgpValidateKeyParamsSize(v->pubkey_algo, (uint8_t *)(v + 1), hlen - sizeof(*v)) == RPMPGP_OK) {
	    DIGEST_CTX ctx = rpmDigestInit(RPM_HASH_SHA1, RPMDIGEST_NONE);
	    uint8_t *d = NULL;
	    size_t dlen = 0;
	    uint8_t in[3] = { 0x99, (hlen >> 8), hlen };

	    (void) rpmDigestUpdate(ctx, in, 3);
	    (void) rpmDigestUpdate(ctx, h, hlen);
	    (void) rpmDigestFinal(ctx, (void **)&d, &dlen, 0);

	    if (dlen == 20) {
		rc = RPMPGP_OK;
		*fp = d;
		*fplen = dlen;
	    } else {
		free(d);
	    }
	}
      }	break;
    default:
	rc = RPMPGP_ERROR_UNSUPPORTED_VERSION;
	break;
    }
    return rc;
}

static rpmpgpRC getKeyID(const uint8_t *h, size_t hlen, pgpKeyID_t keyid)
{
    uint8_t *fp = NULL;
    size_t fplen = 0;
    rpmpgpRC rc = getPubkeyFingerprint(h, hlen, &fp, &fplen);
    if (rc == RPMPGP_OK && fp && fplen > 8)
	memcpy(keyid, (fp + (fplen - 8)), 8);
    else if (rc == RPMPGP_OK)
	rc = RPMPGP_ERROR_INTERNAL;
    free(fp);
    return rc;
}

static rpmpgpRC pgpPrtPkt(struct pgpPkt *p, pgpDigParams _digp)
{
    rpmpgpRC rc = RPMPGP_OK;

    switch (p->tag) {
    case PGPTAG_SIGNATURE:
	rc = pgpPrtSig(p->tag, p->body, p->blen, _digp);
	break;
    case PGPTAG_PUBLIC_KEY:
	rc = pgpPrtKey(p->tag, p->body, p->blen, _digp);
	break;
    case PGPTAG_USER_ID:
	rc = pgpPrtUserID(p->tag, p->body, p->blen, _digp);
	break;
    case PGPTAG_RESERVED:
	rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	break;
    default:
	break;
    }
    return rc;
}

static uint32_t pgpCurrentTime(void) {
    time_t t = time(NULL);
    return (uint32_t)t;
}

static rpmpgpRC pgpVerifySignatureRaw(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx)
{
    DIGEST_CTX ctx;
    uint8_t *hash = NULL;
    size_t hashlen = 0;
    rpmpgpRC rc = RPMPGP_ERROR_SIGNATURE_VERIFICATION; /* assume failure */

    /* make sure the parameters are correct */
    if (sig == NULL || hashctx == NULL)
	return RPMPGP_ERROR_INTERNAL;
    if (sig->tag != PGPTAG_SIGNATURE)
	return RPMPGP_ERROR_INTERNAL;
    if (key && key->tag != PGPTAG_PUBLIC_KEY && key->tag != PGPTAG_PUBLIC_SUBKEY)
	return RPMPGP_ERROR_INTERNAL;

    ctx = rpmDigestDup(hashctx);
    if (sig->hash != NULL)
	rpmDigestUpdate(ctx, sig->hash, sig->hashlen);

    if (sig->version == 4) {
	/* V4 trailer is six octets long (rfc4880) */
	uint8_t trailer[6];
	uint32_t nb = sig->hashlen;
	nb = htonl(nb);
	trailer[0] = sig->version;
	trailer[1] = 0xff;
	memcpy(trailer+2, &nb, 4);
	rpmDigestUpdate(ctx, trailer, sizeof(trailer));
    }

    rpmDigestFinal(ctx, (void **)&hash, &hashlen, 0);
    ctx = NULL;

    /* Compare leading 16 bits of digest for quick check. */
    if (hash == NULL || memcmp(hash, sig->signhash16, 2) != 0)
	goto exit;

    /*
     * If we have a key, verify the signature for real. Otherwise we've
     * done all we can.
     */
    if (key) {
	pgpDigAlg sa = sig->alg;
	pgpDigAlg ka = key->alg;
	if (sa && ka && sa->verify && sig->pubkey_algo == key->pubkey_algo)
	    rc = sa->verify(ka, sa, hash, hashlen, sig->hash_algo);
    } else {
	rc = RPMPGP_OK;
    }
exit:
    free(hash);
    rpmDigestFinal(ctx, NULL, NULL, 0);
    return rc;
}

static rpmpgpRC hashKey(DIGEST_CTX hash, const struct pgpPkt *pkt, int exptag)
{
    rpmpgpRC rc = RPMPGP_ERROR_INTERNAL;
    if (pkt->tag == exptag) {
	uint8_t head[] = {
	    0x99,
	    (pkt->blen >> 8),
	    (pkt->blen     ),
	};
	rpmDigestUpdate(hash, head, 3);
	rpmDigestUpdate(hash, pkt->body, pkt->blen);
	rc = RPMPGP_OK;
    }
    return rc;
}

static rpmpgpRC hashUserID(DIGEST_CTX hash, const struct pgpPkt *pkt)
{
    rpmpgpRC rc = RPMPGP_ERROR_INTERNAL;
    if (pkt->tag == PGPTAG_USER_ID) {
	uint8_t head[] = {
	    0xb4,
	    (pkt->blen >> 24),
	    (pkt->blen >> 16),
	    (pkt->blen >>  8),
	    (pkt->blen     ),
	};
	rpmDigestUpdate(hash, head, 5);
	rpmDigestUpdate(hash, pkt->body, pkt->blen);
	rc = RPMPGP_OK;
    }
    return rc;
}

static rpmpgpRC pgpVerifySelf(pgpDigParams key, pgpDigParams selfsig,
			const struct pgpPkt *mainpkt, const struct pgpPkt *sectionpkt)
{
    int rc = RPMPGP_ERROR_SELFSIG_VERIFICATION;
    DIGEST_CTX hash = rpmDigestInit(selfsig->hash_algo, 0);

    switch (selfsig->sigtype) {
    case PGPSIGTYPE_SUBKEY_BINDING:
    case PGPSIGTYPE_SUBKEY_REVOKE:
    case PGPSIGTYPE_PRIMARY_BINDING:
	if (hash && sectionpkt && sectionpkt->tag == PGPTAG_PUBLIC_SUBKEY) {
	    rc = hashKey(hash, mainpkt, PGPTAG_PUBLIC_KEY);
	    if (rc == RPMPGP_OK)
		rc = hashKey(hash, sectionpkt, PGPTAG_PUBLIC_SUBKEY);
	}
	break;
    case PGPSIGTYPE_GENERIC_CERT:
    case PGPSIGTYPE_PERSONA_CERT:
    case PGPSIGTYPE_CASUAL_CERT:
    case PGPSIGTYPE_POSITIVE_CERT:
    case PGPSIGTYPE_CERT_REVOKE:
	if (hash && sectionpkt && sectionpkt->tag == PGPTAG_USER_ID) {
	    rc = hashKey(hash, mainpkt, PGPTAG_PUBLIC_KEY);
	    if (rc == RPMPGP_OK)
		rc = hashUserID(hash, sectionpkt);
	}
	break;
    case PGPSIGTYPE_SIGNED_KEY:
    case PGPSIGTYPE_KEY_REVOKE:
	if (hash) 
	    rc = hashKey(hash, mainpkt, PGPTAG_PUBLIC_KEY);
	break;
    default:
	break;
    }

    if (rc == RPMPGP_OK) {
	if (key)
	    rc = pgpVerifySignatureRaw(key, selfsig, hash);
	else
	    rc = RPMPGP_ERROR_INTERNAL;
	if (rc == RPMPGP_ERROR_SIGNATURE_VERIFICATION)
	    rc = RPMPGP_ERROR_SELFSIG_VERIFICATION;
    }
    rpmDigestFinal(hash, NULL, NULL, 0);
    return rc;
}

static rpmpgpRC verifyPrimaryBindingSig(struct pgpPkt *mainpkt, struct pgpPkt *subkeypkt, pgpDigParams subkeydig, pgpDigParams bindsigdig)
{
    pgpDigParams emb_digp = NULL;
    int rc = RPMPGP_ERROR_SELFSIG_VERIFICATION;		/* assume failure */
    if (!bindsigdig || !bindsigdig->embedded_sig)
	return rc;
    emb_digp = pgpDigParamsNew(PGPTAG_SIGNATURE);
    if (pgpPrtSig(PGPTAG_SIGNATURE, bindsigdig->embedded_sig, bindsigdig->embedded_sig_len, emb_digp) == 0)
	if (emb_digp->sigtype == PGPSIGTYPE_PRIMARY_BINDING)
	    rc = pgpVerifySelf(subkeydig, emb_digp, mainpkt, subkeypkt);
    emb_digp = pgpDigParamsFree(emb_digp);
    return rc;
}


static const size_t RPM_MAX_OPENPGP_BYTES = 65535; /* max number of bytes in a key */

static int is_same_keyid(pgpDigParams digp, pgpDigParams sigdigp)
{
    return (digp->saved & sigdigp->saved & PGPDIG_SAVED_ID) != 0 &&
	memcmp(digp->signid, sigdigp->signid, sizeof(digp->signid)) == 0;
}

/* Parse a complete pubkey with all associated packets */
/* This is similar to gnupg's merge_selfsigs_main() function */
static int pgpPrtParamsPubkey(const uint8_t * pkts, size_t pktlen, pgpDigParams * ret,
                              char **lints)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgpDigParams digp = NULL;
    pgpDigParams sigdigp = NULL;
    pgpDigParams newest_digp = NULL;
    int useridpkt, subkeypkt;
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    uint32_t key_expire_sig_time = 0;
    uint32_t key_flags_sig_time = 0;
    struct pgpPkt mainpkt, sectionpkt;
    int haveselfsig;
    uint32_t now = 0;

    if (lints)
	*lints = NULL;

    /* parse the main pubkey */
    if (pktlen > RPM_MAX_OPENPGP_BYTES || pgpDecodePkt(p, (pend - p), &mainpkt)) {
	pgpAddErrorLint(NULL, lints, RPMPGP_ERROR_CORRUPT_PGP_PACKET);
	return -1;
    }
    if (mainpkt.tag != PGPTAG_PUBLIC_KEY) {
	pgpAddErrorLint(NULL, lints, RPMPGP_ERROR_UNEXPECTED_PGP_PACKET);
	return -1;	/* pubkey packet must come first */
    }
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    /* create dig for the main pubkey and parse the pubkey packet */
    digp = pgpDigParamsNew(mainpkt.tag);
    if ((rc = pgpPrtPkt(&mainpkt, digp)) != RPMPGP_OK) {
	if (lints)
	    pgpAddErrorLint(digp, lints, rc);
	pgpDigParamsFree(digp);
	return -1;
    }

    useridpkt = subkeypkt = 0;		/* type of the section packet */
    memset(&sectionpkt, 0, sizeof(sectionpkt));
    haveselfsig = 1;

    rc = RPMPGP_OK;
    while (rc == RPMPGP_OK) {
	struct pgpPkt pkt;
	int end_of_section;

	if (p < pend) {
	    if (pgpDecodePkt(p, (pend - p), &pkt)) {
		rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;
		break;
	    }
	    if (pkt.tag == PGPTAG_PUBLIC_KEY) {
		rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		break;	/* start of another public key, error out */
	    }
	} else {
	    pkt.tag = 0;
	}

	end_of_section = p == pend || pkt.tag == PGPTAG_USER_ID || pkt.tag == PGPTAG_PHOTOID || pkt.tag == PGPTAG_PUBLIC_SUBKEY;
	/* did we end a direct/userid/subkey section? if yes, make sure there is a self sig and take the data from the newest signature */
	if (end_of_section && !haveselfsig) {
	    rc = RPMPGP_ERROR_MISSING_SELFSIG;
	    break;
	}
	if (end_of_section && newest_digp) {
	    if (newest_digp->sigtype == PGPSIGTYPE_CERT_REVOKE)
		newest_digp->saved &= ~(PGPDIG_SAVED_KEY_EXPIRE | PGPDIG_SAVED_KEY_FLAGS);	/* just in case */
	    else if (!subkeypkt)
		digp->saved |= PGPDIG_SAVED_VALID;		/* we have at least one good self-sig */
	    /* commit the data from the newest signature */
	    if (!subkeypkt && (newest_digp->saved & PGPDIG_SAVED_KEY_EXPIRE)) {
		if ((!key_expire_sig_time || newest_digp->time > key_expire_sig_time)) {
		    digp->key_expire = newest_digp->key_expire;
		    key_expire_sig_time = newest_digp->time;
		    digp->saved |= PGPDIG_SAVED_KEY_EXPIRE;
		    if (!useridpkt)
			key_expire_sig_time = 0xffffffffU;	/* expires from the direct signatures are final */
		}
	    }
	    if (!subkeypkt && (newest_digp->saved & PGPDIG_SAVED_KEY_FLAGS)) {
		if ((!key_flags_sig_time || newest_digp->time > key_flags_sig_time)) {
		    digp->key_flags = newest_digp->key_flags;
		    key_flags_sig_time = newest_digp->time;
		    digp->saved |= PGPDIG_SAVED_KEY_FLAGS;
		    if (!useridpkt)
			key_flags_sig_time = 0xffffffffU;	/* key flags from the direct signatures are final */
		}
	    }
	    if (useridpkt && newest_digp->sigtype != PGPSIGTYPE_CERT_REVOKE) {
		if (!digp->userid || ((newest_digp->saved & PGPDIG_SAVED_PRIMARY) != 0 && (digp->saved & PGPDIG_SAVED_PRIMARY) == 0)) {
		    if (pgpPrtPkt(&sectionpkt, digp))
			break;
		    if ((newest_digp->saved & PGPDIG_SAVED_PRIMARY) != 0)
			digp->saved |= PGPDIG_SAVED_PRIMARY;
		}
	    }
	    newest_digp = pgpDigParamsFree(newest_digp);
	}

	if (p == pend)
	    break;	/* all packets processed */

	if (pkt.tag == PGPTAG_SIGNATURE) {
	    int needsig = 0;
	    int isselfsig;
	    sigdigp = pgpDigParamsNew(pkt.tag);
	    /* use the NoParams variant because we want to ignore non self-sigs */
	    if ((rc = pgpPrtSigNoParams(pkt.tag, pkt.body, pkt.blen, sigdigp)) != RPMPGP_OK)
		break;

	    isselfsig = is_same_keyid(digp, sigdigp);
	    /* if this is self-signed add MPIs so we can verify */
	    if (isselfsig) {
	        if ((rc = pgpPrtSigParams(pkt.tag, pkt.body, pkt.blen, sigdigp)) != RPMPGP_OK)
		    break;
	    }

	    if (sigdigp->sigtype == PGPSIGTYPE_SUBKEY_BINDING || sigdigp->sigtype == PGPSIGTYPE_SUBKEY_REVOKE) {
		if (!subkeypkt) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		if (!isselfsig) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* the binding signature must be a self signature */
		}
		if ((rc = pgpVerifySelf(digp, sigdigp, &mainpkt, &sectionpkt)) != RPMPGP_OK)
		    break;		/* verification failed */
		haveselfsig = 1;
		needsig = 1;
	    }

	    if (sigdigp->sigtype == PGPSIGTYPE_KEY_REVOKE) {
		/* sections don't matter here */
		if (!isselfsig) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* the binding signature must be a self signature */
		}
		if ((rc = pgpVerifySelf(digp, sigdigp, &mainpkt, NULL)) != RPMPGP_OK)
		    break;		/* verification failed */
		/* can a revokation signature expire? */
		digp->revoked = 1;				/* this is final */
		digp->saved |= PGPDIG_SAVED_VALID;		/* we have at least one correct self-sig */
	    }

	    if (sigdigp->sigtype == PGPSIGTYPE_SIGNED_KEY) {
		if (subkeypkt || useridpkt) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		if (isselfsig) {
		    if ((rc = pgpVerifySelf(digp, sigdigp, &mainpkt, NULL)) != RPMPGP_OK)
			break;		/* verification failed */
		    needsig = 1;
		}
	    }

	    if (sigdigp->sigtype == PGPSIGTYPE_GENERIC_CERT || sigdigp->sigtype == PGPSIGTYPE_PERSONA_CERT || sigdigp->sigtype == PGPSIGTYPE_CASUAL_CERT || sigdigp->sigtype == PGPSIGTYPE_POSITIVE_CERT || sigdigp->sigtype == PGPSIGTYPE_CERT_REVOKE) {
		if (!useridpkt) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		if (isselfsig && sectionpkt.tag == PGPTAG_USER_ID) {
		    if ((rc = pgpVerifySelf(digp, sigdigp, &mainpkt, &sectionpkt)) != RPMPGP_OK)
			break;		/* verification failed */
		    haveselfsig = 1;
		    needsig = 1;
		    /* note that cert revokations may get overwritten by newer certifications (like in gnupg) */
		}
	    }
	    /* check if this signature is expired */
	    if (needsig && (sigdigp->saved & PGPDIG_SAVED_SIG_EXPIRE) != 0 && sigdigp->sig_expire) {
		if (!now)
		    now = pgpCurrentTime();
		if (now < sigdigp->time || sigdigp->sig_expire < now - sigdigp->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }
	    if (needsig && (!newest_digp || sigdigp->time >= newest_digp->time)) {
		newest_digp = pgpDigParamsFree(newest_digp);
		newest_digp = sigdigp;
		sigdigp = NULL;
	    }
	    sigdigp = pgpDigParamsFree(sigdigp);
	} else if (pkt.tag == PGPTAG_USER_ID || pkt.tag == PGPTAG_PHOTOID) {
	    if (subkeypkt) {
		rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		break;		/* no user id packets after subkeys allowed */
	    }
	    useridpkt = 1;
	    sectionpkt = pkt;
	    haveselfsig = pkt.tag == PGPTAG_PHOTOID ? 1 : 0;	/* ignore photo ids with no self-sig */
	} else if (pkt.tag == PGPTAG_PUBLIC_SUBKEY) {
	    subkeypkt = 1;
	    useridpkt = 0;
	    sectionpkt = pkt;
	    haveselfsig = 0;
	} else if (pkt.tag == PGPTAG_RESERVED) {
	    rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	    break;		/* not allowed */
	}
	p += (pkt.body - pkt.head) + pkt.blen;
    }
    if (rc == RPMPGP_OK && p != pend)
	rc = RPMPGP_ERROR_INTERNAL;
    sigdigp = pgpDigParamsFree(sigdigp);
    newest_digp = pgpDigParamsFree(newest_digp);
    if (ret && rc == RPMPGP_OK) {
	*ret = digp;
    } else {
	if (lints)
	    pgpAddErrorLint(digp, lints, rc);
	pgpDigParamsFree(digp);
    }
    return rc == RPMPGP_OK ? 0 : -1;
}
	
/* Return the subkeys for a pubkey. Note that the code in pgpPrtParamsPubkey() already
 * made sure that the signatures are self-signatures and verified ok. */
/* This is similar to gnupg's merge_selfsigs_subkey() function */
int pgpPrtParamsSubkeys(const uint8_t *pkts, size_t pktlen,
			pgpDigParams mainkey, pgpDigParams **subkeys,
			int *subkeysCount)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgpDigParams *digps = NULL, subdigp = NULL;
    pgpDigParams sigdigp = NULL;
    pgpDigParams newest_digp = NULL;
    int count = 0;
    int alloced = 10;
    struct pgpPkt mainpkt, subkeypkt, pkt;
    int rc, i;
    uint32_t now = 0;

    if (pgpDecodePkt(p, (pend - p), &mainpkt) || mainpkt.tag != PGPTAG_PUBLIC_KEY)
	return -1;	/* pubkey packet must come first */
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    memset(&subkeypkt, 0, sizeof(subkeypkt));

    digps = xmalloc(alloced * sizeof(*digps));
    while (1) {
	if (p < pend) {
	    if (pgpDecodePkt(p, (pend - p), &pkt))
		break;
	} else {
	    pkt.tag = 0;
	}

	/* finish up this subkey if we are at the end or a new one comes next */
	if (p == pend || pkt.tag == PGPTAG_PUBLIC_SUBKEY) {
	    if (newest_digp && subdigp) {
		/* copy over the stuff we need from the newest signature */
		subdigp->saved |= PGPDIG_SAVED_VALID;	/* at least one binding sig */
		if ((newest_digp->saved & PGPDIG_SAVED_KEY_FLAGS) != 0) {
		    subdigp->key_flags = newest_digp->key_flags;
		    subdigp->saved |= PGPDIG_SAVED_KEY_FLAGS;
		}
		if ((newest_digp->saved & PGPDIG_SAVED_KEY_EXPIRE) != 0) {
		    subdigp->key_expire = newest_digp->key_expire;
		    subdigp->saved |= PGPDIG_SAVED_KEY_EXPIRE;
		}
	    }
	    newest_digp = pgpDigParamsFree(newest_digp);
	}

	if (p == pend)
	    break;
	p += (pkt.body - pkt.head) + pkt.blen;

	if (pkt.tag == PGPTAG_PUBLIC_SUBKEY) {
	    subdigp = pgpDigParamsNew(PGPTAG_PUBLIC_SUBKEY);
	    /* Copy keyid of main key for error messages */
	    memcpy(subdigp->mainid, mainkey->signid, sizeof(mainkey->signid));
	    /* Copy UID from main key to subkey */
	    subdigp->userid = mainkey->userid ? xstrdup(mainkey->userid) : NULL;
	    /* if the main key is revoked, all the subkeys are also revoked */
	    subdigp->revoked = mainkey->revoked ? 2 : 0;
	    if (pgpPrtKey(pkt.tag, pkt.body, pkt.blen, subdigp)) {
		subdigp = pgpDigParamsFree(subdigp);
	    } else {
		if (count == alloced) {
		    alloced <<= 1;
		    digps = xrealloc(digps, alloced * sizeof(*digps));
		}
		digps[count++] = subdigp;
		subkeypkt = pkt;
	    }
	} else if (pkt.tag == PGPTAG_SIGNATURE && subdigp != NULL) {
	    sigdigp = pgpDigParamsNew(pkt.tag);
	    /* we use the NoParams variant because we do not verify */
	    if (pgpPrtSigNoParams(pkt.tag, pkt.body, pkt.blen, sigdigp) != RPMPGP_OK) {
		sigdigp = pgpDigParamsFree(sigdigp);
	    }
	    if (sigdigp && (sigdigp->saved & PGPDIG_SAVED_SIG_EXPIRE) != 0 && sigdigp->sig_expire) {
		if (!now)
		    now = pgpCurrentTime();
		if (now < sigdigp->time || sigdigp->sig_expire < now - sigdigp->time)
		    sigdigp = pgpDigParamsFree(sigdigp);	/* signature is expired */
	    }
	    if (sigdigp && sigdigp->sigtype == PGPSIGTYPE_SUBKEY_REVOKE) {
		if (subdigp->revoked != 2)
		    subdigp->revoked = 1;
		subdigp->saved |= PGPDIG_SAVED_VALID;	/* at least one binding sig */
	    } else if (sigdigp && sigdigp->sigtype == PGPSIGTYPE_SUBKEY_BINDING) {
		int key_flags = (sigdigp->saved & PGPDIG_SAVED_KEY_FLAGS) ? sigdigp->key_flags : 0;
		/* insist on a embedded primary key binding signature if this is used for signing */
		if (!(key_flags & 0x02) || verifyPrimaryBindingSig(&mainpkt, &subkeypkt, subdigp, sigdigp) == RPMPGP_OK) {
		    if (!newest_digp || sigdigp->time >= newest_digp->time) {
			newest_digp = pgpDigParamsFree(newest_digp);
			newest_digp = sigdigp;
			sigdigp = NULL;
		    }
		}
	    }
	    sigdigp = pgpDigParamsFree(sigdigp);
	}
    }
    rc = (p == pend) ? 0 : -1;

    sigdigp = pgpDigParamsFree(sigdigp);
    newest_digp = pgpDigParamsFree(newest_digp);

    if (rc == 0) {
	*subkeys = xrealloc(digps, count * sizeof(*digps));
	*subkeysCount = count;
    } else {
	for (i = 0; i < count; i++)
	    pgpDigParamsFree(digps[i]);
	free(digps);
    }

    return rc;
}

int pgpPrtParams2(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret, char **lints)
{
    pgpDigParams digp = NULL;
    rpmpgpRC rc;
    struct pgpPkt pkt;

    if (lints)
        *lints = NULL;
    if (pktlen > RPM_MAX_OPENPGP_BYTES || pgpDecodePkt(pkts, pktlen, &pkt)) {
	pgpAddErrorLint(NULL, lints, RPMPGP_ERROR_CORRUPT_PGP_PACKET);
	return -1;
    }

    if (pkttype && pkt.tag != pkttype) {
	pgpAddErrorLint(NULL, lints, RPMPGP_ERROR_UNEXPECTED_PGP_PACKET);
	return -1;
    }

    if (pkt.tag == PGPTAG_PUBLIC_KEY)
	return pgpPrtParamsPubkey(pkts, pktlen, ret, lints);	/* switch to specialized pubkey implementation */

    digp = pgpDigParamsNew(pkt.tag);
    rc = pgpPrtPkt(&pkt, digp);
    if (rc == RPMPGP_OK && (pkt.body - pkt.head) + pkt.blen != pktlen)
	rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET; 		/* trailing data is an error */

    if (ret && rc == RPMPGP_OK)
	*ret = digp;
    else {
	if (lints)
	    pgpAddErrorLint(digp, lints, rc);
	pgpDigParamsFree(digp);
    }
    return rc == RPMPGP_OK ? 0 : -1;
}

int pgpPrtParams(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
                  pgpDigParams * ret)
{
    return pgpPrtParams2(pkts, pktlen, pkttype, ret, NULL);
}

rpmRC pgpPubKeyLint(const uint8_t *pkts, size_t pktslen, char **explanation)
{
    pgpDigParams digp = NULL;
    rpmRC res = pgpPrtParamsPubkey(pkts, pktslen, &digp, explanation) ? RPMRC_FAIL : RPMRC_OK;
    pgpDigParamsFree(digp);
    return res;
}

rpmRC pgpVerifySignature2(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx, char **lints)
{
    rpmRC res = RPMRC_FAIL; /* assume failure */
    rpmpgpRC rc;

    if (lints)
        *lints = NULL;
    
    rc = pgpVerifySignatureRaw(key, sig, hashctx);
    if (rc != RPMPGP_OK)
	goto exit;
    /* now check the meta information of the signature */
    if ((sig->saved & PGPDIG_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
	uint32_t now = pgpCurrentTime();
	if (now < sig->time) {
	    if (lints)
		pgpAddSigLint(sig, lints, "has been created in the future");
	    res = RPMRC_NOTTRUSTED;
	} else if (sig->sig_expire < now - sig->time) {
	    if (lints)
		pgpAddSigExpiredLint(sig, lints);
	    res = RPMRC_NOTTRUSTED;
	}
	if (rc != RPMPGP_OK)
	    goto exit;
    }
    if (!key) {
	/* that's all we can do */
	res = RPMRC_NOKEY;
	goto exit;
    }
    /* now check the meta information of the key */
    if (key->revoked) {
	if (lints)
	    pgpAddKeyLint(key, lints, "has been revoked");
	res = RPMRC_NOTTRUSTED;
    } else if ((key->saved & PGPDIG_SAVED_VALID) == 0) {
	if (lints)
	    pgpAddKeyLint(key, lints, "has no valid binding signature");
	res = RPMRC_NOTTRUSTED;
    } else if (key->tag == PGPTAG_PUBLIC_SUBKEY && ((key->saved & PGPDIG_SAVED_KEY_FLAGS) == 0 || (key->key_flags & 0x02) == 0)) {
	if (lints)
	    pgpAddKeyLint(key, lints, "is not suitable for signing");
	res = RPMRC_NOTTRUSTED;	/* subkey not suitable for signing */
    } else if (key->time > sig->time) {
	if (lints)
	    pgpAddKeyLint(key, lints, "has been created after the signature");
	res = RPMRC_NOTTRUSTED;
    } else if ((key->saved & PGPDIG_SAVED_KEY_EXPIRE) != 0 && key->key_expire && key->key_expire < sig->time - key->time) {
	if (lints)
	    pgpAddKeyExpiredLint(key, lints);
	res = RPMRC_NOTTRUSTED;
    }
exit:
    return res;
}

rpmRC pgpVerifySignature(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx)
{
    return pgpVerifySignature2(key, sig, hashctx, NULL);
}

int pgpPubKeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktslen;
    struct pgpPkt pkt;

    while (p < pend) {
	if (pgpDecodePkt(p, (pend - p), &pkt))
	    return -1;

	if (pkt.tag == PGPTAG_PUBLIC_KEY && pkts != p) {
	    *certlen = p - pkts;
	    return 0;
	}

	p += (pkt.body - pkt.head) + pkt.blen;
    }

    *certlen = pktslen;

    return 0;
}

int pgpPubkeyKeyID(const uint8_t * pkts, size_t pktslen, pgpKeyID_t keyid)
{
    struct pgpPkt pkt;

    if (pgpDecodePkt(pkts, pktslen, &pkt))
	return -1;
    return getKeyID(pkt.body, pkt.blen, keyid) == RPMPGP_OK ? 0 : -1;
}

int pgpPubkeyFingerprint(const uint8_t * pkts, size_t pktslen,
                         uint8_t **fp, size_t *fplen)
{
    struct pgpPkt pkt;

    if (pgpDecodePkt(pkts, pktslen, &pkt))
	return -1;
    return getPubkeyFingerprint(pkt.body, pkt.blen, fp, fplen) == RPMPGP_OK ? 0 : -1;
}


