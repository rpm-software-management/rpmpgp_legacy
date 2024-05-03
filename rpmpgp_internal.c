/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal.c
 * Routines to handle RFC-2440 detached signatures.
 */

#include "system.h"

#include <time.h>
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


static inline unsigned int pgpGrab2(const uint8_t *s)
{
    return s[0] << 8 | s[1];
}

static inline unsigned int pgpGrab4(const uint8_t *s)
{
    return s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3];
}

uint32_t pgpCurrentTime(void) {
    time_t t = time(NULL);
    return (uint32_t)t;
}


/*
 * PGP packet decoding
 *
 * Note that we reject indefinite length/partial bodies and lengths >= 16 MByte
 * right away so that we do not have to worry about integer overflows.
 */

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
static inline size_t pgpNewLen(const uint8_t *s, size_t slen, size_t *lenp)
{
    size_t dlen, hlen;

    if (slen > 1 && s[1] < 192) {
	hlen = 2;
	dlen = s[1];
    } else if (slen > 3 && s[1] < 224) {
	hlen = 3;
	dlen = (((s[1]) - 192) << 8) + s[2] + 192;
    } else if (slen > 6 && s[1] == 255 && s[2] == 0) {
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
static inline size_t pgpSubPktLen(const uint8_t *s, size_t slen, size_t *lenp)
{
    size_t dlen, lenlen;

    if (slen > 0 && *s < 192) {
	lenlen = 1;
	dlen = *s;
    } else if (slen > 2 && *s < 255) {
	lenlen = 2;
	dlen = (((s[0]) - 192) << 8) + s[1] + 192;
    } else if (slen > 5 && *s == 255 && s[1] == 0) {
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

rpmpgpRC pgpDecodePkt(const uint8_t *p, size_t plen, pgpPkt *pkt)
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


/*
 * Key/Signature algorithm parameter handling
 */

static pgpDigAlg pgpDigAlgNew(void)
{
    pgpDigAlg alg;
    alg = xcalloc(1, sizeof(*alg));
    alg->mpis = -1;
    return alg;
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

static inline int pgpMpiLen(const uint8_t *p)
{
    int mpi_bits = (p[0] << 8) | p[1];
    return 2 + ((mpi_bits + 7) >> 3);
}

static rpmpgpRC processMpis(const int mpis, pgpDigAlg alg,
		       const uint8_t *p, const uint8_t *const pend)
{
    int i = 0;
    for (; i < mpis && pend - p >= 2; i++) {
	int mpil = pgpMpiLen(p);
	if (mpil < 2 || pend - p < mpil)
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	if (alg) {
	    rpmpgpRC rc = alg->setmpi ? alg->setmpi(alg, i, p, mpil) : RPMPGP_ERROR_UNSUPPORTED_ALGORITHM;
	    if (rc != RPMPGP_OK)
		return rc;
	}
	p += mpil;
    }

    /* Does the size and number of MPI's match our expectations? */
    return p == pend && i == mpis ? RPMPGP_OK : RPMPGP_ERROR_CORRUPT_PGP_PACKET;
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
	size_t plen = hlen - keyp->mpi_offset;
	int len = plen > 0 ? p[0] : 0;
	if (len == 0 || len == 0xff || len + 1 > plen)
	    return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	curve = pgpCurveByOid(p + 1, len);
	if (!curve)
	    return RPMPGP_ERROR_UNSUPPORTED_CURVE;
	p += len + 1;
    }
    pgpDigAlg alg = pgpDigAlgNew();
    pgpDigAlgInitPubkey(alg, keyp->pubkey_algo, curve);
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

rpmpgpRC pgpPrtSigParams(pgpTag tag, const uint8_t *h, size_t hlen,
		pgpDigParams sigp)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    /* We can't handle more than one sig at a time */
    if (sigp->alg || !sigp->mpi_offset || sigp->mpi_offset > hlen || sigp->tag != PGPTAG_SIGNATURE)
	return RPMPGP_ERROR_INTERNAL;
    pgpDigAlg alg = pgpDigAlgNew();
    pgpDigAlgInitSignature(alg, sigp->pubkey_algo);
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


/*
 *  Key fingerprint calculation
 */

rpmpgpRC pgpGetKeyFingerprint(const uint8_t *h, size_t hlen,
			  uint8_t **fp, size_t *fplen)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */

    if (hlen == 0)
	return rc;

    /* We only permit V4 keys, V3 keys are long long since deprecated */
    switch (h[0]) {
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

rpmpgpRC pgpGetKeyID(const uint8_t *h, size_t hlen, pgpKeyID_t keyid)
{
    uint8_t *fp = NULL;
    size_t fplen = 0;
    rpmpgpRC rc = pgpGetKeyFingerprint(h, hlen, &fp, &fplen);
    if (rc == RPMPGP_OK && fp && fplen > 8)
	memcpy(keyid, (fp + (fplen - 8)), 8);
    else if (rc == RPMPGP_OK)
	rc = RPMPGP_ERROR_INTERNAL;
    free(fp);
    return rc;
}


/*
 *  PGP packet data extraction
 */

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
	    impl = 1;
	    _digp->time = pgpGrab4(p + 1);
	    _digp->saved |= PGPDIG_SAVED_TIME;
	    break;

	case PGPSUBTYPE_ISSUER_KEYID:
	    if (plen - 1 != sizeof(_digp->signid))
		break; /* other lengths not understood */
	    impl = 1;
	    if (!(_digp->saved & PGPDIG_SAVED_ID)) {
		memcpy(_digp->signid, p + 1, sizeof(_digp->signid));
		_digp->saved |= PGPDIG_SAVED_ID;
	    }
	    break;

	case PGPSUBTYPE_KEY_FLAGS:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (_digp->saved & PGPDIG_SAVED_KEY_FLAGS)
		return RPMPGP_ERROR_DUPLICATE_DATA;
	    impl = 1;
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
	    impl = 1;
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
	    impl = 1;
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
	    impl = 1;
	    _digp->embedded_sig_len = plen - 1;
	    _digp->embedded_sig = memcpy(xmalloc(plen - 1), p + 1, plen - 1);
	    break;

	case PGPSUBTYPE_PRIMARY_USERID:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (plen - 1 != 1)
		break; /* other lengths not understood */
	    impl = 1;
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

rpmpgpRC pgpPrtSigNoParams(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    const uint8_t * p;
    size_t plen;

    if (_digp->version || _digp->saved || _digp->tag != PGPTAG_SIGNATURE || tag != _digp->tag)
	return RPMPGP_ERROR_INTERNAL;

    if (hlen == 0)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    _digp->version = h[0];

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

rpmpgpRC pgpPrtSig(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    rpmpgpRC rc = pgpPrtSigNoParams(tag, h, hlen, _digp);
    if (rc == RPMPGP_OK)
	rc = pgpPrtSigParams(tag, h, hlen, _digp);
    return rc;
}

rpmpgpRC pgpPrtKey(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */

    if (_digp->version || _digp->saved)
	return RPMPGP_ERROR_INTERNAL;
    if  ((_digp->tag != PGPTAG_PUBLIC_KEY && _digp->tag != PGPTAG_PUBLIC_SUBKEY) || tag != _digp->tag)
	return RPMPGP_ERROR_INTERNAL;

    if (hlen == 0)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    _digp->version = h[0];

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
	if ((rc = pgpGetKeyID(h, hlen, _digp->signid)) == RPMPGP_OK)
	    _digp->saved |= PGPDIG_SAVED_ID;
    }
    return rc;
}

rpmpgpRC pgpPrtUserID(pgpTag tag, const uint8_t *h, size_t hlen,
			pgpDigParams _digp)
{
    if (_digp->tag != PGPTAG_PUBLIC_KEY || tag != PGPTAG_USER_ID)
	return RPMPGP_ERROR_INTERNAL;
    free(_digp->userid);
    _digp->userid = memcpy(xmalloc(hlen+1), h, hlen);
    _digp->userid[hlen] = '\0';
    return RPMPGP_OK;
}


/*
 * signature verification
 */

rpmpgpRC pgpVerifySignatureRaw(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx)
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
	uint8_t trailer[6] = {
	    sig->version,
	    0xff,
	    (sig->hashlen >> 24),
	    (sig->hashlen >> 16),
	    (sig->hashlen >>  8),
	    (sig->hashlen      )
	};
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

