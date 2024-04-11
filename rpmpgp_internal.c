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

/** \ingroup rpmio
 * Values parsed from OpenPGP signature/pubkey packet(s).
 */
struct pgpDigParams_s {
    uint8_t tag;
    char * userid;		/*!< key user id */
    uint8_t key_flags;		/*!< key usage flags */

    uint8_t version;		/*!< key/signature version number. */
    uint32_t time;		/*!< key/signature creation time. */
    uint8_t pubkey_algo;	/*!< key/signature public key algorithm. */

    uint8_t hash_algo;		/*!< signature hash algorithm */
    uint8_t sigtype;
    uint8_t * hash;
    uint32_t hashlen;
    uint8_t signhash16[2];
    pgpKeyID_t signid;		/*!< key id of pubkey or signature */
    uint32_t key_expire;	/*!< key expire time. */
    int revoked;		/*!< is the key revoked? */
    uint8_t saved;		/*!< Various flags. */
#define	PGPDIG_SAVED_TIME	(1 << 0)
#define	PGPDIG_SAVED_ID		(1 << 1)
#define	PGPDIG_SAVED_KEY_FLAGS	(1 << 2)
#define	PGPDIG_SAVED_KEY_EXPIRE	(1 << 3)
#define	PGPDIG_SAVED_PRIMARY	(1 << 4)
#define	PGPDIG_SAVED_VALID	(1 << 5)

    pgpDigAlg alg;		/*!< algorithm specific data like MPIs */
};

static int getKeyID(const uint8_t *h, size_t hlen, pgpKeyID_t keyid);

static inline
unsigned int pgpGrab2(const uint8_t *s)
{
    return s[0] << 8 | s[1];
}

static inline
unsigned int pgpGrab4(const uint8_t *s)
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
static inline
size_t pgpOldLen(const uint8_t *s, size_t slen, size_t * lenp)
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
static inline
size_t pgpNewLen(const uint8_t *s, size_t slen, size_t * lenp)
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
static inline
size_t pgpSubPktLen(const uint8_t *s, size_t slen, size_t * lenp)
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

static int decodePkt(const uint8_t *p, size_t plen, struct pgpPkt *pkt)
{
    int rc = -1; /* assume failure */

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
	    rc = 0;
	}
    }

    return rc;
}

static int pgpVersion(const uint8_t *h, size_t hlen, uint8_t *version)
{
    if (hlen < 1)
	return -1;

    *version = h[0];
    return 0;
}

static int pgpPrtSubType(const uint8_t *h, size_t hlen, pgpSigType sigtype,
			 pgpDigParams _digp, int hashed)
{
    const uint8_t *p = h;
    int rc = 0;

    while (hlen > 0 && rc == 0) {
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
	    if (plen-1 != 4)
		break; /* other lengths not understood */
	    if (_digp->saved & PGPDIG_SAVED_TIME)
		return 1; /* duplicate timestamps not allowed */
	    impl = *p;
	    _digp->time = pgpGrab4(p + 1);
	    _digp->saved |= PGPDIG_SAVED_TIME;
	    break;

	case PGPSUBTYPE_ISSUER_KEYID:
	    if (plen-1 != sizeof(_digp->signid))
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
		return 1;	/* Reject duplicate key usage flags */
	    impl = *p;
	    _digp->key_flags = plen >= 2 ? p[1] : 0;
	    _digp->saved |= PGPDIG_SAVED_KEY_FLAGS;
	    break;

	case PGPSUBTYPE_KEY_EXPIRE_TIME:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (plen-1 != 4)
		break; /* other lengths not understood */
	    if (_digp->saved & PGPDIG_SAVED_KEY_EXPIRE)
		return 1;	/* Reject duplicate key expire time */
	    impl = *p;
	    _digp->key_expire = pgpGrab4(p + 1);
	    _digp->saved |= PGPDIG_SAVED_KEY_EXPIRE;
	    break;

	case PGPSUBTYPE_EMBEDDED_SIG:
	    /* XXX: need to verify embeded signatures of subkey binding sigs */
	    impl = *p;
	    break;

	case PGPSUBTYPE_PRIMARY_USERID:
	    if (!hashed)
		break;	/* Subpackets in the unhashed section cannot be trusted */
	    if (plen-1 != 1)
		break; /* other lengths not understood */
	    impl = *p;
	    if (p[1])
		_digp->saved |= PGPDIG_SAVED_PRIMARY;
	    break;

	default:
	    break;
	}

	if (!impl && (p[0] & PGPSUBTYPE_CRITICAL))
	    rc = 1;

	p += plen;
	hlen -= plen;
    }

    if (hlen != 0)
	rc = 1;

    return rc;
}

static pgpDigAlg pgpDigAlgFree(pgpDigAlg alg)
{
    if (alg) {
	if (alg->free)
	    alg->free(alg);
	free(alg);
    }
    return NULL;
}

static int processMpis(const int mpis, pgpDigAlg sigalg,
		       const uint8_t *p, const uint8_t *const pend)
{
    int i = 0, rc = 1; /* assume failure */
    for (; i < mpis && pend - p >= 2; i++) {
	unsigned int mpil = pgpMpiLen(p);
	if (pend - p < mpil)
	    return rc;
	if (sigalg && sigalg->setmpi(sigalg, i, p))
	    return rc;
	p += mpil;
    }

    /* Does the size and number of MPI's match our expectations? */
    if (p == pend && i == mpis)
	rc = 0;
    return rc;
}

static int pgpPrtSigParams(pgpTag tag, uint8_t pubkey_algo,
		const uint8_t *p, const uint8_t *h, size_t hlen,
		pgpDigParams sigp)
{
    const uint8_t * pend = h + hlen;
    pgpDigAlg sigalg = pgpDigAlgNewSignature(pubkey_algo);

    int rc = processMpis(sigalg->mpis, sigalg, p, pend);

    /* We can't handle more than one sig at a time */
    if (rc == 0 && sigp->alg == NULL && sigp->tag == PGPTAG_SIGNATURE)
	sigp->alg = sigalg;
    else
	pgpDigAlgFree(sigalg);

    return rc;
}

static int pgpPrtSig(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    uint8_t version = 0;
    const uint8_t * p;
    size_t plen;
    int rc = 1;

    if (_digp->version || _digp->saved)
	return rc;	/* need empty pgpDigParams */

    if (pgpVersion(h, hlen, &version))
	return rc;

    switch (version) {
    case 3:
    {   pgpPktSigV3 v = (pgpPktSigV3)h;

	if (hlen <= sizeof(*v) || v->hashlen != 5)
	    return 1;
	_digp->version = v->version;
	_digp->hashlen = v->hashlen;
	_digp->sigtype = v->sigtype;
	_digp->hash = memcpy(xmalloc(v->hashlen), &v->sigtype, v->hashlen);
	_digp->time = pgpGrab4(v->time);
	memcpy(_digp->signid, v->signid, sizeof(_digp->signid));
	_digp->saved = PGPDIG_SAVED_TIME | PGPDIG_SAVED_ID;
	_digp->pubkey_algo = v->pubkey_algo;
	_digp->hash_algo = v->hash_algo;
	memcpy(_digp->signhash16, v->signhash16, sizeof(_digp->signhash16));
	p = ((uint8_t *)v) + sizeof(*v);
	rc = tag ? pgpPrtSigParams(tag, v->pubkey_algo, p, h, hlen, _digp) : 0;
    }	break;
    case 4:
    {   pgpPktSigV4 v = (pgpPktSigV4)h;
	const uint8_t *const hend = h + hlen;
	int hashed;

	if (hlen <= sizeof(*v))
	    return 1;
	_digp->version = v->version;
	_digp->sigtype = v->sigtype;
	_digp->pubkey_algo = v->pubkey_algo;
	_digp->hash_algo = v->hash_algo;

	/* parse both the hashed and unhashed subpackets */
	p = &v->hashlen[0];
	for (hashed = 1; hashed >= 0; hashed--) {
	    if (p > hend || hend - p < 2)
		return 1;
	    plen = pgpGrab2(p);
	    p += 2;
	    if (hend - p < plen)
		return 1;
	    if (hashed) {
		_digp->hashlen = sizeof(*v) + plen;
		_digp->hash = memcpy(xmalloc(_digp->hashlen), v, _digp->hashlen);
	    }
	    if (pgpPrtSubType(p, plen, v->sigtype, _digp, hashed))
		return 1;
	    p += plen;
	}

	if (!(_digp->saved & PGPDIG_SAVED_TIME))
	    return 1; /* RFC 4880 §5.2.3.4 creation time MUST be present */

	if (p > hend || hend - p < 2)
	    return 1;
	memcpy(_digp->signhash16, p, sizeof(_digp->signhash16));
	p += 2;

	if (p > hend)
	    return 1;

	rc = tag ? pgpPrtSigParams(tag, v->pubkey_algo, p, h, hlen, _digp) : 0;
    }	break;
    default:
	rpmlog(RPMLOG_WARNING, _("Unsupported version of signature: V%d\n"), version);
	rc = 1;
	break;
    }
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

static int isKey(pgpDigParams keyp)
{
    return keyp->tag == PGPTAG_PUBLIC_KEY || keyp->tag == PGPTAG_PUBLIC_SUBKEY;
}

static int pgpPrtPubkeyParams(uint8_t pubkey_algo,
		const uint8_t *p, const uint8_t *h, size_t hlen,
		pgpDigParams keyp)
{
    int rc = 1; /* assume failure */
    const uint8_t *pend = h + hlen;
    int curve = 0;
    if (!isKey(keyp))
	return rc;
    /* We can't handle more than one key at a time */
    if (keyp->alg)
	return rc;
    if (pubkey_algo == PGPPUBKEYALGO_EDDSA) {
	int len = (hlen > 1) ? p[0] : 0;
	if (len == 0 || len == 0xff || len >= hlen)
	    return rc;
	curve = pgpCurveByOid(p + 1, len);
	p += len + 1;
    }
    pgpDigAlg keyalg = pgpDigAlgNewPubkey(pubkey_algo, curve);
    rc = processMpis(keyalg->mpis, keyalg, p, pend);
    if (rc == 0) {
	keyp->pubkey_algo = pubkey_algo;
	keyp->alg = keyalg;
    } else {
	pgpDigAlgFree(keyalg);
    }
    return rc;
}

static int pgpPrtKey(pgpTag tag, const uint8_t *h, size_t hlen,
		     pgpDigParams _digp)
{
    uint8_t version = 0;
    const uint8_t * p = NULL;
    int rc = 1;

    if (_digp->version || _digp->saved)
	return rc;	/* need empty pgpDigParams */

    if (pgpVersion(h, hlen, &version))
	return rc;

    /* We only permit V4 keys, V3 keys are long long since deprecated */
    switch (version) {
    case 4:
    {   pgpPktKeyV4 v = (pgpPktKeyV4)h;

	if (hlen > sizeof(*v)) {
	    _digp->version = v->version;
	    _digp->time = pgpGrab4(v->time);
	    _digp->saved |= PGPDIG_SAVED_TIME;
	    p = ((uint8_t *)v) + sizeof(*v);
	    rc = pgpPrtPubkeyParams(v->pubkey_algo, p, h, hlen, _digp);
	}
    }	break;
    default:
	rpmlog(RPMLOG_WARNING, _("Unsupported version of key: V%d\n"), h[0]);
    }

    /* calculate the key id if we could parse the key */
    if (!rc) {
	rc = getKeyID(h, hlen, _digp->signid);
	if (rc)
	    memset(_digp->signid, 0, sizeof(_digp->signid));
	else
	    _digp->saved |= PGPDIG_SAVED_ID;
    }
    return rc;
}

static int pgpPrtUserID(pgpTag tag, const uint8_t *h, size_t hlen,
			pgpDigParams _digp)
{
    free(_digp->userid);
    _digp->userid = memcpy(xmalloc(hlen+1), h, hlen);
    _digp->userid[hlen] = '\0';
    return 0;
}

static int getPubkeyFingerprint(const uint8_t *h, size_t hlen,
			  uint8_t **fp, size_t *fplen)
{
    int rc = -1; /* assume failure */
    const uint8_t *se;
    const uint8_t *pend = h + hlen;
    uint8_t version = 0;

    if (pgpVersion(h, hlen, &version))
	return rc;

    /* We only permit V4 keys, V3 keys are long long since deprecated */
    switch (version) {
    case 4:
      {	pgpPktKeyV4 v = (pgpPktKeyV4) (h);
	int mpis = -1;

	/* Packet must be strictly larger than v to have room for the
	 * required MPIs and (for EdDSA) the curve ID */
	if (hlen < sizeof(*v) + sizeof(uint8_t))
	    return rc;
	se = (uint8_t *)(v + 1);
	switch (v->pubkey_algo) {
	case PGPPUBKEYALGO_EDDSA:
	    /* EdDSA has a curve id before the MPIs */
	    if (se[0] == 0x00 || se[0] == 0xff || pend - se < 1 + se[0])
		return rc;
	    se += 1 + se[0];
	    mpis = 1;
	    break;
	case PGPPUBKEYALGO_RSA:
	    mpis = 2;
	    break;
	case PGPPUBKEYALGO_DSA:
	    mpis = 4;
	    break;
	default:
	    return rc;
	}

	/* Does the size and number of MPI's match our expectations? */
	if (processMpis(mpis, NULL, se, pend) == 0) {
	    DIGEST_CTX ctx = rpmDigestInit(RPM_HASH_SHA1, RPMDIGEST_NONE);
	    uint8_t *d = NULL;
	    size_t dlen = 0;
	    uint8_t in[3] = { 0x99, (hlen >> 8), hlen };

	    (void) rpmDigestUpdate(ctx, in, 3);
	    (void) rpmDigestUpdate(ctx, h, hlen);
	    (void) rpmDigestFinal(ctx, (void **)&d, &dlen, 0);

	    if (dlen == 20) {
		rc = 0;
		*fp = d;
		*fplen = dlen;
	    } else {
		free(d);
	    }
	}

      }	break;
    default:
	rpmlog(RPMLOG_WARNING, _("Unsupported version of key: V%d\n"), version);
    }
    return rc;
}

static int getKeyID(const uint8_t *h, size_t hlen, pgpKeyID_t keyid)
{
    uint8_t *fp = NULL;
    size_t fplen = 0;
    int rc = getPubkeyFingerprint(h, hlen, &fp, &fplen);
    if (fp && fplen > 8) {
	memcpy(keyid, (fp + (fplen-8)), 8);
	free(fp);
    }
    return rc;
}

static int pgpPrtPkt(struct pgpPkt *p, pgpDigParams _digp)
{
    int rc = 0;

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
	rc = -1;
	break;
    default:
	break;
    }

    return rc;
}

pgpDigParams pgpDigParamsFree(pgpDigParams digp)
{
    if (digp) {
	pgpDigAlgFree(digp->alg);
	free(digp->userid);
	free(digp->hash);
	memset(digp, 0, sizeof(*digp));
	free(digp);
    }
    return NULL;
}

/* compare data of two signatures */
int pgpDigParamsCmp(pgpDigParams p1, pgpDigParams p2)
{
    int rc = 1; /* assume different, eg if either is NULL */
    if (p1 && p2) {
	/* XXX Should we compare something else too? */
	if (p1->tag != p2->tag)
	    goto exit;
	if (p1->hash_algo != p2->hash_algo)
	    goto exit;
	if (p1->pubkey_algo != p2->pubkey_algo)
	    goto exit;
	if (p1->version != p2->version)
	    goto exit;
	if (p1->sigtype != p2->sigtype)
	    goto exit;
	if (memcmp(p1->signid, p2->signid, sizeof(p1->signid)) != 0)
	    goto exit;
	if (p1->userid && p2->userid && strcmp(p1->userid, p2->userid) != 0)
	    goto exit;

	/* Parameters match ... at least for our purposes */
	rc = 0;
    }
exit:
    return rc;
}

int pgpSignatureType(pgpDigParams _digp)
{
    int rc = -1;

    if (_digp && _digp->tag == PGPTAG_SIGNATURE)
	rc = _digp->sigtype;

    return rc;
}

unsigned int pgpDigParamsAlgo(pgpDigParams digp, unsigned int algotype)
{
    unsigned int algo = 0; /* assume failure */
    if (digp) {
	switch (algotype) {
	case PGPVAL_PUBKEYALGO:
	    algo = digp->pubkey_algo;
	    break;
	case PGPVAL_HASHALGO:
	    algo = digp->hash_algo;
	    break;
	}
    }
    return algo;
}

const uint8_t *pgpDigParamsSignID(pgpDigParams digp)
{
    return digp->signid;
}

const char *pgpDigParamsUserID(pgpDigParams digp)
{
    return digp->userid;
}

int pgpDigParamsVersion(pgpDigParams digp)
{
    return digp->version;
}

uint32_t pgpDigParamsCreationTime(pgpDigParams digp)
{
    return digp->time;
}

static pgpDigParams pgpDigParamsNew(uint8_t tag)
{
    pgpDigParams digp = xcalloc(1, sizeof(*digp));
    digp->tag = tag;
    return digp;
}

static int hashKey(DIGEST_CTX hash, const struct pgpPkt *pkt, int exptag)
{
    int rc = -1;
    if (pkt->tag == exptag) {
	uint8_t head[] = {
	    0x99,
	    (pkt->blen >> 8),
	    (pkt->blen     ),
	};

	rpmDigestUpdate(hash, head, 3);
	rpmDigestUpdate(hash, pkt->body, pkt->blen);
	rc = 0;
    }
    return rc;
}

static int hashUserID(DIGEST_CTX hash, const struct pgpPkt *pkt)
{
    int rc = -1;
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
	rc = 0;
    }
    return rc;
}

static int pgpVerifySelf(pgpDigParams key, pgpDigParams selfsig,
			const struct pgpPkt *pubkey, const struct pgpPkt *other)
{
    int rc = -1;
    DIGEST_CTX hash = NULL;

    switch (selfsig->sigtype) {
    case PGPSIGTYPE_SUBKEY_BINDING:
    case PGPSIGTYPE_SUBKEY_REVOKE:
	hash = rpmDigestInit(selfsig->hash_algo, 0);
	if (hash && other && other->tag == PGPTAG_PUBLIC_SUBKEY) {
	    rc = hashKey(hash, pubkey, PGPTAG_PUBLIC_KEY);
	    if (!rc)
		rc = hashKey(hash, other, PGPTAG_PUBLIC_SUBKEY);
	}
	break;
    case PGPSIGTYPE_GENERIC_CERT:
    case PGPSIGTYPE_PERSONA_CERT:
    case PGPSIGTYPE_CASUAL_CERT:
    case PGPSIGTYPE_POSITIVE_CERT:
	hash = rpmDigestInit(selfsig->hash_algo, 0);
	if (hash && other && other->tag == PGPTAG_USER_ID) {
	    rc = hashKey(hash, pubkey, PGPTAG_PUBLIC_KEY);
	    if (!rc)
		rc = hashUserID(hash, other);
	}
	break;
    case PGPSIGTYPE_SIGNED_KEY:
	hash = rpmDigestInit(selfsig->hash_algo, 0);
	if (hash) 
	    rc = hashKey(hash, pubkey, PGPTAG_PUBLIC_KEY);
	break;
    default:
	/* ignore types we can't handle */
	rc = 0;
	break;
    }

    if (hash && rc == 0)
	rc = pgpVerifySignature(key, selfsig, hash);

    rpmDigestFinal(hash, NULL, NULL, 0);

    return rc;
}

static const size_t RPM_MAX_OPENPGP_BYTES = 65535; /* max number of bytes in a key */

static int
is_self_signature(pgpDigParams digp, pgpDigParams sigdigp)
{
    return (digp->saved & sigdigp->saved & PGPDIG_SAVED_ID) != 0 &&
	memcmp(digp->signid, sigdigp->signid, sizeof(digp->signid)) == 0;
}

/* parse a complete pubkey with all associated packets */
static int pgpPrtParamsPubkey(const uint8_t * pkts, size_t pktlen, pgpDigParams * ret)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgpDigParams digp = NULL;
    pgpDigParams sigdigp = NULL;
    pgpDigParams newest_digp = NULL;
    int i = 0, useridpkt = 0, subkeypkt = 0;
    int alloced = 16; /* plenty for normal cases */
    int rc = -1; /* assume failure */
    int prevtag = 0;
    uint32_t key_expire_sig_time = 0;
    uint32_t key_flags_sig_time = 0;

    if (pktlen > RPM_MAX_OPENPGP_BYTES)
	return rc; /* reject absurdly large data */

    struct pgpPkt *all = xmalloc(alloced * sizeof(*all));
    while (1) {
	struct pgpPkt *pkt = &all[i];
	if (p < pend) {
	    if (decodePkt(p, (pend - p), pkt))
		break;
	    if (digp && pkt->tag == PGPTAG_PUBLIC_KEY)
		break;	/* start of another public key, error out */

	    if (!digp) {
		if (pkt->tag != PGPTAG_PUBLIC_KEY)
		    break;
		digp = pgpDigParamsNew(pkt->tag);
	    }
	} else {
	    pkt->tag = 0;
	}

	/* did we end a section selfsig/userid/subkey section? if yes take the data from the newest signature */
	if ((p == pend || pkt->tag == PGPTAG_USER_ID || pkt->tag == PGPTAG_PHOTOID || pkt->tag == PGPTAG_PUBLIC_SUBKEY) && newest_digp) {
	    if (newest_digp->sigtype == PGPSIGTYPE_CERT_REVOKE)
		newest_digp->saved &= ~(PGPDIG_SAVED_KEY_EXPIRE | PGPDIG_SAVED_KEY_FLAGS);	/* just in case */
	    else if (!subkeypkt)
		digp->saved |= PGPDIG_SAVED_VALID;		/* we have at least one self-sig */
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
		    if (pgpPrtPkt(all + useridpkt, digp))
			break;
		    if ((newest_digp->saved & PGPDIG_SAVED_PRIMARY) != 0)
			digp->saved |= PGPDIG_SAVED_PRIMARY;
		}
	    }
	    newest_digp = pgpDigParamsFree(newest_digp);
	}

	if (p == pend)
	    break;	/* all packets processed */

	/* subkeys must be followed by at least one binding signature which we need to verify */
	if (prevtag == PGPTAG_PUBLIC_SUBKEY && pkt->tag != PGPTAG_SIGNATURE)
	    break;

	if (pkt->tag == PGPTAG_SIGNATURE) {
	    int needsig = 0;
	    sigdigp = pgpDigParamsNew(pkt->tag);
	    if (pgpPrtPkt(pkt, sigdigp))
		break;

	    if (prevtag == PGPTAG_PUBLIC_SUBKEY && sigdigp->sigtype != PGPSIGTYPE_SUBKEY_BINDING && sigdigp->sigtype != PGPSIGTYPE_SUBKEY_REVOKE)
		break;			/* a subkey paket must be followed by a binding signature */

	    if (sigdigp->sigtype == PGPSIGTYPE_SUBKEY_BINDING || sigdigp->sigtype == PGPSIGTYPE_SUBKEY_REVOKE) {
		if (!subkeypkt)
		    break;		/* signature in wrong section */
		if (!is_self_signature(digp, sigdigp))
		    break;		/* the binding signature must be a self signature */
		if (pgpVerifySelf(digp, sigdigp, all, all + subkeypkt))
		    break;		/* verification failed */
		needsig = 1;
	    }

	    if (sigdigp->sigtype == PGPSIGTYPE_KEY_REVOKE) {
		/* sections don't matter here */
		if (!is_self_signature(digp, sigdigp))
		    break;		/* the binding signature must be a self signature */
		if (pgpVerifySelf(digp, sigdigp, all, NULL))
		    break;		/* verification failed */
		digp->revoked = 1;				/* this is final */
		digp->saved |= PGPDIG_SAVED_VALID;		/* we have at least one correct self-sig */
	    }

	    if (sigdigp->sigtype == PGPSIGTYPE_SIGNED_KEY) {
		if (subkeypkt || useridpkt)
		    break;		/* signature in wrong section */
		if (is_self_signature(digp, sigdigp)) {
		    if (pgpVerifySelf(digp, sigdigp, all, NULL))
			break;		/* verification failed */
		    needsig = 1;
		}
	    }

	    if (sigdigp->sigtype == PGPSIGTYPE_GENERIC_CERT || sigdigp->sigtype == PGPSIGTYPE_PERSONA_CERT || sigdigp->sigtype == PGPSIGTYPE_CASUAL_CERT || sigdigp->sigtype == PGPSIGTYPE_POSITIVE_CERT || sigdigp->sigtype == PGPSIGTYPE_CERT_REVOKE) {
		if (!useridpkt)
		    break;		/* signature in wrong section */
		if (all[useridpkt].tag == PGPTAG_USER_ID && is_self_signature(digp, sigdigp)) {
		    if (pgpVerifySelf(digp, sigdigp, all, all + useridpkt))
			break;		/* verification failed */
		    needsig = 1;
		    /* note that cert revokations may get overwritten by newer certifications (like in gnupg) */
		}
	    }

	    if (needsig && (!newest_digp || sigdigp->time >= newest_digp->time)) {
		newest_digp = pgpDigParamsFree(newest_digp);
		newest_digp = sigdigp;
		sigdigp = NULL;
	    }
	    sigdigp = pgpDigParamsFree(sigdigp);
	} else if (pkt->tag == PGPTAG_USER_ID || pkt->tag == PGPTAG_PHOTOID) {
	    /* we delay the user id package parsing until we have verified the binding signature */
	    if (subkeypkt)
		break;		/* no user id packets after subkeys allowed */
	    useridpkt = i;
	} else if (pkt->tag == PGPTAG_PUBLIC_SUBKEY) {
	    subkeypkt = i;
	    useridpkt = 0;
	} else {
	    if (pgpPrtPkt(pkt, digp))
		break;
	}

	prevtag = pkt->tag;
	p += (pkt->body - pkt->head) + pkt->blen;

	if (++i >= alloced) {
	    alloced *= 2;
	    all = xrealloc(all, alloced * sizeof(*all));
	}
    }
    rc = (digp && (p == pend) && prevtag != PGPTAG_PUBLIC_SUBKEY) ? 0 : -1;

    free(all);
    sigdigp = pgpDigParamsFree(sigdigp);
    newest_digp = pgpDigParamsFree(newest_digp);
    if (ret && rc == 0) {
	*ret = digp;
    } else {
	pgpDigParamsFree(digp);
    }
    return rc;

}
	
int pgpPrtParams(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret)
{
    pgpDigParams digp = NULL;
    int rc = -1;	/* assume failure */
    struct pgpPkt pkt;

    if (pktlen > RPM_MAX_OPENPGP_BYTES)
	return rc;	/* reject absurdly large data */
    if (decodePkt(pkts, pktlen, &pkt))
	return rc;

    if (pkttype && pkt.tag != pkttype)
	return rc;

    if (pkt.tag == PGPTAG_PUBLIC_KEY)
	return pgpPrtParamsPubkey(pkts, pktlen, ret);	/* switch to specialized pubkey implementation */

    digp = pgpDigParamsNew(pkt.tag);
    if (pgpPrtPkt(&pkt, digp))
	goto exit;
    if ((pkt.body - pkt.head) + pkt.blen != pktlen)
	goto exit;	/* trailing data is an error */
    rc = 0;
exit:
    if (ret && rc == 0)
	*ret = digp;
    else
	pgpDigParamsFree(digp);
    return rc;
}

int pgpPrtParams2(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
                  pgpDigParams * ret, char **lints)
{
    if (lints)
        *lints = NULL;
    return pgpPrtParams(pkts, pktlen, pkttype, ret);
}

/* Return the subkeys for a pubkey. Note that the subkey binding
 * signatures have already been verified when the pubkey was
 * parsed */
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
    struct pgpPkt pkt;
    int rc, i, j;

    digps = xmalloc(alloced * sizeof(*digps));

    while (1) {
	if (p < pend) {
	    if (decodePkt(p, (pend - p), &pkt))
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
	    /* Copy UID from main key to subkey */
	    subdigp->userid = mainkey->userid ? xstrdup(mainkey->userid) : NULL;
	    if (pgpPrtKey(pkt.tag, pkt.body, pkt.blen, subdigp)) {
		subdigp = pgpDigParamsFree(subdigp);
	    } else {
		if (count == alloced) {
		    alloced <<= 1;
		    digps = xrealloc(digps, alloced * sizeof(*digps));
		}
		digps[count++] = subdigp;
	    }
	} else if (pkt.tag == PGPTAG_SIGNATURE && subdigp != NULL) {
	    sigdigp = pgpDigParamsNew(pkt.tag);
	    /* HACK: we use tag 0 to prevent MPI saving as we do not verify */
	    if (pgpPrtSig(0, pkt.body, pkt.blen, sigdigp)) {
		sigdigp = pgpDigParamsFree(sigdigp);
	    }
	    if (sigdigp && sigdigp->sigtype == PGPSIGTYPE_SUBKEY_REVOKE) {
		subdigp->revoked = 1;
	    } else if (sigdigp && sigdigp->sigtype == PGPSIGTYPE_SUBKEY_BINDING) {
		if (!newest_digp || sigdigp->time >= newest_digp->time) {
		    newest_digp = pgpDigParamsFree(newest_digp);
		    newest_digp = sigdigp;
		    sigdigp = NULL;
		}
	    }
	    sigdigp = pgpDigParamsFree(sigdigp);
	}
    }
    rc = (p == pend) ? 0 : -1;

    sigdigp = pgpDigParamsFree(sigdigp);
    newest_digp = pgpDigParamsFree(newest_digp);

    if (rc == 0) {
	/* now strip all not-valid, revoked, or unusable subkeys */
	for (i = j = 0; i < count; i++) {
	    if (!digps[i]->revoked &&
		    (digps[i]->saved & PGPDIG_SAVED_VALID) != 0 &&
		    (digps[i]->saved & PGPDIG_SAVED_KEY_FLAGS) != 0 &&
		    (digps[i]->key_flags & 0x02) != 0) {
		digps[j++] = digps[i];
	    } else {
	        pgpDigParamsFree(digps[i]);
	    }
	}
	count = j;
	*subkeys = xrealloc(digps, count * sizeof(*digps));
	*subkeysCount = count;
    } else {
	for (i = 0; i < count; i++)
	    pgpDigParamsFree(digps[i]);
	free(digps);
    }

    return rc;
}

rpmRC pgpVerifySignature(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx)
{
    DIGEST_CTX ctx = rpmDigestDup(hashctx);
    uint8_t *hash = NULL;
    size_t hashlen = 0;
    rpmRC res = RPMRC_FAIL; /* assume failure */

    if (sig == NULL || ctx == NULL)
	goto exit;

    if (sig->tag != PGPTAG_SIGNATURE)
	goto exit;

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
     * done all we can, return NOKEY to indicate "looks okay but dunno."
     */
    if (key && key->alg) {
	if (!isKey(key))
	    goto exit;
	pgpDigAlg sa = sig->alg;
	pgpDigAlg ka = key->alg;
	if (sa && sa->verify && sig->pubkey_algo == key->pubkey_algo) {
	    if (sa->verify(ka, sa, hash, hashlen, sig->hash_algo) == 0) {
		res = RPMRC_OK;
	    }
	}
    } else {
	res = RPMRC_NOKEY;
    }

exit:
    free(hash);
    rpmDigestFinal(ctx, NULL, NULL, 0);
    return res;

}

rpmRC pgpVerifySignature2(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx, char **lints)
{
    if (lints)
        *lints = NULL;
    return pgpVerifySignature(key, sig, hashctx);
}

int pgpPubKeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktslen;
    struct pgpPkt pkt;

    while (p < pend) {
	if (decodePkt(p, (pend - p), &pkt))
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

    if (decodePkt(pkts, pktslen, &pkt))
	return -1;
    return getKeyID(pkt.body, pkt.blen, keyid);
}

int pgpPubkeyFingerprint(const uint8_t * pkts, size_t pktslen,
                         uint8_t **fp, size_t *fplen)
{
    struct pgpPkt pkt;

    if (decodePkt(pkts, pktslen, &pkt))
	return -1;
    return getPubkeyFingerprint(pkt.body, pkt.blen, fp, fplen);
}


rpmRC pgpPubKeyLint(const uint8_t *pkts, size_t pktslen, char **explanation)
{
    *explanation = NULL;
    return RPMRC_OK;
}

