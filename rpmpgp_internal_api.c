/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal_api.c
 * Public API for the PGP functions
 */

#include "system.h"

#include "rpmpgp_internal.h"

pgpDigParams pgpDigParamsNew(uint8_t tag)
{
    pgpDigParams digp = xcalloc(1, sizeof(*digp));
    digp->tag = tag;
    return digp;
}

pgpDigParams pgpDigParamsFree(pgpDigParams digp)
{
    if (digp) {
	pgpDigAlgFree(digp->alg);
	free(digp->userid);
	free(digp->hash);
	free(digp->embedded_sig);
	memset(digp, 0, sizeof(*digp));
	free(digp);
    }
    return NULL;
}

/* compare data of two signatures or keys */
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

uint32_t pgpDigParamsModificationTime(pgpDigParams digp)
{
    return digp->tag == PGPTAG_PUBLIC_KEY ? digp->key_mtime : 0;
}

rpmRC pgpVerifySignature2(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx, char **lints)
{
    rpmRC res = RPMRC_FAIL;
    if (lints)
        *lints = NULL;

    if (!sig || sig->tag != PGPTAG_SIGNATURE || (sig->sigtype != PGPSIGTYPE_BINARY && sig->sigtype != PGPSIGTYPE_TEXT && sig->sigtype != PGPSIGTYPE_STANDALONE))
	goto exit;
    res = pgpVerifySignatureRaw(key, sig, hashctx) == RPMPGP_OK ? RPMRC_OK : RPMRC_FAIL;
    if (res != RPMRC_OK)
	goto exit;

    /* now check the meta information of the signature */
    if ((sig->saved & PGPDIG_SAVED_SIG_EXPIRE) != 0 && sig->sig_expire) {
	uint32_t now = pgpCurrentTime();
	if (now < sig->time) {
	    if (lints)
		pgpAddLint(sig, lints, RPMPGP_ERROR_SIGNATURE_FROM_FUTURE);
	    res = RPMRC_NOTTRUSTED;
	} else if (sig->sig_expire < now - sig->time) {
	    if (lints)
		pgpAddLint(sig, lints, RPMPGP_ERROR_SIGNATURE_EXPIRED);
	    res = RPMRC_NOTTRUSTED;
	}
	if (res != RPMRC_OK)
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
	    pgpAddLint(key, lints, key->revoked == 2 ? RPMPGP_ERROR_PRIMARY_REVOKED : RPMPGP_ERROR_KEY_REVOKED);
	res = RPMRC_NOTTRUSTED;
    } else if ((key->saved & PGPDIG_SAVED_VALID) == 0) {
	if (lints)
	    pgpAddLint(key, lints, RPMPGP_ERROR_KEY_NOT_VALID);
	res = RPMRC_NOTTRUSTED;
    } else if (key->tag == PGPTAG_PUBLIC_SUBKEY && ((key->saved & PGPDIG_SAVED_KEY_FLAGS) == 0 || (key->key_flags & 0x02) == 0)) {
	if (lints)
	    pgpAddLint(key, lints, RPMPGP_ERROR_KEY_NO_SIGNING);
	res = RPMRC_NOTTRUSTED;	/* subkey not suitable for signing */
    } else if (key->time > sig->time) {
	if (lints)
	    pgpAddLint(key, lints, RPMPGP_ERROR_KEY_CREATED_AFTER_SIG);
	res = RPMRC_NOTTRUSTED;
    } else if ((key->saved & PGPDIG_SAVED_KEY_EXPIRE) != 0 && key->key_expire && key->key_expire < sig->time - key->time) {
	if (lints)
	    pgpAddLint(key, lints, RPMPGP_ERROR_KEY_EXPIRED);
	res = RPMRC_NOTTRUSTED;
    }
exit:
    return res;
}

rpmRC pgpVerifySignature(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx)
{
    return pgpVerifySignature2(key, sig, hashctx, NULL);
}


int pgpPrtParams2(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret, char **lints)
{
    pgpDigParams digp = NULL;
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;	/* assume failure */
    pgpPkt pkt;

    if (lints)
        *lints = NULL;
    if (pktlen > RPM_MAX_OPENPGP_BYTES)
	goto exit;
    if (pgpDecodePkt(pkts, pktlen, &pkt))
	goto exit;

    rc = RPMPGP_ERROR_UNEXPECTED_PGP_PACKET;
    if (pkttype && pkt.tag != pkttype)
	goto exit;

    if (pkt.tag == PGPTAG_PUBLIC_KEY) {
	/* use specialized transferable pubkey implementation */
	digp = pgpDigParamsNew(pkt.tag);
	rc = pgpPrtTransferablePubkey(pkts, pktlen, digp);
    } else if (pkt.tag == PGPTAG_SIGNATURE) {
	digp = pgpDigParamsNew(pkt.tag);
	rc = pgpPrtSig(pkt.tag, pkt.body, pkt.blen, digp);
	/* treat trailing data as error */
	if (rc == RPMPGP_OK && (pkt.body - pkt.head) + pkt.blen != pktlen)
	    rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    }

exit:
    if (ret && rc == RPMPGP_OK)
	*ret = digp;
    else {
	if (lints)
	    pgpAddLint(digp, lints, rc);
	pgpDigParamsFree(digp);
    }
    return rc == RPMPGP_OK ? 0 : -1;
}

int pgpPrtParams(const uint8_t * pkts, size_t pktlen, unsigned int pkttype,
                  pgpDigParams * ret)
{
    return pgpPrtParams2(pkts, pktlen, pkttype, ret, NULL);
}

int pgpPrtParamsSubkeys(const uint8_t *pkts, size_t pktlen,
			pgpDigParams mainkey, pgpDigParams **subkeys,
			int *subkeysCount)
{
    rpmpgpRC rc = pgpPrtTransferablePubkeySubkeys(pkts, pktlen, mainkey, subkeys, subkeysCount);
    return rc == RPMPGP_OK ? 0 : -1;
}

rpmRC pgpPubKeyLint(const uint8_t *pkts, size_t pktslen, char **explanation)
{
    pgpDigParams digp = pgpDigParamsNew(PGPTAG_PUBLIC_KEY);
    rpmpgpRC rc = pgpPrtTransferablePubkey(pkts, pktslen, digp);
    if (rc != RPMPGP_OK && explanation)
	pgpAddLint(digp, explanation, rc);
    pgpDigParamsFree(digp);
    return rc == RPMPGP_OK ? RPMRC_OK : RPMRC_FAIL;
}

int pgpPubKeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktslen;
    pgpPkt pkt;

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
    pgpPkt pkt;

    if (pgpDecodePkt(pkts, pktslen, &pkt))
	return -1;
    return pgpGetKeyID(pkt.body, pkt.blen, keyid) == RPMPGP_OK ? 0 : -1;
}

int pgpPubkeyFingerprint(const uint8_t * pkts, size_t pktslen,
                         uint8_t **fp, size_t *fplen)
{
    pgpPkt pkt;

    if (pgpDecodePkt(pkts, pktslen, &pkt))
	return -1;
    return pgpGetKeyFingerprint(pkt.body, pkt.blen, fp, fplen) == RPMPGP_OK ? 0 : -1;
}

rpmRC pgpPubkeyMerge(const uint8_t *pkts1, size_t pkts1len, const uint8_t *pkts2, size_t pkts2len, uint8_t **pktsm, size_t *pktsmlen, int flags)
{
    rpmpgpRC rc = pgpMergeKeys(pkts1, pkts1len, pkts2, pkts2len, pktsm, pktsmlen);
    return rc == RPMPGP_OK ? RPMRC_OK : RPMRC_FAIL;
}

