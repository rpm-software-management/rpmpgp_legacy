/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal_dig.c
 * Accessor functions for pgpDigParams
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

rpmRC pgpVerifySignature2(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx, char **lints)
{
    rpmRC res;
    if (lints)
        *lints = NULL;
    
    res = pgpVerifySignatureRaw(key, sig, hashctx) == RPMPGP_OK ? RPMRC_OK : RPMRC_FAIL;
    if (res != RPMRC_OK)
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

