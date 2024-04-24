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

