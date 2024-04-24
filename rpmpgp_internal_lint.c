/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal_line.c
 *
 * Error reporting functions
 */

#include "system.h"

#include <time.h>

#include "rpmpgp_internal.h"

void pgpAddErrorLint(pgpDigParams digp, char **lints, rpmpgpRC error)
{
    const char *msg = NULL;
    if (error == RPMPGP_OK || !lints)
	return;
    if (digp) {
	switch (error) {
	case RPMPGP_ERROR_UNSUPPORTED_VERSION:
	    if (digp->tag == PGPTAG_PUBLIC_KEY || digp->tag == PGPTAG_PUBLIC_SUBKEY)
		rasprintf(lints, "Unsupported pubkey version (V%d)", digp->version);
	    else if (digp->tag == PGPTAG_SIGNATURE)
		rasprintf(lints, "Unsupported signature version (V%d)", digp->version);
	    else
		rasprintf(lints, "Unsupported packet version (V%d)", digp->version);
	    return;
	case RPMPGP_ERROR_UNSUPPORTED_ALGORITHM:
	    rasprintf(lints, "Unsupported algorithm (%d)", digp->pubkey_algo);
	    return;
	default:
	    break;
	}
    }
    switch (error) {
    case RPMPGP_ERROR_INTERNAL:
	msg = "Internal PGP parser error";
	break;
    case RPMPGP_ERROR_CORRUPT_PGP_PACKET:
	msg = "Corrupt PGP packet";
	break;
    case RPMPGP_ERROR_UNEXPECTED_PGP_PACKET:
	msg = "Unexpected PGP packet";
	break;
    case RPMPGP_ERROR_NO_CREATION_TIME:
	msg = "Signature without creation time";
	break;
    case RPMPGP_ERROR_DUPLICATE_DATA:
	msg = "Duplicate data in signature";
	break;
    case RPMPGP_ERROR_UNKNOWN_CRITICAL_PKT:
	msg = "Unknown critical packet in signature";
	break;
    case RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE:
	msg = "Bad pubkey structure";
	break;
    case RPMPGP_ERROR_SELFSIG_VERIFICATION:
	msg = "Pubkey self-signature verification failure";
	break;
    case RPMPGP_ERROR_MISSING_SELFSIG:
	msg = "Pubkey misses a self-signature";
	break;
    case RPMPGP_ERROR_UNSUPPORTED_VERSION:
	msg = "Unsupported packet version";
	break;
    case RPMPGP_ERROR_UNSUPPORTED_ALGORITHM:
	msg = "Unsupported pubkey algorithm";
	break;
    case RPMPGP_ERROR_UNSUPPORTED_CURVE:
	msg = "Unsupported pubkey curve";
	break;
    case RPMPGP_ERROR_SIGNATURE_VERIFICATION:
	msg = "Signature verification failure";
	break;
    case RPMPGP_ERROR_BAD_PUBKEY:
	msg = "Pubkey was not accepted by crypto backend";
	break;
    case RPMPGP_ERROR_BAD_SIGNATURE:
	msg = "Signature was not accepted by crypto backend";
	break;
    default:
	rasprintf(lints, "Unknown error (%d)", error);
	return;
    }
    *lints = xstrdup(msg);
}

static char *format_keyid(pgpKeyID_t keyid, char *userid)
{
    char *keyidstr = rpmhex(keyid, sizeof(pgpKeyID_t));
    if (!userid) {
	return keyidstr;
    } else {
	char *ret = NULL;
	rasprintf(&ret, "%s (%s)", keyidstr, userid);
	free(keyidstr);
	return ret;
    }
}

static char *format_time(time_t *t)
{
    char dbuf[BUFSIZ];
    struct tm _tm, *tms;
    char *ret = NULL;

    tms = localtime_r(t, &_tm);
    if (!(tms && strftime(dbuf, sizeof(dbuf), "%Y-%m-%d %H:%M:%S", tms) > 0)) {
	rasprintf(&ret, "Invalid date (%lld)", (long long int)t);
    } else {
	ret = xstrdup(dbuf);
    }
    return ret;
}

void pgpAddKeyLint(pgpDigParams key, char **lints, const char *msg)
{
    char *keyid = format_keyid(key->signid, key->tag == PGPTAG_PUBLIC_SUBKEY ? NULL : key->userid);
    char *main_keyid = key->tag == PGPTAG_PUBLIC_SUBKEY ? format_keyid(key->mainid, key->userid) : NULL;
    *lints = NULL;
    if (key->tag == PGPTAG_PUBLIC_SUBKEY) {
	/* special case the message about subkeys with a revoked primary key */
	if (key->revoked == 2)
	    rasprintf(lints, "Key %s is a subkey of key %s, which has been revoked", keyid, main_keyid);
	else
	    rasprintf(lints, "Subkey %s of key %s %s", keyid, main_keyid, msg);
    } else {
	rasprintf(lints, "Key %s %s", keyid, msg);
    }
    free(keyid);
    free(main_keyid);
}

void pgpAddSigLint(pgpDigParams sig, char **lints, const char *msg)
{
    *lints = NULL;
    rasprintf(lints, "Signature %s", msg);
}

static char *format_expired(uint32_t created, uint32_t expire)
{
    time_t exptime = (time_t)created + expire;
    char *expdate = format_time(&exptime);
    char *msg = NULL;
    rasprintf(&msg, "expired on %s", expdate);
    free(expdate);
    return msg;
}

void pgpAddKeyExpiredLint(pgpDigParams key, char **lints)
{
    char *msg = format_expired(key->time, key->key_expire);
    pgpAddKeyLint(key, lints, msg);
    free(msg);
}

void pgpAddSigExpiredLint(pgpDigParams sig, char **lints)
{
    char *msg = format_expired(sig->time, sig->sig_expire);
    pgpAddSigLint(sig, lints, msg);
    free(msg);
}

