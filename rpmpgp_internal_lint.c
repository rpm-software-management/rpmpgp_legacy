/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal_line.c
 *
 * Error reporting functions
 */

#include "system.h"

#include <time.h>

#include "rpmpgp_internal.h"

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

static void pgpAddKeyLint(pgpDigParams key, char **lints, const char *msg)
{
    char *keyid = format_keyid(key->signid, key->tag == PGPTAG_PUBLIC_SUBKEY ? NULL : key->userid);
    char *main_keyid = key->tag == PGPTAG_PUBLIC_SUBKEY ? format_keyid(key->mainid, key->userid) : NULL;
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

static void pgpAddSigLint(pgpDigParams sig, char **lints, const char *msg)
{
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

void pgpAddLint(pgpDigParams digp, char **lints, rpmpgpRC error)
{
    const char *msg = NULL;
    char *exp_msg;
    if (error == RPMPGP_OK || !lints)
	return;
    *lints = NULL;

    /* if we have suitable DigParams we can make a better error message */
    if (digp && (digp->tag == PGPTAG_PUBLIC_KEY || digp->tag == PGPTAG_PUBLIC_SUBKEY)) {
	switch (error) {
	case RPMPGP_ERROR_UNSUPPORTED_VERSION:
	    rasprintf(lints, "Unsupported pubkey version (V%d)", digp->version);
	    return;
	case RPMPGP_ERROR_KEY_EXPIRED:
	    exp_msg = format_expired(digp->time, digp->key_expire);
	    pgpAddKeyLint(digp, lints, exp_msg);
	    free(exp_msg);
	    return;
	case RPMPGP_ERROR_KEY_REVOKED:
	case RPMPGP_ERROR_PRIMARY_REVOKED:
	    pgpAddKeyLint(digp, lints, "has been revoked");
	    return;
	case RPMPGP_ERROR_KEY_NOT_VALID:
	    pgpAddKeyLint(digp, lints, "has no valid binding signature");
	    return;
	case RPMPGP_ERROR_KEY_NO_SIGNING:
	    pgpAddKeyLint(digp, lints, "is not suitable for signing");
	    return;
	case RPMPGP_ERROR_KEY_CREATED_AFTER_SIG:
	    pgpAddKeyLint(digp, lints, "has been created after the signature");
	    return;
	default:
	    break;
	}
    }
    if (digp && digp->tag == PGPTAG_SIGNATURE) {
	switch (error) {
	case RPMPGP_ERROR_UNSUPPORTED_VERSION:
	    rasprintf(lints, "Unsupported signature version (V%d)", digp->version);
	    return;
	case RPMPGP_ERROR_SIGNATURE_EXPIRED:
	    exp_msg = format_expired(digp->time, digp->sig_expire);
	    pgpAddSigLint(digp, lints, exp_msg);
	    free(exp_msg);
	    return;
	default:
	    break;
	}
    }
    if (digp) {
	switch (error) {
	case RPMPGP_ERROR_UNSUPPORTED_VERSION:
	    rasprintf(lints, "Unsupported packet version (V%d)", digp->version);
	    return;
	case RPMPGP_ERROR_UNSUPPORTED_ALGORITHM:
	    rasprintf(lints, "Unsupported pubkey algorithm (%d)", digp->pubkey_algo);
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
    case RPMPGP_ERROR_BAD_PUBKEY:
	msg = "Pubkey was not accepted by crypto backend";
	break;
    case RPMPGP_ERROR_BAD_SIGNATURE:
	msg = "Signature was not accepted by crypto backend";
	break;
    case RPMPGP_ERROR_SIGNATURE_VERIFICATION:
	msg = "Signature verification failure";
	break;
    case RPMPGP_ERROR_SIGNATURE_FROM_FUTURE:
	msg = "Signature was created in the future";
	break;
    case RPMPGP_ERROR_SIGNATURE_EXPIRED:
	msg = "Signature has expired";
	break;
    case RPMPGP_ERROR_KEY_EXPIRED:
	msg = "Key has expired";
	break;
    case RPMPGP_ERROR_KEY_REVOKED:
	msg = "Key has been revoked";
	break;
    case RPMPGP_ERROR_PRIMARY_REVOKED:
	msg = "Primary key has been revoked";
	break;
    case RPMPGP_ERROR_KEY_NOT_VALID:
	msg = "Key has no valid binding signature";
	break;
    case RPMPGP_ERROR_KEY_NO_SIGNING:
	msg = "Key is not suitable for signing";
	break;
    case RPMPGP_ERROR_KEY_CREATED_AFTER_SIG:
	msg = "Key has been created after the signature";
	break;
    default:
	rasprintf(lints, "Unknown error (%d)", error);
	return;
    }
    *lints = xstrdup(msg);
}

