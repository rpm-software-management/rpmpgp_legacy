/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal_pubkey.c
 * Parse a transferable public key
 */

#include "system.h"

#include "rpmpgp_internal.h"

static rpmpgpRC hashKey(DIGEST_CTX hash, const pgpPkt *pkt, int exptag)
{
    rpmpgpRC rc = RPMPGP_ERROR_INTERNAL;
    if (pkt && pkt->tag == exptag) {
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

static rpmpgpRC hashUserID(DIGEST_CTX hash, const pgpPkt *pkt, int exptag)
{
    rpmpgpRC rc = RPMPGP_ERROR_INTERNAL;
    if (pkt && pkt->tag == exptag) {
	uint8_t head[] = {
	    exptag == PGPTAG_USER_ID ? 0xb4 : 0xd1,
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
			const pgpPkt *mainpkt, const pgpPkt *sectionpkt)
{
    int rc = RPMPGP_ERROR_SELFSIG_VERIFICATION;
    DIGEST_CTX hash = rpmDigestInit(selfsig->hash_algo, 0);

    if (!hash)
	return rc;

    switch (selfsig->sigtype) {
    case PGPSIGTYPE_SUBKEY_BINDING:
    case PGPSIGTYPE_SUBKEY_REVOKE:
    case PGPSIGTYPE_PRIMARY_BINDING:
	rc = hashKey(hash, mainpkt, PGPTAG_PUBLIC_KEY);
	if (rc == RPMPGP_OK)
	    rc = hashKey(hash, sectionpkt, PGPTAG_PUBLIC_SUBKEY);
	break;
    case PGPSIGTYPE_GENERIC_CERT:
    case PGPSIGTYPE_PERSONA_CERT:
    case PGPSIGTYPE_CASUAL_CERT:
    case PGPSIGTYPE_POSITIVE_CERT:
    case PGPSIGTYPE_CERT_REVOKE:
	rc = hashKey(hash, mainpkt, PGPTAG_PUBLIC_KEY);
	if (rc == RPMPGP_OK)
	    rc = hashUserID(hash, sectionpkt, sectionpkt->tag == PGPTAG_PHOTOID ? PGPTAG_PHOTOID : PGPTAG_USER_ID);
	break;
    case PGPSIGTYPE_SIGNED_KEY:
    case PGPSIGTYPE_KEY_REVOKE:
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

static rpmpgpRC verifyPrimaryBindingSig(pgpPkt *mainpkt, pgpPkt *subkeypkt, pgpDigParams subkeydig, pgpDigParams bindsigdig)
{
    pgpDigParams emb_digp = NULL;
    int rc = RPMPGP_ERROR_SELFSIG_VERIFICATION;		/* assume failure */
    if (!bindsigdig || !bindsigdig->embedded_sig)
	return rc;
    emb_digp = pgpDigParamsNew(PGPTAG_SIGNATURE);
    if (pgpPrtSig(PGPTAG_SIGNATURE, bindsigdig->embedded_sig, bindsigdig->embedded_sig_len, emb_digp) == RPMPGP_OK)
	if (emb_digp->sigtype == PGPSIGTYPE_PRIMARY_BINDING)
	    rc = pgpVerifySelf(subkeydig, emb_digp, mainpkt, subkeypkt);
    emb_digp = pgpDigParamsFree(emb_digp);
    return rc;
}

static int is_same_keyid(pgpDigParams digp, pgpDigParams sigdigp)
{
    return (digp->saved & sigdigp->saved & PGPDIG_SAVED_ID) != 0 &&
	memcmp(digp->signid, sigdigp->signid, sizeof(digp->signid)) == 0;
}

/* Parse a complete pubkey with all associated packets */
/* This is similar to gnupg's merge_selfsigs_main() function */
rpmpgpRC pgpPrtTransferablePubkey(const uint8_t * pkts, size_t pktlen, pgpDigParams digp)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgpDigParams sigdigp = NULL;
    pgpDigParams newest_digp = NULL;
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    uint32_t key_expire_sig_time = 0;
    uint32_t key_flags_sig_time = 0;
    pgpPkt mainpkt, sectionpkt;
    int haveselfsig;
    uint32_t now = 0;

    /* parse the main pubkey */
    if (pktlen > RPM_MAX_OPENPGP_BYTES)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    if (pgpDecodePkt(p, (pend - p), &mainpkt) != RPMPGP_OK)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    if (mainpkt.tag != PGPTAG_PUBLIC_KEY)
	return RPMPGP_ERROR_UNEXPECTED_PGP_PACKET;
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    /* Parse the pubkey packet */
    if ((rc = pgpPrtKey(mainpkt.tag, mainpkt.body, mainpkt.blen, digp)) != RPMPGP_OK)
	return rc;
    sectionpkt = mainpkt;
    haveselfsig = 1;
    digp->key_mtime = digp->time;

    rc = RPMPGP_OK;
    while (rc == RPMPGP_OK) {
	pgpPkt pkt;

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

	/* did we end a direct/userid/subkey section? */
	if (p == pend || pkt.tag == PGPTAG_USER_ID || pkt.tag == PGPTAG_PHOTOID || pkt.tag == PGPTAG_PUBLIC_SUBKEY) {
	    /* return an error if there was no self-sig at all */
	    if (!haveselfsig) {
		rc = RPMPGP_ERROR_MISSING_SELFSIG;
		break;
	    }
	    /* take the data from the newest signature */
	    if (newest_digp && (sectionpkt.tag == PGPTAG_USER_ID || sectionpkt.tag == PGPTAG_PUBLIC_KEY) && newest_digp->sigtype != PGPSIGTYPE_CERT_REVOKE) {
		digp->saved |= PGPDIG_SAVED_VALID;	/* we have a valid binding sig */
		if ((newest_digp->saved & PGPDIG_SAVED_KEY_EXPIRE) != 0) {
		    if ((!key_expire_sig_time || newest_digp->time > key_expire_sig_time)) {
			digp->key_expire = newest_digp->key_expire;
			digp->saved |= PGPDIG_SAVED_KEY_EXPIRE;
			key_expire_sig_time = newest_digp->time;
			if (newest_digp->sigtype == PGPSIGTYPE_SIGNED_KEY)
			    key_expire_sig_time = 0xffffffffU;	/* expires from the direct signatures are final */
		    }
		}
		if ((newest_digp->saved & PGPDIG_SAVED_KEY_FLAGS) != 0) {
		    if ((!key_flags_sig_time || newest_digp->time > key_flags_sig_time)) {
			digp->key_flags = newest_digp->key_flags;
			digp->saved |= PGPDIG_SAVED_KEY_FLAGS;
			key_flags_sig_time = newest_digp->time;
			if (newest_digp->sigtype == PGPSIGTYPE_SIGNED_KEY)
			    key_flags_sig_time = 0xffffffffU;	/* key flags from the direct signatures are final */
		    }
		}
		if (sectionpkt.tag == PGPTAG_USER_ID) {
		    if (!digp->userid || ((newest_digp->saved & PGPDIG_SAVED_PRIMARY) != 0 && (digp->saved & PGPDIG_SAVED_PRIMARY) == 0)) {
			if ((rc = pgpPrtUserID(sectionpkt.tag, sectionpkt.body, sectionpkt.blen, digp)) != RPMPGP_OK)
			    break;
			if ((newest_digp->saved & PGPDIG_SAVED_PRIMARY) != 0)
			    digp->saved |= PGPDIG_SAVED_PRIMARY;
		    }
		}
	    }
	    newest_digp = pgpDigParamsFree(newest_digp);
	}

	if (p == pend)
	    break;	/* all packets processed */

	if (pkt.tag == PGPTAG_SIGNATURE) {
	    int isselfsig, needsig = 0;
	    sigdigp = pgpDigParamsNew(pkt.tag);
	    /* use the NoParams variant because we want to ignore non self-sigs */
	    if ((rc = pgpPrtSigNoParams(pkt.tag, pkt.body, pkt.blen, sigdigp)) != RPMPGP_OK)
		break;
	    isselfsig = is_same_keyid(digp, sigdigp);

	    /* check if we understand this signature type and make sure it is in the right section */
	    if (sigdigp->sigtype == PGPSIGTYPE_KEY_REVOKE) {
		/* sections don't matter here */
		needsig = 1;
	    } else if (sigdigp->sigtype == PGPSIGTYPE_SUBKEY_BINDING || sigdigp->sigtype == PGPSIGTYPE_SUBKEY_REVOKE) {
		if (sectionpkt.tag != PGPTAG_PUBLIC_SUBKEY) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = 1;
	    } else if (sigdigp->sigtype == PGPSIGTYPE_SIGNED_KEY) {
		if (sectionpkt.tag != PGPTAG_PUBLIC_KEY) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = isselfsig;
	    } else if (sigdigp->sigtype == PGPSIGTYPE_GENERIC_CERT || sigdigp->sigtype == PGPSIGTYPE_PERSONA_CERT || sigdigp->sigtype == PGPSIGTYPE_CASUAL_CERT || sigdigp->sigtype == PGPSIGTYPE_POSITIVE_CERT || sigdigp->sigtype == PGPSIGTYPE_CERT_REVOKE) {
		if (sectionpkt.tag != PGPTAG_USER_ID && sectionpkt.tag != PGPTAG_PHOTOID) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;		/* signature in wrong section */
		}
		needsig = isselfsig;
		/* note that cert revokations get overwritten by newer certifications (like in gnupg) */
	    }

	    /* verify self signature if we need it */
	    if (needsig) {
		if (!isselfsig) {
		    rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		    break;
		}
		/* add MPIs so we can verify */
	        if ((rc = pgpPrtSigParams(pkt.tag, pkt.body, pkt.blen, sigdigp)) != RPMPGP_OK)
		    break;
		if ((rc = pgpVerifySelf(digp, sigdigp, &mainpkt, &sectionpkt)) != RPMPGP_OK)
		    break;		/* verification failed */
		if (sigdigp->sigtype != PGPSIGTYPE_KEY_REVOKE)
		    haveselfsig = 1;
		if (sigdigp->time > digp->key_mtime)
		    digp->key_mtime = sigdigp->time;
	    }

	    /* check if this signature is expired */
	    if (needsig && (sigdigp->saved & PGPDIG_SAVED_SIG_EXPIRE) != 0 && sigdigp->sig_expire) {
		if (!now)
		    now = pgpCurrentTime();
		if (now < sigdigp->time || sigdigp->sig_expire < now - sigdigp->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle key revokations right away */
	    if (needsig && sigdigp->sigtype == PGPSIGTYPE_KEY_REVOKE) {
		digp->revoked = 1;				/* this is final */
		digp->saved |= PGPDIG_SAVED_VALID;		/* we have at least one correct self-sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_digp || sigdigp->time >= newest_digp->time)) {
		newest_digp = pgpDigParamsFree(newest_digp);
		newest_digp = sigdigp;
		sigdigp = NULL;
	    }
	    sigdigp = pgpDigParamsFree(sigdigp);
	} else if (pkt.tag == PGPTAG_USER_ID || pkt.tag == PGPTAG_PHOTOID) {
	    if (sectionpkt.tag == PGPTAG_PUBLIC_SUBKEY) {
		rc = RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE;
		break;		/* no user id packets after subkeys allowed */
	    }
	    sectionpkt = pkt;
	    haveselfsig = 0;
	} else if (pkt.tag == PGPTAG_PUBLIC_SUBKEY) {
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
    return rc;
}
	
/* Return the subkeys for a pubkey. Note that the code in pgpPrtParamsPubkey() already
 * made sure that the signatures are self-signatures and verified ok. */
/* This is similar to gnupg's merge_selfsigs_subkey() function */
rpmpgpRC pgpPrtTransferablePubkeySubkeys(const uint8_t *pkts, size_t pktlen,
			pgpDigParams mainkey, pgpDigParams **subkeys,
			int *subkeysCount)
{
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgpDigParams *digps = NULL, subdigp = NULL;
    pgpDigParams sigdigp = NULL;
    pgpDigParams newest_digp = NULL;
    rpmpgpRC rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;		/* assume failure */
    int count = 0;
    int alloced = 10;
    pgpPkt mainpkt, subkeypkt, pkt;
    int i;
    uint32_t now = 0;

    if (mainkey->tag != PGPTAG_PUBLIC_KEY || !mainkey->version)
	return RPMPGP_ERROR_INTERNAL;	/* main key must be a parsed pubkey */

    if (pktlen > RPM_MAX_OPENPGP_BYTES)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    if (pgpDecodePkt(p, (pend - p), &mainpkt) != RPMPGP_OK)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    if (mainpkt.tag != PGPTAG_PUBLIC_KEY)
	return RPMPGP_ERROR_UNEXPECTED_PGP_PACKET;
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    memset(&subkeypkt, 0, sizeof(subkeypkt));

    digps = xmalloc(alloced * sizeof(*digps));
    rc = RPMPGP_OK;
    while (rc == RPMPGP_OK) {
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

	/* finish up this subkey if we are at the end or a new one comes next */
	if (p == pend || pkt.tag == PGPTAG_PUBLIC_SUBKEY) {
	    /* take the data from the newest signature */
	    if (newest_digp && subdigp && newest_digp->sigtype == PGPSIGTYPE_SUBKEY_BINDING) {
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
	    int needsig = 0;
	    sigdigp = pgpDigParamsNew(pkt.tag);
	    /* we use the NoParams variant because we do not verify */
	    if (pgpPrtSigNoParams(pkt.tag, pkt.body, pkt.blen, sigdigp) != RPMPGP_OK) {
		sigdigp = pgpDigParamsFree(sigdigp);
	    }

	    /* check if we understand this signature */
	    if (sigdigp && sigdigp->sigtype == PGPSIGTYPE_SUBKEY_REVOKE) {
		needsig = 1;
	    } else if (sigdigp && sigdigp->sigtype == PGPSIGTYPE_SUBKEY_BINDING) {
		/* insist on a embedded primary key binding signature if this is used for signing */
		int key_flags = (sigdigp->saved & PGPDIG_SAVED_KEY_FLAGS) ? sigdigp->key_flags : 0;
		if (!(key_flags & 0x02) || verifyPrimaryBindingSig(&mainpkt, &subkeypkt, subdigp, sigdigp) == RPMPGP_OK)
		    needsig = 1;
	    }

	    /* check if this signature is expired */
	    if (needsig && (sigdigp->saved & PGPDIG_SAVED_SIG_EXPIRE) != 0 && sigdigp->sig_expire) {
		if (!now)
		    now = pgpCurrentTime();
		if (now < sigdigp->time || sigdigp->sig_expire < now - sigdigp->time)
		    needsig = 0;	/* signature is expired, ignore */
	    }

	    /* handle subkey revokations right away */
	    if (needsig && sigdigp->sigtype == PGPSIGTYPE_SUBKEY_REVOKE) {
		if (subdigp->revoked != 2)
		    subdigp->revoked = 1;
		subdigp->saved |= PGPDIG_SAVED_VALID;	/* at least one binding sig */
		needsig = 0;
	    }

	    /* find the newest self-sig for all the other types */
	    if (needsig && (!newest_digp || sigdigp->time >= newest_digp->time)) {
		newest_digp = pgpDigParamsFree(newest_digp);
		newest_digp = sigdigp;
		sigdigp = NULL;
	    }
	    sigdigp = pgpDigParamsFree(sigdigp);
	}
    }
    if (rc == RPMPGP_OK && p != pend)
	rc = RPMPGP_ERROR_INTERNAL;
    sigdigp = pgpDigParamsFree(sigdigp);
    newest_digp = pgpDigParamsFree(newest_digp);

    if (rc == RPMPGP_OK) {
	*subkeys = xrealloc(digps, count * sizeof(*digps));
	*subkeysCount = count;
    } else {
	for (i = 0; i < count; i++)
	    pgpDigParamsFree(digps[i]);
	free(digps);
    }
    return rc;
}

