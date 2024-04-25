/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal_pubkey.c
 * Pubkey parsing functions
 */

#include "system.h"

#include "rpmpgp_internal.h"

static rpmpgpRC hashKey(DIGEST_CTX hash, const pgpPkt *pkt, int exptag)
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

static rpmpgpRC hashUserID(DIGEST_CTX hash, const pgpPkt *pkt)
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
			const pgpPkt *mainpkt, const pgpPkt *sectionpkt)
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

static rpmpgpRC verifyPrimaryBindingSig(pgpPkt *mainpkt, pgpPkt *subkeypkt, pgpDigParams subkeydig, pgpDigParams bindsigdig)
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

static int is_same_keyid(pgpDigParams digp, pgpDigParams sigdigp)
{
    return (digp->saved & sigdigp->saved & PGPDIG_SAVED_ID) != 0 &&
	memcmp(digp->signid, sigdigp->signid, sizeof(digp->signid)) == 0;
}

/* Parse a complete pubkey with all associated packets */
/* This is similar to gnupg's merge_selfsigs_main() function */
int pgpPrtParamsPubkey(const uint8_t * pkts, size_t pktlen, pgpDigParams * ret,
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
    pgpPkt mainpkt, sectionpkt;
    int haveselfsig;
    uint32_t now = 0;

    if (lints)
	*lints = NULL;

    /* parse the main pubkey */
    if (pktlen > RPM_MAX_OPENPGP_BYTES || pgpDecodePkt(p, (pend - p), &mainpkt)) {
	pgpAddLint(NULL, lints, RPMPGP_ERROR_CORRUPT_PGP_PACKET);
	return -1;
    }
    if (mainpkt.tag != PGPTAG_PUBLIC_KEY) {
	pgpAddLint(NULL, lints, RPMPGP_ERROR_UNEXPECTED_PGP_PACKET);
	return -1;	/* pubkey packet must come first */
    }
    p += (mainpkt.body - mainpkt.head) + mainpkt.blen;

    /* create dig for the main pubkey and parse the pubkey packet */
    digp = pgpDigParamsNew(mainpkt.tag);
    if ((rc = pgpPrtKey(mainpkt.tag, mainpkt.body, mainpkt.blen, digp)) != RPMPGP_OK) {
	if (lints)
	    pgpAddLint(digp, lints, rc);
	pgpDigParamsFree(digp);
	return -1;
    }

    useridpkt = subkeypkt = 0;		/* type of the section packet */
    memset(&sectionpkt, 0, sizeof(sectionpkt));
    haveselfsig = 1;

    rc = RPMPGP_OK;
    while (rc == RPMPGP_OK) {
	pgpPkt pkt;
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
		    if ((rc = pgpPrtUserID(sectionpkt.tag, sectionpkt.body, sectionpkt.blen, digp)) != RPMPGP_OK)
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
	    pgpAddLint(digp, lints, rc);
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
    pgpPkt mainpkt, subkeypkt, pkt;
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

