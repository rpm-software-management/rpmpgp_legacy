/** \ingroup rpmio signature
 * \file rpmio/rpmpgp_internal_merge.c
 *
 * Public Key merging
 */

#include "system.h"

#include "rpmpgp_internal.h"


typedef struct pgpMergePkt_s {
    pgpPkt pkt;
    int source;

    /* signature data */
    pgpKeyID_t signid;
    uint32_t time;
    int selfsig;

    size_t hashlen;
    uint32_t hash;
    struct pgpMergePkt_s *next_hash;

    uint32_t section;
    uint32_t subsection;
    struct pgpMergePkt_s *next;
    struct pgpMergePkt_s *sub;
} pgpMergePkt;


#define PGP_NUMSECTIONS 3

typedef struct pgpMergeKey_s {
    pgpMergePkt *hash[512];
    pgpMergePkt *sections[PGP_NUMSECTIONS];
} pgpMergeKey;


/*
 *  PGP Packet plus merge information
 */

static inline uint32_t simplehash(uint32_t h, const uint8_t *data, size_t len)
{
    while (len--)
	h = (h << 3) + *data++;
    return h;
}

static uint32_t pgpMergePktCalcHash(pgpMergePkt *mp)
{
    uint32_t hash = simplehash(mp->pkt.tag, mp->pkt.body, mp->hashlen);
    if (mp->pkt.tag == PGPTAG_SIGNATURE)
	hash = simplehash(hash, mp->signid, sizeof(pgpKeyID_t));
    return hash;
}

static int pgpMergePktIdentical(pgpMergePkt *mp1, pgpMergePkt *mp2)
{
    if (mp1->pkt.tag != mp2->pkt.tag)
	return 0;
    if (mp1->hashlen != mp2->hashlen)
	return 0;
    if (memcmp(mp1->pkt.body, mp2->pkt.body, mp1->hashlen) != 0)
	return 0;
    if (mp1->pkt.tag == PGPTAG_SIGNATURE && memcmp(mp1->signid, mp2->signid, sizeof(pgpKeyID_t)) != 0)
	return 0;
    return 1;
}

static rpmpgpRC pgpMergePktNew(pgpPkt *pkt, int source, pgpKeyID_t primaryid, pgpMergePkt **mpptr) {
    rpmpgpRC rc = RPMPGP_OK;
    pgpMergePkt *mp = xcalloc(1, sizeof(pgpMergePkt));

    mp->pkt = *pkt;
    mp->source = source;
    mp->hashlen = pkt->blen;
    if (pkt->tag == PGPTAG_SIGNATURE) {
        pgpDigParams sigdigp = pgpDigParamsNew(pkt->tag);
	rc = pgpPrtSigNoParams(pkt->tag, pkt->body, pkt->blen, sigdigp);
	if (rc == RPMPGP_OK) {
	    mp->time = sigdigp->time;
	    memcpy(mp->signid, sigdigp->signid, sizeof(pgpKeyID_t));
	    if (primaryid && memcmp(primaryid, mp->signid, sizeof(pgpKeyID_t)) == 0)
		mp->selfsig = 1;
	    if (sigdigp->version > 3)
		mp->hashlen = sigdigp->hashlen;
	}
	pgpDigParamsFree(sigdigp);
    }
    mp->hash = pgpMergePktCalcHash(mp);
    if (rc != RPMPGP_OK)
	free(mp);
    else
	*mpptr = mp;
    return rc;
}

static pgpMergePkt *pgpMergePktFree(pgpMergePkt *mp)
{
    free(mp);
    return NULL;
}


/*
 *  Pubkey data handling
 */

static pgpMergeKey *pgpMergeKeyNew(void) {
    pgpMergeKey *mk = xcalloc(1, sizeof(pgpMergeKey));
    return mk;
}

static pgpMergeKey *pgpMergeKeyFree(pgpMergeKey *mk) {
    if (mk) {
	pgpMergePkt *mp, *smp;
	int i;
	for (i = 0; i < PGP_NUMSECTIONS; i++) {
	    for (mp = mk->sections[i]; mp; mp = mp->next) {
		for (smp = mp->sub; smp; smp = smp->next)
		    pgpMergePktFree(smp);
		pgpMergePktFree(mp);
	    }
	}
    }
    return NULL;
}

static int pgpMergeKeyMaxSource(pgpMergeKey *mk) {
    pgpMergePkt *mp, *smp;
    int i, max = 0;
    for (i = 0; i < PGP_NUMSECTIONS; i++) {
	for (mp = mk->sections[i]; mp; mp = mp->next) {
	    if (mp->source > max)
		max = mp->source;
	    for (smp = mp->sub; smp; smp = smp->next)
		if (smp->source > max)
		    max = smp->source;
	}
    }
    return max;
}


static pgpMergePkt *pgpMergeKeyHashFind(pgpMergeKey *mk, pgpMergePkt *mp, int checksubsection) {
    int hh = mp->hash % (sizeof(mk->hash) / sizeof(*mk->hash));
    pgpMergePkt *h = mk->hash[hh];
    for (; h; h = h->next_hash)
	if (pgpMergePktIdentical(h, mp) && h->section == mp->section && (!checksubsection || h->subsection == mp->subsection))
	    break;
    return h;
}

static void pgpMergeKeyHashAdd(pgpMergeKey *mk, pgpMergePkt *mp) {
    int hh = mp->hash % (sizeof(mk->hash) / sizeof(*mk->hash));
    mp->next_hash = mk->hash[hh];
    mk->hash[hh] = mp;
}

static void pgpMergeKeySectionAdd(pgpMergeKey *mk, pgpMergePkt *mp) {
    pgpMergePkt **mpp = mk->sections + mp->section;
    mp->subsection = 0;
    while (*mpp) {
	mpp = &(*mpp)->next;
	mp->subsection++;
    }
    *mpp = mp;
}

static void pgpMergeKeySubAddSig(pgpMergePkt *mp_section, pgpMergePkt *mp) {
    pgpMergePkt *lastsig = NULL, **mpp, *mp2;
    for (mpp = &mp_section->sub; (mp2 = *mpp) != NULL; mpp = &mp2->next) {
	if (mp2->pkt.tag == PGPTAG_SIGNATURE && mp2->selfsig == mp->selfsig) {
	    if (mp->time >= mp2->time)
		break;
	    lastsig = mp2;
	}
    }
    if (!*mpp) {
	if (lastsig) {
	    /* all the matched signatures are newer than us. put us right behind the last one */
	    mpp = &lastsig->next;
	} else if (mp->selfsig) {
	    /* first selfsig. add to front */
	    mpp = &mp_section->sub;
	}
    }
    mp->next = *mpp;
    *mpp = mp;
}

static void pgpMergeKeySubAdd(pgpMergePkt *mp_section, pgpMergePkt *mp) {
    /* signatures are ordered by creation time, everything else goes to the end */
    /* (we only change the order of new packets, i.e. where source is not zero) */
    if (mp->pkt.tag == PGPTAG_SIGNATURE && mp->source != 0) {
	pgpMergeKeySubAddSig(mp_section, mp);
    } else {
	pgpMergePkt **mpp;
	for (mpp = &mp_section->sub; *mpp; mpp = &(*mpp)->next)
	    ;
	*mpp = mp;
    }
}

static rpmpgpRC pgpMergeKeyAddPubkey(pgpMergeKey *mk, int source, const uint8_t * pkts, size_t pktlen) {
    rpmpgpRC rc;
    const uint8_t *p = pkts;
    const uint8_t *pend = pkts + pktlen;
    pgpPkt pkt;
    pgpKeyID_t mainkeyid;
    pgpMergePkt *mp_section = NULL;
    pgpMergePkt *mp, *omp;

    if (pgpDecodePkt(p, (pend - p), &pkt) != RPMPGP_OK)
	return RPMPGP_ERROR_CORRUPT_PGP_PACKET;
    if (pkt.tag != PGPTAG_PUBLIC_KEY)
	return RPMPGP_ERROR_UNEXPECTED_PGP_PACKET;
    if ((rc = pgpGetKeyID(pkt.body, pkt.blen, mainkeyid)) != RPMPGP_OK)
	return rc;
    if ((rc = pgpMergePktNew(&pkt, source, mainkeyid, &mp)) != RPMPGP_OK)
	return rc;
    if (mk->sections[0]) {
	if (!pgpMergePktIdentical(mk->sections[0], mp)) {
	    pgpMergePktFree(mp);
	    return RPMPGP_ERROR_INTERNAL;
	}
	pgpMergePktFree(mp);
    } else {
	mk->sections[0] = mp;
	pgpMergeKeyHashAdd(mk, mp);
    }
    p += (pkt.body - pkt.head) + pkt.blen;

    mp_section = mk->sections[0];
    while (p < pend) {
	if (pgpDecodePkt(p, (pend - p), &pkt) != RPMPGP_OK) {
	    rc = RPMPGP_ERROR_CORRUPT_PGP_PACKET;
	    break;
	}
	if (pkt.tag == PGPTAG_PUBLIC_KEY || pkt.tag == PGPTAG_SECRET_KEY) {
	    rc = RPMPGP_ERROR_UNEXPECTED_PGP_PACKET;
	    break;
	}
	if ((rc = pgpMergePktNew(&pkt, source, mainkeyid, &mp)) != RPMPGP_OK)
	    break;
	if (pkt.tag == PGPTAG_USER_ID || pkt.tag == PGPTAG_PHOTOID || pkt.tag == PGPTAG_PUBLIC_SUBKEY) {
	    mp->section = pkt.tag == PGPTAG_PUBLIC_SUBKEY ? 2 : 1;
	    mp->subsection = -1;
	    omp = pgpMergeKeyHashFind(mk, mp, 0);
	    if (omp) {
		pgpMergePktFree(mp);
		mp_section = omp;
	    } else {
		pgpMergeKeySectionAdd(mk, mp);
		pgpMergeKeyHashAdd(mk, mp);
		mp_section = mp;
	    }
	} else {
	    mp->section = mp_section->section;
	    mp->subsection = mp_section->subsection;
	    omp = pgpMergeKeyHashFind(mk, mp, 1);
	    if (omp) {
		pgpMergePktFree(mp);
	    } else {
		pgpMergeKeySubAdd(mp_section, mp);
		pgpMergeKeyHashAdd(mk, mp);
	    }
	}
	p += (pkt.body - pkt.head) + pkt.blen;
    }
    if (rc == RPMPGP_OK && p != pend)
	rc = RPMPGP_ERROR_INTERNAL;
    return rc;
}

static rpmpgpRC pgpMergeKeyConcat(pgpMergeKey *mk, uint8_t **pktsm, size_t *pktlenm)
{
    pgpMergePkt *mp, *smp;
    int i;
    uint8_t *pkts, *p;
    size_t len = 0;

    for (i = 0; i < PGP_NUMSECTIONS; i++) {
	for (mp = mk->sections[i]; mp; mp = mp->next) {
	    len += (mp->pkt.body - mp->pkt.head) + mp->pkt.blen;
	    for (smp = mp->sub; smp; smp = smp->next)
		len += (smp->pkt.body - smp->pkt.head) + smp->pkt.blen;
	}
    }
    p = pkts = xmalloc(len);
    for (i = 0; i < PGP_NUMSECTIONS; i++) {
	for (mp = mk->sections[i]; mp; mp = mp->next) {
	    memcpy(p, mp->pkt.head, (mp->pkt.body - mp->pkt.head) + mp->pkt.blen);
	    p += (mp->pkt.body - mp->pkt.head) + mp->pkt.blen;
	    for (smp = mp->sub; smp; smp = smp->next) {
		memcpy(p, smp->pkt.head, (smp->pkt.body - smp->pkt.head) + smp->pkt.blen);
		p += (smp->pkt.body - smp->pkt.head) + smp->pkt.blen;
	    }
	}
    }
    *pktsm = pkts;
    *pktlenm = len;
    return RPMPGP_OK;
}

rpmpgpRC pgpMergeKeys(const uint8_t *pkts1, size_t pktlen1, const uint8_t *pkts2, size_t pktlen2, uint8_t **pktsm, size_t *pktlenm) {
    rpmpgpRC rc;
    pgpMergeKey *mk = pgpMergeKeyNew();

    if (pkts1 != NULL && (rc = pgpMergeKeyAddPubkey(mk, 0, pkts1, pktlen1)) != RPMPGP_OK)
	goto exit;
    if ((rc = pgpMergeKeyAddPubkey(mk, 1, pkts2, pktlen2)) != RPMPGP_OK)
	goto exit;
    if (pgpMergeKeyMaxSource(mk) == 0) {
	/* no new key material, return old key */
	*pktsm = memcpy(xmalloc(pktlen1), pkts1, pktlen1);
	*pktlenm = pktlen1;
    } else {
	rc = pgpMergeKeyConcat(mk, pktsm, pktlenm);
    }
exit:
    pgpMergeKeyFree(mk);
    return rc;
}

