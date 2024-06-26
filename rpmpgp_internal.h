#ifndef _RPMPGP_INTERNAL_H
#define _RPMPGP_INTERNAL_H

#include <rpm/rpmpgp.h>

/* max number of bytes in a key */
#define RPM_MAX_OPENPGP_BYTES (65535)

typedef enum rpmpgpRC_e {
    RPMPGP_OK				= 0,
    RPMPGP_ERROR_INTERNAL		= 10,
    RPMPGP_ERROR_CORRUPT_PGP_PACKET	= 11,
    RPMPGP_ERROR_UNEXPECTED_PGP_PACKET	= 12,
    RPMPGP_ERROR_UNSUPPORTED_VERSION	= 13,
    RPMPGP_ERROR_UNSUPPORTED_ALGORITHM	= 14,
    RPMPGP_ERROR_UNSUPPORTED_CURVE	= 15,
    RPMPGP_ERROR_NO_CREATION_TIME	= 16,
    RPMPGP_ERROR_DUPLICATE_DATA		= 17,
    RPMPGP_ERROR_UNKNOWN_CRITICAL_PKT	= 18,
    RPMPGP_ERROR_BAD_PUBKEY_STRUCTURE	= 19,
    RPMPGP_ERROR_MISSING_SELFSIG	= 20,
    RPMPGP_ERROR_SELFSIG_VERIFICATION	= 21,
    RPMPGP_ERROR_SIGNATURE_VERIFICATION	= 22,
    RPMPGP_ERROR_BAD_PUBKEY		= 23,
    RPMPGP_ERROR_BAD_SIGNATURE		= 24,
    RPMPGP_ERROR_SIGNATURE_FROM_FUTURE  = 25,
    RPMPGP_ERROR_SIGNATURE_EXPIRED	= 26,
    RPMPGP_ERROR_KEY_EXPIRED		= 27,
    RPMPGP_ERROR_KEY_REVOKED		= 28,
    RPMPGP_ERROR_PRIMARY_REVOKED	= 29,
    RPMPGP_ERROR_KEY_NOT_VALID		= 30,
    RPMPGP_ERROR_KEY_NO_SIGNING		= 31,
    RPMPGP_ERROR_KEY_CREATED_AFTER_SIG	= 32
} rpmpgpRC;

typedef struct pgpDigAlg_s * pgpDigAlg;

typedef rpmpgpRC (*setmpifunc)(pgpDigAlg digp, int num, const uint8_t *p, int mlen);
typedef rpmpgpRC (*verifyfunc)(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                          uint8_t *hash, size_t hashlen, int hash_algo);
typedef void (*freefunc)(pgpDigAlg digp);

struct pgpDigAlg_s {
    setmpifunc setmpi;
    verifyfunc verify;
    freefunc free;
    int curve;
    int mpis;
    void *data;			/*!< algorithm specific private data */
};

/*
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
    uint32_t sig_expire;	/*!< signature expire time. */
    int revoked;		/*!< is the key revoked? */
    uint8_t saved;		/*!< Various flags. */
#define	PGPDIG_SAVED_TIME	(1 << 0)
#define	PGPDIG_SAVED_ID		(1 << 1)
#define	PGPDIG_SAVED_KEY_FLAGS	(1 << 2)
#define	PGPDIG_SAVED_KEY_EXPIRE	(1 << 3)
#define	PGPDIG_SAVED_PRIMARY	(1 << 4)
#define	PGPDIG_SAVED_VALID	(1 << 5)
#define	PGPDIG_SAVED_SIG_EXPIRE	(1 << 6)
    uint8_t * embedded_sig;	/* embedded signature */
    size_t embedded_sig_len;	/* length of the embedded signature */
    pgpKeyID_t mainid;		/* key id of main key if this is a subkey */
    uint32_t key_mtime;		/* last modification time */

    size_t mpi_offset;		/* start of mpi data */
    pgpDigAlg alg;		/*!< algorithm specific data like MPIs */
};

/*
 * decoded PGP packet
 */
typedef struct pgpPkt_s {
    uint8_t tag;		/* decoded PGP tag */
    const uint8_t *head;	/* pointer to start of packet (header) */
    const uint8_t *body;	/* pointer to packet body */
    size_t blen;		/* length of body in bytes */
} pgpPkt;


/* pgp packet decoding */
RPM_GNUC_INTERNAL
rpmpgpRC pgpDecodePkt(const uint8_t *p, size_t plen, pgpPkt *pkt);


/* allocation */
RPM_GNUC_INTERNAL
pgpDigParams pgpDigParamsNew(uint8_t tag);

RPM_GNUC_INTERNAL
pgpDigAlg pgpDigAlgFree(pgpDigAlg alg);

RPM_GNUC_INTERNAL
void pgpDigAlgInitPubkey(pgpDigAlg alg, int algo, int curve);

RPM_GNUC_INTERNAL
void pgpDigAlgInitSignature(pgpDigAlg alg, int algo);

/* pgp packet data extraction */
RPM_GNUC_INTERNAL
rpmpgpRC pgpPrtKey(pgpTag tag, const uint8_t *h, size_t hlen, pgpDigParams _digp);

RPM_GNUC_INTERNAL
rpmpgpRC pgpPrtSig(pgpTag tag, const uint8_t *h, size_t hlen, pgpDigParams _digp);

RPM_GNUC_INTERNAL
rpmpgpRC pgpPrtSigNoParams(pgpTag tag, const uint8_t *h, size_t hlen, pgpDigParams _digp);

RPM_GNUC_INTERNAL
rpmpgpRC pgpPrtSigParams(pgpTag tag, const uint8_t *h, size_t hlen, pgpDigParams sigp);

RPM_GNUC_INTERNAL
rpmpgpRC pgpPrtUserID(pgpTag tag, const uint8_t *h, size_t hlen, pgpDigParams _digp);

RPM_GNUC_INTERNAL
rpmpgpRC pgpGetKeyFingerprint(const uint8_t *h, size_t hlen, uint8_t **fp, size_t *fplen);

RPM_GNUC_INTERNAL
rpmpgpRC pgpGetKeyID(const uint8_t *h, size_t hlen, pgpKeyID_t keyid);


/* diagnostics */
RPM_GNUC_INTERNAL
void pgpAddLint(pgpDigParams digp, char **lints, rpmpgpRC error);

/* transferable pubkey parsing */
RPM_GNUC_INTERNAL
rpmpgpRC pgpPrtTransferablePubkey(const uint8_t * pkts, size_t pktlen, pgpDigParams digp);

RPM_GNUC_INTERNAL
rpmpgpRC pgpPrtTransferablePubkeySubkeys(const uint8_t * pkts, size_t pktlen, pgpDigParams mainkey,
				   pgpDigParams **subkeys, int *subkeysCount);

/* signature verification */
RPM_GNUC_INTERNAL
rpmpgpRC pgpVerifySignatureRaw(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx);

/* pubkey merging */
RPM_GNUC_INTERNAL
rpmpgpRC pgpMergeKeys(const uint8_t *pkts1, size_t pktlen1, const uint8_t *pkts2, size_t pktlen2, uint8_t **pktsm, size_t *pktlenm);

/* misc */
RPM_GNUC_INTERNAL
uint32_t pgpCurrentTime(void);

RPM_GNUC_INTERNAL
uint32_t pgpDigParamsModificationTime(pgpDigParams digp);

#endif /* _RPMPGP_INTERNAL_H */
