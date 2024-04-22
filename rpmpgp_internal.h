#ifndef _RPMPGP_INTERNAL_H
#define _RPMPGP_INTERNAL_H

#include <rpm/rpmpgp.h>

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
    RPMPGP_ERROR_SELFSIG_VERIFICATION	= 21
} rpmpgpRC;

typedef struct pgpDigAlg_s * pgpDigAlg;

typedef int (*setmpifunc)(pgpDigAlg digp, int num, const uint8_t *p, int mlen);
typedef int (*verifyfunc)(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
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

pgpDigAlg pgpDigAlgNewPubkey(int algo, int curve);
pgpDigAlg pgpDigAlgNewSignature(int algo);

#endif /* _RPMPGP_INTERNAL_H */
