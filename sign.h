#ifndef SIGN_H
#define SIGN_H 

#include <stdlib.h>

void *aligned_alloc( size_t alignment, size_t size );

#if SUSHSY

#include "sushsy/parameters.h"
#include "sushsy/sushsy.h"

#endif

#if MUD

#include "mud/parameters.h"
#include "mud/mud.h"

#endif

#define SIG_HASH(sig) (sig)
#define SIG_RESPONSES(sig) (SIG_HASH(sig) + HASH_BYTES)
#define SIG_SEEDS(sig) (SIG_RESPONSES(sig) + RESPONSE_BYTES)
#define SIG_BYTES (SIG_SEEDS(0)+ (SETUPS-EXECUTIONS)*(SEED_BYTES+HASH_BYTES)  )

void sign(const unsigned char *sk,  const unsigned char *pk,const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len);
int verify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const unsigned char *sig);

#endif