#ifndef MUD_H
#define MUD_H 


#include <openssl/rand.h>
#include "stdint.h"
#include "parameters.h"
#include "../merkletree.h"
#include "F4.h"

#define SK_SEED(sk) (sk)
#define SK_BYTES SEED_BYTES

#define PK_V(pk) (pk)
#define PK_SEED(pk) (PK_V(pk) + sizeof(block))
#define PK_BYTES (PK_SEED(0) + SEED_BYTES )

#define SETUP_BLOCKS ((SETUPS+63)/64)
#define EXECUTION_BLOCKS ((EXECUTIONS+63)/64)

#define HELPER_R0(helper)    (helper)
#define HELPER_E(helper)     (HELPER_R0(helper)  + SETUP_BLOCKS*sizeof(block))
#define HELPER_T(helper)     (HELPER_E(helper)   + SETUP_BLOCKS*sizeof(block))
#define HELPER_FR0(helper)   (HELPER_T(helper)   + SETUP_BLOCKS*sizeof(block))
#define HELPER_DATA(helper)  (HELPER_FR0(helper) + sizeof(vect[SETUP_BLOCKS*64]))
#define HELPER_R1(helper)    (HELPER_DATA(helper)+ sizeof(vect[8*SETUPS]))
#define HELPER_TREES(helper) (HELPER_R1(helper)  + SETUP_BLOCKS*64*sizeof(vect))
#define HELPER_BYTES         (HELPER_TREES(0) + SETUPS*TREE_BYTES)

#define RESPONSE_VECTS(rsp) (rsp)
#define RESPONSE_PATHS(rsp) (RESPONSE_VECTS(rsp) + (EXECUTIONS*N*2*3+7)/8 )
#define RESPONSE_BYTES (RESPONSE_PATHS(0) + EXECUTIONS*PATH_BYTES)

void keygen(unsigned char *pk, unsigned char *sk);
void setup(const unsigned char *pk, const unsigned char *seeds, const unsigned char *indices, unsigned char *aux, unsigned char *helper);
void commit(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, const unsigned char *helper, unsigned char *commitments);
void respond(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, const unsigned char *indices, const uint16_t *challenges, const unsigned char *helper, unsigned char *responses);
void check(const unsigned char *pk, const unsigned char *indices, unsigned char *aux, unsigned char *commitments, const uint16_t *challenges, const unsigned char *responses);	

#endif