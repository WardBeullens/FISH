#ifndef SUSHSY_H
#define SUSHSY_H

#include <openssl/rand.h>
#include "parameters.h"
#include "../merkletree.h"

#define SK_SEED(sk) (sk)
#define SK_BYTES SEED_BYTES

#define PK_SEED(pk) (pk)
#define PK_A_LAST_COL(pk) (pk+SEED_BYTES)
#define PK_BYTES (PK_A_LAST_COL(0) + A_ROWS*2)

#define HELPER_COMMITMENT_RANDOMNESS(helper) (helper)
#define HELPER_R(helper) (HELPER_COMMITMENT_RANDOMNESS(helper) + 3*SEED_BYTES)
#define HELPER_SIGMA(helper) (HELPER_R(helper) + A_COLS*sizeof(uint16_t))
#define HELPER_V_SIGMA(helper) (HELPER_SIGMA(helper) + (A_COLS+1)/2*2 )
#define HELPER_TREE(helper) (HELPER_V_SIGMA(helper)+ A_COLS*sizeof(uint16_t))
#define HELPER_BYTES (HELPER_TREE(0) + TREE_BYTES)

#define RESPONSE_COMMITMENT_RANDOMNESS(rsp) (rsp)
#define RESPONSE_RHOS(rsp) (RESPONSE_COMMITMENT_RANDOMNESS(rsp) + EXECUTIONS*SEED_BYTES*2)
#define RESPONSE_PATHS(rsp) (RESPONSE_RHOS(rsp) + (EXECUTIONS*A_COLS*PERM_BITS+7)/8 )
#define RESPONSE_XS(rsp) (RESPONSE_PATHS(rsp) + EXECUTIONS*PATH_BYTES)
#define RESPONSE_BYTES (RESPONSE_XS(0) + (EXECUTIONS*A_COLS*FIELD_BITS+7)/8 )

void keygen(unsigned char *pk, unsigned char *sk);
void setup(const unsigned char *pk, const unsigned char *seeds, const unsigned char *indices, unsigned char *aux, unsigned char *helper);
void commit(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, unsigned char *helper, unsigned char *commitments);
void respond(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, const unsigned char *indices, const uint16_t *challenges, const unsigned char *helper, unsigned char *responses);
void check(const unsigned char *pk, const unsigned char *indices, unsigned char *aux, unsigned char *commitments, const uint16_t *challenges, const unsigned char *responses);	

#endif