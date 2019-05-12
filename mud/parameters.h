
#include <openssl/sha.h>
#include "libkeccak.a.headers/SimpleFIPS202.h"

#define SL1

#ifdef SL1

#define N 84
#define FIELD_BITS 2
#define DEPTH  2

#define SEED_BYTES 16
#define HASH_BYTES 32
#define HASHES  (1<<8)

#define SETUPS 163
#define EXECUTIONS 64
#define SEED_DEPTH 8

#endif

#ifdef SL3

#define N 116
#define FIELD_BITS 2
#define DEPTH  2

#define SEED_BYTES 24
#define HASH_BYTES 48
#define HASHES  (1<<9)

#define SETUPS 256
#define EXECUTIONS 101
#define SEED_DEPTH 9

#endif

#ifdef SL5

#define N 152
#define FIELD_BITS 2
#define DEPTH  2

#define SEED_BYTES 32
#define HASH_BYTES 64
#define HASHES  (1<<10)

#define SETUPS 384
#define EXECUTIONS 128
#define SEED_DEPTH 9

#endif

#define LEAF_BYTES (A_COLS*sizeof(uint16_t))
#define LEAVES (1 << DEPTH)
#define TREE_BYTES ((2*LEAVES-1)*HASH_BYTES)
#define PATH_BYTES (DEPTH*HASH_BYTES)

//#define HASH SHA256
#define HASH(data,len,out) SHAKE128(out, HASH_BYTES, data, len);
#define EXPAND(data,len,out,outlen) SHAKE256(out, outlen, data, len);


#define FIELD_MASK ((1<<FIELD_BITS) -1)
#define POS_MASK ((1<<SEED_DEPTH) -1)