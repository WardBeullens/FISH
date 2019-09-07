
#include <openssl/sha.h>
#include "libkeccak.a.headers/SimpleFIPS202.h"

#define LOG_1(n) (((n) >= 2) ? 1 : 0)
#define LOG_2(n) (((n) >= 1<<2) ? (2 + LOG_1((n)>>2)) : LOG_1(n))
#define LOG_4(n) (((n) >= 1<<4) ? (4 + LOG_2((n)>>4)) : LOG_2(n))
#define LOG_8(n) (((n) >= 1<<8) ? (8 + LOG_4((n)>>8)) : LOG_4(n))
#define LOG(n)   (((n-1) >= 1<<16) ? (17 + LOG_8((n-1)>>16)) : (1+ LOG_8(n-1)))

#define SL1

#ifdef SL1

#define N 84
#define SETUPS 163
#define EXECUTIONS 64
#define SEED_BYTES 16
#define HASH_BYTES 32

#endif

#ifdef SL3

#define N 116
#define SEED_BYTES 24
#define HASH_BYTES 48
#define SETUPS 256
#define EXECUTIONS 101

#endif

#ifdef SL5

#define N 152
#define SEED_BYTES 32
#define HASH_BYTES 64
#define SETUPS 384
#define EXECUTIONS 128

#endif

#define FIELD_BITS 2
#define DEPTH 2
#define SEED_DEPTH LOG(SETUPS)

#define LEAF_BYTES (2*sizeof(vect)+SEED_BYTES)
#define LEAVES (1 << DEPTH)
#define TREE_BYTES ((2*LEAVES-1)*HASH_BYTES)
#define PATH_BYTES (DEPTH*HASH_BYTES)
#define HASHES 0

//#define HASH SHA256
#define HASH(data,len,out) SHAKE128(out, HASH_BYTES, data, len);
#define EXPAND(data,len,out,outlen) SHAKE256(out, outlen, data, len);


#define FIELD_MASK ((1<<FIELD_BITS) -1)
#define POS_MASK ((1<<SEED_DEPTH) -1)