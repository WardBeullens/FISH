
#include <openssl/sha.h>
#include "libkeccak.a.headers/SimpleFIPS202.h"

#define LOG_1(n) (((n) >= 2) ? 1 : 0)
#define LOG_2(n) (((n) >= 1<<2) ? (2 + LOG_1((n)>>2)) : LOG_1(n))
#define LOG_4(n) (((n) >= 1<<4) ? (4 + LOG_2((n)>>4)) : LOG_2(n))
#define LOG_8(n) (((n) >= 1<<8) ? (8 + LOG_4((n)>>8)) : LOG_4(n))
#define LOG(n)   (((n-1) >= 1<<16) ? (17 + LOG_8((n-1)>>16)) : (1+ LOG_8(n-1)))

#define SL1
//#define SL3
//#define SL5

//#define FAST
#define MEDIUM
//#define COMPACT

#ifdef SL1

	#define A_COLS 61
	#define A_ROWS 28
	#define FIELD_PRIME 977
	#define PERM_BITS 6
	#define SEED_BYTES 16
	#define HASH_BYTES 32

	#ifdef FAST
		#define DEPTH  2
		#define SETUPS 204
		#define EXECUTIONS 61
	#endif

	#ifdef MEDIUM
		#define DEPTH  4
		#define SETUPS 242
		#define EXECUTIONS 33
	#endif

	#ifdef COMPACT
		#define DEPTH  7
		#define SETUPS 1011
		#define EXECUTIONS 16
	#endif

#endif

#ifdef SL3

	#define A_COLS 87
	#define A_ROWS 42
	#define FIELD_PRIME 1409
	#define PERM_BITS 7
	#define SEED_BYTES 24
	#define HASH_BYTES 48

	#ifdef FAST
		#define DEPTH  2
		#define SETUPS 310
		#define EXECUTIONS 93
	#endif

	#ifdef MEDIUM
		#define DEPTH  4
		#define SETUPS 406
		#define EXECUTIONS 49
	#endif

	#ifdef COMPACT
		#define DEPTH  7
		#define SETUPS 1024
		#define EXECUTIONS 28
	#endif

#endif

#ifdef SL5

	#define A_COLS 111
	#define A_ROWS 55
	#define FIELD_PRIME 1889
	#define PERM_BITS 7
	#define SEED_BYTES 32
	#define HASH_BYTES 64

	#ifdef FAST
		#define DEPTH  2
		#define SETUPS 384
		#define EXECUTIONS 128
	#endif

	#ifdef MEDIUM
		#define DEPTH  4
		#define SETUPS 607
		#define EXECUTIONS 64
	#endif

	#ifdef COMPACT
		#define DEPTH  7
		#define SETUPS 2048
		#define EXECUTIONS 36
	#endif

#endif

#if A_COLS > 256
	This implementation does not work for A_COLS > 256
#endif

#define HASHES 0
#define FIELD_BITS LOG(FIELD_PRIME)
#define SEED_DEPTH LOG(SETUPS)
#define LEAVES (1 << DEPTH)
#define LEAF_BYTES (A_COLS*sizeof(uint16_t) + SEED_BYTES)
#define TREE_BYTES ((2*LEAVES-1)*HASH_BYTES)
#define PATH_BYTES (DEPTH*HASH_BYTES)

//#define HASH SHA256
#define HASH(data,len,out) SHAKE128(out, HASH_BYTES, data, len);
#define EXPAND(data,len,out,outlen) SHAKE128(out, outlen, data, len);


#define FIELD_MASK ((1<<FIELD_BITS) -1)
#define POS_MASK ((1<<SEED_DEPTH) -1)