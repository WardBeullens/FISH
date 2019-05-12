
#include "sign.h"

static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %lu \n",#A ,rdtsc() - cl); cl = rdtsc();

void combine_hashes(const unsigned char *m_hash, const unsigned char *aux_hash, const unsigned char *commitment_hash, unsigned char *master_hash){
	unsigned char input[HASH_BYTES*3];
	
	memcpy(input,m_hash,HASH_BYTES);
	memcpy(input+HASH_BYTES,aux_hash,HASH_BYTES);
	memcpy(input+2*HASH_BYTES,commitment_hash,HASH_BYTES);
	HASH(input,3*HASH_BYTES,master_hash);
}

void get_indices_and_challenges(const unsigned char *master_hash, unsigned char *indices, uint16_t *challenges){
	unsigned char hash[HASH_BYTES];
	memcpy(hash,master_hash,HASH_BYTES);

	for(int i=0; i<HASHES; i+=4){
		HASH(hash,HASH_BYTES,hash);
		HASH(hash,HASH_BYTES,hash);
		HASH(hash,HASH_BYTES,hash);
		HASH(hash,HASH_BYTES,hash);
	}

	uint16_t randomness[SETUPS*3+50+EXECUTIONS] = {0};
	EXPAND(hash,HASH_BYTES,(unsigned char *) randomness,(SETUPS*3+50+EXECUTIONS)*sizeof(uint16_t));

	int a = 0;
	int cur_r = 0;
	while( a < EXECUTIONS ){
		uint16_t candidate = (randomness[cur_r++] & POS_MASK);
		if( candidate < SETUPS && indices[candidate] == 0 ){
			a++;
			indices[candidate] = 1;
		}
	}

	for(int i=SETUPS; i<(1<<SEED_DEPTH) ; i++){
		indices[i] = 1;
	}

	for(int i=0; i<EXECUTIONS; i++){
		challenges[i] =  0;//randomness[cur_r++] & ((1 << DEPTH)-1);
	}
}

void sign(const unsigned char *sk, const unsigned char *pk, const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len){
	// hash the message
	unsigned char m_hash[HASH_BYTES];
	HASH(m,mlen,m_hash);

	// pick random root seed and generate a tree of random seeds
	unsigned char seed_tree[SEED_BYTES*((2<<SEED_DEPTH)-1)];
	unsigned char *seeds = seed_tree + ((1<<SEED_DEPTH) -1)*SEED_BYTES;
	RAND_bytes(seed_tree,SEED_BYTES);
	generate_seed_tree(seed_tree);

	// generate the auxiliary information
	unsigned char aux[SETUPS*HASH_BYTES];
	unsigned char *helper;
	helper = aligned_alloc(32, (HELPER_BYTES*SETUPS+31)/32*32 );
	unsigned char indices[1<<SEED_DEPTH] = {0};
	setup(pk, seeds , indices, aux , helper);

	// hash the auxiliary information
	unsigned char aux_hash[HASH_BYTES];
	HASH(aux,SETUPS*HASH_BYTES,aux_hash);

	// generate commitments for instances in index set
	unsigned char commitments[HASH_BYTES*(1<<SEED_DEPTH)] = {0};
	commit(pk,sk,seeds,helper,commitments);

	// hash commitments in merkle tree
	unsigned char commitment_merkle_tree[((2<<SEED_DEPTH)-1)*HASH_BYTES];
	build_tree(commitments,HASH_BYTES,SEED_DEPTH,commitment_merkle_tree);

	//printf("aux_hash \n");
	//print_hash(aux_hash);

	// generate master_hash
	combine_hashes(m_hash,aux_hash,commitment_merkle_tree,SIG_HASH(sig));

	// generate indices and challenges
	uint16_t challenges[EXECUTIONS];
	get_indices_and_challenges(SIG_HASH(sig),indices,challenges);

	// generate responses 
	respond(pk, sk, seeds, indices, challenges, helper, SIG_RESPONSES(sig));

	free(helper);

	// release seeds to let verifier check auxiliary information
	uint16_t nodes_released;
	release_nodes(seed_tree, SEED_BYTES, SEED_DEPTH, indices, SIG_SEEDS(sig), &nodes_released );

	// release commitments to let verifier reconstruct commitment_hash
	release_nodes(commitment_merkle_tree,HASH_BYTES, SEED_DEPTH, indices, SIG_SEEDS(sig) + nodes_released*SEED_BYTES, &nodes_released);

	// set signature length
	(*sig_len) = SIG_SEEDS(0) + nodes_released*(SEED_BYTES+HASH_BYTES); 
}

int verify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const unsigned char *sig){

	// hash the message
	unsigned char m_hash[HASH_BYTES];
	HASH(m,mlen,m_hash);

	// generate indices and challenges
	unsigned char indices[1<<SEED_DEPTH] = {0};
	uint16_t challenges[EXECUTIONS];
	get_indices_and_challenges(SIG_HASH(sig),indices,challenges);

	// reconstruct some of aux and some of commitments
	unsigned char aux[SETUPS*HASH_BYTES] = {0};
	unsigned char commitments[HASH_BYTES*(1<<SEED_DEPTH)] = {0};
	unsigned char *helper;
	helper = malloc(HELPER_BYTES*SETUPS);
	check(pk,indices,aux,commitments,challenges,SIG_RESPONSES(sig));

	// fill the remaining seeds
	unsigned char seed_tree[SEED_BYTES*((2<<SEED_DEPTH)-1)] = {0};
	unsigned char *seeds = seed_tree + ((1<<SEED_DEPTH) -1)*SEED_BYTES;
	uint16_t nodes_used = 0;
	fill_down(seed_tree, indices, SIG_SEEDS(sig), &nodes_used);

	// regenerate aux from the seeds
	setup(pk,seeds,indices,aux,helper);
	free(helper);

	// hash the auxiliary information
	unsigned char aux_hash[HASH_BYTES];
	HASH(aux,SETUPS*HASH_BYTES,aux_hash);

	// get commitment root
	unsigned char commitment_hash[HASH_BYTES];
	hash_up(commitments,indices, SIG_SEEDS(sig)+ nodes_used*SEED_BYTES, nodes_used, commitment_hash);

	//printf("aux_hash \n");
	//print_hash(aux_hash);

	// combine hashes
	unsigned char master_hash[HASH_BYTES];
	combine_hashes(m_hash,aux_hash,commitment_hash,master_hash);

	for (int i = 0; i < HASH_BYTES; ++i)
	{
		if(master_hash[i] != SIG_HASH(sig)[i]){
			return -1;
		}
	}

	return 1;
}
