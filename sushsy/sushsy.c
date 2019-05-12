
#include "sushsy.h"

void generate_permutation(const unsigned char *seed, unsigned char *permutation){
	int i=0;

	unsigned char permutation_randomness[A_COLS*3+50];
	EXPAND(seed,SEED_BYTES,permutation_randomness,A_COLS*3+50);

	for (i = 0; i < A_COLS; i++)
	{
		permutation[i] = i;
	}

	int cur_rand = 0;
	int cur_index = A_COLS-1;
	int mask = 255;
	while( cur_index > 0 )
	{
		if(cur_index <= mask/2){
			mask /= 2;
		}
	
		if( (permutation_randomness[cur_rand] & mask) <= cur_index){
			unsigned char tmp = permutation[cur_index];
			permutation[cur_index] = permutation[permutation_randomness[cur_rand] & mask];
			permutation[permutation_randomness[cur_rand] & mask] = tmp;
			cur_index --;
		}
		cur_rand++;
	}
}

void permute_vector(const uint16_t *vec, const unsigned char *permutation, uint16_t *out){
	int i;
	for (i = 0; i < A_COLS; i++)
	{
		out[permutation[i]] = vec[i];
	}
}

#define PK_RANDOMNESS_BYTES ((A_COLS + (A_COLS-1)*A_ROWS)*6+100)

void gen_v_and_A(const unsigned char *public_seed,uint16_t *v, uint16_t *A){
	// expand public seed to get pseudorandomness to generate v and A from
	uint16_t A_randomness[PK_RANDOMNESS_BYTES/2];
	EXPAND(public_seed,SEED_BYTES,(unsigned char *) A_randomness,PK_RANDOMNESS_BYTES);

	// generate good v (i.e. nonzero and distinct entries)
	int cur_v = 0;
	int cur_rand = 0;
	while(cur_v < A_COLS){
		uint16_t candidate = (A_randomness[cur_rand] & FIELD_MASK);
		if( candidate < FIELD_PRIME && candidate > 0 ) {
			int good = 1;
			int i;
			for(i=0; i<cur_v; i++){
				if(candidate == v[i]){
					good = 0;
					break;
				}
			}
			if (good){
				v[cur_v++] = ( A_randomness[cur_rand] & FIELD_MASK);
			}
		}
		cur_rand++;
	}

	// generate A
	int cur_A = 0;
	while(cur_A < (A_COLS-1)*A_ROWS){
		if( ( A_randomness[cur_rand] & FIELD_MASK) < FIELD_PRIME ) {
			A[cur_A++] = ( A_randomness[cur_rand] & FIELD_MASK);
		}
		cur_rand++;
	}
}

// embarrasingly slow, but thats ok
uint16_t minus_inverse(uint32_t a){
	uint32_t i;
	for(i=1; i<FIELD_PRIME; i++){
		if((i*a)%FIELD_PRIME == FIELD_PRIME-1){
			return (uint16_t) i;
		}
	}
	return 0;
}

void get_last_col(uint16_t *v, uint16_t *A, unsigned char *permutation_seed, uint16_t *col){
	// generate pi
	unsigned char pi[A_COLS];
	generate_permutation(permutation_seed, pi);

	// compute v_pi
	uint16_t v_pi[A_COLS];
	permute_vector(v,pi,v_pi);

	// compute last col
	uint32_t last_col[A_ROWS] = {0};

	int i,j;
	for(i=0; i<A_COLS-1; i++){
		for(j=0; j<A_ROWS; j++){
			last_col[j] += ((uint32_t) v_pi[i])*((uint32_t) A[i*A_ROWS+j]);
		}
	}

	uint16_t c = minus_inverse(v_pi[A_COLS-1]);
	for(j=0; j<A_ROWS; j++){
		last_col[j] %= FIELD_PRIME;
		last_col[j] *= c;
		col[j] = (uint16_t) (last_col[j] % FIELD_PRIME);
	}
}

void generate_r_and_sigma(const unsigned char *seed, uint16_t *r, unsigned char *sigma){
	uint16_t A_randomness[A_COLS*3+50];
	EXPAND(seed,SEED_BYTES,(unsigned char *) A_randomness,(A_COLS*3+50)*sizeof(uint16_t));

	// generate r
	int cur_A = 0;
	int cur_rand = 0;
	while(cur_A < A_COLS){
		if( ( A_randomness[cur_rand] & FIELD_MASK) < FIELD_PRIME ) {
			r[cur_A++] = ( A_randomness[cur_rand] & FIELD_MASK);
		}
		cur_rand++;
	}

	generate_permutation((unsigned char *)&A_randomness[cur_rand],sigma);
}

void keygen(unsigned char *pk, unsigned char *sk){
	// pick random secret key
	RAND_bytes(	SK_SEED(sk) , SEED_BYTES);

	// expand secret key into a public seed and a permutation seed
	unsigned char keygen_buf[SEED_BYTES*2];
	EXPAND(SK_SEED(sk),SEED_BYTES,keygen_buf,SEED_BYTES*2);

	// copy public seed to public key
	memcpy(PK_SEED(pk),keygen_buf,SEED_BYTES);

	// generate v and A from public seed 
	uint16_t v[A_COLS];
	uint16_t A[(A_COLS-1)*A_ROWS];
	gen_v_and_A(PK_SEED(pk),v,A);
	
	// compute last column of A
	get_last_col(v,A,keygen_buf + SEED_BYTES, (uint16_t *) PK_A_LAST_COL(pk));
}

void setup(const unsigned char *pk, const unsigned char *seeds, const unsigned char *indices, unsigned char *aux, unsigned char *helper){
	uint16_t v[A_COLS];
	uint16_t A[(A_COLS-1)*A_ROWS];
	gen_v_and_A(PK_SEED(pk),v,A);

	int inst;
	for (inst = 0; inst < SETUPS; inst++)
	{
		if(indices[inst] == 1){
			continue;
		}

		uint16_t data[LEAVES*A_COLS];
		unsigned char *Data = (unsigned char *) data;

		uint16_t *r = (uint16_t *) (HELPER_R(helper) + inst*HELPER_BYTES);
		unsigned char *sigma = HELPER_SIGMA(helper) + inst*HELPER_BYTES;
		uint16_t *v_sigma = (uint16_t *) (HELPER_V_SIGMA(helper) + inst*HELPER_BYTES);
		unsigned char *tree = HELPER_TREE(helper) + inst*HELPER_BYTES;

		generate_r_and_sigma(seeds + inst*SEED_BYTES, data, sigma);
		memcpy((unsigned char *)r, Data, A_COLS*sizeof(uint16_t));
		permute_vector(v,sigma,v_sigma);

		int i,j;
		for(i=1; i<LEAVES; i++){
			for(j=0; j<A_COLS; j++){
				data[i*A_COLS + j] = (data[(i-1)*A_COLS + j] + v_sigma[j]) % FIELD_PRIME;
			}
		}

		build_tree(Data, LEAF_BYTES, DEPTH, tree);

		memcpy(aux + inst*HASH_BYTES, tree, HASH_BYTES);
	}
}

void compose_perm_ab_inv(const unsigned char *a, const unsigned char *b, unsigned char *ab_inv){
	int i;
	for(i=0; i<A_COLS; i++){
		ab_inv[b[i]] = a[i];
	}
}

void mat_mul(const uint16_t *A, uint16_t *last_col, uint16_t *vec, uint16_t *out){
	uint32_t tmp[A_ROWS]= {0};

	int i,j;
	for(i=0; i<A_COLS-1; i++){
		for(j=0; j<A_ROWS; j++){
			tmp[j] += A[i*A_ROWS + j]*vec[i];
		}
	}

	for(j=0; j<A_ROWS; j++){
		tmp[j] += last_col[j]*vec[A_COLS-1];
		tmp[j] %= FIELD_PRIME;
		out[j] = (uint16_t) tmp[j];
	}
}

void commit(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, const unsigned char *helper, unsigned char *commitments){
	uint16_t v[A_COLS];
	uint16_t A[(A_COLS-1)*A_ROWS];
	gen_v_and_A(PK_SEED(pk),v,A);

	uint16_t *last_col = (uint16_t *) PK_A_LAST_COL(pk);

	// expand secret key into a public seed and a permutation seed
	unsigned char keygen_buf[SEED_BYTES*2];
	EXPAND(SK_SEED(sk),SEED_BYTES,keygen_buf,SEED_BYTES*2);

	// generate pi
	unsigned char pi[A_COLS];
	generate_permutation(keygen_buf + SEED_BYTES, pi);

	int inst;
	for (inst = 0; inst < SETUPS; inst++)
	{
		uint16_t buf[(A_COLS+1)/2 + A_ROWS] = {0};

		// compute rho
		compose_perm_ab_inv(pi,HELPER_SIGMA(helper) + inst*HELPER_BYTES, (unsigned char *) buf);

		// compute A*r_rho
		uint16_t *r = (uint16_t *)(HELPER_R(helper) + inst*HELPER_BYTES);
		uint16_t r_rho[A_COLS];
		permute_vector(r,(unsigned char *) buf,r_rho);

		mat_mul(A,last_col,r_rho,buf + (A_COLS+1)/2);

		HASH((unsigned char *) buf,((A_COLS+1)/2 + A_ROWS)*sizeof(uint16_t), commitments + inst*HASH_BYTES);
	}
}

void compress_vecs(const uint16_t *data, int len, unsigned char *out){
	int cur_in = 0;
	int cur_out = 0;
	int bits  = 0;
	uint32_t buf = 0;
	while(cur_in<len || bits>=8){
		if(bits >= 8){
			out[cur_out++] = (unsigned char) buf;
			bits -= 8;
			buf >>= 8;
		}
		else{
			buf |= (((uint32_t) data[cur_in++]) << bits);
			bits += FIELD_BITS;
		}
	}
	if(bits > 0){
	out[cur_out] = 0;
	out[cur_out] |= (unsigned char) buf;
	}
}

void decompress_vecs(const unsigned char *data, int len , uint16_t *out){
	int cur_in = 0;
	int cur_out = 0;
	int bits  = 0;
	uint32_t buf = 0;
	while(cur_out< len){
		if(bits >= FIELD_BITS){
			out[cur_out++] = (((uint16_t)buf) & FIELD_MASK);
			bits -= FIELD_BITS;
			buf >>= FIELD_BITS;
		}
		else{
			buf |= (((uint32_t) data[cur_in++]) << bits);
			bits += 8;
		}
	}
}

void compress_perms(const unsigned char *data, int len, unsigned char *out){
	int cur_in = 0;
	int cur_out = 0;
	int bits  = 0;
	uint32_t buf = 0;
	while(cur_in<len || bits>=8){
		if(bits >= 8){
			out[cur_out++] = (unsigned char) buf;
			bits -= 8;
			buf >>= 8;
		}
		else{
			buf |= (((uint32_t) data[cur_in++]) << bits);
			bits += PERM_BITS;
		}
	}
	if(bits > 0){
	out[cur_out] = 0;
	out[cur_out] |= (unsigned char) buf;
	}
}

void decompress_perms(const unsigned char *data, int len , unsigned char *out){
	int cur_in = 0;
	int cur_out = 0;
	int bits  = 0;
	uint32_t buf = 0;
	while(cur_out< len){
		if(bits >= PERM_BITS){
			out[cur_out++] = (((uint16_t)buf) & ((1<<PERM_BITS)-1) );
			bits -= PERM_BITS;
			buf >>= PERM_BITS;
		}
		else{
			buf |= (((uint32_t) data[cur_in++]) << bits);
			bits += 8;
		}
	}
}

void respond(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, const unsigned char *indices, const uint16_t *challenges, const unsigned char *helper, unsigned char *responses){
	uint16_t vectors[EXECUTIONS*A_COLS];
	unsigned char perms[EXECUTIONS*A_COLS];

	// expand secret key into a public seed and a permutation seed
	unsigned char keygen_buf[SEED_BYTES*2];
	EXPAND(SK_SEED(sk),SEED_BYTES,keygen_buf,SEED_BYTES*2);

	// generate pi
	unsigned char pi[A_COLS];
	generate_permutation(keygen_buf + SEED_BYTES, pi);

	int inst;
	int executions_done = 0;
	for(inst =0; inst <SETUPS; inst++){
		if(indices[inst] == 0){
			continue;
		}

		// compute rho
		compose_perm_ab_inv(pi,HELPER_SIGMA(helper) + inst*HELPER_BYTES, perms + executions_done*A_COLS);

		uint16_t *r = (uint16_t *)(HELPER_R(helper) + inst*HELPER_BYTES);
		uint16_t *v_sigma = (uint16_t *)(HELPER_V_SIGMA(helper) + inst*HELPER_BYTES);

		get_path(HELPER_TREE(helper) + inst*HELPER_BYTES, DEPTH, challenges[executions_done], RESPONSE_PATHS(responses) + PATH_BYTES*executions_done);

		int i;
		for(i=0; i<A_COLS; i++){
			vectors[executions_done*A_COLS + i] = (uint16_t) ( (((uint32_t) r[i]) + ((uint32_t) challenges[executions_done])*((uint32_t) v_sigma[i]) ) % FIELD_PRIME );
		}

		executions_done ++;
	}

	compress_perms(perms,EXECUTIONS*A_COLS,RESPONSE_RHOS(responses));

	compress_vecs(vectors,EXECUTIONS*A_COLS,RESPONSE_XS(responses));
}

void check(const unsigned char *pk, const unsigned char *indices, unsigned char *aux, unsigned char *commitments, const uint16_t *challenges, const unsigned char *responses){
	uint16_t v[A_COLS];
	uint16_t A[(A_COLS-1)*A_ROWS];
	gen_v_and_A(PK_SEED(pk),v,A);

	uint16_t *last_col = (uint16_t *) PK_A_LAST_COL(pk);

	unsigned char perms[EXECUTIONS*A_COLS] = {0};
	decompress_perms(RESPONSE_RHOS(responses),EXECUTIONS*A_COLS,perms);

	uint16_t vectors[EXECUTIONS*A_COLS] = {0};
	decompress_vecs(RESPONSE_XS(responses),EXECUTIONS*A_COLS,vectors);

	int inst;
	int executions_done = 0;
	for(inst =0; inst <SETUPS; inst++){
		if(indices[inst] == 0){
			continue;
		}

		const unsigned char *rho = perms + A_COLS*executions_done;

		uint16_t buf[(A_COLS+1)/2 + A_ROWS]= {0};
		memcpy((unsigned char *)buf,rho,A_COLS);

		uint16_t x_rho[A_COLS];
		permute_vector(vectors + executions_done*A_COLS,rho,x_rho);

		mat_mul(A,last_col,x_rho,buf + (A_COLS+1)/2);

		HASH((unsigned char *)buf,(A_COLS+1)/2*2 + sizeof(uint16_t)*A_ROWS,commitments + inst*HASH_BYTES);

		follow_path( (unsigned char *) (vectors + A_COLS*executions_done), LEAF_BYTES, DEPTH,RESPONSE_PATHS(responses) + executions_done*PATH_BYTES, challenges[executions_done], aux + HASH_BYTES*inst);

		executions_done ++;
	}

}