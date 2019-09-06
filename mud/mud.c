#include "mud.h"

static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %lu \n",#A ,rdtsc() - cl); cl = rdtsc();

void evalF(const unsigned char* coefs, const block *in, block *out){
	uint64_t tmp[8*N] = {0};
	int cur_coef = 0;
	for (int i = 0; i < N; ++i)
	{
		for(int j=i; j<N; j++){
			uint64_t prod[2] = {0};
			mulandadd(&in->x[2*i],&in->x[2*j],prod);

			for(int k=0; k<N; k+=4){
				add(prod, tmp + 8*(k+0) + 2*((coefs[cur_coef]   ) & 3));
				add(prod, tmp + 8*(k+1) + 2*((coefs[cur_coef]>>2) & 3));
				add(prod, tmp + 8*(k+2) + 2*((coefs[cur_coef]>>4) & 3));
				add(prod, tmp + 8*(k+3) + 2*((coefs[cur_coef]>>6) & 3));
				cur_coef ++;
			}
		}
	}

	for(int k=0; k<N; k++){
		out->x[2*k]   = tmp[k*8+2] ^ tmp[k*8+5] ^ tmp[k*8+6] ^ tmp[k*8+7];
		out->x[2*k+1] = tmp[k*8+3] ^ tmp[k*8+4] ^ tmp[k*8+5] ^ tmp[k*8+6];
 	}
}

void evalG(const unsigned char* coefs, const block *in1 , const block *in2 , block *out){
	uint64_t tmp[8*N] = {0};
	int cur_coef = 0;
 	for (int i = 0; i < N; ++i)
	{
		for(int j=i; j<N; j++){
			uint64_t prod[2] = {0};
			mulandadd(&in1->x[2*i],&in2->x[2*j],prod);
			mulandadd(&in2->x[2*i],&in1->x[2*j],prod);

			for(int k=0; k<N; k+=4){
				add(prod, tmp + 8*(k+0) + 2*((coefs[cur_coef]   )& 3));
				add(prod, tmp + 8*(k+1) + 2*((coefs[cur_coef]>>2)& 3));
				add(prod, tmp + 8*(k+2) + 2*((coefs[cur_coef]>>4)& 3));
				add(prod, tmp + 8*(k+3) + 2*((coefs[cur_coef]>>6)& 3));
				cur_coef ++;
			}
		}
	}

 	for(int k=0; k<N; k++){
		out->x[2*k]   = tmp[k*8+2] ^ tmp[k*8+5] ^ tmp[k*8+6] ^ tmp[k*8+7];
		out->x[2*k+1] = tmp[k*8+3] ^ tmp[k*8+4] ^ tmp[k*8+5] ^ tmp[k*8+6];
 	}
}

void generate_s(const unsigned char *seed, block *S){
	unsigned char s[(N+3)/4];
	EXPAND(seed,SEED_BYTES,s,(N+3)/4);

	for(int i=0; i<2*N; i++){
		if(s[i/8] & (1<<(i%8))){
			S->x[i] = -1;
		} else {
			S->x[i] = 0;
		}
	}
}

void keygen(unsigned char *pk, unsigned char *sk){
	// pick random pk and sk

	RAND_bytes(PK_SEED(pk),SEED_BYTES);
	RAND_bytes(SK_SEED(sk),SEED_BYTES);

	// generate F from seed
	unsigned char coefs[(N*N*(N+1)/2)/4];
	EXPAND(PK_SEED(pk),SEED_BYTES,coefs,(N*N*(N+1)/2)/4);

	// generate s and compute v = F(s)
	block S;
	block *V = (block *) PK_V(pk);
	generate_s(SK_SEED(sk),&S);
	evalF(coefs,&S, V);

	/* // put v in public key
	PK_V(pk)[(2*N-1)/8] = 0;
	for(int i=0; i<2*N; i++){
		if(V.x[i]){
			PK_V(pk)[i/8] |= (1<<i%8);
		}
	} */
}

void pack(unsigned char *vectors, block *packed, int index){
	for(int i=0; i<N ; i+=4 ){
		packed->x[i]   |= ((uint64_t ) ((vectors[i/4] &  1) >> 0)) << index;
		packed->x[i+1] |= ((uint64_t ) ((vectors[i/4] &  2) >> 1)) << index;

		packed->x[i+2] |= ((uint64_t ) ((vectors[i/4] &  4) >> 2)) << index;
		packed->x[i+3] |= ((uint64_t ) ((vectors[i/4] &  8) >> 3)) << index;

		packed->x[i+4] |= ((uint64_t ) ((vectors[i/4] & 16) >> 4)) << index;
		packed->x[i+5] |= ((uint64_t ) ((vectors[i/4] & 32) >> 5)) << index;

		packed->x[i+6] |= ((uint64_t ) ((vectors[i/4] & 64) >> 6)) << index;
		packed->x[i+7] |= ((uint64_t ) ((vectors[i/4] &128) >> 7)) << index;
	}
}

void print_mat(uint64_t *mat){
	for(int i=0; i<64; i++){
		printBits(8,mat+i);
	}
	printf("\n");
}

void transpose_64x64(uint64_t *mat){
	const uint64_t mask11 = 0x00000000ffffffff;
	const uint64_t mask12 = 0xffffffff00000000;
	for(int i=0 ; i<32; i++ ){
		mat[i+32] ^= ((mat[i   ] & mask11) << 32);
		mat[i]    ^= ((mat[i+32] & mask12) >> 32);
		mat[i+32] ^= ((mat[i   ] & mask11) << 32);
	}

	const uint64_t mask21 = 0x0000ffff0000ffff;
	const uint64_t mask22 = 0xffff0000ffff0000;
	for(int i=0 ; i<16; i++ ){
		for(int j=0 ; j<2; j++){
			mat[j*32+i+16] ^= ((mat[j*32+i   ] & mask21) << 16);
			mat[j*32+i]    ^= ((mat[j*32+i+16] & mask22) >> 16);
			mat[j*32+i+16] ^= ((mat[j*32+i   ] & mask21) << 16);
		}
	}

	const uint64_t mask31 = 0x00ff00ff00ff00ff;
	const uint64_t mask32 = 0xff00ff00ff00ff00;
	for(int i=0 ; i<8; i++ ){
		for(int j=0 ; j<4; j++){
			mat[j*16+i+8] ^= ((mat[j*16+i  ] & mask31) << 8);
			mat[j*16+i]   ^= ((mat[j*16+i+8] & mask32) >> 8);
			mat[j*16+i+8] ^= ((mat[j*16+i  ] & mask31) << 8);
		}
	}

	const uint64_t mask41 = 0x0f0f0f0f0f0f0f0f;
	const uint64_t mask42 = 0xf0f0f0f0f0f0f0f0;
	for(int i=0 ; i<4; i++ ){
		for(int j=0 ; j<8; j++){
			mat[j*8+i+4] ^= ((mat[j*8+i  ] & mask41) << 4);
			mat[j*8+i]   ^= ((mat[j*8+i+4] & mask42) >> 4);
			mat[j*8+i+4] ^= ((mat[j*8+i  ] & mask41) << 4);
		}
	}

	const uint64_t mask51 = 0x3333333333333333;
	const uint64_t mask52 = 0xcccccccccccccccc;
	for(int i=0 ; i<2; i++ ){
		for(int j=0 ; j<16; j++){
			mat[j*4+i+2] ^= ((mat[j*4+i  ] & mask51) << 2);
			mat[j*4+i]   ^= ((mat[j*4+i+2] & mask52) >> 2);
			mat[j*4+i+2] ^= ((mat[j*4+i  ] & mask51) << 2);
		}
	}

	const uint64_t mask61 = 0x5555555555555555;
	const uint64_t mask62 = 0xaaaaaaaaaaaaaaaa;
	for(int j=0 ; j<32; j++){
		mat[j*2+1] ^= ((mat[j*2  ] & mask61) << 1);
		mat[j*2]   ^= ((mat[j*2+1] & mask62) >> 1);
		mat[j*2+1] ^= ((mat[j*2  ] & mask61) << 1);
	}
}

// take 3x64 vectors and pack them into 3 blocks
void fill3blocks(vect *vectors, block *R0, block *E, block *T){
	for(int i=0; i<(N+63)/64; i++){
		uint64_t temp[64*6];
		for(int j=0; j<64; j++){
			temp[j    ] = (vectors+3*j)->x[i*2];
			temp[j+64 ] = (vectors+3*j)->x[i*2+1];

			temp[j+128] = (vectors+3*j+1)->x[i*2];
			temp[j+192] = (vectors+3*j+1)->x[i*2+1];

			temp[j+256] = (vectors+3*j+2)->x[i*2];
			temp[j+320] = (vectors+3*j+2)->x[i*2+1];
		}

		transpose_64x64(temp);
		transpose_64x64(temp+64);
		transpose_64x64(temp+128);
		transpose_64x64(temp+192);
		transpose_64x64(temp+256);
		transpose_64x64(temp+320);

		for(int j=0; j<64; j++){
			R0->x[i*64*2 + 2*j] = temp[j];
			R0->x[i*64*2 + 2*j+1] = temp[j+64];

			E->x[i*64*2 + 2*j] = temp[j+128];
			E->x[i*64*2 + 2*j+1] = temp[j+192];

			T->x[i*64*2 + 2*j] = temp[j+256];
			T->x[i*64*2 + 2*j+1] = temp[j+320];
		}
	}
}

// unpacks a block into 64 vectors
void unpackblock(block *b, vect *vectors){
	uint64_t temp[64*2];
	int i;
	for(i=0; i<N/64; i++){
		for(int j=0; j<64; j++){
			temp[j    ] = b->x[2*(j+64*i)];
			temp[j+64 ] = b->x[2*(j+64*i)+1];
		}

		transpose_64x64(temp);
		transpose_64x64(temp+64);

		for(int j=0; j<64; j++){
			(vectors+j)->x[2*i]   = temp[j];
			(vectors+j)->x[2*i+1] = temp[j+64];
		}
	}

	#if N%64 != 0
		for(int j=0; j<64; j++){
			temp[j    ] = b->x[2*(j+64*i)];
			temp[j+64 ] = b->x[2*(j+64*i)+1];
		}
		transpose_64x64(temp);
		transpose_64x64(temp+64);

		for(int j=0; j<64; j++){
			(vectors+j)->x[2*i]   = temp[j]    & ((((uint64_t) 0) -1) << (64-(N%64))); 
			(vectors+j)->x[2*i+1] = temp[j+64] & ((((uint64_t) 0) -1) << (64-(N%64))); 
		}
	#endif
}

void setup(const unsigned char *pk, const unsigned char *seeds, const unsigned char *indices, unsigned char *aux, unsigned char *helper){
	block *r_0  = (block*) HELPER_R0(helper);
	block *e    = (block*) HELPER_E(helper);
	block *t    = (block*) HELPER_T(helper);
	block *Fr_0 = (block*) HELPER_FR0(helper);

	vect randomness[(SETUP_BLOCKS*64)*3] = {0};
	for(int i=0; i<SETUPS; i++){
		EXPAND(seeds + i*SEED_BYTES, SEED_BYTES, (unsigned char *) (randomness + i*3) , 3*sizeof(vect) );
		//EXPAND(seeds, SEED_BYTES, (unsigned char *) (randomness + i*3) , 3*sizeof(vect) );
	}

	for(int i=0; i<SETUP_BLOCKS; i++){
		fill3blocks(randomness + i*64*3 , r_0+i,e+i,t+i);
	}

	// generate F from seed
	unsigned char coefs[(N*N*(N+1)/2)/4];
	EXPAND(PK_SEED(pk),SEED_BYTES,coefs,(N*N*(N+1)/2)/4);

	// e, e+F(r_0), e + alpha*F(r_0), e + (1+alpha)*F(r_0) 
	vect data_e[4][64*SETUP_BLOCKS] = {0};

	// t, t+r_0, t + alpha*r_0, t + (1+alpha)*r_0 
	vect data_t[4][64*SETUP_BLOCKS] = {0};

	// compute F(r_0) and write to date_e and data _t
	for(int i=0; i<SETUP_BLOCKS; i++){
		evalF(coefs,r_0+i, Fr_0+i);

		{
			// write e
			unpackblock(e+i, &(data_e[0][i*64]));

			// write e + F(r_0)
			block tmp0 = {0};
			add_block(Fr_0+i,&tmp0);
			add_block(e+i, &tmp0);

			unpackblock(&tmp0, &(data_e[1][i*64]));

			// write e + (1+alpha)*F(r_0)
			block tmp1 = {0};
			times_alpha_block(Fr_0+i,&tmp1);
			add_block(&tmp1,&tmp0);
			unpackblock(&tmp0, &(data_e[3][i*64]));
		
			// write e + alpha*F(r_0)
			add_block(Fr_0+i,&tmp0);
			unpackblock(&tmp0, &(data_e[2][i*64]));
		}

		{
			// write t
			unpackblock(t+i, &(data_t[0][i*64]));

			// write t + r_0
			block tmp0 = {0};
			add_block(r_0+i, &tmp0);
			add_block(t+i, &tmp0);
			unpackblock(&tmp0, &(data_t[1][i*64]));

			// write t + (1+alpha)*r_0
			block tmp1 = {0};
			times_alpha_block(r_0+i, &tmp1);
			add_block(&tmp1, &tmp0);
			unpackblock(&tmp0, &(data_t[3][i*64]));
		
			// write t + alpha*r_0
			add_block(r_0+i, &tmp0);
			unpackblock(&tmp0, &(data_t[2][i*64]));
		}

	}

	// make trees
	for (int i = 0; i < SETUPS; ++i)
	{
		if(indices[i] == 1){
			continue;
		}
		vect *data = ((vect*) HELPER_DATA(helper)) +  8*i;

		data[0] = data_e[0][i];
		data[1] = data_t[0][i];
		data[2] = data_e[1][i];
		data[3] = data_t[1][i];
		data[4] = data_e[2][i];
		data[5] = data_t[2][i];
		data[6] = data_e[3][i];
		data[7] = data_t[3][i];

		build_tree((unsigned char *) data, sizeof(vect[2]) , DEPTH, HELPER_TREES(helper) + i*TREE_BYTES);

		memcpy(aux + i*HASH_BYTES, HELPER_TREES(helper) + i*TREE_BYTES, HASH_BYTES);
	}
}

void commit(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, const unsigned char *helper, unsigned char *commitments){
	// generate s from seed
	block S;
	generate_s(SK_SEED(sk),&S);

	// generate F from seed
	unsigned char coefs[(N*N*(N+1)/2)/4];
	EXPAND(PK_SEED(pk),SEED_BYTES,coefs,(N*N*(N+1)/2)/4);

	// compute r_1 = s + r_0 and 
	// comppute x = e + G(r_1,t)
	block r1[SETUP_BLOCKS] = {0};
	block x[SETUP_BLOCKS] = {0};
	for (int i = 0; i < SETUP_BLOCKS; ++i)
	{
		add_block( (block *) (HELPER_R0(helper) + i*sizeof(block)) , r1 + i );
		add_block( &S , r1 + i );

		block tmp = {0};
		add_block( (block *) (HELPER_E(helper) + i*sizeof(block)) , x + i );

		evalG(coefs, r1+i, (block *) (HELPER_T(helper) + i*sizeof(block)) , &tmp);
		add_block(&tmp, x+i);
	}

	// unpack vectors
	vect *data_r_1 = (vect *) HELPER_R1(helper);
	vect data_x[SETUP_BLOCKS*64];
	for(int i=0; i<SETUP_BLOCKS; i++){
		unpackblock(r1+i,data_r_1 + 64*i);
		unpackblock(x+i,data_x + 64*i);
	}

	// make commitments
	for(int i=0; i<SETUPS; i++){
		vect data[2];
		data[0] = data_r_1[i];
		data[1] = data_x[i];

		HASH((unsigned char *) data, sizeof(vect[2]) , commitments + i*HASH_BYTES );
	}
}

#if N>=128
	#define FV 4
#elif N>=64
	#define FV 2
#else
	#define FV 0 
#endif

void serialize_vects(const vect *vectors, unsigned char *out){
	uint64_t * V = (uint64_t *) vectors;
	for(int i=0 ; i<EXECUTIONS*3; i++){
		memcpy(out + sizeof(uint64_t)*FV*i    , V+((FV+2)*i)  , FV*sizeof(uint64_t));
	}

	int cur_in = FV;
	int cur_out = 0;
	int bits  = 0;
	uint64_t buf = 0;
	out += EXECUTIONS*3*FV*sizeof(uint64_t);

	#if N%64 != 0

	while(cur_in<EXECUTIONS*3*(FV+2)){		
		buf |= ( V[cur_in] >> ((64-(N%64))-bits) );
		bits += (N%64);
		while(bits >= 8){
			out[cur_out++] = (unsigned char) buf;
			bits -= 8;
			buf >>= 8;
		}

		buf |= ( V[cur_in+1] >> ((64-(N%64))-bits) );
		bits += (N%64);
		cur_in += FV+2;

		while(bits >= 8){
			out[cur_out++] = (unsigned char) buf;
			bits -= 8;
			buf >>= 8;
		}
	}
	if(bits > 0){
		out[cur_out] = 0;
		out[cur_out] |= (unsigned char) buf;
	}

	#endif
}

void deserialize_vects(const unsigned char *in, vect *vectors){
	uint64_t * V = (uint64_t *) vectors;
	for(int i=0 ; i<EXECUTIONS*3; i++){
		memcpy(V+((FV+2)*i)  , in + sizeof(uint64_t)*FV*i    , FV*sizeof(uint64_t));
	}

	int cur_in = 0;
	int cur_out = FV;
	int bits  = 0;
	uint64_t buf = 0;
	in += sizeof(uint64_t)*EXECUTIONS*3*FV;
	while(cur_out< EXECUTIONS*3*(FV+2)){
		while(bits < N%64){
			buf |= (((uint64_t) in[cur_in++]) << bits);
			bits += 8;
		}

		V[cur_out] = buf << (64-(N%64));
		bits -= (N%64);
		buf >>= (N%64);

		while(bits < N%64){
			buf |= (((uint64_t) in[cur_in++]) << bits);
			bits += 8;
		}

		V[cur_out+1] = buf << (64-(N%64));
		bits -= (N%64);
		buf >>= (N%64);
		cur_out += FV+2;
	}
}

void respond(const unsigned char *pk, const unsigned char *sk, const unsigned char *seeds, const unsigned char *indices, const uint16_t *challenges, const unsigned char *helper, unsigned char *responses){
	vect *data_r_1 = (vect *) HELPER_R1(helper);
	vect *data = (vect *) HELPER_DATA(helper);

	vect response_vects[EXECUTIONS*3];

	int executions_done =0;
	for(int i=0; i<SETUPS; i++){
		if(indices[i] == 0){
			continue;
		}

		// copy vectors to response
		memcpy(response_vects + executions_done*3   , (unsigned char *) (data_r_1 + i) , sizeof(vect));
		memcpy(response_vects + executions_done*3+1 , (unsigned char *) (data + i*8+ challenges[executions_done]*2 ), sizeof(vect[2])); 

		// generate paths
		get_path(HELPER_TREES(helper) + i*TREE_BYTES, DEPTH, challenges[executions_done], RESPONSE_PATHS(responses) + executions_done*PATH_BYTES);

		executions_done ++;
	}

	serialize_vects(response_vects, RESPONSE_VECTS(responses));
}

void multiply_by_challenges(block *in, const uint16_t *challenges, block *out){
	for(int i=0; i<EXECUTIONS; i++){
		if(challenges[i] & 1){
			out->x[2*i  ] = in->x[2*i];
			out->x[2*i+1] = in->x[2*i+1];
		}
		if(challenges[i] & 2){
			out->x[2*i  ] ^= in->x[2*i+1] ;
			out->x[2*i+1] ^= (in->x[2*i] ^ in->x[2*i+1]);
		}
	}
}

void check(const unsigned char *pk, const unsigned char *indices, unsigned char *aux, unsigned char *commitments, const uint16_t *challenges, const unsigned char *responses){
	// generate F from seed

	unsigned char coefs[(N*N*(N+1)/2)/4];
	EXPAND(PK_SEED(pk),SEED_BYTES,coefs,(N*N*(N+1)/2)/4);

	vect response_vects[EXECUTIONS*3];
	deserialize_vects(RESPONSE_VECTS(responses), response_vects);


	vect x_vect[EXECUTION_BLOCKS*64];

	for(int i=0; i< EXECUTION_BLOCKS; i++){
		block x = {0},tmp = {0};
		block r_1 = {0};
		block e_alpha = {0};
		block t_alpha = {0};

		fill3blocks(response_vects + 3*64*i, &r_1, &e_alpha, &t_alpha);

		evalF(coefs,&r_1,&tmp);

		add_block((block *) PK_V(pk),&tmp);

		uint64_t challengevec[2] = {0};
		for (int j = 0; j < 64 ; ++j)
		{
			if (challenges[j+i*64] & 1)
				challengevec[0] |=  (((uint64_t) 1 ) << (63-j));
			if (challenges[j+i*64] & 2)
				challengevec[1] |=  (((uint64_t) 1 ) << (63-j));
		}

		for (int j = 0; j < N; ++j)
		{
			mulandadd(tmp.x + 2*j, challengevec , x.x+2*j);
		}

		add_block(&e_alpha,&x);

		evalG(coefs,&r_1,&t_alpha,&tmp);
		add_block(&tmp,&x);

		unpackblock(&x,x_vect + i*64);
	}


	int executions_done = 0;
	for(int i=0; i<SETUPS; i++){
		if(indices[i] == 0){
			continue;
		}

		vect data[2];
		data[0] = *(response_vects + executions_done*3);
		data[1] = x_vect[executions_done];

		HASH((unsigned char *) data, sizeof(vect[2]), commitments + i*HASH_BYTES);

		follow_path((unsigned char *)(response_vects + (executions_done*3+1)), sizeof(vect[2]), DEPTH, RESPONSE_PATHS(responses) + executions_done*PATH_BYTES , challenges[executions_done] , aux + i*HASH_BYTES  );

		executions_done ++;
	}
}

void test(){
	unsigned char seed[SEED_BYTES] = {0};
	//RAND_bytes(seed,SEED_BYTES);

	// generate F from seed
	unsigned char coefs[(N*N*(N+1)/2)/4] = {0};
	EXPAND(seed,SEED_BYTES,coefs,(N*N*(N+1)/2)/4);
	//coefs[0] = 1;

	block a = {0};
	block b = {0};
	block aplusb = {0};
	block temp1 = {0};
	block temp2 = {0};

	vect randomness[(SETUP_BLOCKS*64)*3] = {0};
	for(int i=0; i<SETUPS; i++){
		seed[0]++;
		EXPAND(seed, SEED_BYTES, (unsigned char *) (randomness + i*3) , 3*sizeof(vect) );
	}

	fill3blocks(randomness, &a, &b, &aplusb);

	printf("a\n");
	print_block(&a);

	printf("b\n");
	print_block(&b);

	memset(&aplusb,0,sizeof(block));
	add_block(&a,&aplusb);
	add_block(&b,&aplusb);

	evalG(coefs,&a,&b,&temp1);
	printf("G(a,b)\n");
	print_block(&temp1);

	evalF(coefs,&aplusb,&temp1);
	add_block(&temp1,&temp2);
	evalF(coefs,&a,&temp1);
	add_block(&temp1,&temp2);
	evalF(coefs,&b,&temp1);
	add_block(&temp1,&temp2);

	printf("F(a+b) -F(a) - F(b) \n");
	print_block(&temp2);

}