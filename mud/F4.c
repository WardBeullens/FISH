#include "F4.h"

void add(const uint64_t *A, uint64_t *out){
	*out ^= *A;
	*(out+1) ^= *(A+1);	
}

void mulandadd(const uint64_t *A, const uint64_t *B, uint64_t *out){
	*out ^= *A & *B;
	*out ^= *(A+1) & *(B+1);
	*(out+1) ^= *(A+1) & *(B+1);
	*(out+1) ^= *(A+1) & *B;
	*(out+1) ^= *A & *(B+1);
}

void add_block(block* A, block*B){
	for(int i=0; i<(N+63)/64*64*2; i++){
		B->x[i] ^= A->x[i];
	}
}

void times_alpha_block(block* IN, block*OUT){
	uint64_t alpha[2];
	alpha[0] = 0;
	alpha[1] = 0xffffffffffffffff;

	for(int i=0; i<(N+63)/64*64*2; i+=2){
		mulandadd((IN->x) +i, alpha, (OUT->x)+i);
	}
}

void printBits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}

void print_block(block * b){
	for(int i=0; i<N*2; i++){
		printf("%d ", i/2);
		printBits(8, &(b->x[i]));
	}
	printf("\n");
}

void print_vect(vect * v){
	for(int i=0; i<(N+63)/64*2; i++){
		printf("%lu ", v->x[i] );
	}
	printf("\n");
}