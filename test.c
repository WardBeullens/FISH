#include <stdio.h>
#include <stdint.h>
#include "sign.h"

#define TRIALS 1000

static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %lu \n",#A ,rdtsc() - cl); cl = rdtsc();

void main(){

	//test();
	//return;

	int executions_done,i;
	unsigned char pk[PK_BYTES] = {0};
	unsigned char sk[SK_BYTES] = {0};

	printf("pk bytes : %ld\n", PK_BYTES );
	printf("sk bytes : %d\n", SK_BYTES );

	unsigned char message[1];
	message[0] = 42;
	unsigned char sig[SIG_BYTES];
	uint64_t sig_len;


	uint64_t keygenTime = 0;
	uint64_t signTime = 0;
	uint64_t verifyTime = 0;
	uint64_t sig_size = 0;
	uint64_t sig_size_max = 0;
	uint64_t sig_size_min = 10000000;
	uint64_t t;

	for(int i=0 ; i<TRIALS; i++){
		t = rdtsc();
		keygen(pk,sk);
		keygenTime += rdtsc()-t;

		t = rdtsc();
		sign(sk,pk,message,1,sig,&sig_len);
		signTime += rdtsc()-t;
		sig_size += sig_len;

		sig_size_max = ( sig_len > sig_size_max ? sig_len : sig_size_max );
		sig_size_min = ( sig_len > sig_size_min ? sig_size_min : sig_len );

		t = rdtsc();
		int ver = verify(pk,message,1,sig);
		verifyTime += rdtsc()-t;

		if(ver <0){
			printf("Signature invalid! \n");
		}
	}

	printf("average sig bytes: %ld\n", sig_size/TRIALS); 
	printf("maximum sig bytes: %ld\n", sig_size_max); 
	printf("minimum sig bytes: %ld\n\n", sig_size_min); 

	printf("keygen cycles :       %lu \n", keygenTime/TRIALS );
	printf("signing cycles :      %lu \n", signTime/TRIALS );
	printf("verification cycles : %lu \n", verifyTime/TRIALS );

}