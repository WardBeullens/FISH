#ifndef F4_H
#define F4_H 

#include "stdint.h"
#include "stdio.h"
#include "parameters.h"

typedef struct block { uint64_t x[(N+63)/64*64*2]; } block;
typedef struct vect  { uint64_t x[(N+63)/64*2]; } vect;

void add(const uint64_t *A, uint64_t *out);
void mulandadd(const uint64_t *A, const uint64_t *B, uint64_t *out);

void add_block(block* A, block*B);
void times_alpha_block(block* IN, block*OUT);

void printBits(size_t const size, void const * const ptr);
void print_block(block * b);

void copy_vect(vect *in, vect *out);
void print_vect(vect * v);

#endif