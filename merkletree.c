#include "merkletree.h"

#define LEFT_CHILD(i) (2*i+1)
#define RIGHT_CHILD(i) (2*i+2)
#define PARENT(i) ((i-1)/2)
#define SIBLING(i) (((i)%2)? i+1 : i-1 )
#define IS_LEFT_SIBLING(i) (i%2)

void generate_seed_tree(unsigned char *seed_tree){
	int i;
	for(i=0; i<((1<<SEED_DEPTH)-1); i++){
		EXPAND(seed_tree + i*SEED_BYTES,SEED_BYTES,seed_tree + LEFT_CHILD(i)*SEED_BYTES, 2*SEED_BYTES);
	}
}

void build_tree(const unsigned char *data, int leaf_size, int depth, unsigned char *tree){
	int i;
	// hash data to get bottom layer of the tree
	for(i = 0; i<(1<<depth) ; i++){
		HASH(data+i*leaf_size, leaf_size, tree + ((1<<depth)-1+i)*HASH_BYTES);
	}

	// hash the interior of the tree
	for(i = (1<<depth)-2; i >=0; i--)
	{
		HASH(tree + LEFT_CHILD(i)*HASH_BYTES, 2*HASH_BYTES, tree + i*HASH_BYTES);
	}
}

void get_path(const unsigned char *tree, int depth, int leaf_index, unsigned char *path){
	int i;

	int index = leaf_index+(1<<depth)-1;
	// copy hash values to path
	for (i = 0; i < depth; ++i)
	{
		memcpy(path + i*HASH_BYTES,tree + SIBLING(index)*HASH_BYTES,HASH_BYTES);
		index = PARENT(index);
	}
}

void follow_path(const unsigned char *leaf, int leaf_size, int depth, const unsigned char *path, int leaf_index, unsigned char *root){
	unsigned char in_buf[2*HASH_BYTES];
	int i;

	int index = leaf_index+LEAVES-1;

	// hash leaf data
	HASH(leaf,leaf_size,root);

	//hash up the tree
	for (i = 0; i < depth; ++i)
	{
		if(IS_LEFT_SIBLING(index)){
			memcpy(in_buf,root,HASH_BYTES);
			memcpy(in_buf+HASH_BYTES,path+i*HASH_BYTES,HASH_BYTES);
		}
		else {
			memcpy(in_buf+HASH_BYTES,root,HASH_BYTES);
			memcpy(in_buf,path+i*HASH_BYTES,HASH_BYTES);
		}
		
		HASH(in_buf,2*HASH_BYTES,root);
		index = PARENT(index);
	}
}

void fill_tree(const unsigned char *indices, unsigned char *tree, int depth){
	int i;

	// 1 = cannot be released
	// 0 = has to be released
	memcpy(tree+(1<<depth)-1,indices, 1<<depth);

	// fill up the internal part of tree
	for(i= (1<<depth)-2; i>=0; i--){
		if((tree[LEFT_CHILD(i)] == 0)  && (tree[RIGHT_CHILD(i)] == 0) ){
			tree[i] = 0;
		}
		else{
			tree[i] = 1;
		}
	}
}

void release_nodes(unsigned char *tree, int node_size, int depth, unsigned char *indices, unsigned char *out, uint16_t *nodes_released ){
	(*nodes_released) = 0;
	unsigned char class_tree[(2<<SEED_DEPTH) -1] = {0};
	fill_tree(indices,class_tree,depth);

	int i;
	for(i=0; i<(2<<depth)-1; i++){
		if((class_tree[i] == 0) && (class_tree[PARENT(i)] == 1)){
			memcpy(out + ((*nodes_released)++)*node_size, tree + i*node_size, node_size);
		}
	}
}

void fill_down(unsigned char *tree, const unsigned char *indices, const unsigned char *in, uint16_t *nodes_used){
	unsigned char class_tree[(2<<SEED_DEPTH) -1] = {0};
	fill_tree(indices,class_tree,SEED_DEPTH);

	int i;
	(*nodes_used) = 0;
	for(i=0; i<(2<<SEED_DEPTH)-1; i++){
		if(class_tree[i] == 0){
			if(class_tree[PARENT(i)] == 1){
				memcpy(tree + SEED_BYTES*i, in + SEED_BYTES*((*nodes_used)++), SEED_BYTES);
			}
			if(i<(1<<SEED_DEPTH)-1){
				EXPAND(tree + SEED_BYTES*i, SEED_BYTES,tree + SEED_BYTES*LEFT_CHILD(i), 2*SEED_BYTES);
			}
		}
	}
}

void hash_up(unsigned char *data, unsigned char *indices, const unsigned char *in, int in_len, unsigned char *root){
	unsigned char tree[((2<<SEED_DEPTH)-1)*HASH_BYTES] = {0};

	unsigned char class_tree[(2<<SEED_DEPTH) -1] = {0};
	fill_tree(indices,class_tree,SEED_DEPTH);

	int i;
	int nodes_not_used = in_len;
	// hash data to get bottom layer of the tree
	for(i = ((2<<SEED_DEPTH) -2) ; i>=((1<<SEED_DEPTH) -1) ; i--){
		if(class_tree[i] == 1){
			HASH(data+ (i-((1<<SEED_DEPTH) -1))*HASH_BYTES, HASH_BYTES, tree + i*HASH_BYTES);
		} 
		else if (class_tree[SIBLING(i)] == 1){
			memcpy(tree + i*HASH_BYTES , in + HASH_BYTES*(--nodes_not_used), HASH_BYTES );
		}
	}

	// hash the interior of the tree
	for(i = (1<<SEED_DEPTH)-2; i >=0; i--)
	{
		if(class_tree[i] == 1){
			HASH(tree + LEFT_CHILD(i)*HASH_BYTES, 2*HASH_BYTES, tree + i*HASH_BYTES);
		}
		else if( class_tree[SIBLING(i)] ==  1 ){
			memcpy(tree + i*HASH_BYTES , in + HASH_BYTES*(--nodes_not_used), HASH_BYTES );
		}
	}

	memcpy(root,tree,HASH_BYTES);
}

void print_seed(const unsigned char *seed){
	int i=0;
	for(i=0; i<SEED_BYTES ; i++){
		printf("%2X ", seed[i]);
	}
	printf("\n");
}

void print_hash(const unsigned char *hash){
	int i=0;
	for(i=0; i<HASH_BYTES ; i++){
		printf("%2X ", hash[i]);
	}
	printf("\n");
}

void print_tree(const unsigned char *tree, int depth){
	int i=0;
	for(i=0; i<(2<<depth)-1 ; i++){
		printf("%4d: ", i);
		print_hash(tree + HASH_BYTES*i);
	}
	printf("\n");
}