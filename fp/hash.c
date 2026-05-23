#include <string.h>
#include <stdlib.h>
#include "hash.h"
#include "utils.h"




#if BLOCKSIZE == 48

#define IV 0x050403020100

#elif BLOCKSIZE == 64

#define IV 0x0706050403020100

#else

#define IV 0x03020100

#endif



// in util.c 
// 	for BLOCKSIZE = {32,48,64}
// HLEN = MLEN = {4,6,8}
// BLEN = KLEN = {8,12,16}



// Davies-Meyer construction: f(h,m) = Em(h) xor h

// m is the key and h is the plain text message
void compression(byte h[HLEN], const byte m[BLEN]){
	// save original h into hash
	byte hash[HLEN];
	memcpy(hash,h,HLEN);
	// h now is c -> h[i] = c[i]
	// h = Em(h)
	speck_enc(m,h,h); 
	for(int i = 0; i < HLEN; i++){
		h[i] = h[i] ^ hash[i]; // Em(h) xor h
	}
}

void hash(const byte *m, size_t len, byte h[HLEN]){
	// h starts with IV
	// copy the IV into hash my own way cuz why not :)
	for(int i = 0; i < HLEN; i++){
		h[i] = (IV >> (i*8)) & 0xFF;
	}

	// we always have a mandatory padded block (even if perfectly divisible)
	size_t nb_blocks = (len + BLEN - 1) / BLEN;


	byte *message = calloc(nb_blocks * BLEN, 1); // create a padded message buffer
	// copy the message to the padded buffer
	memcpy(message,m,len);
	
	// flip the very first bit (should be 0) after the actual message to 
	// produce a 100...000 padding like we saw in the TD
	
	//*(message + len) ^= 0b10000000; 
	
	// the padding strategy as far as I understood is just padding with zeros


	for(int i = 0; i < nb_blocks; i++){
		compression(h,message + i * BLEN); // iterate block by block
	}

	// last iteration is an additional block with the message length
	// as the content of that block
	
	byte *last_block = calloc(BLEN,1);
	// the assignment describes |m| as bit length so we just multiply len by 8
	int bit_length = (int)len * 8;
	memcpy(last_block,&bit_length,sizeof(int)); // last block contains |m|
	
	// ht+1 = E_|m|(h) xor h
	compression(h,last_block);


	// free allocated buffers
	free(message);
	free(last_block);

}


// same as hash but we just save intermediate steps
void intermediate_digests(const byte *m, size_t len, byte *h){
	// hash starts with IV
	
	byte hash[HLEN] = {0};
	// copy the IV into hash my own way cuz why not :)
	for(int i = 0; i < HLEN; i++){
		hash[i] = (IV >> (i*8)) & 0xFF;
	}
	// store IV as very first h
	memcpy(h, hash, HLEN);

	// we always have a mandatory padded block (even if perfectly divisible)
	size_t nb_blocks = (len + BLEN - 1) / BLEN;


	byte *message = calloc(nb_blocks * BLEN, 1); // create a padded message buffer
	// copy the message to the padded buffer
	memcpy(message,m,len);
	
	
	// the padding strategy as far as I understood is just padding with zeros 
	int i = 0;
	for(i = 0; i < nb_blocks; i++){
		compression(hash,message + i * BLEN); // iterate block by block
		memcpy(h + ((i + 1)* HLEN),hash,HLEN); // save intermediate hash in h, we start from h[1] and go up to h[t]
	}

	// last iteration is an additional block with the message length
	// as the content of that block
	
	byte *last_block = calloc(BLEN,1);
	// the assignment describes |m| as bit length so we just multiply len by 8
	int bit_length = (int)len * 8;
	memcpy(last_block,&bit_length,sizeof(int)); // last block contains |m|
	
	// ht+1 = E_|m|(h) xor h
	compression(hash,last_block);
	memcpy(h + ((i + 1) * HLEN),hash,HLEN); // save last hash, i should be incremented by the loop to point now to the last index

	// free allocated buffers
	free(message);
	free(last_block);

}
