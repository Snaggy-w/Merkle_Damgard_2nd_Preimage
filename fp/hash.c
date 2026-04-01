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


void compression(byte h[HLEN], const byte m[BLEN]){
	byte hash[HLEN];
	memcpy(hash,h,HLEN);
	// h now is c -> h[i] = c[i]
	speck_enc(m,h,h);
	for(int i = 0; i < HLEN; i++){
		h[i] = h[i] ^ hash[i];
	}
}

void hash(const byte *m, size_t len, byte h[HLEN]){
	byte hash[HLEN]; // starts with IV
	for(int i = 0, i < HLEN; i++){
		hash[i] = (IV >> (i*8)) & 0xFF;
	}
	int nb_blocks = len / MLEN;
	// pad if message length is not dividable by MLEN
	byte *message = malloc(len*sizeof(byte));
	if(len % MLEN != 0){
		nb_blocks++;
		int pad_len = MLEN - (len % MLEN);
		message = realloc(message,len + pad_len);
		for(int i = 0; i < pad_len; i++){
			message[len + i] = '\0';
		}
	}
	
	for(int i = 0; i < nb_blocks; i++){
		// TODO: m[BLEN] but we need MLEN
		compression(hash,message + i);
	}

}
