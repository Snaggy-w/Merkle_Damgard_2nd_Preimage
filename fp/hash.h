#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "utils.h"


#if BLOCKSIZE == 48

#define IV 0x050403020100

#elif BLOCKSIZE == 64

#define IV 0x0706050403020100

#else

#define IV 0x03020100

#endif

void compression(byte h[HLEN], const byte m[BLEN]);
void hash(const byte *m, size_t len, byte h[HLEN]);
void intermediate_digests(const byte *m, size_t len, byte *h);

#endif // HASH_H
