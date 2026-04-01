#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "utils.h"


void compression(byte h[HLEN], const byte m[BLEN]);
void hash(const byte *m, size_t len, byte h[HLEN]);
void intermediate_digests(const byte *m, size_t len, byte *h);

#endif // HASH_H
