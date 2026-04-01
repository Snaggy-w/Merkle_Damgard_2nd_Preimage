#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "hash.h"

#define HASHSIZE (1<<24)
#define HASH(h) (h[0] + (h[1]<<8) + (h[2]<<16))

typedef struct
{
    byte h[HLEN];
    byte m[BLEN];
    int8_t side;
} cell;

typedef cell* hash_tbl;

double collision(byte ms[BLEN], byte mf[BLEN], byte hf[HLEN]);
double linkmsg(byte ml[BLEN], int *ind, const byte hf[HLEN], const byte *h, size_t len);
double attack(const byte *m, size_t len, byte *m2);
