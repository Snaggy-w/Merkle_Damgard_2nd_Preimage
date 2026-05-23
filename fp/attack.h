/*#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "hash.h"

// hash size defined in the makefile to scale with block size (2^24 is not enough for 64 bit ones so we need larger tables to accomodate all entries in the table)
#ifndef HASHSIZE
#define HASHSIZE (1<<24) // hashtable size (2^24): 3 bytes to represent the index in hashtable
#endif

#define HASH(h) (h[0] + (h[1]<<8) + (h[2]<<16)) // take the first 3 bytes of hash digest

typedef struct
{
    byte h[HLEN]; // the digest
    byte m[BLEN]; // the block that produced the digest
    int8_t side; // from which side the entry came: left = 1, right = -1, neither (empty cell) = 0
} cell;

typedef cell* hash_tbl;

double collision(byte ms[BLEN], byte mf[BLEN], byte hf[HLEN]);
double linkmsg(byte ml[BLEN], int *ind, const byte hf[HLEN], const byte *h, size_t len);
double attack(const byte *m, size_t len, byte *m2);*/

// DO NOT CHANGE THIS FILE

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

