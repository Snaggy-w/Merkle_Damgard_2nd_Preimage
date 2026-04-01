#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define byte uint8_t

#ifndef BLOCKSIZE
#define BLOCKSIZE 32
#endif

#if BLOCKSIZE == 32
  #define KLEN 8 // key byte-length for SPECK
  #define MLEN 4 // message byte-length for SPECK
#elif BLOCKSIZE == 48
  #define KLEN 12 // key byte-length for SPECK
  #define MLEN 6 // message byte-length for SPECK
#else // BLOCKSIZE == 64 
  #define KLEN 16 // key byte-length for SPECK
  #define MLEN 8 // message byte-length for SPECK
#endif

#define BLEN KLEN // block byte-length for the hash function
#define HLEN MLEN // digest byte-length of the hash function
                            

void speck_enc(const byte k[KLEN], const byte m[MLEN], byte c[MLEN]);
void speck_dec(const byte k[KLEN], byte m[MLEN], const byte c[MLEN]);
void random_init(uint64_t seed[4]);
void random_bytes(byte* array, size_t len);
void print_bytes(const byte *array, size_t len);
void read_bytes(char* str, byte *array, size_t len);

#endif // UTILS_H
