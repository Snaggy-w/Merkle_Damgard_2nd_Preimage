#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"
#include "utils.h"

// SPECK_M: message to use for speck test
// HASH_M2 and HASH_M3: the second and third messages to test hashing with

#if BLOCKSIZE == 32
    #define SPECK_M   "db608390"
    #define HASH_M2   "0123456789abcdef"
    #define HASH_M3   "0123456789abcdef0123456789abcdef"
#elif BLOCKSIZE == 48
    #define SPECK_M   "dad97e7053ea"
    #define HASH_M2   "0123456789abcdef01234567"
    #define HASH_M3   "0123456789abcdef0123456789abcdef0123456789abcdef"
#else // BLOCKSIZE == 64
    #define SPECK_M   "8c8f4a901e18661a"
    #define HASH_M2   "0123456789abcdef0123456789abcdef"
    #define HASH_M3   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#endif

// cyclic key as specified in the pdf test 
#define SPECK_K "0123456789abcdef0123456789abcdef"

// test speck encryption like the pdf test
void test_speck() {
    printf("*** SPECK\n");
    byte k[KLEN], m[MLEN], c[MLEN];

    read_bytes(SPECK_K, k, KLEN);
    read_bytes(SPECK_M, m, MLEN);

    printf("Key:\n k = "); 
    print_bytes(k, KLEN); 
    printf("\n");
    
    printf("Message block:\n m = "); 
    print_bytes(m, MLEN); 
    printf("\n");

    speck_enc(k, m, c);
    printf("Ciphertext block: c = "); 
    print_bytes(c, MLEN); 
    printf("\n");
}

void test_compression() {
    printf("*** COMPRESSION\n");
    byte m[BLEN], h[HLEN];

    // m = key in the compression function
    read_bytes(SPECK_K, m, BLEN);

    // in the compression test given, h0 is IV
    for (int i = 0; i < HLEN; i++)
        h[i] = (IV >> (i * 8)) & 0xFF;

    printf("m = ");
    print_bytes(m, BLEN); 
    printf("\n");
    
    printf("h0 = ");
    print_bytes(h, HLEN);
    printf("\n");

    // Em{h0) xor h0
    compression(h, m);

    printf("f(h0,m) = ");
    print_bytes(h, HLEN);
    printf("\n");
}

// test the hashing of a single message
void test_hash_single(const char *hex_msg) {
    // the messages are strings representing bytes in hex format
    // since each two chars represent a byte we divide by 2 to get the actual length as read_bytes expects that string format
    size_t hex_len = strlen(hex_msg);
    size_t len = hex_len / 2;
    
    // copy message to buffer
    byte *m = calloc(len, 1);
    read_bytes((char*)hex_msg, m, len);

    printf("Message: m = %s\n", hex_msg);

    // hashing
    byte h[HLEN];
    hash(m, len, h);
    printf("Digest: h = ");
    print_bytes(h, HLEN);
    printf("\n");

    // intermediate digests: t + 1 (IV) + 1 (the last digest t+1)
    size_t nb_blocks = (len + BLEN - 1) / BLEN + 1; // +1 at the end to accomodate t+1 for the length digest
    size_t nb_digests = nb_blocks + 1; // +1 at the end accomodate IV for h0
    byte *hs = calloc(nb_digests * HLEN, 1);
    intermediate_digests(m, len, hs);
    printf("Intermediate digests:\n");
    for (size_t i = 0; i < nb_digests; i++) {
        printf("h[%zu] = ", i);
        print_bytes(hs + i * HLEN, HLEN);
        printf("\n");
    }

    free(m);
    free(hs);
}

// test hashing of the three messages
void test_hash() {
    printf("*** HASH\n");
    test_hash_single("01");
    test_hash_single(HASH_M2);
    test_hash_single(HASH_M3);
}

int main() {
    printf("==========================\n");
    printf("Message size: %d (%d bytes)\n", BLOCKSIZE, MLEN);
    printf("Key size: %d (%d bytes)\n", BLOCKSIZE * 2, KLEN);
    printf("==========================\n");
    
    // actual tests
    test_speck();
    test_compression();
    test_hash();

    return 0;
}
