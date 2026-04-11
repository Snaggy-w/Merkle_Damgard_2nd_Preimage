#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "hash.h"
#include "utils.h"
#include "attack.h"

// I don't get the math behind the output, they seem close to powers of 2 but they are not
#if BLOCKSIZE == 32
    // must be that?
    //#define MSG_LEN (1 << 16)
    #define MSG_LEN 65686 // the message length of the pdf demo
    #define PRINT_BYTES 80  // bytes to print on each truncation of the output
#elif BLOCKSIZE == 48
    //#define MSG_LEN (1 << 24)
    #define MSG_LEN 16777446 // the message length of the pdf demo
    #define PRINT_BYTES 120  // bytes to print on each truncation of the output
#else
    // idk honestly...
    #define MSG_LEN (1 << 32)
    #define PRINT_BYTES 160
#endif


// truncated print hex encoded bytes
void print_truncated(const byte *m, size_t len) {
    if (len <= 2 * PRINT_BYTES) {
        print_bytes(m, len);
    } else {
        // print first PRINT_BYTES bytes
        for (size_t i = 0; i < PRINT_BYTES; i++)
            printf("%02x", m[len - 1 - i]);
        printf(" ... (%zu more bytes) ... ", len - 2 * PRINT_BYTES);
        // print last PRINT_BYTES bytes
        for (size_t i = PRINT_BYTES; i > 0; i--)
            printf("%02x", m[i - 1]);
    }
    printf("\n");
}

// test step 1 in the attack
void test_collision() {
    printf("*** Collision\n");
    byte ms[BLEN], mf[BLEN], hf[HLEN];
    double count = collision(ms, mf, hf); // get power of 2 representation of the number of samples via log base 2
    printf("Collision found using approx. 2^%f samples:\n", log2(count));

    printf("ms = ");
    print_bytes(ms, BLEN);
    printf("\n");

    printf("mf = ");
    print_bytes(mf, BLEN);
    printf("\n");
    
    printf("hf = ");
    print_bytes(hf, HLEN);
    printf("\n");
}

// test step 2 of the attack
void test_linkmsg(const byte *m, size_t len) {
    printf("*** Link message\n");

    // need hf first from collision, so we call collision again
    byte ms[BLEN], mf[BLEN], hf[HLEN];
    collision(ms, mf, hf);

    // get intermediate digests
    size_t nb_blocks = (len + BLEN - 1) / BLEN;
    size_t nb_digests = nb_blocks + 2;
    byte *h = calloc(nb_digests * HLEN, 1);
    intermediate_digests(m, len, h);

    byte ml[BLEN];
    int ind;
    double count = linkmsg(ml, &ind, hf, h, len);

    // compute f(hf, ml) to display
    byte tmp[HLEN];
    memcpy(tmp, hf, HLEN);
    compression(tmp, ml);

    printf("Link msg found using approx. 2^%f samples:\n", log2(count));

    printf("m = ");
    print_bytes(ml, BLEN);
    printf("\n");

    printf("f(");
    print_bytes(hf, HLEN);
    printf(",");
    print_bytes(ml, BLEN);
    printf(") = ");
    print_bytes(tmp, HLEN);
    printf("\n");
    
    printf("Intermediate digest h[%d] = ", ind);
    print_bytes(h + ind * HLEN, HLEN);
    printf("\n");

    free(h);
}

void test_full_attack(const byte *m, size_t len) {
    printf("*** Full attack\n");

    // compute H(m)
    byte hm[HLEN];
    hash(m, len, hm);

    // allocate m2 to be same length as m
    byte *m2 = calloc(len, 1);
    double count = attack(m, len, m2);

    // compute H(m2) to prove that it should be equal to H(m)
    byte hm2[HLEN];
    hash(m2, len, hm2);

    printf("Attack using approx. 2^%f samples:\n", log2(count));

    printf("H(m) = ");
    print_bytes(hm, HLEN);
    printf("\n");

    printf("H(m2)= ");
    print_bytes(hm2, HLEN);
    printf("\n");

    printf("m = ");
    print_truncated(m, len);
    printf("m2= ");
    print_truncated(m2, len);

    free(m2);
}

int main() {
    printf("===========================\n");
    printf("Hash size: %d (%d bytes)\n", BLOCKSIZE, HLEN);
    printf("Block length: %d (%d bytes)\n", BLOCKSIZE * 2, BLEN);
    printf("==========================\n");

    // generate large random message
    size_t len = MSG_LEN;
    byte *m = calloc(len, 1);
    random_bytes(m, len);

    test_collision();
    test_linkmsg(m, len);
    test_full_attack(m, len);

    free(m);
    return 0;
}
