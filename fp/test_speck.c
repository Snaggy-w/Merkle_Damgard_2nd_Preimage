#include <stdio.h>
#include "utils.h"

int main(int argc, char* argv[]) {
    size_t i;
    printf("Message size: %d (%d bytes)\nKey size: %d (%d bytes)\n",MLEN<<3,MLEN,KLEN<<3,KLEN);
   
    byte k[KLEN];
    byte m[MLEN], c[MLEN], d[MLEN];

    if (argc > 1) 
        read_bytes(argv[1],k,KLEN);
    else 
        random_bytes(k, KLEN);

    if (argc > 2)
        read_bytes(argv[2],m,MLEN);
    else
        random_bytes(m, MLEN);

    printf("Key:              k = "); print_bytes(k,KLEN); printf("\n");
    printf("Message block:    m = "); print_bytes(m, MLEN); printf("\n");

    speck_enc(k,m,c);
    
    printf("Ciphertext block: c = "); print_bytes(c, MLEN); printf("\n");

    speck_dec(k,d,c);
    
    printf("Decrypted block:  d = "); print_bytes(d, MLEN); printf("\n");

    return 0;

}
