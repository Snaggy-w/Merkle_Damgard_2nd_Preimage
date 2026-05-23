#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "utils.h"

/*
 * Compute H(0^len) without allocating a len-byte buffer.
 * Feeds len/BLEN zero blocks through compression(), then the
 * standard Merkle-Damgard length block, exactly as hash.c does.
 */
static void hash_zeros(size_t len, byte out[HLEN])
{
    for (int i = 0; i < HLEN; i++)
        out[i] = (IV >> (i * 8)) & 0xFF;

    size_t nb_blocks = (len + BLEN - 1) / BLEN;
    byte zero[BLEN]  = {0};
    for (size_t i = 0; i < nb_blocks; i++)
        compression(out, zero);

    /* Length block: same cast as hash.c — (int)len * 8.
     * For len = 2^32 this overflows to 0, which is intentional:
     * we must replicate hash.c exactly to get the same digest.  */
    byte last[BLEN] = {0};
    int bit_len = (int)len * 8;
    memcpy(last, &bit_len, sizeof(int));
    compression(out, last);
}

/*
 * Compute H(m2) by reading exactly `len` bytes from `fp` in chunks.
 * Uses the same Merkle-Damgård construction as hash.c.
 * Returns 1 on success, 0 on read error.
 */
static int hash_stream(FILE *fp, size_t len, byte out[HLEN])
{
    for (int i = 0; i < HLEN; i++)
        out[i] = (IV >> (i * 8)) & 0xFF;

    /* 64 MB read buffer — large enough to amortise I/O cost,
     * rounded down to a whole number of BLEN-byte blocks.     */
    const size_t BUF_BYTES = (67108864 / BLEN) * BLEN;  /* 64 MB */
    byte *buf = malloc(BUF_BYTES);
    if (!buf) { perror("malloc"); return 0; }

    size_t remaining = len;
    size_t total_read = 0;
    while (remaining > 0) {
        size_t want = (remaining < BUF_BYTES) ? remaining : BUF_BYTES;
        memset(buf, 0, want);                  /* zero-pad a potential short tail */
        size_t got = fread(buf, 1, want, fp);
        total_read += got;
        if (got != want) {
            fprintf(stderr, "hash_stream: read %zu of %zu expected bytes "
                            "(total so far: %zu / %zu)\n",
                    got, want, total_read, len);
            free(buf);
            return 0;
        }
        size_t nb = (want + BLEN - 1) / BLEN;
        for (size_t i = 0; i < nb; i++)
            compression(out, buf + i * BLEN);
        remaining -= want;
    }
    free(buf);

    byte last[BLEN] = {0};
    int bit_len = (int)len * 8;
    memcpy(last, &bit_len, sizeof(int));
    compression(out, last);
    return 1;
}

int main(int argc, char *argv[])
{
    /* BLOCKSIZE=64: target is 0^{2^32} */
    const size_t len = (size_t)1 << 32;

    printf("=== Second-preimage attack verification (BLOCKSIZE=%d) ===\n\n",
           BLOCKSIZE);
    printf("Target message : 0^{2^32}  (%zu bytes)\n", len);
    printf("Candidate m2   : %s\n\n",
           argc >= 2 ? argv[1] : "stdin");

    /* --- Step 1: H(0^{2^32}) ---------------------------------------- */
    fprintf(stderr, "Hashing zero message (2^28 compression calls)...\n");
    byte h_zero[HLEN];
    hash_zeros(len, h_zero);

    printf("H(0^{2^32}) = ");
    print_bytes(h_zero, HLEN);
    printf("\n");

    /* --- Step 2: H(m2) from file or stdin ---------------------------- */
    FILE *fp  = stdin;
    const char *src = "stdin";
    if (argc >= 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) { perror(argv[1]); return 1; }
        src = argv[1];
    }

    fprintf(stderr, "Hashing m2 from %s (reading %zu bytes)...\n", src, len);
    byte h_m2[HLEN];
    if (!hash_stream(fp, len, h_m2)) return 1;
    if (fp != stdin) fclose(fp);

    printf("H(m2)       = ");
    print_bytes(h_m2, HLEN);
    printf("\n\n");

    /* --- Step 3: compare -------------------------------------------- */
    if (memcmp(h_zero, h_m2, HLEN) == 0) {
        printf("MATCH — second preimage attack successful!\n");
        return 0;
    } else {
        printf("MISMATCH — hashes differ, attack failed.\n");
        return 1;
    }
}
