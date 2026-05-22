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
    // MSG_LEN for the challenge 0^32 (I presume 32 bits of zeros)
    #define MSG_LEN (1 << 32)
    #define PRINT_BYTES 160
#endif


#if BLOCKSIZE != 64

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
    size_t nb_blocks = (len + BLEN - 1) / BLEN;
    byte *m2 = calloc(nb_blocks * BLEN, 1);//calloc(len, 1);
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


// 64-bit challenge
//
// Target message: 2^32 zero bytes  (0^{2^32} in crypto notation)
// We cannot materialise the ~4 GB second preimage m2 in memory, so instead
// we print a self-contained Python 3 script to stdout.  Redirect it to a file:
//
//   ./test_attack > gen_m2.py
//   python3 gen_m2.py > m2.bin          # streams ~4 GB to disk
//
// Checkpoints are written after each expensive step so that on a crash or
// Ctrl-C the computation can resume without restarting from scratch:
//   ckpt_collision.bin  — saved after step 1 (collision search)
//   ckpt_linkmsg.bin    — saved after step 3 (linkmsg search)
// Delete them to force a full restart.
//
// Memory budget (BLOCKSIZE=64):
//   collision table   HASHSIZE(=2^30) × sizeof(cell)  ≈ 25 GB  (step 1)
//   intermediate h    (2^28+2) × 8 bytes              ≈  2 GB  (step 2)
//   linkmsg LUT       LUT_MAX_ENTRIES×4 × 12 bytes    ≈  0.75 GB (step 3)
// You will need a machine with ≥ 28 GB RAM for step 1.
// If your machine has less, reduce HASHSIZE in the Makefile for step 1.
#else

/* ------------------------------------------------------------------ *
 *  Checkpoint helpers — tiny binary files, one per expensive step.   *
 *  Format is fixed-size raw bytes; fields written in declaration      *
 *  order with no padding (use only scalar types and byte arrays).    *
 * ------------------------------------------------------------------ */

#define CKPT_COLLISION "ckpt_collision.bin"
#define CKPT_LINKMSG   "ckpt_linkmsg.bin"

/* Step 1: ms[BLEN] | mf[BLEN] | hf[HLEN] | count(double) */
static int save_collision(const byte *ms, const byte *mf, const byte *hf, double count)
{
    FILE *f = fopen(CKPT_COLLISION, "wb");
    if (!f) { perror("save_collision: fopen"); return 0; }
    int ok = (fwrite(ms,     1,             BLEN,   f) == (size_t)BLEN  &&
              fwrite(mf,     1,             BLEN,   f) == (size_t)BLEN  &&
              fwrite(hf,     1,             HLEN,   f) == (size_t)HLEN  &&
              fwrite(&count, sizeof(double), 1,     f) == 1);
    fclose(f);
    if (ok) fprintf(stderr, "  checkpoint saved: %s\n", CKPT_COLLISION);
    return ok;
}

static int load_collision(byte *ms, byte *mf, byte *hf, double *count)
{
    FILE *f = fopen(CKPT_COLLISION, "rb");
    if (!f) return 0;
    int ok = (fread(ms,     1,             BLEN,   f) == (size_t)BLEN  &&
              fread(mf,     1,             BLEN,   f) == (size_t)BLEN  &&
              fread(hf,     1,             HLEN,   f) == (size_t)HLEN  &&
              fread(count,  sizeof(double), 1,     f) == 1);
    fclose(f);
    return ok;
}

/* Step 3: ml[BLEN] | link_idx(int) | count(double) */
static int save_linkmsg(const byte *ml, int link_idx, double count)
{
    FILE *f = fopen(CKPT_LINKMSG, "wb");
    if (!f) { perror("save_linkmsg: fopen"); return 0; }
    int ok = (fwrite(ml,        1,             BLEN,   f) == (size_t)BLEN &&
              fwrite(&link_idx, sizeof(int),    1,     f) == 1             &&
              fwrite(&count,    sizeof(double), 1,     f) == 1);
    fclose(f);
    if (ok) fprintf(stderr, "  checkpoint saved: %s\n", CKPT_LINKMSG);
    return ok;
}

static int load_linkmsg(byte *ml, int *link_idx, double *count)
{
    FILE *f = fopen(CKPT_LINKMSG, "rb");
    if (!f) return 0;
    int ok = (fread(ml,        1,             BLEN,   f) == (size_t)BLEN &&
              fread(link_idx,  sizeof(int),    1,     f) == 1             &&
              fread(count,     sizeof(double), 1,     f) == 1);
    fclose(f);
    return ok;
}

/* Helper: print BLEN bytes as a lowercase hex string (no spaces, no newline). */
static void print_hex(const byte *buf, size_t n) {
    for (size_t i = 0; i < n; i++)
        printf("%02x", buf[i]);
}

int main(void) {
    fprintf(stderr, "BLOCKSIZE=64 attack on 0^{2^32}\n");
    fprintf(stderr, "Target: 2^32 zero bytes | BLEN=%d HLEN=%d\n\n", BLEN, HLEN);

    const size_t len      = (size_t)1 << 32;      /* 4 GB — must not be plain int */
    size_t nb_blocks      = (len + BLEN - 1) / BLEN;   /* = 2^28 */

    byte   ms[BLEN], mf[BLEN], hf[HLEN];
    byte   ml[BLEN];
    int    link_idx = -1;
    double count1 = 0.0, count3 = 0.0;

    /* ---------------------------------------------------------------- *
     * Step 1 — collision: h0 -[ms]-> hf, E^{-1}_{mf}(0) = hf         *
     * Checkpoint: ckpt_collision.bin                                   *
     * ---------------------------------------------------------------- */
    if (load_collision(ms, mf, hf, &count1)) {
        fprintf(stderr, "[Step 1] Loaded from checkpoint %s  (~2^%.2f samples)\n",
                CKPT_COLLISION, log2(count1));
    } else {
        fprintf(stderr, "[Step 1] Collision search (expect ~2^32 samples)...\n");
        count1 = collision(ms, mf, hf);
        fprintf(stderr, "  done: ~2^%.2f samples\n", log2(count1));
        save_collision(ms, mf, hf, count1);
    }

    /* ---------------------------------------------------------------- *
     * Step 3 can be skipped entirely if its checkpoint already exists. *
     * Step 2 (intermediate digests) is fast (~3 s) and not persisted. *
     * ---------------------------------------------------------------- */
    if (load_linkmsg(ml, &link_idx, &count3)) {
        fprintf(stderr, "[Step 3] Loaded from checkpoint %s  (link_idx=%d, ~2^%.2f samples)\n",
                CKPT_LINKMSG, link_idx, log2(count3));
    } else {
        /* ------------------------------------------------------------ *
         * Step 2 — intermediate digests.                               *
         * Recomputed each run (fast, and h would be another 2 GB file). *
         * ------------------------------------------------------------ */
        fprintf(stderr, "[Step 2] Computing intermediate digests (~2 GB)...\n");
        byte *m = calloc(len, 1);   /* target message: 4 GB of zeros */
        if (!m) { fprintf(stderr, "OOM allocating target message\n"); return 1; }

        size_t nb_digests = nb_blocks + 2;
        byte  *h          = calloc(nb_digests, HLEN);
        if (!h) { fprintf(stderr, "OOM allocating digest array\n"); free(m); return 1; }

        intermediate_digests(m, len, h);
        free(m);   /* no longer needed */
        fprintf(stderr, "  done.\n");

        /* ------------------------------------------------------------ *
         * Step 3 — linkmsg: hf -[ml]-> h[link_idx]                    *
         * Checkpoint: ckpt_linkmsg.bin                                 *
         * ------------------------------------------------------------ */
        fprintf(stderr, "[Step 3] linkmsg search (LUT_MAX_ENTRIES=%zu, expect ~2^%.0f samples)...\n",
                (size_t)LUT_MAX_ENTRIES,
                64.0 - log2((double)LUT_MAX_ENTRIES));
        count3 = linkmsg(ml, &link_idx, hf, h, len);
        free(h);
        fprintf(stderr, "  done: link_idx=%d  ~2^%.2f samples\n", link_idx, log2(count3));
        save_linkmsg(ml, link_idx, count3);
    }

    /* ---------------------------------------------------------------- *
     * Step 4 — validate and compute m2 parameters.                    *
     * m2 = ms || mf^k || ml || 0^suffix_zeros                         *
     * ---------------------------------------------------------------- */
    if (link_idx < 2) {
        fprintf(stderr, "Attack failed: link_idx=%d < 2 (need i >= 2). "
                        "Delete checkpoints and retry.\n", link_idx);
        return 1;
    }

    long long k            = (long long)link_idx - 2;
    size_t    suffix_zeros = ((size_t)(nb_blocks - (size_t)link_idx)) * (size_t)BLEN;
    size_t    total_bytes  = (size_t)BLEN
                           + (size_t)k * (size_t)BLEN
                           + (size_t)BLEN
                           + suffix_zeros;

    fprintf(stderr, "\n--- m2 parameters ---\n");
    fprintf(stderr, "  k            = %lld  (mf repetitions)\n", k);
    fprintf(stderr, "  suffix_zeros = %zu bytes (all zeros from original msg)\n", suffix_zeros);
    fprintf(stderr, "  total |m2|   = %zu bytes  (expected %zu)\n", total_bytes, len);
    fprintf(stderr, "  total work   = ~2^%.2f compression calls\n", log2(count1 + count3));
    fprintf(stderr, "\nWriting Python generator to stdout...\n");

    /* ---------------------------------------------------------------- *
     * Step 5 — emit Python script that streams m2 to stdout.          *
     *                                                                  *
     * The script never builds the full multi-GB bytes object in RAM:   *
     *  - mf^k is written in 64 KB chunks                              *
     *  - the zero suffix is written in 64 KB bytearray slices         *
     * ---------------------------------------------------------------- */
    printf("#!/usr/bin/env python3\n");
    printf("\"\"\"Generated by test_attack (BLOCKSIZE=64).\n");
    printf("\n");
    printf("Streams m2, a second preimage of 0^{2^32}, to stdout as raw bytes.\n");
    printf("  python3 gen_m2.py > m2.bin           # ~4 GB file\n");
    printf("  python3 gen_m2.py | your_verifier    # pipe without touching disk\n");
    printf("\n");
    printf("Structure: ms || mf^k || ml || 0^suffix_zeros\n");
    printf("Total:     %zu bytes\n", total_bytes);
    printf("Work:     ~2^%.2f compression calls\n", log2(count1 + count3));
    printf("\"\"\"\n");
    printf("import sys\n\n");

    printf("ms           = bytes.fromhex('"); print_hex(ms, BLEN); printf("')\n");
    printf("mf           = bytes.fromhex('"); print_hex(mf, BLEN); printf("')\n");
    printf("ml           = bytes.fromhex('"); print_hex(ml, BLEN); printf("')\n");
    printf("k            = %lld\n", k);
    printf("suffix_zeros = %zu\n\n", suffix_zeros);

    printf("out = sys.stdout.buffer\n");
    printf("out.write(ms)\n\n");

    printf("# mf repeated k times — written in 64 KB chunks to avoid a huge bytes object.\n");
    printf("if k > 0:\n");
    printf("    REPS  = max(1, 65536 // len(mf))   # ~4096 copies per chunk for BLEN=16\n");
    printf("    chunk = mf * REPS\n");
    printf("    full, rem = divmod(k, REPS)\n");
    printf("    for _ in range(full):\n");
    printf("        out.write(chunk)\n");
    printf("    if rem:\n");
    printf("        out.write(mf * rem)\n\n");

    printf("out.write(ml)\n\n");

    printf("# Suffix: all zeros (original message was 0^{2^32}).\n");
    printf("if suffix_zeros > 0:\n");
    printf("    CHUNK = 1 << 16\n");
    printf("    buf   = bytearray(CHUNK)\n");
    printf("    left  = suffix_zeros\n");
    printf("    while left > 0:\n");
    printf("        n = min(CHUNK, left)\n");
    printf("        out.write(memoryview(buf)[:n])\n");
    printf("        left -= n\n");

    return 0;
}

#endif
