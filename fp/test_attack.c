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


// 64 bit challenge
#else

/* ------------------------------------------------------------------ *
 * Checkpoint helpers — save/load each expensive step to a small file *
 * so the program can resume after a crash or Ctrl-C.                 *
 *                                                                     *
 * File formats (raw binary, no padding):                             *
 *   ckpt_collision.bin : ms[BLEN] | mf[BLEN] | hf[HLEN] | count(double) *
 *   ckpt_linkmsg.bin   : ml[BLEN] | link_idx(int) | count(double)    *
 *                                                                     *
 * Delete the files to force a full restart.                          *
 * ------------------------------------------------------------------ */

#define CKPT_COLLISION "ckpt_collision.bin"
#define CKPT_LINKMSG   "ckpt_linkmsg.bin"

static int save_collision(const byte *ms, const byte *mf,
                          const byte *hf, double count)
{
    FILE *f = fopen(CKPT_COLLISION, "wb");
    if (!f) { perror("save_collision"); return 0; }
    int ok = fwrite(ms,     1,              BLEN, f) == (size_t)BLEN
          && fwrite(mf,     1,              BLEN, f) == (size_t)BLEN
          && fwrite(hf,     1,              HLEN, f) == (size_t)HLEN
          && fwrite(&count, sizeof(double), 1,    f) == 1;
    fclose(f);
    if (ok) fprintf(stderr, "  saved %s\n", CKPT_COLLISION);
    return ok;
}

static int load_collision(byte *ms, byte *mf, byte *hf, double *count)
{
    FILE *f = fopen(CKPT_COLLISION, "rb");
    if (!f) return 0;
    int ok = fread(ms,     1,              BLEN, f) == (size_t)BLEN
          && fread(mf,     1,              BLEN, f) == (size_t)BLEN
          && fread(hf,     1,              HLEN, f) == (size_t)HLEN
          && fread(count,  sizeof(double), 1,    f) == 1;
    fclose(f);
    return ok;
}

static int save_linkmsg(const byte *ml, int link_idx, double count)
{
    FILE *f = fopen(CKPT_LINKMSG, "wb");
    if (!f) { perror("save_linkmsg"); return 0; }
    int ok = fwrite(ml,        1,              BLEN, f) == (size_t)BLEN
          && fwrite(&link_idx, sizeof(int),    1,    f) == 1
          && fwrite(&count,    sizeof(double), 1,    f) == 1;
    fclose(f);
    if (ok) fprintf(stderr, "  saved %s\n", CKPT_LINKMSG);
    return ok;
}

static int load_linkmsg(byte *ml, int *link_idx, double *count)
{
    FILE *f = fopen(CKPT_LINKMSG, "rb");
    if (!f) return 0;
    int ok = fread(ml,        1,              BLEN, f) == (size_t)BLEN
          && fread(link_idx,  sizeof(int),    1,    f) == 1
          && fread(count,     sizeof(double), 1,    f) == 1;
    fclose(f);
    return ok;
}

static void print_hex(const byte *buf, size_t n) {
    for (size_t i = 0; i < n; i++)
        printf("%02x", buf[i]);
}

int main(void) {
    fprintf(stderr, "BLOCKSIZE=64 attack on 0^{2^32}\n");
    fprintf(stderr, "Target message: 2^32 zero bytes\n\n");

    /* MSG_LEN = (size_t)1 << 32 — must use size_t to avoid 32-bit UB. */
    const size_t len = (size_t)1 << 32;

    /* ------------------------------------------------------------------ *
     * Step 0 – allocate and zero-fill the target message.                *
     * calloc gives zeroed memory, which is exactly our target: 0^{2^32}. *
     * ------------------------------------------------------------------ */
    fprintf(stderr, "Allocating target message (%.1f GB)...\n",
            (double)len / (1ULL << 30));
    byte *m = calloc(len, 1);
    if (!m) { fprintf(stderr, "OOM allocating m\n"); return 1; }

    /* ------------------------------------------------------------------ *
     * Step 1 – find fixed-point collision (or load from checkpoint).     *
     * ------------------------------------------------------------------ */
    byte ms[BLEN], mf[BLEN], hf[HLEN];
    double count = 0.0;
    double c1 = 0.0;
    if (load_collision(ms, mf, hf, &c1)) {
        fprintf(stderr, "Step 1: loaded from %s (~2^%.2f samples)\n",
                CKPT_COLLISION, log2(c1));
        count += c1;
    } else {
        fprintf(stderr, "Step 1: collision search...\n");
        c1 = collision(ms, mf, hf);
        count += c1;
        fprintf(stderr, "  collision found using ~2^%.2f samples\n", log2(c1));
        save_collision(ms, mf, hf, c1);
    }

    /* ------------------------------------------------------------------ *
     * Step 2 – compute all intermediate digests of m.                   *
     * ------------------------------------------------------------------ */
    fprintf(stderr, "Step 2: computing intermediate digests (~2 GB)...\n");
    size_t nb_blocks  = (len + BLEN - 1) / BLEN;   /* = 2^28 */
    size_t nb_digests = nb_blocks + 2;
    byte  *h          = calloc(nb_digests, HLEN);
    if (!h) { fprintf(stderr, "OOM allocating digest array\n"); free(m); return 1; }
    intermediate_digests(m, len, h);

    /* We no longer need the raw message bytes. */
    free(m);  m = NULL;

    /* ------------------------------------------------------------------ *
     * Step 3 – find linking block ml (or load from checkpoint).          *
     * ------------------------------------------------------------------ */
    byte ml[BLEN];
    int  link_idx;
    double c3 = 0.0;
    if (load_linkmsg(ml, &link_idx, &c3)) {
        fprintf(stderr, "Step 3: loaded from %s (link_idx=%d, ~2^%.2f samples)\n",
                CKPT_LINKMSG, link_idx, log2(c3));
        count += c3;
    } else {
        fprintf(stderr, "Step 3: linkmsg search...\n");
        c3 = linkmsg(ml, &link_idx, hf, h, len);
        count += c3;
        fprintf(stderr, "  linkmsg found using ~2^%.2f samples (i=%d)\n",
                log2(c3), link_idx);
        save_linkmsg(ml, link_idx, c3);
    }
    free(h);  h = NULL;

    /* ------------------------------------------------------------------ *
     * Step 4 – compute k and suffix.                                     *
     *                                                                     *
     * m2 = ms || mf^k || ml || 0^suffix_zeros                           *
     * k = link_idx - 2  (so total block count equals nb_blocks)         *
     * suffix is zero bytes because m was all zeros.                      *
     * ------------------------------------------------------------------ */
    if (link_idx < 2) {
        fprintf(stderr, "Attack failed: link_idx=%d < 2\n", link_idx);
        return 1;
    }

    /* Use long long / size_t to avoid overflow for large indices. */
    long long  k            = (long long)link_idx - 2;
    size_t     suffix_zeros = ((size_t)(nb_blocks - (size_t)link_idx)) * (size_t)BLEN;
    size_t     total_bytes  = (size_t)BLEN              /* ms */
                            + (size_t)k * (size_t)BLEN  /* mf^k */
                            + (size_t)BLEN              /* ml */
                            + suffix_zeros;             /* zeros */

    fprintf(stderr, "\nParameters for m2:\n");
    fprintf(stderr, "  k            = %lld  (mf repetitions)\n", k);
    fprintf(stderr, "  suffix_zeros = %zu bytes\n", suffix_zeros);
    fprintf(stderr, "  total m2     = %zu bytes (should equal %zu)\n",
            total_bytes, len);
    fprintf(stderr, "\nPrinting Python generator script to stdout...\n");

    /* ------------------------------------------------------------------ *
     * Step 5 – emit the Python script.                                   *
     *                                                                     *
     * The script streams m2 to sys.stdout.buffer in memory-efficient     *
     * chunks, never building the full multi-GB bytes object at once.     *
     * ------------------------------------------------------------------ */
    printf("#!/usr/bin/env python3\n");
    printf("\"\"\"Generated by test_attack (BLOCKSIZE=64).\n");
    printf("\n");
    printf("Outputs m2, a second preimage of 0^{2^32}, to stdout as raw bytes.\n");
    printf("\n");
    printf("Usage:\n");
    printf("    python3 gen_m2.py > m2.bin          # write ~4 GB to disk\n");
    printf("    python3 gen_m2.py | sha256sum        # pipe anywhere\n");
    printf("\n");
    printf("m2 structure:  ms || mf^k || ml || 0^suffix_zeros\n");
    printf("Total size:    %zu bytes\n", total_bytes);
    printf("Attack used:  ~2^%.2f compression-function calls\n", log2(count));
    printf("\"\"\"\n");
    printf("import sys\n\n");

    /* The three key blocks (hard-coded hex literals). */
    printf("ms           = bytes.fromhex('"); print_hex(ms, BLEN); printf("')\n");
    printf("mf           = bytes.fromhex('"); print_hex(mf, BLEN); printf("')\n");
    printf("ml           = bytes.fromhex('"); print_hex(ml, BLEN); printf("')\n");
    printf("k            = %lld\n", k);
    printf("suffix_zeros = %zu\n", suffix_zeros);
    printf("\n");
    printf("out = sys.stdout.buffer\n\n");

    /* ms */
    printf("out.write(ms)\n\n");

    /* mf^k — write in chunks of REPS_PER_CHUNK copies to stay memory-light. */
    printf("# Write mf repeated k times in large chunks.\n");
    printf("if k > 0:\n");
    printf("    REPS = max(1, 65536 // len(mf))  # ~4096 for BLEN=16\n");
    printf("    chunk = mf * REPS\n");
    printf("    full, rem = divmod(k, REPS)\n");
    printf("    for _ in range(full):\n");
    printf("        out.write(chunk)\n");
    printf("    if rem:\n");
    printf("        out.write(mf * rem)\n\n");

    /* ml */
    printf("out.write(ml)\n\n");

    /* zero suffix — chunked so Python never builds a huge bytes object. */
    printf("# Zero suffix (original message was all zeros).\n");
    printf("if suffix_zeros > 0:\n");
    printf("    CHUNK = 1 << 16  # 64 KB\n");
    printf("    buf   = bytearray(CHUNK)\n");
    printf("    left  = suffix_zeros\n");
    printf("    while left > 0:\n");
    printf("        n = min(CHUNK, left)\n");
    printf("        out.write(memoryview(buf)[:n])\n");
    printf("        left -= n\n");

    return 0;
}
#endif
