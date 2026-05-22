#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef _OPENMP
#  include <omp.h>
#endif
#include "hash.h"
#include "utils.h"
#include "attack.h"


// lookup table for linked-message stage

typedef struct { 
	byte digest[HLEN]; 
	int32_t idx; 
} lut_entry;

static lut_entry *build_lut(const byte *h, size_t nb_blocks, uint32_t *mask_out)
{
    size_t sz = 1;
    while (sz < nb_blocks * 4) sz <<= 1;   /* next power-of-2 for cheap & masking */
    *mask_out = (uint32_t)(sz - 1);
    uint32_t mask = *mask_out;

    lut_entry *lut = malloc(sz * sizeof(lut_entry));
    if (!lut) return NULL;

    /* memset 0xFF: every int32_t idx field becomes 0xFFFFFFFF = -1 (empty).
     * Digest bytes are irrelevant until a slot is claimed.             */
    memset(lut, 0xFF, sz * sizeof(lut_entry));

#ifdef _OPENMP
    /*
     * Parallel insertion with N_STRIPES coarse-grained locks.
     * Each lock protects sz/N_STRIPES consecutive slots.
     * N_STRIPES must be a power of 2 so we can mask instead of mod.
     *
     * Protocol for inserting entry j at slot s:
     *   1. acquire lock for stripe(s)
     *   2. if lut[s].idx == -1: write digest + idx, release, done
     *   3. else: release, probe s+1, repeat
     * Two threads can never both claim the same slot because the check
     * and the write happen under the same lock.
     */
    enum { N_STRIPES = 4096 };
    omp_lock_t locks[N_STRIPES];
    for (int s = 0; s < N_STRIPES; s++) omp_init_lock(&locks[s]);

    #pragma omp parallel for schedule(static)
    for (size_t j = 1; j < nb_blocks; j++) {
        const byte *d = h + j * HLEN;
        uint32_t slot = HASH(d) & mask;
        for (;;) {
            int stripe = (int)(slot & (N_STRIPES - 1));
            omp_set_lock(&locks[stripe]);
            int was_empty = (lut[slot].idx == -1);
            if (was_empty) {
                memcpy(lut[slot].digest, d, HLEN);
                lut[slot].idx = (int32_t)(j <= (size_t)INT32_MAX ? j : INT32_MAX);
            }
            omp_unset_lock(&locks[stripe]);
            if (was_empty) break;
            slot = (slot + 1) & mask;   /* occupied — linear probe to next slot */
        }
    }

    for (int s = 0; s < N_STRIPES; s++) omp_destroy_lock(&locks[s]);

#else
    /* Sequential fallback (used by the non-OMP #else build). */
    for (size_t j = 1; j < nb_blocks; j++) {
        const byte *d = h + j * HLEN;
        uint32_t slot = HASH(d) & mask;
        while (lut[slot].idx != -1)
            slot = (slot + 1) & mask;
        memcpy(lut[slot].digest, d, HLEN);
        lut[slot].idx = (int32_t)j;
    }
#endif

    return lut;
}

/* Returns the stored block index for `digest`, or -1 if absent. */
static inline int lut_lookup(const lut_entry *lut, uint32_t mask, const byte *digest)
{
    uint32_t slot = HASH(digest) & mask;
    while (lut[slot].idx != -1) {
        if (memcmp(lut[slot].digest, digest, HLEN) == 0)
            return lut[slot].idx;
        slot = (slot + 1) & mask;
    }
    return -1;
}


// 3 versions: 
// 	- the original (at the very bottom in the else block), sequential
// 	- OMP accelerated version 
//	- GPU accelerated version with HIP which should work on both AMD HIP and nvidia CUDA


#ifdef USE_HIP
#include <stdint.h>
#include <stdatomic.h>

/* Declared in gpu_linkmsg.hip, compiled separately by hipcc */
extern double gpu_linkmsg(uint8_t *ml, int *ind, const uint8_t *hf, const uint8_t *h, size_t len);

double collision(byte ms[BLEN], byte mf[BLEN], byte hf[HLEN]) {
 
    hash_tbl tbl = calloc(HASHSIZE, sizeof(cell));
 
    byte h0[HLEN];
    for (int i = 0; i < HLEN; i++)
        h0[i] = (IV >> (i * 8)) & 0xFF;
 
    byte zero[HLEN] = {0};
 
    /* Shared result written by the winning thread. */
    volatile atomic_int found = 0;   /* 0 = searching, 1 = done         */
    byte   res_ms[BLEN], res_mf[BLEN], res_hf[HLEN];
    atomic_llong total_count = 0;    /* accumulate across threads        */
 
    #pragma omp parallel shared(tbl, found, total_count, res_ms, res_mf, res_hf)
    {
        byte block[BLEN], tmp[HLEN];
        long long local_count = 0;
 
        while (!atomic_load_explicit(&found, memory_order_relaxed)) {
 
            /* ---- LEFT side: f(h0, ms) -------------------------------- */
            random_bytes(block, BLEN);
            local_count++;
 
            memcpy(tmp, h0, HLEN);
            compression(tmp, block);                /* tmp = f(h0, ms)  */
 
            uint32_t idx = HASH(tmp) % HASHSIZE;
 
            /* Check for a right-side entry written by any thread. */
            if (tbl[idx].side == -1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) {
                /* Only the first thread to reach here records the result. */
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ms, block,         BLEN);
                    memcpy(res_mf, tbl[idx].m,    BLEN);
                    memcpy(res_hf, tmp,           HLEN);
                }
            } else if (tbl[idx].side == 0) {
                /* Empty slot — write left-side entry.
                 * Two threads could race here; the second write is
                 * harmless because both entries are valid left-side
                 * candidates that will be re-verified on match.        */
                memcpy(tbl[idx].h, tmp,   HLEN);
                memcpy(tbl[idx].m, block, BLEN);
                tbl[idx].side = 1;
            }
 
            if (atomic_load_explicit(&found, memory_order_relaxed)) break;
 
            /* ---- RIGHT side: E^{-1}_mf(0) --------------------------- */
            random_bytes(block, BLEN);
            local_count++;
 
            speck_dec(block, tmp, zero);            /* tmp = E^-1_mf(0) */
 
            idx = HASH(tmp) % HASHSIZE;
 
            if (tbl[idx].side == 1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) {
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ms, tbl[idx].m, BLEN);
                    memcpy(res_mf, block,      BLEN);
                    memcpy(res_hf, tmp,        HLEN);
                }
            } else if (tbl[idx].side == 0) {
                memcpy(tbl[idx].h, tmp,   HLEN);
                memcpy(tbl[idx].m, block, BLEN);
                tbl[idx].side = -1;
            }
        }
 
        /* Each thread adds its local count atomically at the end. */
        atomic_fetch_add(&total_count, local_count);
    }
 
    memcpy(ms, res_ms, BLEN);
    memcpy(mf, res_mf, BLEN);
    memcpy(hf, res_hf, HLEN);
 
    free(tbl);
    return (double)atomic_load(&total_count);
}

// wrapper around the GPU version
double linkmsg(byte ml[BLEN], int *ind, const byte hf[HLEN], const byte *h, size_t len) {
    return gpu_linkmsg(ml, ind, hf, h, len);
}

// nothing changed about the attack function
double attack(const byte *m, size_t len, byte *m2) {
    double count = 0;
 
    byte ms[BLEN], mf[BLEN], hf[HLEN];
    count += collision(ms, mf, hf);
 
    size_t nb_blocks  = (len + BLEN - 1) / BLEN;
    size_t nb_digests = nb_blocks + 2;
    byte  *h          = calloc(nb_digests * HLEN, 1);
    intermediate_digests(m, len, h);
 
    byte ml[BLEN];
    int  i;
    count += linkmsg(ml, &i, hf, h, len);
 
    int k = i - 2;
    if (k < 0) {
        fprintf(stderr, "attack failed: i=%d too small, need i >= 2\n", i);
        free(h);
        return count;
    }
 
    size_t suffix_len = (nb_blocks - i) * BLEN;
    size_t offset     = 0;
 
    memcpy(m2 + offset, ms, BLEN);
    offset += BLEN;
 
    for (int j = 0; j < k; j++) {
        memcpy(m2 + offset, mf, BLEN);
        offset += BLEN;
    }
 
    memcpy(m2 + offset, ml, BLEN);
    offset += BLEN;
 
    memcpy(m2 + offset, m + i * BLEN, suffix_len);
 
    free(h);
    return count;
}



// OMP version with no GPU acceleration
#elif defined(_OPENMP)
#include <stdatomic.h>

/*
double collision(byte ms[BLEN], byte mf[BLEN], byte hf[HLEN]) {

    hash_tbl tbl = calloc(HASHSIZE, sizeof(cell));

    byte h0[HLEN];
    for (int i = 0; i < HLEN; i++)
        h0[i] = (IV >> (i * 8)) & 0xFF;

    byte zero[HLEN] = {0};

    volatile atomic_int found = 0;
    byte   res_ms[BLEN], res_mf[BLEN], res_hf[HLEN];
    atomic_llong total_count = 0;

    #pragma omp parallel shared(tbl, found, total_count, res_ms, res_mf, res_hf)
    {
        byte block[BLEN], tmp[HLEN];
        long long local_count = 0;

        while (!atomic_load_explicit(&found, memory_order_relaxed)) {

            random_bytes(block, BLEN);
            local_count++;

            memcpy(tmp, h0, HLEN);
            compression(tmp, block);

            uint32_t idx = HASH(tmp) % HASHSIZE;

            if (tbl[idx].side == -1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) {
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ms, block,         BLEN);
                    memcpy(res_mf, tbl[idx].m,    BLEN);
                    memcpy(res_hf, tmp,           HLEN);
                }
            } else if (tbl[idx].side == 0) {
                memcpy(tbl[idx].h, tmp,   HLEN);
                memcpy(tbl[idx].m, block, BLEN);
                tbl[idx].side = 1;
            }

            if (atomic_load_explicit(&found, memory_order_relaxed)) break;

            random_bytes(block, BLEN);
            local_count++;

            speck_dec(block, tmp, zero);

            idx = HASH(tmp) % HASHSIZE;

            if (tbl[idx].side == 1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) {
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ms, tbl[idx].m, BLEN);
                    memcpy(res_mf, block,      BLEN);
                    memcpy(res_hf, tmp,        HLEN);
                }
            } else if (tbl[idx].side == 0) {
                memcpy(tbl[idx].h, tmp,   HLEN);
                memcpy(tbl[idx].m, block, BLEN);
                tbl[idx].side = -1;
            }
        }

        atomic_fetch_add(&total_count, local_count);
    }

    memcpy(ms, res_ms, BLEN);
    memcpy(mf, res_mf, BLEN);
    memcpy(hf, res_hf, HLEN);

    free(tbl);
    return (double)atomic_load(&total_count);
}


double linkmsg(byte ml[BLEN], int *ind,
               const byte hf[HLEN], const byte *h, size_t len)
{
    size_t nb_blocks = (len + BLEN - 1) / BLEN;

    uint32_t lut_mask;
    lut_entry *lut = build_lut(h, nb_blocks, &lut_mask);
    if (!lut) {
        fprintf(stderr, "linkmsg: out of memory building LUT\n");
        *ind = -1;
        return 0.0;
    }

    volatile atomic_int found = 0;
    byte     res_ml[BLEN];
    int      res_ind = -1;
    atomic_llong total_count = 0;

    #pragma omp parallel shared(found, total_count, res_ml, res_ind)
    {
        byte local_ml[BLEN], tmp[HLEN];
        long long local_count = 0;

        while (!atomic_load_explicit(&found, memory_order_relaxed)) {
            random_bytes(local_ml, BLEN);
            local_count++;

            memcpy(tmp, hf, HLEN);
            compression(tmp, local_ml); 

            int hit = lut_lookup(lut, lut_mask, tmp);
            if (hit >= 0) {
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ml, local_ml, BLEN);
                    res_ind = hit;
                }
            }
        }

        atomic_fetch_add(&total_count, local_count);
    }

    free(lut);
    memcpy(ml, res_ml, BLEN);
    *ind = res_ind;
    return (double)atomic_load(&total_count);
}

double attack(const byte *m, size_t len, byte *m2) {
    double count = 0;

    byte ms[BLEN], mf[BLEN], hf[HLEN];
    count += collision(ms, mf, hf);

    size_t nb_blocks  = (len + BLEN - 1) / BLEN;
    size_t nb_digests = nb_blocks + 2;
    byte  *h          = calloc(nb_digests * HLEN, 1);
    intermediate_digests(m, len, h);

    byte ml[BLEN];
    int  i;
    count += linkmsg(ml, &i, hf, h, len);

    int k = i - 2;
    if (k < 0) {
        fprintf(stderr, "attack failed: i=%d too small, need i >= 2\n", i);
        free(h);
        return count;
    }

    size_t suffix_len = (nb_blocks - i) * BLEN;
    size_t offset     = 0;

    memcpy(m2 + offset, ms, BLEN);  offset += BLEN;
    for (int j = 0; j < k; j++) {
        memcpy(m2 + offset, mf, BLEN);  offset += BLEN;
    }
    memcpy(m2 + offset, ml, BLEN);  offset += BLEN;
    memcpy(m2 + offset, m + i * BLEN, suffix_len);

    free(h);
    return count;
}
*/

static inline uint64_t tl_next(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}
 
static inline void tl_random_bytes(byte *buf, int n, uint64_t *s) {
    int i = 0;
    while (i < n) {
        uint64_t r = tl_next(s);
        for (int j = 0; j < 8 && i < n; j++, i++) {
            buf[i] = r & 0xff;
            r >>= 8;
        }
    }
}
 
/*
 * Step 1 — collision()
 * h0 -[ms]-> hf -[mf]-> hf (fixed point via Davies-Meyer)
 */
double collision(byte ms[BLEN], byte mf[BLEN], byte hf[HLEN]) {
 
    hash_tbl tbl = calloc(HASHSIZE, sizeof(cell));
 
    byte h0[HLEN];
    for (int i = 0; i < HLEN; i++)
        h0[i] = (IV >> (i * 8)) & 0xFF;
 
    byte zero[HLEN] = {0};
 
    volatile atomic_int found = 0;
    byte res_ms[BLEN], res_mf[BLEN], res_hf[HLEN];
    atomic_llong total_count = 0;
 
    #pragma omp parallel shared(tbl, found, total_count, res_ms, res_mf, res_hf)
    {
        /* Seed per-thread RNG from the global one — critical so threads
         * don't race on the global xoshiro256** state at startup.       */
        uint64_t tl_rng;
        #pragma omp critical
        {
            byte seed_buf[8];
            random_bytes(seed_buf, 8);
            memcpy(&tl_rng, seed_buf, 8);
            if (tl_rng == 0) tl_rng = 1;
        }
 
        byte block[BLEN], tmp[HLEN];
        long long local_count = 0;
 
        while (!atomic_load_explicit(&found, memory_order_relaxed)) {
 
            /* ---- LEFT side: f(h0, ms) -------------------------------- */
            tl_random_bytes(block, BLEN, &tl_rng);
            local_count++;
 
            memcpy(tmp, h0, HLEN);
            compression(tmp, block);
 
            uint32_t idx = HASH(tmp) % HASHSIZE;
 
            if (tbl[idx].side == -1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) {
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ms, block,      BLEN);
                    memcpy(res_mf, tbl[idx].m, BLEN);
                    memcpy(res_hf, tmp,        HLEN);
                }
            } else if (tbl[idx].side == 0) {
                memcpy(tbl[idx].h, tmp,   HLEN);
                memcpy(tbl[idx].m, block, BLEN);
                tbl[idx].side = 1;
            }
 
            if (atomic_load_explicit(&found, memory_order_relaxed)) break;
 
            /* ---- RIGHT side: E^{-1}_mf(0) --------------------------- */
            tl_random_bytes(block, BLEN, &tl_rng);
            local_count++;
 
            speck_dec(block, tmp, zero);
 
            idx = HASH(tmp) % HASHSIZE;
 
            if (tbl[idx].side == 1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) {
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ms, tbl[idx].m, BLEN);
                    memcpy(res_mf, block,      BLEN);
                    memcpy(res_hf, tmp,        HLEN);
                }
            } else if (tbl[idx].side == 0) {
                memcpy(tbl[idx].h, tmp,   HLEN);
                memcpy(tbl[idx].m, block, BLEN);
                tbl[idx].side = -1;
            }
        }
 
        atomic_fetch_add(&total_count, local_count);
    }
 
    memcpy(ms, res_ms, BLEN);
    memcpy(mf, res_mf, BLEN);
    memcpy(hf, res_hf, HLEN);
 
    free(tbl);
    return (double)atomic_load(&total_count);
}
 
/*
 * Step 2 — linkmsg()
 * hf -[ml]-> h[i]  (link fixed point into the target message chain)
 */
double linkmsg(byte ml[BLEN], int *ind,
               const byte hf[HLEN], const byte *h, size_t len)
{
    size_t nb_blocks = (len + BLEN - 1) / BLEN;

    /* Build LUT once before spawning threads — read-only inside parallel region */
    uint32_t lut_mask;
    lut_entry *lut = build_lut(h, nb_blocks, &lut_mask);
    if (!lut) {
        fprintf(stderr, "linkmsg: out of memory building LUT\n");
        *ind = -1;
        return 0.0;
    }

    volatile atomic_int found = 0;
    byte res_ml[BLEN];
    int  res_ind = -1;
    atomic_llong total_count = 0;
 
    #pragma omp parallel shared(lut, lut_mask, found, total_count, res_ml, res_ind)
    {
        uint64_t tl_rng;
        #pragma omp critical
        {
            byte seed_buf[8];
            random_bytes(seed_buf, 8);
            memcpy(&tl_rng, seed_buf, 8);
            if (tl_rng == 0) tl_rng = 1;
        }
 
        byte local_ml[BLEN], tmp[HLEN];
        long long local_count = 0;
 
        while (!atomic_load_explicit(&found, memory_order_relaxed)) {
            tl_random_bytes(local_ml, BLEN, &tl_rng);
            local_count++;
 
            memcpy(tmp, hf, HLEN);
            compression(tmp, local_ml);

            /* O(1) lookup instead of O(nb_blocks) linear scan */
            int hit = lut_lookup(lut, lut_mask, tmp);
            if (hit >= 0) {
                int expected = 0;
                if (atomic_compare_exchange_strong(&found, &expected, 1)) {
                    memcpy(res_ml, local_ml, BLEN);
                    res_ind = hit;
                }
            }
        }
 
        atomic_fetch_add(&total_count, local_count);
    }

    free(lut);
    memcpy(ml, res_ml, BLEN);
    *ind = res_ind;
    return (double)atomic_load(&total_count);
}
 
/*
 * Step 3 — attack()
 * h0 -[ms]-> hf -[mf]^k -> hf -[ml]-> h[i] -[m[i..t-1]]-> h[t] -[|m|]-> H(m)
 */
double attack(const byte *m, size_t len, byte *m2) {
    double count = 0;
 
    byte ms[BLEN], mf[BLEN], hf[HLEN];
    count += collision(ms, mf, hf);
 
    size_t nb_blocks  = (len + BLEN - 1) / BLEN;
    size_t nb_digests = nb_blocks + 2;
    byte  *h          = calloc(nb_digests * HLEN, 1);
    intermediate_digests(m, len, h);
 
    byte ml[BLEN];
    int  i;
    count += linkmsg(ml, &i, hf, h, len);
 
    int k = i - 2;
    if (k < 0) {
        fprintf(stderr, "attack failed: i=%d too small, need i >= 2\n", i);
        free(h);
        return count;
    }
 
    size_t suffix_len = (nb_blocks - i) * BLEN;
    size_t offset     = 0;
 
    memcpy(m2 + offset, ms, BLEN);
    offset += BLEN;
 
    for (int j = 0; j < k; j++) {
        memcpy(m2 + offset, mf, BLEN);
        offset += BLEN;
    }
 
    memcpy(m2 + offset, ml, BLEN);
    offset += BLEN;
 
    memcpy(m2 + offset, m + i * BLEN, suffix_len);
 
    free(h);
    return count;
}


// Original slow implementation
#else

/*
 * Step 1
 */

// 1. we sample random message to start with ms on the left side
// 	- use h0 (IV) to find hf
// 	- h0 --> f(h0,ms) --> hf
//
// 2. on the right side, we go backwards starting from hf
// 	- sample random mf to decrypt 0
// 	- hf --> E-1_mf --> 0 in other words E-1_mf(0) = hf
// 	- xoring with 0 has no effect, thus: f-1(0,mf) = 0 xor E-1_mf(0) = E-1_mf(0)
// 
// 3. we keep sampling both sides until we find: f(h0,ms) = E-1_mf(0) = hf  
//
// f(hf,mf) = E_mf(hf) xor hf = E_mf(E-1_mf(0)) xor hf = 0 xor hf = hf

// returns number of (ms,mf) pairs sampled until both sides left and right meet
double collision(byte ms[BLEN], byte mf[BLEN], byte hf[HLEN]) {
    // initialize hash table of cells, all initialized with zeros to make side = 0
    hash_tbl tbl = calloc(HASHSIZE, sizeof(cell));

    // h0 = IV
    byte h0[HLEN];
    for (int i = 0; i < HLEN; i++)
        h0[i] = (IV >> (i * 8)) & 0xFF;

    double count = 0; // number of cycles to find collision
    byte tmp[HLEN]; // to hold f(h0,block) as it will get overriten
    byte block[BLEN];
    byte zero[HLEN] = {0}; // digest of all zeros

    while (1) {
	// left side: sample ms randomly and start computing f(h0, ms) forward
        random_bytes(block, BLEN); // ms = block
        count++;
        memcpy(tmp, h0, HLEN); // start with IV on the left side
        compression(tmp, block); // f(h0,ms)

	// index in the hash table: get the 3 first bytes of the digest to use as hashtable index
        uint32_t idx = HASH(tmp) % HASHSIZE;

        if (tbl[idx].side == -1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) { // right side entry at this slot and actual digest match
            memcpy(ms, block, BLEN); // save ms generated
            memcpy(mf, tbl[idx].m, BLEN); // save the fixed message found from hashtable
            memcpy(hf, tmp, HLEN); // save the fixed hash hf
            free(tbl);
            return count;
        } else if (tbl[idx].side == 0) {  // if empty slot
            memcpy(tbl[idx].h, tmp, HLEN); // copy hash to cell
            memcpy(tbl[idx].m, block, BLEN); // copy message generating the digest
            tbl[idx].side = 1; // mark as left side generated cell
        }

	// ride side: sample mf randomly, and start computing E-1_mf(0) backwards
        random_bytes(block, BLEN); // sample mf randomly
        count++;
        speck_dec(block, tmp, zero);      // tmp = E-1_mf(0)

        idx = HASH(tmp) % HASHSIZE; // get index in hash table
        if (tbl[idx].side == 1 && memcmp(tmp, tbl[idx].h, HLEN) == 0) { // left side entry at this slot and actual digest match
            memcpy(ms, tbl[idx].m, BLEN); // save ms found from hashtable
            memcpy(mf, block, BLEN); // save mf generated
            memcpy(hf, tmp, HLEN); // save fixed digest hf
            free(tbl);
            return count;
        } else if (tbl[idx].side == 0) {  // if empty slot
            memcpy(tbl[idx].h, tmp, HLEN); // copy digest to cell at that index
            memcpy(tbl[idx].m, block, BLEN); // copy message associated with digest to cell
            tbl[idx].side = -1; // mark as right side generated cell
        }
    }
}

/*
 * Step 2
 */

// ml:	when we find a matching digest, ml is our message we want
// ind: index of the intermidiate digest that matched
// hf:	fixed point hash from step 1 -> starting point of our compression in step 2
// h: input array of all intermediate digests of the target message m
// returns how many ml blocks sampled before f(hl,ml) hit intermediate digest
double linkmsg(byte ml[BLEN], int *ind, const byte hf[HLEN], const byte *h, size_t len) {
    
    size_t nb_blocks = (len + BLEN - 1) / BLEN;

    // linkmsg lookup table
    uint32_t lut_mask;
    lut_entry *lut = build_lut(h, nb_blocks, &lut_mask);
    if (!lut) {
        fprintf(stderr, "linkmsg: out of memory building LUT\n");
        *ind = -1;
        return 0.0;
    }

    // return the number of iterations -> nb of blocks sampled before finding a match
    double count = 0;
    byte tmp[HLEN]; // temp buffer to hold digests as they get ovveriden by compression()

    // brute-force with randomly sampled messages
    while (1) {
	// sample a random message ml
        random_bytes(ml, BLEN);
        count++;

	// save the fixed point hash into tmp as compression() will overwrite tmp
        memcpy(tmp, hf, HLEN);
        compression(tmp, ml);

        // f(hf, ml) match any intermediate digest? if so return index of intermediate digest and number of sampled blocks
        // skip h[0] as it is the IV
	/*for (size_t j = 1; j < nb_blocks; j++) {
            if (memcmp(tmp, h + j * HLEN, HLEN) == 0) {
                *ind = (int)j;   // store which intermediate digest matched
                return count;
            }
        }*/
	// rather than doing the whole calculation over each hash just use the lookup table
	int hit = lut_lookup(lut, lut_mask, tmp);
        if (hit >= 0) {
            *ind = hit;
            free(lut);
            return count;
        }

    }
}



/*
 * Step 3
 */

// The actual attack stage:
// h0 -[ms]-> hf -[mf]-> hf -[mf]-> ... -[mf]-> hf -[ml]-> h[i] -[m[i]]-> ... -[m[t-1]]-> h[t] -[|m'|]-> H(m)
// returns number of samples done by step 1 and 2 in total
double attack(const byte *m, size_t len, byte *m2) {
    double count = 0;

    // find ms, mf, hf from stage 1
    byte ms[BLEN], mf[BLEN], hf[HLEN];
    count += collision(ms, mf, hf);

    // compute intermediate digests of m
    size_t nb_blocks = (len + BLEN - 1) / BLEN;
    size_t nb_digests = nb_blocks + 2; // IV + message blocks + length block
    byte *h = calloc(nb_digests * HLEN, 1); // list of digests of m
    intermediate_digests(m, len, h);

    // find ml and index i such that f(hf, ml) = h[i] from stage 2
    // hf -[ml]-> h[i]
    byte ml[BLEN];
    int i;
    count += linkmsg(ml, &i, hf, h, len);

    // step 3: building m' = ms || mf^k || ml || m[i*BLEN:]
    // k chosen so |m'| = |m| (length blocks match)
    // m'  = ms | mf×k | ml | m[i:] -> 1  +  k  +  1 + (t-i) must equal t
    // 1 + k + 1 + (t-i) = t
    // k = t - 2 - t + i
    // k = i - 2
    //
    // t - i represents the meeting point of the two sides
    // k represents how many times we should repeat mf to get equal message length |m'| = |m|
    //
    // E_mf(0) = hf as we established previously, so any number of repeatitions in the chain
    // f(hf,mf) = E_mf(hf) xor hf = 0 xor hf = hf
    // hf -[mf] -> hf -[mf]-> hf -...-> hf (no matter how many times k we repeat

    int k = i - 2;
    
    // suppose m has 5 blocks and linkmsg finds i = 4
    // m  = [m0 | m1 | m2 | m3 | m4]  (5 blocks = t)
    //
    // hash chain on m: h0 -[m0]-> h1 -[m1]-> h2 -[m2]-> h3 -[m3]-> h4 -[m4]-> h5 -[|m|]-> H(m)
    // m' needs to reach h4 since i = 4 using ms and ml
    // with the following chain: h0 -[ms]-> hf -[ml]-> h4 -[m4]-> h5 -[|m'|]-> H(m')
    //
    // m' here has 3 blocks while m has 5 -> |m| != |m'| -> H(m') != H(m)
    // so we need to pad mf in the middle of m' to make it the same length as m:
    // 		m' = [ms | mf | mf | ml | m4] (5 blocks, same as m)
    //
    // in our example i = 4 -> k = 2 -> 2 mf blocks are needed
    // if linkmsg found i = 2 -> k = 0 -> no repeatitions of mf needed
    // if i = 1 -> k = -1 -> logically impossible
    if (k < 0) {
        fprintf(stderr, "attack failed: i=%d too small, need i >= 2\n", i);
        free(h);
        return count;
    }


    // building m'
    size_t suffix_len = (nb_blocks - i) * BLEN;  // m[i] to m[t-1]: tail of the ultimate chain
    //size_t m2_len = (2 + k) * BLEN + suffix_len; // should equal len

    size_t offset = 0; // tracks location to copy blocks to in m2
    
    // building m2 the resulting chain

    // copy ms block to start m2:
    // 		m2 = [ ms |  |  |  | ...]
    memcpy(m2 + offset, ms, BLEN);
    offset += BLEN;
    // copy mf blocks as needed (according to k) to m2 chain
    // 		m2 = [ ms | mf | mf | mf | ... | | | ]
    for (int j = 0; j < k; j++) {
        memcpy(m2 + offset, mf, BLEN);           // mf repeated k times
        offset += BLEN;
    }

    // copy the ml block
    // 		m2 = = [ ms | mf | mf | mf | ... | ml | | | ]
    memcpy(m2 + offset, ml, BLEN);
    offset += BLEN;

    // copy rest of chain from i to end of chain m[i:]
    // 		m2 = = [ ms | mf | mf | mf | ... | ml | mi| mi+1 | mi+2...]
    memcpy(m2 + offset, m + i * BLEN, suffix_len);
    offset += suffix_len;

    free(h);
    return count;
}
#endif
