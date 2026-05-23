/*
 * gpu_linkmsg.hip
 *
 * GPU implementation of linkmsg() for both AMD (HIP) and NVIDIA (CUDA).
 *
 * Key change from original:
 *   The old kernel scanned all nb_blocks intermediate digests linearly
 *   for every sampled ml block — O(nb_blocks) per sample.  For BLOCKSIZE=64,
 *   that is 2^28 comparisons per sample: completely infeasible.
 *
 *   The new kernel mirrors the OMP implementation: a hash table (LUT) is
 *   built on the CPU and transferred to device memory once.  Each GPU thread
 *   then does an O(1) lookup per sample, the same as the OMP path in attack.c.
 *
 * CUDA / HIP compatibility:
 *   Compile with hipcc for both targets (AMD and NVIDIA).
 *   For nvcc directly, the shim below maps hip* → cuda* so the same
 *   source compiles without modification:
 *     nvcc -x cu -O3 -std=c++17 -DBLOCKSIZE=64 ... -c -o gpu_linkmsg.o gpu_linkmsg.hip
 */

/* ======================================================================
 * HIP / CUDA compatibility shim
 *
 * hipcc targeting NVIDIA translates hip* → cuda* automatically.
 * When compiling with nvcc directly, the macros below do the same job.
 * All kernel syntax (__global__, __device__, <<<>>>...) is identical.
 * ====================================================================== */
#if defined(__NVCC__) || defined(__CUDACC__)
#  include <cuda_runtime.h>
#  define hipMalloc             cudaMalloc
#  define hipFree               cudaFree
#  define hipMemcpy             cudaMemcpy
#  define hipMemset             cudaMemset
#  define hipDeviceSynchronize  cudaDeviceSynchronize
#  define hipMemcpyHostToDevice cudaMemcpyHostToDevice
#  define hipMemcpyDeviceToHost cudaMemcpyDeviceToHost
#else
#  include <hip/hip_runtime.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Pull in the same compile-time constants as the rest of the project.
 * BLOCKSIZE, HLEN, BLEN, MLEN, KLEN, ROUND are all defined via utils.h.
 */
extern "C" {
#include "utils.h"
#include "hash.h"
}

/* ======================================================================
 * Speck constants — mirror utils.c exactly
 * ====================================================================== */
#if BLOCKSIZE == 32
  #define SPECK_ALPHA   7
  #define SPECK_BETA    2
  #define SPECK_ROUND  22
  #define SPECK_MASK   0xffffu
  typedef uint16_t hw_t;   /* half-word */
#elif BLOCKSIZE == 48
  #define SPECK_ALPHA   8
  #define SPECK_BETA    3
  #define SPECK_ROUND  23
  #define SPECK_MASK   0xffffffu
  typedef uint32_t hw_t;
#else /* 64 */
  #define SPECK_ALPHA   8
  #define SPECK_BETA    3
  #define SPECK_ROUND  27
  #define SPECK_MASK   0xffffffffu
  typedef uint32_t hw_t;
#endif

#define SPECK_ROTL(x,n) (((x) << (n)) ^ ((x) >> (BLOCKSIZE/2-(n)))) & SPECK_MASK
#define SPECK_ROTR(x,n) (((x) >> (n)) ^ ((x) << (BLOCKSIZE/2-(n)))) & SPECK_MASK

/* Encryption round and decryption round — identical to R() and D() macros */
#define SPECK_R(x,y,k) \
    (x) = SPECK_ROTR((x), SPECK_ALPHA); \
    (x) = ((x) + (y)) & SPECK_MASK;    \
    (x) ^= (k);                         \
    (y) = SPECK_ROTL((y), SPECK_BETA); \
    (y) ^= (x)

#define SPECK_D(x,y,k) \
    (y) ^= (x);                          \
    (y) = SPECK_ROTR((y), SPECK_BETA) & SPECK_MASK; \
    (x) ^= (k);                          \
    (x) = ((x) - (y)) & SPECK_MASK;     \
    (x) = SPECK_ROTL((x), SPECK_ALPHA) & SPECK_MASK

/* ======================================================================
 * Device helpers: byte ↔ halfword conversion
 * (Direct port of byte2halfblock / halfblocks2bytes from utils.c)
 * ====================================================================== */

/* Read MLEN/2 bytes from buf[start] into *dest, little-endian. */
__device__ static void d_byte2hw(hw_t *dest, const uint8_t *buf, int start)
{
    *dest = 0;
    for (int j = MLEN/2 - 1; j >= 0; j--) {
        *dest <<= 8;
        *dest |= (hw_t)buf[start + j];
    }
}

/* Write two halfwords to dest[0..MLEN-1].
 * NOTE: destructive on orig[] — mirrors utils.c behaviour. */
__device__ static void d_hw2bytes(uint8_t *dest, hw_t *orig)
{
    for (int i = 0; i < MLEN/2; i++) {
        dest[i]        = orig[0] & 0xff; orig[0] >>= 8;
        dest[i+MLEN/2] = orig[1] & 0xff; orig[1] >>= 8;
    }
}

/* ======================================================================
 * Device key schedule
 * ====================================================================== */
__device__ static void d_key_schedule(const uint8_t k[KLEN], hw_t rk[SPECK_ROUND])
{
    hw_t l[4];
    d_byte2hw(rk,   k, 0);
    d_byte2hw(l,    k, MLEN/2);
    d_byte2hw(l+1,  k, MLEN);
    d_byte2hw(l+2,  k, 3*MLEN/2);

    for (int i = 0; i < SPECK_ROUND - 1; i++) {
        rk[i+1] = rk[i];
        SPECK_R(l[0], rk[i+1], i);
        l[3] = l[0];
        for (int j = 0; j < 3; j++) l[j] = l[j+1];
    }
}

/* ======================================================================
 * Device speck_enc / speck_dec — direct port of utils.c
 * ====================================================================== */
__device__ static void d_speck_enc(const uint8_t k[KLEN],
                                    const uint8_t m[MLEN],
                                    uint8_t       c[MLEN])
{
    hw_t cc[2] = {0, 0};
    d_byte2hw(cc,   m, 0);
    d_byte2hw(cc+1, m, MLEN/2);

    hw_t rk[SPECK_ROUND];
    d_key_schedule(k, rk);

    for (int i = 0; i < SPECK_ROUND; i++) {
        SPECK_R(cc[1], cc[0], rk[i]);
    }

    d_hw2bytes(c, cc);
}

__device__ static void d_speck_dec(const uint8_t k[KLEN],
                                    uint8_t       m[MLEN],
                                    const uint8_t c[MLEN])
{
    hw_t mm[2] = {0, 0};
    d_byte2hw(mm,   c, 0);
    d_byte2hw(mm+1, c, MLEN/2);

    hw_t rk[SPECK_ROUND];
    d_key_schedule(k, rk);

    for (int i = SPECK_ROUND - 1; i >= 0; i--) {
        SPECK_D(mm[1], mm[0], rk[i]);
    }

    d_hw2bytes(m, mm);
}

/* ======================================================================
 * Device Davies-Meyer compression: f(h, m) = E_m(h) XOR h
 * h is both input and output (mirrors compression() in hash.c).
 * ====================================================================== */
__device__ static void d_compression(uint8_t h[HLEN], const uint8_t m[BLEN])
{
    uint8_t orig[HLEN];
    for (int i = 0; i < HLEN; i++) orig[i] = h[i];
    d_speck_enc(m, h, h);                       /* h = E_m(h)        */
    for (int i = 0; i < HLEN; i++) h[i] ^= orig[i]; /* Davies-Meyer  */
}

/* ======================================================================
 * Per-thread xoshiro256** — state lives in registers
 *
 * We give each thread its own independent stream by:
 *   1. seeding a splitmix64 with (host_seed XOR tid)
 *   2. using its output to fill the 256-bit xoshiro256** state
 *
 * This is the same strategy recommended by Blackman & Vigna for
 * parallel use of xoshiro256**.
 * ====================================================================== */
typedef struct { uint64_t s[4]; } xo_state;

__device__ static uint64_t splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

__device__ static xo_state xo_seed(uint64_t seed)
{
    xo_state st;
    st.s[0] = splitmix64(&seed);
    st.s[1] = splitmix64(&seed);
    st.s[2] = splitmix64(&seed);
    st.s[3] = splitmix64(&seed);
    return st;
}

__device__ static inline uint64_t xo_rotl(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

__device__ static uint64_t xo_next(xo_state *st)
{
    const uint64_t result = xo_rotl(st->s[1] * 5, 7) * 9;
    const uint64_t t      = st->s[1] << 17;

    st->s[2] ^= st->s[0];
    st->s[3] ^= st->s[1];
    st->s[1] ^= st->s[2];
    st->s[0] ^= st->s[3];
    st->s[2] ^= t;
    st->s[3]  = xo_rotl(st->s[3], 45);

    return result;
}

__device__ static void xo_random_bytes(uint8_t *buf, int n, xo_state *st)
{
    int i = 0;
    while (i < n) {
        uint64_t r = xo_next(st);
        for (int j = 0; j < 8 && i < n; j++, i++) {
            buf[i] = r & 0xff;
            r >>= 8;
        }
    }
}

/* ======================================================================
 * LUT — same design as attack.c's lut_entry / lut_hash / lut_lookup
 *
 * The LUT is built once on the CPU (build_lut_host) and copied to device
 * memory.  All GPU threads share the read-only copy via the L2 cache.
 * ====================================================================== */

typedef struct {
    uint8_t digest[HLEN];
    int32_t idx;            /* -1 = empty slot */
} lut_entry;

/*
 * 4-byte hash → 32-bit slot index.
 * The HASH() macro in attack.h only uses 3 bytes (24-bit output), which
 * causes every entry to cluster in the first 1.6% of a 2^30 table.
 * Using 4 bytes covers table sizes up to 2^32 and gives uniform spread.
 * All block sizes have HLEN >= 4 so d[3] is always a valid byte.
 */
__device__ static inline uint32_t d_lut_hash(const uint8_t *d)
{
    return (uint32_t)d[0]
         | ((uint32_t)d[1] <<  8)
         | ((uint32_t)d[2] << 16)
         | ((uint32_t)d[3] << 24);
}

/* O(1) lookup: returns matching block index or -1 if not in table. */
__device__ static int d_lut_lookup(const lut_entry * __restrict__ lut,
                                    uint32_t mask, const uint8_t *digest)
{
    uint32_t slot = d_lut_hash(digest) & mask;
    while (lut[slot].idx != -1) {
        bool match = true;
        for (int i = 0; i < HLEN; i++) {
            if (lut[slot].digest[i] != digest[i]) { match = false; break; }
        }
        if (match) return lut[slot].idx;
        slot = (slot + 1) & mask;   /* linear probe */
    }
    return -1;
}

/*
 * CPU-side LUT build — sequential; mirrors the #else path of build_lut()
 * in attack.c.  For large block sizes the OMP-parallel build in attack.c
 * already ran before gpu_linkmsg is called, so this is just for the GPU
 * copy; timing is dominated by the GPU search, not this build.
 */
static lut_entry *build_lut_host(const uint8_t *h, size_t nb_blocks,
                                  uint32_t *mask_out)
{
    size_t sz = 1;
    while (sz < nb_blocks * 4) sz <<= 1;   /* next power-of-2, ~25% load */
    *mask_out = (uint32_t)(sz - 1);
    uint32_t mask = *mask_out;

    lut_entry *lut = (lut_entry *)malloc(sz * sizeof(lut_entry));
    if (!lut) return NULL;
    memset(lut, 0xFF, sz * sizeof(lut_entry));  /* all idx = -1 (empty) */

    for (size_t j = 1; j < nb_blocks; j++) {
        const uint8_t *d = h + j * HLEN;
        uint32_t slot = ((uint32_t)d[0] | ((uint32_t)d[1] << 8)
                       | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24))
                       & mask;
        while (lut[slot].idx != -1)
            slot = (slot + 1) & mask;
        memcpy(lut[slot].digest, d, HLEN);
        lut[slot].idx = (int32_t)(j <= (size_t)INT32_MAX ? j : INT32_MAX);
    }
    return lut;
}

/* ======================================================================
 * linkmsg kernel — O(1) LUT lookup per sample
 *
 * Each thread independently:
 *   1. samples a random ml block
 *   2. computes tmp = f(hf, ml) via Davies-Meyer
 *   3. looks up tmp in the read-only LUT (O(1) average with 25% load)
 *   4. on match: atomicCAS to claim the result slot, then exits
 * ====================================================================== */
__global__ void linkmsg_kernel(
    const uint8_t   * __restrict__ hf,       /* fixed-point hash  [HLEN]     */
    const lut_entry * __restrict__ lut,       /* intermediate digest LUT      */
    uint32_t          lut_mask,               /* sz-1 for power-of-2 masking  */
    uint64_t          host_seed,              /* entropy from /dev/urandom    */
    uint8_t          *res_ml,                 /* output: winning ml [BLEN]    */
    int              *res_ind,                /* output: matched digest index */
    int              *found,                  /* shared stop flag             */
    unsigned long long *total_count           /* total samples (all threads)  */
) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    /* Each thread gets a fully independent xoshiro256** stream. */
    xo_state rng = xo_seed(host_seed ^ (uint64_t)tid);

    uint8_t ml[BLEN], tmp[HLEN];
    unsigned long long local_count = 0;

    while (!atomicAdd(found, 0)) {
        xo_random_bytes(ml, BLEN, &rng);
        local_count++;

        for (int i = 0; i < HLEN; i++) tmp[i] = hf[i];
        d_compression(tmp, ml);             /* tmp = f(hf, ml) */

        int hit = d_lut_lookup(lut, lut_mask, tmp);
        if (hit >= 0) {
            /* First thread to find a match wins. */
            if (atomicCAS(found, 0, 1) == 0) {
                for (int b = 0; b < BLEN; b++) res_ml[b] = ml[b];
                *res_ind = hit;
            }
        }
    }
    atomicAdd(total_count, local_count);
}

/* ======================================================================
 * Host-side wrapper
 *
 * Flow:
 *   1. Build LUT on CPU (sequential; fast for BLOCKSIZE 32/48,
 *      acceptable for 64 — GPU search time dominates anyway).
 *   2. Transfer LUT to device memory.
 *   3. Launch kernel; threads do O(1) lookups per sample.
 *   4. Retrieve result and clean up.
 *
 * On unified-memory GPUs (e.g. AMD 780M, Intel Arc) hipMalloc places
 * the allocation in the shared pool; no explicit PCIe copy occurs.
 * On discrete GPUs the hipMemcpy is a one-time cost that is tiny
 * compared to the search time.
 * ====================================================================== */
extern "C"
double gpu_linkmsg(uint8_t *ml, int *ind,
                   const uint8_t *hf, const uint8_t *h, size_t len)
{
    size_t nb_blocks = (len + BLEN - 1) / BLEN;

    /* --- Build LUT on CPU -------------------------------------------- */
    fprintf(stderr, "  GPU: building LUT (%zu blocks)...\n", nb_blocks);
    uint32_t lut_mask;
    lut_entry *h_lut = build_lut_host(h, nb_blocks, &lut_mask);
    if (!h_lut) { fprintf(stderr, "  GPU: OOM building LUT\n"); return 0.0; }

    size_t lut_sz    = (size_t)lut_mask + 1;
    size_t lut_bytes = lut_sz * sizeof(lut_entry);
    fprintf(stderr, "  GPU: LUT %.0f MB (%zu slots at 25%% load)\n",
            (double)lut_bytes / (1 << 20), lut_sz);

    /* --- Device allocations ------------------------------------------ */
    uint8_t            *d_hf;
    lut_entry          *d_lut;
    uint8_t            *d_ml;
    int                *d_ind, *d_found;
    unsigned long long *d_count;

    hipMalloc(&d_hf,    HLEN);
    hipMalloc(&d_lut,   lut_bytes);
    hipMalloc(&d_ml,    BLEN);
    hipMalloc(&d_ind,   sizeof(int));
    hipMalloc(&d_found, sizeof(int));
    hipMalloc(&d_count, sizeof(unsigned long long));

    hipMemcpy(d_hf,  hf,    HLEN,       hipMemcpyHostToDevice);
    hipMemcpy(d_lut, h_lut, lut_bytes,  hipMemcpyHostToDevice);
    hipMemset(d_found, 0, sizeof(int));
    hipMemset(d_count, 0, sizeof(unsigned long long));
    free(h_lut);   /* device has its own copy now */

    /* --- Seed from /dev/urandom --------------------------------------- */
    uint64_t seed = 0xdeadbeefcafeULL;
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) { fread(&seed, sizeof(seed), 1, fp); fclose(fp); }

    /* --- Launch ------------------------------------------------------- */
    /* 128 blocks × 256 threads = 32 768 concurrent work items.
     * For discrete GPUs with many SMs, increase blocks (e.g. 512×256). */
    dim3 threads(256);
    dim3 blocks(128);
    fprintf(stderr, "  GPU: launching %u×%u threads...\n",
            blocks.x, threads.x);

    linkmsg_kernel<<<blocks, threads>>>(
        d_hf, d_lut, lut_mask, seed,
        d_ml, d_ind, d_found, d_count);

    hipDeviceSynchronize();
    fprintf(stderr, "  GPU: kernel finished\n");

    /* --- Retrieve results --------------------------------------------- */
    hipMemcpy(ml,  d_ml,   BLEN,        hipMemcpyDeviceToHost);
    hipMemcpy(ind, d_ind,  sizeof(int), hipMemcpyDeviceToHost);

    unsigned long long count = 0;
    hipMemcpy(&count, d_count, sizeof(count), hipMemcpyDeviceToHost);

    /* --- Cleanup ------------------------------------------------------ */
    hipFree(d_hf);   hipFree(d_lut);   hipFree(d_ml);
    hipFree(d_ind);  hipFree(d_found); hipFree(d_count);

    return (double)count;
}
