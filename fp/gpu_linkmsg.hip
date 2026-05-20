/*
 * gpu_linkmsg.hip
 *
 * GPU implementation of linkmsg() using HIP (AMD + NVIDIA).
 * Ports speck_enc/dec and xoshiro256** from utils.c to __device__ functions.
 * collision() is intentionally left on the CPU (random hash table writes
 * are a poor fit for GPU memory access patterns).
 */

#include <hip/hip_runtime.h>
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
 * linkmsg kernel
 *
 * Each thread independently:
 *   1. samples a random ml block
 *   2. computes f(hf, ml)
 *   3. scans the read-only intermediate digest array
 *
 * First thread to find a match sets *found via atomicCAS and writes
 * the result. All other threads stop on the next iteration.
 * ====================================================================== */
__global__ void linkmsg_kernel(
    const uint8_t * __restrict__ hf,          /* fixed-point hash  [HLEN]        */
    const uint8_t * __restrict__ h_digests,   /* intermediate hashes [nb*HLEN]   */
    int              nb_blocks,               /* blocks in target message         */
    uint64_t         host_seed,              /* entropy from /dev/urandom        */
    uint8_t         *res_ml,                 /* output: winning ml [BLEN]        */
    int             *res_ind,                /* output: matched digest index     */
    int             *found,                  /* shared stop flag                 */
    unsigned long long *total_count          /* total samples across all threads */
) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    /* Each thread gets a fully independent xoshiro256** stream */
    xo_state rng = xo_seed(host_seed ^ (uint64_t)tid);

    uint8_t ml[BLEN], tmp[HLEN];
    unsigned long long local_count = 0;

    while (!atomicAdd(found, 0)) {
        xo_random_bytes(ml, BLEN, &rng);
        local_count++;

        /* tmp = f(hf, ml) */
        for (int i = 0; i < HLEN; i++) tmp[i] = hf[i];
        d_compression(tmp, ml);

        /* Scan intermediate digests — skip h[0] which is the IV */
        for (int j = 1; j < nb_blocks; j++) {
            bool match = true;
            for (int b = 0; b < HLEN; b++) {
                if (tmp[b] != h_digests[j * HLEN + b]) { match = false; break; }
            }
            if (match) {
                /* Only the first thread to arrive writes the result */
                if (atomicCAS(found, 0, 1) == 0) {
                    for (int b = 0; b < BLEN; b++) res_ml[b] = ml[b];
                    *res_ind = j;
                }
                goto done;
            }
        }
    }
done:
    atomicAdd(total_count, local_count);
}

/* ======================================================================
 * Host-side wrapper
 *
 * On your 780M (iGPU, unified memory) hipMalloc still works fine —
 * the driver places the allocation in the shared pool and the GPU
 * accesses it directly without a PCIe copy.
 * ====================================================================== */
extern "C"
double gpu_linkmsg(uint8_t *ml, int *ind,
                   const uint8_t *hf, const uint8_t *h, size_t len)
{
    size_t nb_blocks  = (len + BLEN - 1) / BLEN;
    size_t nb_digests = nb_blocks + 2;   /* IV + message blocks + length block */

    /* --- device allocations ------------------------------------------ */
    uint8_t            *d_hf, *d_h, *d_ml;
    int                *d_ind, *d_found;
    unsigned long long *d_count;

    hipMalloc(&d_hf,    HLEN);
    hipMalloc(&d_h,     nb_digests * HLEN);
    hipMalloc(&d_ml,    BLEN);
    hipMalloc(&d_ind,   sizeof(int));
    hipMalloc(&d_found, sizeof(int));
    hipMalloc(&d_count, sizeof(unsigned long long));

    hipMemcpy(d_hf, hf, HLEN,              hipMemcpyHostToDevice);
    hipMemcpy(d_h,  h,  nb_digests * HLEN, hipMemcpyHostToDevice);
    hipMemset(d_found, 0, sizeof(int));
    hipMemset(d_count, 0, sizeof(unsigned long long));

    /* --- seed from /dev/urandom --------------------------------------- */
    uint64_t seed = 0xdeadbeefcafeULL;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(&seed, sizeof(seed), 1, f); fclose(f); }

    /* --- launch: 780M has 12 CUs, 64 threads/wavefront -------------- */
    /* 128 blocks × 256 threads = 32 768 concurrent work items          */
    dim3 threads(256);
    dim3 blocks(128);

    linkmsg_kernel<<<blocks, threads>>>(
        d_hf, d_h, (int)nb_blocks, seed,
        d_ml, d_ind, d_found, d_count);

    hipDeviceSynchronize();

    /* --- retrieve results --------------------------------------------- */
    hipMemcpy(ml,  d_ml,  BLEN,       hipMemcpyDeviceToHost);
    hipMemcpy(ind, d_ind, sizeof(int), hipMemcpyDeviceToHost);

    unsigned long long count = 0;
    hipMemcpy(&count, d_count, sizeof(count), hipMemcpyDeviceToHost);

    /* --- cleanup ------------------------------------------------------ */
    hipFree(d_hf); hipFree(d_h);    hipFree(d_ml);
    hipFree(d_ind); hipFree(d_found); hipFree(d_count);

    return (double)count;
}
