#include "utils.h"

/* Toy implementation of SPECK32/64, 48/96, and 64/128
 * For educational purpose only 
 * B. Grenet, from existing code
 */

#if BLOCKSIZE == 32
    #define ALPHA 7
    #define BETA 2
    #define ROUND 22
    #define halfblock uint16_t
    #define MASK 0xffff
#elif BLOCKSIZE == 48
    #define ALPHA 8
    #define BETA 3
    #define ROUND 23
    #define halfblock uint32_t
    #define MASK 0xffffff
#else // BLOCKSIZE == 64 
    #define ALPHA 8
    #define BETA 3
    #define ROUND 27
    #define halfblock uint32_t
    #define MASK 0xffffffff
#endif

#define ROTL(x,n) (((x << n) ^ (x >> (BLOCKSIZE/2-n)))&MASK)
#define ROTR(x,n) (((x >> n) ^ (x << (BLOCKSIZE/2-n)))&MASK)
#define R(x,y,k) (x=ROTR(x,ALPHA), x+=y, x&=MASK, x^=k, y=ROTL(y,BETA), y^=x)
#define D(x,y,k) (y^=x, y=ROTR(y,BETA)&MASK, x^=k, x-=y, x&=MASK, x=ROTL(x,ALPHA)&MASK)

void byte2halfblock(halfblock *dest, const byte *orig, int start)
{    
    *dest = 0;
    for (int j=MLEN/2-1; j>=0; j--) 
    {
        *dest <<= 8;
        *dest |= (halfblock)orig[start+j];
    }
}

void halfblocks2bytes(byte* dest, halfblock* orig, int start)
{
    for (int i=0; i < MLEN/2; i++)
    {
        dest[i] = orig[0] & 0xff;
        orig[0] >>= 8;
        dest[i+MLEN/2] = orig[1] & 0xff;
        orig[1] >>= 8;
    }
}

void key_schedule(const byte k[KLEN], halfblock rk[ROUND])
{
    halfblock l[4];
    byte2halfblock(rk, k, 0);
    byte2halfblock(l, k, MLEN/2);
    byte2halfblock(l+1, k, MLEN);
    byte2halfblock(l+2, k, 3*MLEN/2);
    for (int i=0; i < ROUND-1; i++) {
        rk[i+1] = rk[i];
        R(l[0],rk[i+1],i);
        l[3] = l[0];
        for(int j=0; j<3;j++) l[j] = l[j+1];
    }
}

void speck_enc(const byte k[KLEN], const byte m[MLEN], byte c[MLEN])
{
    halfblock cc[2] = {0, 0};
    byte2halfblock(cc, m, 0);
    byte2halfblock(cc+1, m, MLEN/2);
    halfblock rk[ROUND];
    key_schedule(k, rk);
    for (int i=0; i < ROUND; i++) 
        R(cc[1],cc[0],rk[i]);
    halfblocks2bytes(c, cc, 0);
    return;
}

void speck_dec(const byte k[KLEN], byte m[MLEN], const byte c[MLEN])
{
    halfblock mm[2] = {0, 0};
    byte2halfblock(mm, c, 0);
    byte2halfblock(mm+1, c, MLEN/2);
    halfblock rk[ROUND];
    key_schedule(k, rk);
    for (int i=ROUND-1; i >=0; i--) 
        D(mm[1],mm[0],rk[i]);
    halfblocks2bytes(m, mm, 0);
    return;
}

#undef ROTL
#undef ROTR
#undef R
#undef D
#undef ALPHA
#undef BETA
#undef ROUND
#undef halfblock
#undef MASK

/*  Implementation of xoshiro256** */
/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

	To the extent possible under law, the author has dedicated all copyright
	and related and neighboring rights to this software to the public domain
	worldwide. This software is distributed without any warranty.

	See <http://creativecommons.org/publicdomain/zero/1.0/>. */

/* This is xoshiro256** 1.0, our all-purpose, rock-solid generator. It has
   excellent (sub-ns) speed, a state (256 bits) that is large enough for
   any parallel application, and it passes all tests we are aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. */

static inline uint64_t __my_little_xoshiro256starstar__rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}

static int __my_little_init_was_done = 0;
static uint64_t __my_little_xoshiro256starstar__s[4];

/* Inits */

void __my_little_xoshiro256starstar_initialization(uint64_t iv[4])
{
	__my_little_xoshiro256starstar__s[0] = iv[0];
	__my_little_xoshiro256starstar__s[1] = iv[1];
	__my_little_xoshiro256starstar__s[2] = iv[2];
	__my_little_xoshiro256starstar__s[3] = iv[3];
    __my_little_init_was_done = 1;

    return;
}

/* This function initializes one state with a key from /dev/urandom */
void __my_little_xoshiro256starstar_unseeded_init()
{
	FILE *urd = fopen("/dev/urandom", "r");
	uint64_t iv[4] = {1,1,1,1};

	if (urd == NULL)
	{
		fprintf(stderr, "failed to initialize the little xoshiro256** prng [No file called /dev/urandom]\n");
		__my_little_xoshiro256starstar_initialization(iv);
		return;
	}

	if(1 != fread((uint8_t *)iv, 32, 1, urd))
	{
		fprintf(stderr, "failed to initialize the little8 xoshiro256** prng [Not enough p$ bytes]\n");
	}
	fclose(urd);
	__my_little_xoshiro256starstar_initialization(iv);
	return;
}

uint64_t __my_little_xoshiro256starstar__next__unsafe(void) {
	const uint64_t result_starstar = __my_little_xoshiro256starstar__rotl(__my_little_xoshiro256starstar__s[1] * 5, 7) * 9;

	const uint64_t t = __my_little_xoshiro256starstar__s[1] << 17;

	__my_little_xoshiro256starstar__s[2] ^= __my_little_xoshiro256starstar__s[0];
	__my_little_xoshiro256starstar__s[3] ^= __my_little_xoshiro256starstar__s[1];
	__my_little_xoshiro256starstar__s[1] ^= __my_little_xoshiro256starstar__s[2];
	__my_little_xoshiro256starstar__s[0] ^= __my_little_xoshiro256starstar__s[3];

	__my_little_xoshiro256starstar__s[2] ^= t;

	__my_little_xoshiro256starstar__s[3] = __my_little_xoshiro256starstar__rotl(__my_little_xoshiro256starstar__s[3], 45);

	return result_starstar;
}

uint64_t __my_little_xoshiro256starstar__next(void) {
	if (!__my_little_init_was_done)
	{
		__my_little_xoshiro256starstar_unseeded_init();
		__my_little_init_was_done = 1;
	}

	return __my_little_xoshiro256starstar__next__unsafe();
}

/* This is the jump function for the generator. It is equivalent
   to 2^128 calls to __my_little_xoshiro256starstar__next(); it can be used to generate 2^128
   non-overlapping subsequences for parallel computations. */

void __my_little_xoshiro256starstar__jump(void) {
	static const uint64_t JUMP[] = { 0x180ec6d33cfd0aba, 0xd5a61266f0c9392c, 0xa9582618e03fc9aa, 0x39abdc4529b1661c };

	uint64_t s0 = 0;
	uint64_t s1 = 0;
	uint64_t s2 = 0;
	uint64_t s3 = 0;
	for(int i = 0; i < sizeof JUMP / sizeof *JUMP; i++)
		for(int b = 0; b < 64; b++) {
			if (JUMP[i] & UINT64_C(1) << b) {
				s0 ^= __my_little_xoshiro256starstar__s[0];
				s1 ^= __my_little_xoshiro256starstar__s[1];
				s2 ^= __my_little_xoshiro256starstar__s[2];
				s3 ^= __my_little_xoshiro256starstar__s[3];
			}
			__my_little_xoshiro256starstar__next();
		}

	__my_little_xoshiro256starstar__s[0] = s0;
	__my_little_xoshiro256starstar__s[1] = s1;
	__my_little_xoshiro256starstar__s[2] = s2;
	__my_little_xoshiro256starstar__s[3] = s3;
}

/* This is the long-jump function for the generator. It is equivalent to
   2^192 calls to __my_little_xoshiro256starstar__next(); it can be used to generate 2^64 starting points,
   from each of which jump() will generate 2^64 non-overlapping
   subsequences for parallel distributed computations. */

void __my_little_xoshiro256starstar__long_jump(void) {
	static const uint64_t LONG_JUMP[] = { 0x76e15d3efefdcbbf, 0xc5004e441c522fb3, 0x77710069854ee241, 0x39109bb02acbe635 };

	uint64_t s0 = 0;
	uint64_t s1 = 0;
	uint64_t s2 = 0;
	uint64_t s3 = 0;
	for(int i = 0; i < sizeof LONG_JUMP / sizeof *LONG_JUMP; i++)
		for(int b = 0; b < 64; b++) {
			if (LONG_JUMP[i] & UINT64_C(1) << b) {
				s0 ^= __my_little_xoshiro256starstar__s[0];
				s1 ^= __my_little_xoshiro256starstar__s[1];
				s2 ^= __my_little_xoshiro256starstar__s[2];
				s3 ^= __my_little_xoshiro256starstar__s[3];
			}
			__my_little_xoshiro256starstar__next();
		}

	__my_little_xoshiro256starstar__s[0] = s0;
	__my_little_xoshiro256starstar__s[1] = s1;
	__my_little_xoshiro256starstar__s[2] = s2;
	__my_little_xoshiro256starstar__s[3] = s3;
}

/*
 * Aliases
 */


/* Utils for working with byte arrays
 * B. Grenet */

void random_init(uint64_t seed[4])
{
	__my_little_xoshiro256starstar_initialization(seed);
}

void random_bytes(byte* array, size_t len)
{
    size_t blocks = len/8;
    if (len % 8) blocks++;

    uint64_t r;
    size_t j=0, t=0;
    for (size_t i=0; i<blocks; i++)
    {
        r = __my_little_xoshiro256starstar__next();
        for(t=0;t<8 && j<len;t++,j++) {
            array[j] = r & 0xff;
            r >>= 8;
        }
    }
}

void print_bytes(const byte *array, size_t len)
{
    for (size_t i=0; i < len; i++) printf("%02x",array[len-i-1]);
}

byte toByte(char c)
{
  if (c >= '0' && c <= '9') return      c - '0';
  if (c >= 'A' && c <= 'F') return 10 + c - 'A';
  if (c >= 'a' && c <= 'f') return 10 + c - 'a';
  return -1;
}

void read_bytes(char* str, byte *array, size_t len)
{
    size_t slen = strlen(str);
    size_t i = 0;
    for (; i < len && (2*i+1) < slen; i++)
        array[len-i-1] = (toByte(str[2*i])<<4) + toByte(str[2*i+1]);
    if (i < len && 2*i < slen) array[len-i-1] = toByte(str[2*i] << 4);
    for (; i < len; i++) array[len-i-1] = 0x00;
}
