#include <string.h>
#include <stdlib.h>
#include "hash.h"
#include "utils.h"
#include "attack.h"

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
	for (size_t j = 1; j < nb_blocks; j++) {
            if (memcmp(tmp, h + j * HLEN, HLEN) == 0) {
                *ind = (int)j;   // store which intermediate digest matched
                return count;
            }
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
