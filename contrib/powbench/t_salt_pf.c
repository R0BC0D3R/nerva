/* Run-ahead prefetching of the salt's block-cache reads.
 *
 * Not from the published report. It came out of t_salt_profile, which showed
 * HC128_EncryptMessage costing 560 cycles for sixteen update steps while the
 * same sixteen steps inside HC128_Init cost about 6.5 cycles each. The
 * difference is cache pollution: four random reads into a 236 MB table happen
 * between every encrypt and evict P and Q, so each NextKeys reloads them. The
 * picks' real cost is therefore larger than their measured 19.3% and part of it
 * is hiding inside encrypt.
 *
 * The opening: HC128_NextKeys advances the cipher state independently of the
 * message being encrypted, and HC128_U32 consumes keystream whose sequence is
 * likewise data-independent. So every pick index for a sixteen-count block can
 * be computed before any block-cache read happens. Compute all 64 up front,
 * prefetch as each one is produced, and the block's 64 dependent memory
 * latencies collapse into one pipelined batch.
 *
 * The only thing in the loop that does depend on the fetched data is the
 * reseed at the end of each block, which keys HC128_Init from the output
 * buffer. That is why the run-ahead is per block and not longer.
 *
 * Output must be byte-identical to the reference. That is checked, not assumed.
 *
 * Local experiment. Nothing here is wired into the daemon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <x86intrin.h>

#include "hc128.h"

#define CNA_V6_WINDOW_BLOCKS     100000U
#define CNA_V6_FULL_HISTORY_ODDS 13U
#define SALT_BYTES               262144

typedef struct {
    unsigned char hash[32];
    uint64_t timestamp;
    uint64_t diff_lo;
    uint64_t coins;
} bcd_t;

static bcd_t *g_cache;
static uint64_t g_height, g_window_size, g_window_base;

/* Hint choice is worth measuring rather than assuming: the whole problem is
 * that 236 MB of block-cache traffic evicts P and Q, and NTA exists precisely
 * so a streaming read does not do that. Hint 4 disables prefetching entirely,
 * which separates the two effects, since part of the gain is simply not
 * interleaving the cipher with the random reads. */
static int g_hint = 3;   /* 3=T0 2=T1 1=T2 0=NTA 4=none */

static inline void pf(const void *p)
{
    switch (g_hint)
    {
    case 3: _mm_prefetch((const char *)p, _MM_HINT_T0); break;
    case 2: _mm_prefetch((const char *)p, _MM_HINT_T1); break;
    case 1: _mm_prefetch((const char *)p, _MM_HINT_T2); break;
    case 0: _mm_prefetch((const char *)p, _MM_HINT_NTA); break;
    default: break;
    }
}


static inline uint64_t pick(HC128_State *rng, size_t *ki)
{
    if (HC128_U32(rng, ki, 256) < CNA_V6_FULL_HISTORY_ODDS)
        return HC128_U32(rng, ki, (uint32_t)g_height);
    return g_window_base + HC128_U32(rng, ki, (uint32_t)g_window_size);
}

/* ------------------------------------------------------------- reference */

static void salt_ref(HC128_State *rng, unsigned char *out)
{
    size_t ki = 0;
    unsigned char msg[64];
    size_t msgpos;
    unsigned char *optr = out;
    uint64_t count = 0;
    const bcd_t *bi;
    size_t k;

#define REF_BODY()                                                            \
    do {                                                                      \
        bi = &g_cache[pick(rng, &ki)]; memcpy(msg, bi->hash, 32); msgpos = 32; \
        bi = &g_cache[pick(rng, &ki)]; memcpy(msg + msgpos, &bi->timestamp, 8); msgpos += 8; \
        bi = &g_cache[pick(rng, &ki)]; memcpy(msg + msgpos, &bi->diff_lo, 8); msgpos += 8;   \
        bi = &g_cache[pick(rng, &ki)]; memcpy(msg + msgpos, &bi->coins, 8); msgpos += 8;     \
        memcpy(msg + msgpos, &count, 8);                                      \
        HC128_EncryptMessage(rng, msg, optr, sizeof(msg));                    \
        optr += 16 * sizeof(uint32_t);                                        \
        count++;                                                              \
    } while (0)

#define REF_RESEED()                                                          \
    do {                                                                      \
        unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);     \
        unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);     \
        HC128_Init(rng, key, iv);                                             \
    } while (0)

    while (count < 2048) { HC128_NextKeys(rng); for (k = 0; k < 16; k++) REF_BODY(); REF_RESEED(); }

    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    HC128_EncryptMessage(rng, msg, optr, sizeof(msg));
    HC128_Init(rng, optr, optr + 16);

    while (count < 4096) { HC128_NextKeys(rng); for (k = 0; k < 16; k++) REF_BODY(); REF_RESEED(); }
}

/* ------------------------------------------------------- run-ahead + prefetch */

static void salt_pf(HC128_State *rng, unsigned char *out)
{
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    size_t k, j;
    uint64_t idx[16][4];
    uint32_t ks[16][16];

    /* One block: run the cipher forward over all sixteen counts, recording the
     * pick indices and the keystream each encrypt will use, prefetching every
     * index the moment it exists. No block-cache value is read in this pass, so
     * nothing here can stall on memory. */
#define PF_BLOCK()                                                            \
    do {                                                                      \
        HC128_NextKeys(rng);                                                  \
        for (k = 0; k < 16; k++)                                              \
        {                                                                     \
            for (j = 0; j < 4; j++)                                           \
            {                                                                 \
                idx[k][j] = pick(rng, &ki);                                   \
                pf(&g_cache[idx[k][j]]);                                     \
            }                                                                 \
            /* EncryptMessage's state advance does not depend on the message, \
             * so it can run now and its keystream be kept for later. */      \
            HC128_NextKeys(rng);                                              \
            memcpy(ks[k], rng->keystream, 64);                                \
        }                                                                     \
        for (k = 0; k < 16; k++)                                              \
        {                                                                     \
            const bcd_t *b0 = &g_cache[idx[k][0]];                            \
            const bcd_t *b1 = &g_cache[idx[k][1]];                            \
            const bcd_t *b2 = &g_cache[idx[k][2]];                            \
            const bcd_t *b3 = &g_cache[idx[k][3]];                            \
            memcpy(msg, b0->hash, 32);                                        \
            memcpy(msg + 32, &b1->timestamp, 8);                              \
            memcpy(msg + 40, &b2->diff_lo, 8);                                \
            memcpy(msg + 48, &b3->coins, 8);                                  \
            memcpy(msg + 56, &count, 8);                                      \
            for (j = 0; j < 16; j++)                                          \
                ((uint32_t *)optr)[j] = ((const uint32_t *)msg)[j] ^ ks[k][j]; \
            optr += 64;                                                       \
            count++;                                                          \
        }                                                                     \
        {                                                                     \
            unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16); \
            unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16); \
            HC128_Init(rng, key, iv);                                         \
        }                                                                     \
    } while (0)

    while (count < 2048) PF_BLOCK();

    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    HC128_EncryptMessage(rng, msg, optr, sizeof(msg));
    HC128_Init(rng, optr, optr + 16);

    while (count < 4096) PF_BLOCK();
}

/* ------------------------------------------------------------------ main */

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    const int salts = (argc > 1) ? atoi(argv[1]) : 40;
    const uint64_t height = (argc > 2) ? strtoull(argv[2], NULL, 10) : 4424749ull;
    const char *hint_names[5] = { "NTA", "T2", "T1", "T0", "none" };
    unsigned char *a, *b;
    HC128_State rng;
    unsigned char seed[32];
    uint64_t i;
    int s;
    double t0, tref, tpf;

    g_height = height;
    g_window_size = (height > CNA_V6_WINDOW_BLOCKS) ? CNA_V6_WINDOW_BLOCKS : height;
    g_window_base = height - g_window_size;

    g_cache = (bcd_t *)malloc((size_t)height * sizeof(bcd_t));
    a = (unsigned char *)malloc(SALT_BYTES);
    b = (unsigned char *)malloc(SALT_BYTES);
    if (!g_cache || !a || !b) { fprintf(stderr, "alloc failed\n"); return 2; }

    for (i = 0; i < height; i++)
    {
        g_cache[i].timestamp = i * 0x9E3779B97F4A7C15ull;
        g_cache[i].diff_lo   = i ^ 0x5851F42D4C957F2Dull;
        g_cache[i].coins     = i * 1000000ull;
        memcpy(g_cache[i].hash, &i, 8);
    }
    printf("block cache %.0f MB\n", (double)height * sizeof(bcd_t) / (1024.0 * 1024.0));

    /* Correctness first: same seed in, same 256 KB out. */
    for (i = 0; i < 32; i++) seed[i] = (unsigned char)(i * 7 + 1);
    for (s = 0; s < 8; s++)
    {
        seed[0] = (unsigned char)s;
        HC128_Init(&rng, seed, seed + 16); salt_ref(&rng, a);
        HC128_Init(&rng, seed, seed + 16); salt_pf(&rng, b);
        if (memcmp(a, b, SALT_BYTES) != 0)
        {
            size_t d = 0;
            while (d < SALT_BYTES && a[d] == b[d]) d++;
            printf("MISMATCH at byte %zu: ref %02x pf %02x\n", d, a[d], b[d]);
            return 1;
        }
    }
    printf("run-ahead output is byte-identical over 8 salts\n");

    seed[0] = 0x5a;
    HC128_Init(&rng, seed, seed + 16); salt_ref(&rng, a);   /* warm */

    t0 = now_s();
    for (s = 0; s < salts; s++) { seed[0] = (unsigned char)s; HC128_Init(&rng, seed, seed + 16); salt_ref(&rng, a); }
    tref = now_s() - t0;

    printf("\n%d salts\n", salts);
    printf("  %-14s %8.1f us per salt\n", "reference", tref * 1e6 / salts);
    for (g_hint = 4; g_hint >= 0; g_hint--)
    {
        HC128_Init(&rng, seed, seed + 16); salt_pf(&rng, b);   /* warm this variant */
        t0 = now_s();
        for (s = 0; s < salts; s++) { seed[0] = (unsigned char)s; HC128_Init(&rng, seed, seed + 16); salt_pf(&rng, b); }
        tpf = now_s() - t0;
        printf("  run-ahead %-4s %8.1f us per salt   %.2fx\n",
               hint_names[g_hint], tpf * 1e6 / salts, tref / tpf);
    }

    free(g_cache); free(a); free(b);
    return 0;
}
