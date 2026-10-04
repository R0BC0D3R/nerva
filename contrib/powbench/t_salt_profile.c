/* Where does get_cna_v6_data actually spend its time?
 *
 * This is the Amdahl gate for the eight-lane HC-128 work. An eight-lane
 * HC128_Init is 2.55x faster than the scalar one (t_hc128_x8), but that only
 * matters in proportion to the share of the salt that HC128_Init occupies, and
 * the last time a change was made on a predicted speedup without checking the
 * share first, the measured result was +0.5% (computed-goto VM dispatch).
 *
 * The salt loop is reproduced here faithfully from
 * BlockchainLMDB::get_cna_v6_data, against a synthetic block cache of the same
 * size and shape as the real one, with rdtsc accumulators around the three
 * components:
 *
 *   init     257 HC128_Init calls, the reseeds. What x8 would speed up.
 *   picks    16384 pick_index() draws and the block-cache reads they feed,
 *            95% inside the recent-100000-block window, 5% full history.
 *   encrypt  4096 HC128_EncryptMessage calls of 64 bytes.
 *
 * The block cache is the real size: a mainnet height of about 4.42M entries at
 * 56 bytes is roughly 248 MB, so the access pattern's cache behaviour is
 * represented rather than guessed at.
 *
 * Shares are what this is for. Absolute numbers move with machine load.
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

/* Mirrors block_cache_data in db_lmdb.h: 32 + 8 + 8 + 8. */
typedef struct {
    unsigned char hash[32];
    uint64_t timestamp;
    uint64_t diff_lo;
    uint64_t coins;
} bcd_t;

static bcd_t *g_cache;
static uint64_t g_height;

static uint64_t c_init, c_picks, c_encrypt, c_total;
static uint64_t n_init, n_picks, n_encrypt;

static inline uint64_t tsc(void) { return __rdtsc(); }

static void salt_once(HC128_State *rng, unsigned char *out)
{
    const uint64_t height = g_height;
    const uint64_t window_size = (height > CNA_V6_WINDOW_BLOCKS) ? CNA_V6_WINDOW_BLOCKS : height;
    const uint64_t window_base = height - window_size;
    size_t rng_key_idx = 0;
    unsigned char msg[64];
    size_t msgpos;
    unsigned char *optr = out;
    uint64_t count = 0;
    uint64_t t0;
    const bcd_t *bi;

#define PICK() ( (HC128_U32(rng, &rng_key_idx, 256) < CNA_V6_FULL_HISTORY_ODDS) \
                 ? (uint64_t)HC128_U32(rng, &rng_key_idx, (uint32_t)height)     \
                 : window_base + HC128_U32(rng, &rng_key_idx, (uint32_t)window_size) )

#define BODY()                                                                 \
    do {                                                                       \
        t0 = tsc();                                                            \
        bi = &g_cache[PICK()]; memcpy(msg, bi->hash, 32); msgpos = 32;          \
        bi = &g_cache[PICK()]; memcpy(msg + msgpos, &bi->timestamp, 8); msgpos += 8; \
        bi = &g_cache[PICK()]; memcpy(msg + msgpos, &bi->diff_lo, 8); msgpos += 8;   \
        bi = &g_cache[PICK()]; memcpy(msg + msgpos, &bi->coins, 8); msgpos += 8;     \
        memcpy(msg + msgpos, &count, 8);                                       \
        c_picks += tsc() - t0; n_picks += 4;                                   \
        t0 = tsc();                                                            \
        HC128_EncryptMessage(rng, msg, optr, sizeof(msg));                     \
        c_encrypt += tsc() - t0; n_encrypt++;                                  \
        optr += 16 * sizeof(uint32_t);                                         \
        count++;                                                               \
    } while (0)

#define RESEED()                                                               \
    do {                                                                       \
        unsigned char *iv  = optr - 512  + HC128_U32(rng, &rng_key_idx, 512 - 16); \
        unsigned char *key = optr - 1024 + HC128_U32(rng, &rng_key_idx, 512 - 16); \
        t0 = tsc();                                                            \
        HC128_Init(rng, key, iv);                                              \
        c_init += tsc() - t0; n_init++;                                        \
    } while (0)

    while (count < 2048)
    {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++) BODY();
        RESEED();
    }

    memcpy(msg, optr - 131072 + HC128_U32(rng, &rng_key_idx, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &rng_key_idx, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &rng_key_idx, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &rng_key_idx, 131072U - 16U), 16);
    t0 = tsc();
    HC128_EncryptMessage(rng, msg, optr, sizeof(msg));
    c_encrypt += tsc() - t0; n_encrypt++;
    t0 = tsc();
    HC128_Init(rng, optr, optr + 16);
    c_init += tsc() - t0; n_init++;

    while (count < 4096)
    {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++) BODY();
        RESEED();
    }
}

int main(int argc, char **argv)
{
    const int salts = (argc > 1) ? atoi(argv[1]) : 20;
    const uint64_t height = (argc > 2) ? strtoull(argv[2], NULL, 10) : 4424749ull;
    unsigned char *out;
    HC128_State rng;
    unsigned char seed[32];
    uint64_t i, t0;
    int s;

    g_height = height;
    printf("block cache: %llu entries x %u bytes = %.0f MB\n",
           (unsigned long long)height, (unsigned)sizeof(bcd_t),
           (double)height * sizeof(bcd_t) / (1024.0 * 1024.0));

    g_cache = (bcd_t *)malloc((size_t)height * sizeof(bcd_t));
    out = (unsigned char *)malloc(SALT_BYTES);
    if (g_cache == NULL || out == NULL) { fprintf(stderr, "alloc failed\n"); return 2; }

    /* Fill it with something; the values do not matter, the size and the
     * access pattern do. Touch every page so none of this is a first-touch
     * fault inside the measurement. */
    for (i = 0; i < height; i++)
    {
        g_cache[i].timestamp = i * 0x9E3779B97F4A7C15ull;
        g_cache[i].diff_lo   = i ^ 0x5851F42D4C957F2Dull;
        g_cache[i].coins     = i * 1000000ull;
        memcpy(g_cache[i].hash, &i, 8);
    }

    for (i = 0; i < 32; i++) seed[i] = (unsigned char)(i * 7 + 1);
    HC128_Init(&rng, seed, seed + 16);
    salt_once(&rng, out);                     /* warm, discarded */
    c_init = c_picks = c_encrypt = 0;
    n_init = n_picks = n_encrypt = 0;

    t0 = tsc();
    for (s = 0; s < salts; s++)
    {
        HC128_Init(&rng, seed, seed + 16);
        seed[0]++;
        salt_once(&rng, out);
    }
    c_total = tsc() - t0;

    printf("\n%d salts\n", salts);
    printf("  %-10s %6s  %14s  %10s  %s\n", "component", "share", "cycles/salt", "count", "cycles each");
    printf("  %-10s %5.1f%%  %14.0f  %10.0f  %.1f\n", "init",
           100.0 * c_init / c_total, (double)c_init / salts, (double)n_init / salts,
           (double)c_init / n_init);
    printf("  %-10s %5.1f%%  %14.0f  %10.0f  %.1f\n", "picks",
           100.0 * c_picks / c_total, (double)c_picks / salts, (double)n_picks / salts,
           (double)c_picks / n_picks);
    printf("  %-10s %5.1f%%  %14.0f  %10.0f  %.1f\n", "encrypt",
           100.0 * c_encrypt / c_total, (double)c_encrypt / salts, (double)n_encrypt / salts,
           (double)c_encrypt / n_encrypt);
    printf("  %-10s %5.1f%%  %14.0f\n", "unattributed",
           100.0 * (double)(c_total - c_init - c_picks - c_encrypt) / c_total,
           (double)(c_total - c_init - c_picks - c_encrypt) / salts);
    printf("  %-10s %5.1f%%  %14.0f\n", "total", 100.0, (double)c_total / salts);

    {
        const double init_share = (double)c_init / c_total;
        const double x8 = 2.55;   /* measured in t_hc128_x8 on this machine */
        const double salt_speedup = 1.0 / (1.0 - init_share + init_share / x8);
        printf("\nIf HC128_Init alone goes %.2fx faster, the salt goes %.2fx faster.\n", x8, salt_speedup);
        printf("The rdtsc calls themselves inflate the smaller components, so\n");
        printf("treat init's share as a floor and the speedup as a ceiling.\n");
    }

    free(g_cache);
    free(out);
    return 0;
}
