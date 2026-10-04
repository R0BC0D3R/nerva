/* What is nonce screening actually worth on v13, measured end to end?
 *
 * FINDINGS F6b modelled this at 1.3 to 1.4x against a stock pipeline, while the
 * published miner attributes 319 to 976 H/s to screening alone, a 3.06x break.
 * Both can be right: screening is worth more the more optimised the rest of the
 * miner is, because what it removes is a share of the part that varies. This
 * measures it directly on our pipeline, with the run-ahead salt in place, and
 * reports the whole acceptance curve rather than one point.
 *
 * Method, which avoids the modelling that has gone wrong twice already:
 *   for each nonce, record the cheap estimate and the real measured hash time,
 *   then sweep the threshold over the recorded pairs. Nothing is assumed about
 *   how estimate and cost relate.
 *
 * Cost model per nonce, all of it measured here rather than taken from a table:
 *   rejected: keccak + HC128_Init + one salt iteration + the screen
 *   accepted: the above, plus a full salt, plus the real hash
 * The accepted path pays the screen too, which is the honest accounting.
 *
 * Synthetic block cache of the real size, so the salt's cache behaviour is
 * represented. The hashes are therefore not mainnet-valid, which does not
 * matter: cost depends on the program, and the program depends on the seed.
 *
 * Local experiment. The screen itself lives in cna-vm.c; this only measures it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <cpuid.h>

#include "hash-ops.h"
#include "hc128.h"
#include "cna-vm.h"

#define CNA_V6_WINDOW_BLOCKS     100000U
#define CNA_V6_FULL_HISTORY_ODDS 13U

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

void cn_slow_hash_v13(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *);

typedef struct {
    unsigned char hash[32];
    uint64_t timestamp;
    uint64_t diff_lo;
    uint64_t coins;
} bcd_t;

static bcd_t *g_cache;
static uint64_t g_height, g_wsize, g_wbase;

static inline uint64_t pick(HC128_State *rng, size_t *ki)
{
    if (HC128_U32(rng, ki, 256) < CNA_V6_FULL_HISTORY_ODDS)
        return HC128_U32(rng, ki, (uint32_t)g_height);
    return g_wbase + HC128_U32(rng, ki, (uint32_t)g_wsize);
}

/* The first 64 bytes of the salt, which is all the program seed needs. One
 * loop iteration out of 4096. This is what makes the screen cheap, and it is
 * the property v8 removes by drawing its parameters only after a full fill. */
static void salt_prefix(HC128_State *rng, unsigned char *out64)
{
    size_t ki = 0;
    unsigned char msg[64];
    const bcd_t *bi;
    size_t msgpos;

    HC128_NextKeys(rng);
    bi = &g_cache[pick(rng, &ki)]; memcpy(msg, bi->hash, 32); msgpos = 32;
    bi = &g_cache[pick(rng, &ki)]; memcpy(msg + msgpos, &bi->timestamp, 8); msgpos += 8;
    bi = &g_cache[pick(rng, &ki)]; memcpy(msg + msgpos, &bi->diff_lo, 8); msgpos += 8;
    bi = &g_cache[pick(rng, &ki)]; memcpy(msg + msgpos, &bi->coins, 8); msgpos += 8;
    memset(msg + msgpos, 0, 8);                    /* count == 0 */
    HC128_EncryptMessage(rng, msg, out64, sizeof(msg));
}

/* Full salt, run-ahead form, matching what the daemon now does. */
static void salt_full(HC128_State *rng, unsigned char *out)
{
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    uint64_t idx[16][4];
    uint32_t ks[16][16];
    size_t k, j;

#define BLOCK()                                                               \
    do {                                                                      \
        HC128_NextKeys(rng);                                                  \
        for (k = 0; k < 16; k++) {                                            \
            for (j = 0; j < 4; j++) idx[k][j] = pick(rng, &ki);               \
            HC128_NextKeys(rng);                                              \
            memcpy(ks[k], rng->keystream, 64);                                \
        }                                                                     \
        for (k = 0; k < 16; k++) {                                            \
            const bcd_t *b0 = &g_cache[idx[k][0]], *b1 = &g_cache[idx[k][1]]; \
            const bcd_t *b2 = &g_cache[idx[k][2]], *b3 = &g_cache[idx[k][3]]; \
            memcpy(msg, b0->hash, 32);                                        \
            memcpy(msg + 32, &b1->timestamp, 8);                              \
            memcpy(msg + 40, &b2->diff_lo, 8);                                \
            memcpy(msg + 48, &b3->coins, 8);                                  \
            memcpy(msg + 56, &count, 8);                                      \
            for (j = 0; j < 16; j++) {                                        \
                uint32_t w; memcpy(&w, msg + j * 4, 4); w ^= ks[k][j];         \
                memcpy(optr + j * 4, &w, 4);                                  \
            }                                                                 \
            optr += 64; count++;                                              \
        }                                                                     \
        {                                                                     \
            unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16); \
            unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16); \
            HC128_Init(rng, key, iv);                                         \
        }                                                                     \
    } while (0)

    while (count < 2048) BLOCK();
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072U - 16U), 16);
    HC128_EncryptMessage(rng, msg, optr, sizeof(msg));
    HC128_Init(rng, optr, optr + 16);
    while (count < 4096) BLOCK();
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Reference walk over a fully generated program, to prove lazy generation in
 * cn_vm_screen_cost reaches the same answer. */
static uint32_t screen_reference(const uint8_t seed[32])
{
    cn_vm_program_t prog;
    int pc = 0, step;
    uint32_t memops = 0;
    cn_vm_generate_program(&prog, seed);
    for (step = 0; step < CN_PROGRAM_SIZE; step++)
    {
        const cn_vm_instruction_t *ins = &prog.instructions[pc & (CN_PROGRAM_SIZE - 1)];
        if (ins->op == CN_OP_SP_READ || ins->op == CN_OP_SP_WRITE) memops++;
        if (ins->op == CN_OP_CBRANCH)
            pc = (pc + (int)((int8_t)ins->shift) + CN_PROGRAM_SIZE) & (CN_PROGRAM_SIZE - 1);
        else
            pc = pc + 1;
    }
    return memops;
}

static int cmp_u32(const void *a, const void *b)
{
    const uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    const int nonces = (argc > 1) ? atoi(argv[1]) : 400;
    const uint64_t height = (argc > 2) ? strtoull(argv[2], NULL, 10) : 4424749ull;
    cn_hash_context_t *ctx;
    unsigned char blob[76], prefix[64], seed[32], bh[32];
    char h[HASH_SIZE];
    uint32_t *est;
    double *ht;
    double t0, t_screen_total = 0.0, t_screen_ee_total = 0.0, t_saltfull_total = 0.0;
    const uint32_t ee_limit = 37;   /* the measured optimum threshold */
    uint64_t i;
    int n, bad = 0;

    g_height = height;
    g_wsize = (height > CNA_V6_WINDOW_BLOCKS) ? CNA_V6_WINDOW_BLOCKS : height;
    g_wbase = height - g_wsize;

    g_cache = (bcd_t *)malloc((size_t)height * sizeof(bcd_t));
    est = (uint32_t *)malloc(sizeof(uint32_t) * nonces);
    ht = (double *)malloc(sizeof(double) * nonces);
    ctx = cn_hash_context_create();
    if (!g_cache || !est || !ht || !ctx) { fprintf(stderr, "alloc failed\n"); return 2; }

    for (i = 0; i < height; i++)
    {
        g_cache[i].timestamp = i * 0x9E3779B97F4A7C15ull;
        g_cache[i].diff_lo   = i ^ 0x5851F42D4C957F2Dull;
        g_cache[i].coins     = i * 1000000ull;
        memcpy(g_cache[i].hash, &i, 8);
    }
    printf("block cache %.0f MB, %d nonces\n",
           (double)height * sizeof(bcd_t) / (1024.0 * 1024.0), nonces);

    /* lazy generation must agree with full generation */
    for (n = 0; n < 2000; n++)
    {
        for (i = 0; i < 32; i++) seed[i] = (unsigned char)(n * 31 + i * 7 + 1);
        {
            const uint32_t exact = cn_vm_screen_cost(seed, UINT32_MAX);
            if (exact != screen_reference(seed)) { bad = 1; break; }
            /* Early exit must not change the verdict at any threshold: the
             * count only rises, so (early <= T) must equal (exact <= T). */
            {
                static const uint32_t thr[6] = { 0, 14, 37, 130, 200, 400 };
                int t;
                for (t = 0; t < 6; t++)
                {
                    const uint32_t early = cn_vm_screen_cost(seed, thr[t]);
                    if ((early <= thr[t]) != (exact <= thr[t])) { bad = 2; break; }
                    if (early <= thr[t] && early != exact) { bad = 3; break; }
                }
                if (bad) break;
            }
        }
    }
    if (bad) { printf("MISMATCH: lazy screen disagrees with full generation at %d\n", n); return 1; }
    printf("lazy screen matches full generation over 2000 programs\n");

    for (i = 0; i < 76; i++) blob[i] = (unsigned char)(i * 13 + 5);
    cn_slow_hash_v13(ctx, blob, sizeof(blob), h, (const uint8_t *)blob);  /* allocate */

    for (n = 0; n < nonces; n++)
    {
        HC128_State rng;
        memcpy(blob + 39, &n, 4);
        cn_fast_hash(blob, sizeof(blob), (char *)bh);

        t0 = now_s();
        HC128_Init(&rng, bh, bh + 16);
        salt_prefix(&rng, prefix);
        for (i = 0; i < 32; i++) seed[i] = bh[i] ^ prefix[i];
        est[n] = cn_vm_screen_cost(seed, UINT32_MAX);
        t_screen_total += now_s() - t0;

        /* The same screen as a miner would really run it, stopping as soon as
         * the verdict is settled. Same fixed prefix work, so the difference is
         * the walk and the slot generation it drives. */
        t0 = now_s();
        HC128_Init(&rng, bh, bh + 16);
        salt_prefix(&rng, prefix);
        for (i = 0; i < 32; i++) seed[i] = bh[i] ^ prefix[i];
        (void)cn_vm_screen_cost(seed, ee_limit);
        t_screen_ee_total += now_s() - t0;

        t0 = now_s();
        HC128_Init(&rng, bh, bh + 16);
        salt_full(&rng, (unsigned char *)ctx->salt);
        t_saltfull_total += now_s() - t0;

        memset(&ctx->random_values, 0, sizeof(ctx->random_values));
        t0 = now_s();
        cn_slow_hash_v13(ctx, blob, sizeof(blob), h, seed);
        ht[n] = now_s() - t0;
    }

    {
        const double t_screen = t_screen_ee_total / nonces;
        const double t_screen_full = t_screen_total / nonces;
        const double t_salt   = t_saltfull_total / nonces;
        double sum = 0.0;
        uint32_t *sorted = (uint32_t *)malloc(sizeof(uint32_t) * nonces);
        int j;

        for (n = 0; n < nonces; n++) sum += ht[n];
        memcpy(sorted, est, sizeof(uint32_t) * nonces);
        qsort(sorted, nonces, sizeof(uint32_t), cmp_u32);

        printf("\nscreen, full walk    %7.1f us   (keccak + init + one salt iteration + walk)\n", t_screen_full * 1e6);
        printf("screen, early exit   %7.1f us   at limit %u, %.0f%% cheaper\n",
               t_screen * 1e6, ee_limit, 100.0 * (1.0 - t_screen / t_screen_full));
        printf("full salt     %7.1f us\n", t_salt * 1e6);
        printf("hash          %7.2f ms mean\n", sum / nonces * 1e3);
        printf("estimate      min %u  p50 %u  p99 %u  max %u\n",
               sorted[0], sorted[nonces / 2], sorted[(nonces * 99) / 100], sorted[nonces - 1]);

        {
            const double unscreened = (double)nonces / (t_salt * nonces + sum);
            printf("\nunscreened    %8.1f H/s per thread\n\n", unscreened);
            printf("  accept   thr   n     mean hash   effective H/s   vs unscreened\n");
            for (j = 0; j < 7; j++)
            {
                static const double qs[7] = { 0.01, 0.02, 0.05, 0.10, 0.25, 0.50, 1.00 };
                const double q = qs[j];
                int idx = (int)(q * nonces) - 1;
                uint32_t thr;
                int cnt = 0;
                double acc = 0.0, total, eff;
                if (idx < 0) idx = 0;
                thr = sorted[idx];
                for (n = 0; n < nonces; n++)
                    if (est[n] <= thr) { cnt++; acc += ht[n]; }
                if (cnt == 0) continue;
                /* every nonce pays the screen; only accepted ones pay salt+hash */
                total = (double)nonces * t_screen + (double)cnt * t_salt + acc;
                eff = (double)cnt / total;
                printf("  %5.0f%%  %4u  %4d   %7.2f ms   %9.1f H/s   %8.2fx\n",
                       q * 100.0, thr, cnt, acc / cnt * 1e3, eff, eff / unscreened);
            }
        }
        free(sorted);
    }

    free(g_cache); free(est); free(ht);
    cn_hash_context_free(ctx);
    return 0;
}
