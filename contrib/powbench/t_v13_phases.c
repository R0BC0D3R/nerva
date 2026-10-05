/* Where a screened v13 nonce's time actually goes, measured under contention.
 *
 * The roadmap had the trace JIT next on the strength of an instruction count:
 * about 1.05M interpreted VM instructions per hash against about 15.7M AES
 * operations. Turning those counts into a time budget accounted for only about
 * 60% of a hash, which is not a basis for weeks of emitter work. This measures
 * the split instead.
 *
 * It models the miner's duty cycle rather than timing a hash in isolation,
 * because the screen runs about 244 times per accepted nonce and that cost is
 * part of what a hash really costs. Each thread draws candidate seeds, screens
 * them, and hashes the ones that pass, exactly as miner.cpp does.
 *
 * **The control that makes the breakdown trustworthy is the hashrate it
 * reports.** If this harness does not reproduce the daemon's H/s at the same
 * thread count, it is not measuring the same thing and the shares below it mean
 * nothing. Check that line first.
 *
 * Threads default to 30, which is the cap on this machine: it is a workstation
 * running a desktop, not a rig.
 *
 *   t_v13_phases [threads] [seconds] [threshold]
 *
 * Local experiment, not kept.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <x86intrin.h>
#include <cpuid.h>

#include "hash-ops.h"
#include "cna-vm.h"
#include "hc128.h"

#if !defined(CN_V13_PHASE_TIMING)
#error "build with -DCN_V13_PHASE_TIMING=1, see build-v13-phases.sh"
#endif

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

void cn_slow_hash_v13_hw(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *);
/* The pad and the salt are allocated lazily by the dispatcher, not by the arm,
 * so the warm hash has to go through it or the first arm call reads a NULL pad. */
void cn_slow_hash_v13(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *);

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void fill_salt(char *salt, uint32_t s)
{
    uint64_t x = 0x9E3779B97F4A7C15ull ^ ((uint64_t)s * 0xD1B54A32D192ED03ull);
    uint32_t i;
    if (x == 0) x = 1;
    for (i = 0; i < (uint32_t)CN_SALT_MEMORY; i += 8)
    {
        uint64_t v;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        v = x * 0x2545F4914F6CDD1Dull;
        memcpy(salt + i, &v, 8);
    }
}

static void fill_random_values(cn_random_values_t *rv, uint32_t s)
{
    uint64_t x = 0xA24BAED4963EE407ull ^ ((uint64_t)s * 0x9E3779B97F4A7C15ull);
    int i;
    if (x == 0) x = 1;
    for (i = 0; i < CN_RANDOM_VALUES; i++)
    {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        rv->operators[i] = (uint8_t)(ADD + (x % 7u));
        rv->indices[i]   = (uint32_t)((x >> 13) % (uint64_t)CN_SCRATCHPAD_MEMORY_V13);
        rv->values[i]    = (int8_t)((x >> 41) | 1u);
    }
}

static void make_seed(uint8_t seed[32], uint64_t s)
{
    uint64_t x = 0x2545F4914F6CDD1Dull ^ (s * 0xBF58476D1CE4E5B9ull);
    int i;
    if (x == 0) x = 1;
    for (i = 0; i < 32; i += 8)
    {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        memcpy(seed + i, &x, 8);
    }
}

static volatile int g_stop = 0;
static double   g_seconds = 20.0;
static uint32_t g_threshold = 4;
static int      g_recompute = 1;
static int      g_nt_fill = 1;

typedef struct {
    int       id;
    uint64_t  hashes;
    uint64_t  screened;      /* candidates rejected by the screen */
    uint64_t  screen_cycles;     /* the whole screen path, as the daemon runs it */
    uint64_t  phase[CN_PH_COUNT];
} worker_t;

static void *worker(void *arg)
{
    worker_t *w = (worker_t *)arg;
    cn_hash_context_t *ctx = cn_hash_context_create();
    char h[HASH_SIZE];
    uint8_t seed[32];
    uint64_t s = (uint64_t)w->id * 0x100000000ull;
    unsigned char blob[76];
    double deadline;
    int i;

    memset(blob, (int)(w->id + 1), sizeof(blob));
    if (ctx == NULL) { fprintf(stderr, "thread %d: no context\n", w->id); return NULL; }

    /* Match the configuration being measured, per thread, as miner.cpp does. */
    if (g_recompute && !cn_vm_dirty_enable(1))
    { fprintf(stderr, "thread %d: no dirty map\n", w->id); return NULL; }
    cn_nt_fill_enable(g_nt_fill);

    /* One hash first, so the lazy allocations happen outside the timed window.
     * The salt cannot be filled before it: it does not exist until then. */
    make_seed(seed, s);
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v13(ctx, "warm", 4, h, seed);
    if (ctx->salt == NULL || ctx->cna_scratchpad == NULL)
    { fprintf(stderr, "thread %d: lazy allocation did not happen\n", w->id); return NULL; }
    fill_salt(ctx->salt, (uint32_t)w->id + 1u);
    fill_random_values(&ctx->random_values, (uint32_t)w->id + 1u);

    memset(cn_v13_phase_cycles, 0, sizeof(cn_v13_phase_cycles));
    deadline = now_s() + g_seconds;

    while (!g_stop)
    {
        uint64_t t0, t1;

        /* screen_block_nonce_v13 does four things per candidate, and an
         * earlier version of this harness timed only the last of them. That
         * made it report 3726.7 H/s against the daemon's 2875.8, which is how
         * the omission was caught: the harness has to reproduce the daemon's
         * rate or its breakdown is a breakdown of something else.
         *
         * Modelled here: the blob hash, the HC-128 schedule the salt prefix is
         * drawn from, and the cost walk. Not modelled: get_cna_v6_seed's reads
         * into the block cache, which need the database. Whatever rate gap is
         * left is that. */
        uint32_t est;
        make_seed(seed, ++s);
        t0 = __rdtsc();
        {
            char bh[HASH_SIZE];
            HC128_State prefix_rng;
            blob[0] = (unsigned char)s; blob[1] = (unsigned char)(s >> 8);
            blob[2] = (unsigned char)(s >> 16); blob[3] = (unsigned char)(s >> 24);
            cn_fast_hash(blob, sizeof(blob), bh);
            HC128_Init(&prefix_rng, (unsigned char *)bh, (unsigned char *)bh + 16);
            est = cn_vm_screen_cost(seed, g_threshold);
        }
        t1 = __rdtsc();
        w->screen_cycles += t1 - t0;
        if (g_threshold != 0 && est > g_threshold)
        {
            w->screened++;
            if ((w->screened & 1023) == 0 && now_s() > deadline) break;
            continue;
        }

        cn_slow_hash_v13_hw(ctx, "nerva v13 phase breakdown", 25, h, seed);
        w->hashes++;
        if (now_s() > deadline) break;
    }

    for (i = 0; i < CN_PH_COUNT; i++)
        w->phase[i] = cn_v13_phase_cycles[i];

    cn_vm_dirty_enable(0);
    cn_nt_fill_enable(0);
    cn_hash_context_free(ctx);
    return NULL;
}

int main(int argc, char **argv)
{
    int threads = (argc > 1) ? atoi(argv[1]) : 30;
    worker_t *w;
    pthread_t *th;
    uint64_t total_phase[CN_PH_COUNT];
    uint64_t hashes = 0, screened = 0, screen_cycles = 0, hash_cycles = 0, grand;
    double t0, elapsed;
    int i, p;

    if (argc > 2) g_seconds = atof(argv[2]);
    if (argc > 3) g_threshold = (uint32_t)strtoul(argv[3], NULL, 10);
    if (getenv("NO_RECOMPUTE")) g_recompute = 0;
    if (getenv("NO_NT")) g_nt_fill = 0;

    if (threads < 1) threads = 1;
    w  = (worker_t *)calloc((size_t)threads, sizeof(worker_t));
    th = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
    memset(total_phase, 0, sizeof(total_phase));

    printf("v13 phase breakdown, %d threads, %.0f s, threshold %u, recompute %s, nt fill %s\n",
           threads, g_seconds, g_threshold, g_recompute ? "on" : "off", g_nt_fill ? "on" : "off");
    fflush(stdout);

    t0 = now_s();
    for (i = 0; i < threads; i++) { w[i].id = i; pthread_create(&th[i], NULL, worker, &w[i]); }
    for (i = 0; i < threads; i++) pthread_join(th[i], NULL);
    elapsed = now_s() - t0;

    for (i = 0; i < threads; i++)
    {
        hashes += w[i].hashes;
        screened += w[i].screened;
        screen_cycles += w[i].screen_cycles;
        for (p = 0; p < CN_PH_COUNT; p++) { total_phase[p] += w[i].phase[p]; hash_cycles += w[i].phase[p]; }
    }

    if (hashes == 0) { printf("no hashes completed\n"); return 1; }

    printf("\n  %.1f H/s over %.1f s   (compare this with the daemon at the same\n"
           "  thread count: if it does not match, nothing below is about the daemon)\n",
           (double)hashes / elapsed, elapsed);
    printf("  acceptance %.2f%%, %llu screened per accepted nonce\n\n",
           100.0 * (double)hashes / (double)(hashes + screened),
           (unsigned long long)(screened / hashes));

    grand = hash_cycles + screen_cycles;
    printf("  phase                          cycles/hash      share of a nonce\n");
    for (p = 0; p < CN_PH_COUNT; p++)
        printf("  %-28s %12llu   %8.2f%%\n", cn_v13_phase_name(p),
               (unsigned long long)(total_phase[p] / hashes),
               100.0 * (double)total_phase[p] / (double)grand);
    printf("  %-28s %12llu   %8.2f%%\n", "screen (rejected candidates)",
           (unsigned long long)(screen_cycles / hashes),
           100.0 * (double)screen_cycles / (double)grand);
    printf("  %-28s %12llu   %8.2f%%\n", "total",
           (unsigned long long)(grand / hashes), 100.0);

    /* The phase counters are read inside the hash, so they cannot see time the
     * thread spent descheduled between phases. Printing the gap makes that
     * visible rather than silently inflating whichever phase it lands in. */
    {
        const double wall_cycles_per_hash =
            (double)grand / (double)hashes;
        printf("\n  measured cycles per hash %.3g; at %.1f H/s on %d threads a hash\n"
               "  occupies %.3g ns of thread time\n",
               wall_cycles_per_hash,
               (double)hashes / elapsed, threads,
               1e9 * (double)threads * elapsed / (double)hashes);
    }

    free(w); free(th);
    return 0;
}
