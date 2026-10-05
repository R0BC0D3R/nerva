/* Do non-temporal stores help v8's fill, the way they helped v6's?
 *
 * They were worth +22% on v13, whose pad is 8 MB a thread: at any useful thread
 * count that cannot stay in cache, so an ordinary store pays a
 * read-for-ownership out to DRAM and streaming skips it.
 *
 * v8's pad is 1 MB. At 16 threads that is 16 MB against 32 MB of L3 per CCD, so
 * the pad plausibly lives in cache for the whole hash, the fill's stores never
 * reach DRAM, and there is no read-for-ownership to save. Streaming would then
 * only force traffic that was not happening. **The prediction, recorded before
 * running this, is that it loses.**
 *
 * If that holds it is a result about v8's design rather than about this patch:
 * the small pad is itself the defence against this particular attack, and the
 * bandwidth argument for v8 should be made at 1 MB of cached stores rather than
 * 2 MB of DRAM traffic.
 *
 * Method, following what this project learned the hard way:
 *
 *   A-B-B-A per thread, per group of four nonces, so drift and boost behaviour
 *   hit both arms equally instead of landing on whichever ran second. Cycles
 *   are counted per arm with rdtsc rather than wall clock, so a descheduled
 *   thread does not land entirely on one arm.
 *
 *   Parameters are drawn from the ranges get_block_longhash_v14 uses, and the
 *   same draw feeds all four nonces of a group, so the two arms always hash
 *   identical work. Work per nonce varies several-fold in v8, so unmatched
 *   parameters would measure the draw and not the change.
 *
 *   t_v8_nt [threads] [seconds]
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

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static double g_seconds = 20.0;

typedef struct {
    int      id;
    uint64_t n[2];        /* nonces hashed, [0] = ordinary, [1] = streaming */
    uint64_t cyc[2];
    int      mismatches;
} worker_t;

static void *worker(void *arg)
{
    worker_t *w = (worker_t *)arg;
    cn_hash_context_t *ctx = cn_hash_context_create();
    char *salt0 = (char *)malloc(CN_SALT_MEMORY);
    char blob[76];
    char h[2][HASH_SIZE];
    uint64_t rs = 0x9E3779B97F4A7C15ull ^ ((uint64_t)w->id * 0xD1B54A32D192ED03ull);
    double deadline;
    int i;

    if (ctx == NULL) { fprintf(stderr, "thread %d: no context\n", w->id); return NULL; }
    memset(blob, (int)(w->id + 1), sizeof(blob));

    /* lazy allocation happens on the first call, outside the timed window */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_nt_fill_enable(0);
    cn_slow_hash_v14(ctx, blob, sizeof(blob), h[0], 8, CN_V8_INIT_SIZE_BLK, 4, 4);
    if (ctx->salt == NULL || salt0 == NULL) { fprintf(stderr, "thread %d: no salt\n", w->id); return NULL; }

    /* v8's sweeps write into the salt through salt_pad_v8_defer, so the state a
     * nonce starts from is not the state the previous nonce started from. Both
     * arms have to start from the same salt or they are not hashing the same
     * work, and their digests cannot be compared at all. Snapshot once, restore
     * before every nonce; the restore costs both arms equally. */
    memcpy(salt0, ctx->salt, CN_SALT_MEMORY);

    deadline = now_s() + g_seconds;

    while (now_s() < deadline)
    {
        /* one draw, four nonces: off, on, on, off */
        static const int arm[4] = {0, 1, 1, 0};
        size_t   iters;
        uint16_t xx, yy;

        rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27;
        xx = (uint16_t)(4 + (rs >> 3) % 5);
        yy = (uint16_t)(4 + (rs >> 11) % 5);
        iters = (size_t)((rs >> 19) % (1 + (rs >> 27) % 64));

        for (i = 0; i < 4; i++)
        {
            const int a = arm[i];
            uint64_t t0, t1;
            memcpy(ctx->salt, salt0, CN_SALT_MEMORY);
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            cn_nt_fill_enable(a);
            t0 = __rdtsc();
            cn_slow_hash_v14(ctx, blob, sizeof(blob), h[a], iters,
                             CN_V8_INIT_SIZE_BLK, xx, yy);
            t1 = __rdtsc();
            w->cyc[a] += t1 - t0;
            w->n[a]++;
        }
        /* the two arms hashed identical work, so they must agree; this is a
         * correctness check riding along with the timing one */
        if (memcmp(h[0], h[1], HASH_SIZE) != 0)
            w->mismatches++;
    }

    cn_nt_fill_enable(0);
    free(salt0);
    cn_hash_context_free(ctx);
    return NULL;
}

int main(int argc, char **argv)
{
    int threads = (argc > 1) ? atoi(argv[1]) : 16;
    worker_t *w;
    pthread_t *th;
    uint64_t n[2] = {0, 0}, cyc[2] = {0, 0};
    int mismatches = 0;
    double t0, elapsed;
    int i;

    if (argc > 2) g_seconds = atof(argv[2]);
    if (threads < 1) threads = 1;

    w  = (worker_t *)calloc((size_t)threads, sizeof(worker_t));
    th = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));

    printf("v8 fill: ordinary stores vs streaming, %d threads, %.0f s\n",
           threads, g_seconds);
    printf("pad %d KB a thread, %d KB total\n\n",
           CN_SCRATCHPAD_MEMORY_V8 / 1024,
           (int)((long)CN_SCRATCHPAD_MEMORY_V8 * threads / 1024));
    fflush(stdout);

    t0 = now_s();
    for (i = 0; i < threads; i++) { w[i].id = i; pthread_create(&th[i], NULL, worker, &w[i]); }
    for (i = 0; i < threads; i++) pthread_join(th[i], NULL);
    elapsed = now_s() - t0;

    for (i = 0; i < threads; i++)
    {
        n[0] += w[i].n[0];   n[1] += w[i].n[1];
        cyc[0] += w[i].cyc[0]; cyc[1] += w[i].cyc[1];
        mismatches += w[i].mismatches;
    }

    if (n[0] == 0 || n[1] == 0) { printf("no nonces completed\n"); return 1; }

    /* Per-arm throughput comes from that arm's own cycles, not from wall clock
     * over a count the A-B-B-A pattern makes equal by construction. */
    printf("  ordinary stores   %8.0f cycles/nonce\n", (double)cyc[0] / (double)n[0]);
    printf("  streaming stores  %8.0f cycles/nonce\n", (double)cyc[1] / (double)n[1]);
    printf("  combined rate     %8.1f H/s over %.1f s\n",
           (double)(n[0] + n[1]) / elapsed, elapsed);
    printf("\n  streaming is %+.2f%% on cycles per nonce\n",
           100.0 * (((double)cyc[0] / (double)n[0]) / ((double)cyc[1] / (double)n[1]) - 1.0));
    printf("  %llu and %llu nonces, %d digest mismatches between the arms\n",
           (unsigned long long)n[0], (unsigned long long)n[1], mismatches);
    if (mismatches)
        printf("  MISMATCHES: the two arms did not compute the same hash\n");

    free(w); free(th);
    return mismatches ? 1 : 0;
}
