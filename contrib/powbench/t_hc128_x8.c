/* Eight-lane AVX2 HC128_Init, checked bit for bit against the scalar one.
 *
 * Why this exists
 * ---------------
 * get_cna_v6_data is roughly 40% of a v13 nonce, and inside it the dominant
 * cost is HC128_Init: the salt loop reseeds every 16 picks, so one salt runs
 * 129 inits, each a 1264-term W recurrence followed by 1024 update steps. The
 * recurrence is latency bound with a dependency distance of two, so a single
 * salt leaves most of the machine idle. Eight independent salts, one per lane
 * of a ymm register, fill it.
 *
 * The reseed points are identical in every lane, because the salt loop's shape
 * does not depend on the data, so eight inits always run in lockstep. That is
 * what makes this possible at all. The pick loop between reseeds is NOT in
 * lockstep, because HC128_U32 uses rejection sampling and so consumes a
 * data-dependent number of keystream words, and it is deliberately left alone
 * here.
 *
 * Layout: lane-interleaved, element i of lane L at [i * 8 + L]. A vector load
 * of element i across all lanes is then a single aligned 32-byte load.
 *
 * The h1/h2 table lookups are the hard part: each lane indexes its own table
 * with its own byte, so they cannot be a vector load. Both forms are built
 * here, scalar extraction and vpgatherdd, selected at run time, because the
 * published report measured gather as the slower of the two on Zen 3 and this
 * machine is Zen 4.
 *
 * Usage:
 *   t_hc128_x8            verify only, 256 random key/iv sets
 *   t_hc128_x8 verify N   verify with N sets
 *   t_hc128_x8 bench N    verify, then time scalar against both x8 forms
 *
 * Local experiment. Nothing here is wired into the daemon yet.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>

#include "hc128.h"

#define LANES 8

/* ---------------------------------------------------------------- scalar ref
 * hc128.c keeps HC128_Init's helpers private, so the reference here is the
 * real HC128_Init from the tree. Comparing against a reimplementation would
 * only prove the two reimplementations agree.
 */

/* ------------------------------------------------------------------ vectors */

static inline __m256i rotr32_v(__m256i x, int n)
{
    return _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - n));
}

static inline __m256i rotl32_v(__m256i x, int n)
{
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

/* f1(x) = ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3) */
static inline __m256i f1_v(__m256i x)
{
    return _mm256_xor_si256(_mm256_xor_si256(rotr32_v(x, 7), rotr32_v(x, 18)),
                            _mm256_srli_epi32(x, 3));
}

/* f2(x) = ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10) */
static inline __m256i f2_v(__m256i x)
{
    return _mm256_xor_si256(_mm256_xor_si256(rotr32_v(x, 17), rotr32_v(x, 19)),
                            _mm256_srli_epi32(x, 10));
}

/* f(a,b,c,d) = f2(a) + b + f1(c) + d */
static inline __m256i f_v(__m256i a, __m256i b, __m256i c, __m256i d)
{
    return _mm256_add_epi32(_mm256_add_epi32(f2_v(a), b),
                            _mm256_add_epi32(f1_v(c), d));
}

typedef struct
{
    uint32_t P[512 * LANES] __attribute__((aligned(32)));
    uint32_t Q[512 * LANES] __attribute__((aligned(32)));
    uint32_t counter1024;
} hc128_x8_t;

#define VLD(base, i) _mm256_load_si256((const __m256i *)&(base)[(i) * LANES])
#define VST(base, i, v) _mm256_store_si256((__m256i *)&(base)[(i) * LANES], (v))

/* h1: tem = T[x & 0xff] + T[256 + ((x >> 16) & 0xff)], per lane, each lane
 * indexing its own interleaved table. Two shapes of the same thing. */

static const __m256i *lane_ramp_ptr(void)
{
    static __m256i ramp;
    static int init = 0;
    if (!init) { ramp = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7); init = 1; }
    return &ramp;
}

static inline __m256i h_lookup_gather(const uint32_t *T, __m256i x)
{
    const __m256i ramp = *lane_ramp_ptr();
    const __m256i lo = _mm256_and_si256(x, _mm256_set1_epi32(0xff));
    const __m256i hi = _mm256_and_si256(_mm256_srli_epi32(x, 16), _mm256_set1_epi32(0xff));
    /* interleaved index: element e of lane L lives at e * 8 + L */
    const __m256i ia = _mm256_add_epi32(_mm256_slli_epi32(lo, 3), ramp);
    const __m256i ic = _mm256_add_epi32(
        _mm256_slli_epi32(_mm256_add_epi32(hi, _mm256_set1_epi32(256)), 3), ramp);
    const __m256i va = _mm256_i32gather_epi32((const int *)T, ia, 4);
    const __m256i vc = _mm256_i32gather_epi32((const int *)T, ic, 4);
    return _mm256_add_epi32(va, vc);
}

static inline __m256i h_lookup_scalar(const uint32_t *T, __m256i x)
{
    uint32_t xs[LANES] __attribute__((aligned(32)));
    uint32_t r[LANES] __attribute__((aligned(32)));
    int L;
    _mm256_store_si256((__m256i *)xs, x);
    for (L = 0; L < LANES; L++)
    {
        const uint32_t a = xs[L] & 0xff;
        const uint32_t c = (xs[L] >> 16) & 0xff;
        r[L] = T[a * LANES + L] + T[(256 + c) * LANES + L];
    }
    return _mm256_load_si256((const __m256i *)r);
}

static int g_use_gather = 0;

static inline __m256i h_lookup(const uint32_t *T, __m256i x)
{
    return g_use_gather ? h_lookup_gather(T, x) : h_lookup_scalar(T, x);
}

/* One update step. dst is the element being written; m511/m3/m10/m12 are the
 * element indices the scalar macro reads. rot picks the P form (rotate right)
 * or the Q form (rotate left); T is the other table, which is not being
 * written during this half and so is stable. */
#define UPDATE_STEP(arr, T, ROT, i0, i511, i3, i10, i12)                       \
    do {                                                                      \
        const __m256i t0 = ROT(VLD(arr, i511), 23);                           \
        const __m256i t1 = ROT(VLD(arr, i3), 10);                             \
        const __m256i t2 = ROT(VLD(arr, i10), 8);                             \
        __m256i m0 = VLD(arr, i0);                                            \
        m0 = _mm256_add_epi32(m0, _mm256_add_epi32(t2, _mm256_xor_si256(t0, t1))); \
        m0 = _mm256_xor_si256(h_lookup((T), VLD(arr, i12)), m0);               \
        VST(arr, i0, m0);                                                     \
    } while (0)

/* The index pattern is lifted straight from UpdateSixteenSteps in hc128.c; the
 * sixteen steps there are written out longhand with the same shape. */
static void update_sixteen_x8(hc128_x8_t *s)
{
    const uint32_t cc = s->counter1024 & 0x1ff;
    const uint32_t dd = (cc + 16) & 0x1ff;
    const uint32_t ee = (cc - 16) & 0x1ff;

    if (s->counter1024 < 512)
    {
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  0, cc +  1, ee + 13, ee +  6, ee +  4);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  1, cc +  2, ee + 14, ee +  7, ee +  5);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  2, cc +  3, ee + 15, ee +  8, ee +  6);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  3, cc +  4, cc +  0, ee +  9, ee +  7);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  4, cc +  5, cc +  1, ee + 10, ee +  8);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  5, cc +  6, cc +  2, ee + 11, ee +  9);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  6, cc +  7, cc +  3, ee + 12, ee + 10);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  7, cc +  8, cc +  4, ee + 13, ee + 11);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  8, cc +  9, cc +  5, ee + 14, ee + 12);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc +  9, cc + 10, cc +  6, ee + 15, ee + 13);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc + 10, cc + 11, cc +  7, cc +  0, ee + 14);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc + 11, cc + 12, cc +  8, cc +  1, ee + 15);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc + 12, cc + 13, cc +  9, cc +  2, cc +  0);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc + 13, cc + 14, cc + 10, cc +  3, cc +  1);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc + 14, cc + 15, cc + 11, cc +  4, cc +  2);
        UPDATE_STEP(s->P, s->Q, rotr32_v, cc + 15, dd +  0, cc + 12, cc +  5, cc +  3);
    }
    else
    {
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  0, cc +  1, ee + 13, ee +  6, ee +  4);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  1, cc +  2, ee + 14, ee +  7, ee +  5);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  2, cc +  3, ee + 15, ee +  8, ee +  6);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  3, cc +  4, cc +  0, ee +  9, ee +  7);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  4, cc +  5, cc +  1, ee + 10, ee +  8);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  5, cc +  6, cc +  2, ee + 11, ee +  9);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  6, cc +  7, cc +  3, ee + 12, ee + 10);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  7, cc +  8, cc +  4, ee + 13, ee + 11);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  8, cc +  9, cc +  5, ee + 14, ee + 12);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc +  9, cc + 10, cc +  6, ee + 15, ee + 13);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc + 10, cc + 11, cc +  7, cc +  0, ee + 14);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc + 11, cc + 12, cc +  8, cc +  1, ee + 15);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc + 12, cc + 13, cc +  9, cc +  2, cc +  0);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc + 13, cc + 14, cc + 10, cc +  3, cc +  1);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc + 14, cc + 15, cc + 11, cc +  4, cc +  2);
        UPDATE_STEP(s->Q, s->P, rotl32_v, cc + 15, dd +  0, cc + 12, cc +  5, cc +  3);
    }

    s->counter1024 = (s->counter1024 + 16) & 0x3ff;
}

/* keys[L] and ivs[L] are 16 bytes each. */
static void hc128_init_x8(hc128_x8_t *s, const uint8_t *keys, const uint8_t *ivs)
{
    uint32_t i;
    int L;

    /* Key and iv expansion stays scalar: 32 stores, and it is the one part
     * that reads eight different inputs. */
    for (L = 0; L < LANES; L++)
    {
        const uint32_t *k = (const uint32_t *)(keys + L * 16);
        const uint32_t *v = (const uint32_t *)(ivs + L * 16);
        for (i = 0; i < 4; i++)
        {
            s->P[(i + 0) * LANES + L] = k[i];
            s->P[(i + 4) * LANES + L] = k[i];
            s->P[(i + 8) * LANES + L] = v[i];
            s->P[(i + 12) * LANES + L] = v[i];
        }
    }

    for (i = 16; i < 256 + 16; i++)
        VST(s->P, i, _mm256_add_epi32(
            f_v(VLD(s->P, i - 2), VLD(s->P, i - 7), VLD(s->P, i - 15), VLD(s->P, i - 16)),
            _mm256_set1_epi32((int)i)));

    for (i = 0; i < 16; i++)
        VST(s->P, i, VLD(s->P, i + 256));

    for (i = 16; i < 512; i++)
        VST(s->P, i, _mm256_add_epi32(
            f_v(VLD(s->P, i - 2), VLD(s->P, i - 7), VLD(s->P, i - 15), VLD(s->P, i - 16)),
            _mm256_set1_epi32((int)(256 + i))));

    for (i = 0; i < 16; i++)
        VST(s->Q, i, VLD(s->P, 512 - 16 + i));

    for (i = 16; i < 32; i++)
        VST(s->Q, i, _mm256_add_epi32(
            f_v(VLD(s->Q, i - 2), VLD(s->Q, i - 7), VLD(s->Q, i - 15), VLD(s->Q, i - 16)),
            _mm256_set1_epi32((int)(256 + 512 + (i - 16)))));

    for (i = 0; i < 16; i++)
        VST(s->Q, i, VLD(s->Q, i + 16));

    for (i = 16; i < 512; i++)
        VST(s->Q, i, _mm256_add_epi32(
            f_v(VLD(s->Q, i - 2), VLD(s->Q, i - 7), VLD(s->Q, i - 15), VLD(s->Q, i - 16)),
            _mm256_set1_epi32((int)(768 + i))));

    s->counter1024 = 0;
    for (i = 0; i < 64; i++)
        update_sixteen_x8(s);
}

/* --------------------------------------------------------------- harness */

static uint64_t rng_state = 0x243F6A8885A308D3ull;

static uint32_t rnd32(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return (uint32_t)((rng_state * 0x2545F4914F6CDD1Dull) >> 32);
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static int verify(int sets)
{
    uint8_t keys[LANES * 16], ivs[LANES * 16];
    HC128_State ref[LANES];
    hc128_x8_t *v8 = (hc128_x8_t *)_mm_malloc(sizeof(hc128_x8_t), 32);
    int set, L, i, bad = 0;

    if (v8 == NULL) { fprintf(stderr, "alloc failed\n"); return 1; }

    for (set = 0; set < sets && bad == 0; set++)
    {
        for (i = 0; i < LANES * 16; i++) { keys[i] = (uint8_t)rnd32(); ivs[i] = (uint8_t)rnd32(); }

        for (L = 0; L < LANES; L++)
            HC128_Init(&ref[L], keys + L * 16, ivs + L * 16);

        hc128_init_x8(v8, keys, ivs);

        for (L = 0; L < LANES && bad == 0; L++)
        {
            for (i = 0; i < 512; i++)
            {
                if (ref[L].P[i] != v8->P[i * LANES + L])
                { printf("set %d lane %d P[%d] ref %08x x8 %08x\n", set, L, i, ref[L].P[i], v8->P[i * LANES + L]); bad = 1; break; }
                if (ref[L].Q[i] != v8->Q[i * LANES + L])
                { printf("set %d lane %d Q[%d] ref %08x x8 %08x\n", set, L, i, ref[L].Q[i], v8->Q[i * LANES + L]); bad = 1; break; }
            }
            if (!bad && ref[L].counter1024 != v8->counter1024)
            { printf("set %d lane %d counter ref %u x8 %u\n", set, L, ref[L].counter1024, v8->counter1024); bad = 1; }
        }
    }

    _mm_free(v8);
    if (bad) { printf("MISMATCH\n"); return 1; }
    printf("x8 matches scalar on %d sets (%d inits), %s lookup\n",
           sets, sets * LANES, g_use_gather ? "gather" : "scalar");
    return 0;
}

static void bench(int iters)
{
    uint8_t keys[LANES * 16], ivs[LANES * 16];
    HC128_State ref[LANES];
    hc128_x8_t *v8 = (hc128_x8_t *)_mm_malloc(sizeof(hc128_x8_t), 32);
    double t0, t1, ts, g1, s1;
    int it, L, i;
    volatile uint32_t sink = 0;

    for (i = 0; i < LANES * 16; i++) { keys[i] = (uint8_t)rnd32(); ivs[i] = (uint8_t)rnd32(); }

    /* warm */
    for (L = 0; L < LANES; L++) HC128_Init(&ref[L], keys + L * 16, ivs + L * 16);
    hc128_init_x8(v8, keys, ivs);

    /* The key is perturbed every iteration. With a fixed key the whole call is
     * loop-invariant and the compiler is entitled to hoist it, which would
     * time an empty loop and report a spectacular speedup. */
    t0 = now_s();
    for (it = 0; it < iters; it++)
    {
        keys[0] = (uint8_t)it; keys[1] = (uint8_t)(it >> 8);
        for (L = 0; L < LANES; L++) HC128_Init(&ref[L], keys + L * 16, ivs + L * 16);
        sink += ref[0].P[0];
    }
    t1 = now_s();
    ts = t1 - t0;

    g_use_gather = 0;
    t0 = now_s();
    for (it = 0; it < iters; it++)
    {
        keys[0] = (uint8_t)it; keys[1] = (uint8_t)(it >> 8);
        hc128_init_x8(v8, keys, ivs);
        sink += v8->P[0];
    }
    t1 = now_s();
    s1 = t1 - t0;

    g_use_gather = 1;
    t0 = now_s();
    for (it = 0; it < iters; it++)
    {
        keys[0] = (uint8_t)it; keys[1] = (uint8_t)(it >> 8);
        hc128_init_x8(v8, keys, ivs);
        sink += v8->P[0];
    }
    t1 = now_s();
    g1 = t1 - t0;

    printf("\n%d batches of 8 inits each\n", iters);
    printf("  scalar x8        %8.3f s   %8.2f us per init\n", ts, ts * 1e6 / (iters * LANES));
    printf("  x8 scalar lookup %8.3f s   %8.2f us per init   %.2fx\n", s1, s1 * 1e6 / (iters * LANES), ts / s1);
    printf("  x8 gather lookup %8.3f s   %8.2f us per init   %.2fx\n", g1, g1 * 1e6 / (iters * LANES), ts / g1);
    (void)sink;
    _mm_free(v8);
}

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "verify";
    const int n = (argc > 2) ? atoi(argv[2]) : 256;
    int rc;

    g_use_gather = 0;
    rc = verify(n);
    if (rc) return rc;
    g_use_gather = 1;
    rc = verify(n);
    if (rc) return rc;

    if (strcmp(mode, "bench") == 0)
        bench(n);
    return 0;
}
