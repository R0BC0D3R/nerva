// Copyright (c) 2026, The Nerva Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or materials
//    provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/* Eight-lane AVX2 HC-128 key schedule. See hc128-x8.h for what it is for.
 *
 * Layout while computing: lane-interleaved, element i of lane L at [i * 8 + L],
 * so a vector load of element i across all lanes is one aligned 32-byte load.
 * The result is transposed back into ordinary HC128_State values, so no other
 * caller has to change.
 *
 * The h-function lookups are the one thing that cannot be a vector load, since
 * each lane indexes its own table with its own byte. Both forms were measured:
 * vpgatherdd gives 2.55x over scalar HC128_Init on Zen 4 while scalar
 * extraction gives 1.51x, which is the reverse of what the published report
 * found on Zen 3. Gather is used for that reason, and the choice is worth
 * re-measuring on a new microarchitecture rather than inherited.
 *
 * This translation unit is compiled with AVX2 while the rest of the binary
 * stays at the baseline ISA, the same arrangement slow-hash-hw.c uses for
 * AES-NI, and the entry point falls back to scalar when the CPU lacks it.
 */

#include <string.h>
#include "hc128-x8.h"

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#define HC128_X8_X86 1
#endif

#if defined(HC128_X8_X86) && defined(HC128_X8_AVX2_BUILT)

#include <immintrin.h>
#if defined(__GNUC__)
#include <cpuid.h>
#endif

#define LANES HC128_X8_LANES

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

typedef struct {
    uint32_t P[512 * LANES] __attribute__((aligned(32)));
    uint32_t Q[512 * LANES] __attribute__((aligned(32)));
    uint32_t counter1024;
} hc128_x8_t;

#define VLD(base, i) _mm256_load_si256((const __m256i *)&(base)[(i) * LANES])
#define VST(base, i, v) _mm256_store_si256((__m256i *)&(base)[(i) * LANES], (v))

/* T[x & 0xff] + T[256 + ((x >> 16) & 0xff)], each lane in its own table. */
static inline __m256i h_lookup(const uint32_t *T, __m256i x)
{
    const __m256i ramp = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
    const __m256i lo = _mm256_and_si256(x, _mm256_set1_epi32(0xff));
    const __m256i hi = _mm256_and_si256(_mm256_srli_epi32(x, 16), _mm256_set1_epi32(0xff));
    /* interleaved index: element e of lane L lives at e * 8 + L */
    const __m256i ia = _mm256_add_epi32(_mm256_slli_epi32(lo, 3), ramp);
    const __m256i ic = _mm256_add_epi32(
        _mm256_slli_epi32(_mm256_add_epi32(hi, _mm256_set1_epi32(256)), 3), ramp);
    return _mm256_add_epi32(_mm256_i32gather_epi32((const int *)T, ia, 4),
                            _mm256_i32gather_epi32((const int *)T, ic, 4));
}

#define UPDATE_STEP(arr, T, ROT, i0, i511, i3, i10, i12)                           \
    do {                                                                           \
        const __m256i t0 = ROT(VLD(arr, i511), 23);                                \
        const __m256i t1 = ROT(VLD(arr, i3), 10);                                  \
        const __m256i t2 = ROT(VLD(arr, i10), 8);                                  \
        __m256i m0 = VLD(arr, i0);                                                 \
        m0 = _mm256_add_epi32(m0, _mm256_add_epi32(t2, _mm256_xor_si256(t0, t1))); \
        m0 = _mm256_xor_si256(h_lookup((T), VLD(arr, i12)), m0);                    \
        VST(arr, i0, m0);                                                          \
    } while (0)

/* Index pattern lifted from UpdateSixteenSteps in hc128.c. The sixteen steps
 * are written out longhand there and keep the same shape here; the order is the
 * cipher definition and must not be rearranged. */
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

/* 8x8 transpose of 32-bit lanes, in place over r[0..7]. */
static inline void transpose8(__m256i *r)
{
    const __m256i a0 = _mm256_unpacklo_epi32(r[0], r[1]);
    const __m256i a1 = _mm256_unpackhi_epi32(r[0], r[1]);
    const __m256i a2 = _mm256_unpacklo_epi32(r[2], r[3]);
    const __m256i a3 = _mm256_unpackhi_epi32(r[2], r[3]);
    const __m256i a4 = _mm256_unpacklo_epi32(r[4], r[5]);
    const __m256i a5 = _mm256_unpackhi_epi32(r[4], r[5]);
    const __m256i a6 = _mm256_unpacklo_epi32(r[6], r[7]);
    const __m256i a7 = _mm256_unpackhi_epi32(r[6], r[7]);

    const __m256i b0 = _mm256_unpacklo_epi64(a0, a2);
    const __m256i b1 = _mm256_unpackhi_epi64(a0, a2);
    const __m256i b2 = _mm256_unpacklo_epi64(a1, a3);
    const __m256i b3 = _mm256_unpackhi_epi64(a1, a3);
    const __m256i b4 = _mm256_unpacklo_epi64(a4, a6);
    const __m256i b5 = _mm256_unpackhi_epi64(a4, a6);
    const __m256i b6 = _mm256_unpacklo_epi64(a5, a7);
    const __m256i b7 = _mm256_unpackhi_epi64(a5, a7);

    r[0] = _mm256_permute2x128_si256(b0, b4, 0x20);
    r[1] = _mm256_permute2x128_si256(b1, b5, 0x20);
    r[2] = _mm256_permute2x128_si256(b2, b6, 0x20);
    r[3] = _mm256_permute2x128_si256(b3, b7, 0x20);
    r[4] = _mm256_permute2x128_si256(b0, b4, 0x31);
    r[5] = _mm256_permute2x128_si256(b1, b5, 0x31);
    r[6] = _mm256_permute2x128_si256(b2, b6, 0x31);
    r[7] = _mm256_permute2x128_si256(b3, b7, 0x31);
}

/* interleaved [i * 8 + L] back out to eight contiguous per-lane tables */
static void scatter_out(const uint32_t *src, HC128_State *states, int to_q)
{
    int i, L;
    for (i = 0; i < 512; i += 8)
    {
        __m256i r[8];
        int k;
        for (k = 0; k < 8; k++)
            r[k] = _mm256_load_si256((const __m256i *)&src[(i + k) * LANES]);
        transpose8(r);
        for (L = 0; L < LANES; L++)
            _mm256_storeu_si256((__m256i *)(to_q ? &states[L].Q[i] : &states[L].P[i]), r[L]);
    }
}

static int avx2_present(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;
#if defined(__GNUC__)
    cached = 0;
    if (__get_cpuid_max(0, NULL) >= 7)
    {
        unsigned int a = 0, b = 0, c = 0, d = 0;
        __cpuid_count(7, 0, a, b, c, d);
        if (b & (1u << 5))                      /* AVX2 */
        {
            unsigned int a1, b1, c1, d1;
            /* OSXSAVE and AVX, then XGETBV, because AVX2 in cpuid does not mean
             * the OS is preserving YMM state across a context switch. */
            if (__get_cpuid(1, &a1, &b1, &c1, &d1) && (c1 & (1u << 27)) && (c1 & (1u << 28)))
            {
                unsigned int eax, edx;
                __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
                cached = ((eax & 0x6) == 0x6);
            }
        }
    }
#else
    cached = 0;
#endif
    return cached;
}

int hc128_x8_hardware(void) { return avx2_present(); }

static void init_scalar(HC128_State *states, const unsigned char *keys, const unsigned char *ivs)
{
    int L;
    for (L = 0; L < LANES; L++)
        HC128_Init(&states[L], (unsigned char *)(keys + L * 16), (unsigned char *)(ivs + L * 16));
}

/* The interleaved tables are 64 KB. Allocating and freeing them per call cost
 * more than the vectorisation saved: a miner screening at 0.4% acceptance calls
 * this twice per batch of eight, hundreds of thousands of times a second. One
 * buffer per thread, reused. */
static __thread hc128_x8_t *tls_buf = NULL;

static void hc128_init_x8_avx2(HC128_State *states, const unsigned char *keys, const unsigned char *ivs)
{
    hc128_x8_t *s = tls_buf;
    uint32_t i;
    int L;

    if (s == NULL)
    {
        s = (hc128_x8_t *)_mm_malloc(sizeof(hc128_x8_t), 32);
        if (s == NULL)                  /* fall back rather than fail */
        {
            init_scalar(states, keys, ivs);
            return;
        }
        tls_buf = s;
    }

    for (L = 0; L < LANES; L++)
    {
        uint32_t k[4], v[4];
        memcpy(k, keys + L * 16, 16);
        memcpy(v, ivs + L * 16, 16);
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

    scatter_out(s->P, states, 0);
    scatter_out(s->Q, states, 1);
    for (L = 0; L < LANES; L++)
        states[L].counter1024 = s->counter1024;
}

void HC128_Init_x8(HC128_State *states, const unsigned char *keys, const unsigned char *ivs)
{
    if (avx2_present())
        hc128_init_x8_avx2(states, keys, ivs);
    else
        init_scalar(states, keys, ivs);
}

#else   /* no AVX2 in this build: correct, just not fast */

int hc128_x8_hardware(void) { return 0; }

void HC128_Init_x8(HC128_State *states, const unsigned char *keys, const unsigned char *ivs)
{
    int L;
    for (L = 0; L < HC128_X8_LANES; L++)
        HC128_Init(&states[L], (unsigned char *)(keys + L * 16), (unsigned char *)(ivs + L * 16));
}

#endif
