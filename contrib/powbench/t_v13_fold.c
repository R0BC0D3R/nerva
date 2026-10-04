/* v13 digest harness for the fused-pad-init change.
 *
 * Differs from t_v13_digest.c in two ways that matter here:
 *
 *  1. The salt is filled with a non-zero, per-seed-varying pattern. The old
 *     harness zeroed it, which would have made a broken salt fold invisible:
 *     XOR with zero is the identity, so any wrong salt offset still produces
 *     the right digest.
 *  2. Both arms are called explicitly, not through the dispatcher, so the
 *     software path is covered on a machine that has AES-NI.
 *
 * argv[1] = HW seed count (default 400), argv[2] = SW seed count (default 40).
 * Local experiment, not kept.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "hash-ops.h"
#include <cpuid.h>

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

void cn_slow_hash_v13_hw(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *);
void cn_slow_hash_v13_sw(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *);
void cn_slow_hash_v13(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *);

static const char *inputs[4] = {
    "nerva v13 fused pad init vector A",
    "nerva v13 fused pad init vector B",
    "",
    "x"
};

/* xorshift64*, so the salt is dense and every byte offset is distinguishable
 * from its neighbours. A wrong wrap or a wrong offset then changes the digest. */
static void fill_salt(char *salt, uint32_t s)
{
    uint64_t x = 0x9E3779B97F4A7C15ull ^ ((uint64_t)s * 0xD1B54A32D192ED03ull);
    uint32_t i;
    if (x == 0) x = 1;
    /* SALT_ZERO=1 proves the salt reaches the digest: if it does, the
     * digests change. If it does not, this harness checks nothing. */
    if (getenv("SALT_ZERO") != NULL) { memset(salt, 0, CN_SALT_MEMORY); return; }
    for (i = 0; i < (uint32_t)CN_SALT_MEMORY; i += 8)
    {
        uint64_t v;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        v = x * 0x2545F4914F6CDD1Dull;
        memcpy(salt + i, &v, 8);
    }
}

static int run(cn_hash_context_t *ctx, const char *tag, int seeds,
               void (*fn)(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *))
{
    char h[HASH_SIZE];
    uint8_t seed[32];
    int s, k, i, n = 0;

    for (s = 0; s < seeds; s++)
    {
        for (i = 0; i < 32; i++)
            seed[i] = (uint8_t)(s * 37u + i * 11u + 3u);
        fill_salt(ctx->salt, (uint32_t)s);
        for (k = 0; k < 4; k++)
        {
            /* random_values is applied to the pad after the fill, so pin it
             * rather than leaving whatever the last call left behind. */
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            fn(ctx, inputs[k], strlen(inputs[k]), h, seed);
            printf("%s s=%03d k=%d ", tag, s, k);
            for (i = 0; i < HASH_SIZE; i++)
                printf("%02x", (unsigned char)h[i]);
            putchar('\n');
            n++;
        }
    }
    return n;
}

int main(int argc, char **argv)
{
    cn_hash_context_t *ctx = cn_hash_context_create();
    char h[HASH_SIZE];
    uint8_t seed[32];
    int hw_seeds = (argc > 1) ? atoi(argv[1]) : 400;
    int sw_seeds = (argc > 2) ? atoi(argv[2]) : 40;
    int n = 0;

    if (ctx == NULL) { fprintf(stderr, "no context\n"); return 2; }

    memset(seed, 0, sizeof(seed));
    cn_slow_hash_v13(ctx, "warm", 4, h, seed);           /* lazy allocation */
    if (ctx->salt == NULL) { fprintf(stderr, "no salt\n"); return 2; }

    n += run(ctx, "hw", hw_seeds, cn_slow_hash_v13_hw);
    n += run(ctx, "sw", sw_seeds, cn_slow_hash_v13_sw);

    fprintf(stderr, "%d v13 digests (%d hw seeds, %d sw seeds)\n", n, hw_seeds, sw_seeds);
    cn_hash_context_free(ctx);
    return 0;
}
