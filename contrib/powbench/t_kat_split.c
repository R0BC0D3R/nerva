/* Does a build change any hash variant, and does the non-temporal fill?
 *
 * Two jobs, neither of which cn_slow_hash_known_answer_test can do on its own
 * because it folds every vector into a single ok flag:
 *
 *  1. Print a digest per variant, so two builds can be diffed and the variant
 *     that changed can be named.
 *  2. Run every variant twice, with the non-temporal fill off and on, and
 *     compare. Streaming stores must leave the pad byte for byte identical, so
 *     a difference here is a bug in cn_fill_store rather than a property of the
 *     algorithm. This matters because expand_key() is shared by v8, v11, v10
 *     and v9, so one change to it touches four consensus paths at once.
 *
 * Inputs and parameters are the known-answer test's own, transcribed from its
 * tables, including its zeroed salt and zeroed random values.
 *
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

static const char live_in[] = "nerva live-algorithm known-answer vector";
static const char v8_in[]   = "nerva cna v8 known-answer vector";

enum { V7_8 = 78, V9 = 9, V10 = 10, V11 = 11, V13 = 13, V14 = 14 };

typedef struct {
    const char *tag;
    int         ver;
    uint32_t    iters;
    uint8_t     blk;
    uint16_t    xx, yy, zz, ww;
} kat_case_t;

/* v14's block count comes from CN_V8_INIT_SIZE_BLK, not from its table. */
static const kat_case_t cases[] = {
    { "v10 kat[0] iters=0",  V10,  0, 8, 2, 2, 2, 2 },
    { "v10 kat[1] iters=17", V10, 17, 4, 3, 2, 2, 3 },
    { "v10 kat[2] iters=64", V10, 64, 2, 2, 3, 3, 2 },
    { "v11 kat[0] iters=0",  V11,  0, 8, 4, 4, 0, 0 },
    { "v11 kat[1] iters=17", V11, 17, 4, 5, 6, 0, 0 },
    { "v11 kat[2] iters=63", V11, 63, 2, 8, 8, 0, 0 },
    { "v13 kat",             V13,  0, 0, 0, 0, 0, 0 },
    { "v14 kat[0] iters=0",  V14,  0, 0, 4, 4, 0, 0 },
    { "v14 kat[1] iters=1",  V14,  1, 0, 4, 5, 0, 0 },
    { "v14 kat[2] iters=17", V14, 17, 0, 5, 4, 0, 0 },
    { "v14 kat[3] iters=64", V14, 64, 0, 6, 6, 0, 0 },
    { "v14 kat[4] iters=63", V14, 63, 0, 8, 8, 0, 0 },
    { "v9  iters=8",         V9,   8, 0, 0, 0, 0, 0 },
    { "v7_8 iters=8",        V7_8, 8, 0, 0, 0, 0, 0 },
};

static void run_case(cn_hash_context_t *ctx, const kat_case_t *c, char *h)
{
    uint8_t seed[32];
    int i;

    /* the known-answer test pins both before every vector */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);

    switch (c->ver)
    {
    case V10:
        cn_slow_hash_v10(ctx, live_in, sizeof(live_in) - 1, h,
                         c->iters, c->blk, c->xx, c->yy, c->zz, c->ww);
        break;
    case V11:
        cn_slow_hash_v11(ctx, live_in, sizeof(live_in) - 1, h,
                         c->iters, c->blk, c->xx, c->yy);
        break;
    case V13:
        for (i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7u + 3u);
        cn_slow_hash_v13(ctx, live_in, sizeof(live_in) - 1, h, seed);
        break;
    case V14:
        cn_slow_hash_v14(ctx, v8_in, sizeof(v8_in) - 1, h,
                         c->iters, CN_V8_INIT_SIZE_BLK, c->xx, c->yy);
        break;
    case V9:
        cn_slow_hash_v9(ctx, live_in, sizeof(live_in) - 1, h, c->iters);
        break;
    default:
        cn_slow_hash_v7_8(ctx, live_in, sizeof(live_in) - 1, h, c->iters);
        break;
    }
}

static void hex(const char *h)
{
    int i;
    for (i = 0; i < HASH_SIZE; i++) printf("%02x", (unsigned char)h[i]);
}

int main(void)
{
    cn_hash_context_t *ctx = cn_hash_context_create();
    char warm[HASH_SIZE];
    size_t k;
    int mismatches = 0;

    if (ctx == NULL) { fprintf(stderr, "no context\n"); return 2; }

    /* the dispatchers allocate lazily, so run one hash before touching salt */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v11(ctx, live_in, sizeof(live_in) - 1, warm, 8, 8, 4, 4);
    if (ctx->salt == NULL) { fprintf(stderr, "no salt\n"); return 2; }

    for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
    {
        char h_off[HASH_SIZE], h_on[HASH_SIZE];

        cn_nt_fill_enable(0);
        run_case(ctx, &cases[k], h_off);
        cn_nt_fill_enable(1);
        run_case(ctx, &cases[k], h_on);
        cn_nt_fill_enable(0);

        printf("%-22s ", cases[k].tag);
        hex(h_off);
        if (memcmp(h_off, h_on, HASH_SIZE) != 0)
        {
            mismatches++;
            printf("   NON-TEMPORAL MISMATCH -> ");
            hex(h_on);
        }
        putchar('\n');
    }

    printf("\n%d cases, %d non-temporal mismatches\n",
           (int)(sizeof(cases) / sizeof(cases[0])), mismatches);
    printf("known-answer test: %s\n",
           cn_slow_hash_known_answer_test() ? "PASS" : "FAIL");

    cn_hash_context_free(ctx);
    return mismatches ? 1 : 0;
}
