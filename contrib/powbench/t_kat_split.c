/* Which hash variant does a build change?
 *
 * cn_slow_hash_known_answer_test accumulates one ok flag across v10, v11, v13
 * and v14, so a failure says only that the build is wrong, not where. This
 * prints a digest per variant so two builds can be diffed and the culprit named.
 *
 * Inputs and parameters match the known-answer test's, including its zeroed
 * salt and zeroed random values, so a difference here is a difference there.
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

static void show(const char *tag, const char *h)
{
    int i;
    printf("%-26s ", tag);
    for (i = 0; i < HASH_SIZE; i++) printf("%02x", (unsigned char)h[i]);
    putchar('\n');
}

int main(void)
{
    cn_hash_context_t *ctx = cn_hash_context_create();
    char h[HASH_SIZE];
    uint8_t seed[32];
    int i;

    if (ctx == NULL) { fprintf(stderr, "no context\n"); return 2; }
    for (i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7u + 3u);

    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v11(ctx, live_in, sizeof(live_in) - 1, h, 8, 8, 4, 4);
    if (ctx->salt == NULL) { fprintf(stderr, "no salt\n"); return 2; }

#define RESET() do { memset(&ctx->random_values, 0, sizeof(ctx->random_values)); \
                     memset(ctx->salt, 0, CN_SALT_MEMORY); } while (0)

    /* the known-answer test's own parameter sets, read out of its tables */
    RESET(); cn_slow_hash_v10(ctx, live_in, sizeof(live_in) - 1, h, 0, 8, 2, 2, 2, 2);
    show("v10 kat[0] iters=0", h);
    RESET(); cn_slow_hash_v10(ctx, live_in, sizeof(live_in) - 1, h, 17, 4, 3, 2, 2, 3);
    show("v10 kat[1] iters=17", h);
    RESET(); cn_slow_hash_v10(ctx, live_in, sizeof(live_in) - 1, h, 64, 2, 2, 3, 3, 2);
    show("v10 kat[2] iters=64", h);

    RESET(); cn_slow_hash_v11(ctx, live_in, sizeof(live_in) - 1, h, 0, 8, 4, 4);
    show("v11 kat[0] iters=0", h);
    RESET(); cn_slow_hash_v11(ctx, live_in, sizeof(live_in) - 1, h, 17, 4, 5, 6);
    show("v11 kat[1] iters=17", h);
    RESET(); cn_slow_hash_v11(ctx, live_in, sizeof(live_in) - 1, h, 63, 2, 8, 8);
    show("v11 kat[2] iters=63", h);

    RESET(); cn_slow_hash_v13(ctx, live_in, sizeof(live_in) - 1, h, seed);
    show("v13 kat", h);

    RESET(); cn_slow_hash_v14(ctx, v8_in, sizeof(v8_in) - 1, h, 0, CN_V8_INIT_SIZE_BLK, 4, 4);
    show("v14 kat[0] iters=0", h);
    RESET(); cn_slow_hash_v14(ctx, v8_in, sizeof(v8_in) - 1, h, 64, CN_V8_INIT_SIZE_BLK, 6, 6);
    show("v14 kat[3] iters=64", h);

    /* Same arguments, same process, same context: does the digest depend on
     * anything other than its inputs? Run once, run an unrelated hash, run
     * again. A difference here is a reproducibility bug, not a timing one. */
    RESET(); cn_slow_hash_v10(ctx, live_in, sizeof(live_in) - 1, h, 0, 8, 2, 2, 2, 2);
    show("v10 kat[0] first", h);
    RESET(); cn_slow_hash_v13(ctx, live_in, sizeof(live_in) - 1, h, seed);
    RESET(); cn_slow_hash_v10(ctx, live_in, sizeof(live_in) - 1, h, 0, 8, 2, 2, 2, 2);
    show("v10 kat[0] after v13", h);
    RESET(); cn_slow_hash_v11(ctx, live_in, sizeof(live_in) - 1, h, 63, 2, 8, 8);
    RESET(); cn_slow_hash_v10(ctx, live_in, sizeof(live_in) - 1, h, 0, 8, 2, 2, 2, 2);
    show("v10 kat[0] after v11", h);

    {
        cn_hash_context_t *fresh = cn_hash_context_create();
        char h2[HASH_SIZE];
        memset(&fresh->random_values, 0, sizeof(fresh->random_values));
        cn_slow_hash_v11(fresh, live_in, sizeof(live_in) - 1, h2, 8, 8, 4, 4);
        memset(&fresh->random_values, 0, sizeof(fresh->random_values));
        memset(fresh->salt, 0, CN_SALT_MEMORY);
        cn_slow_hash_v10(fresh, live_in, sizeof(live_in) - 1, h2, 0, 8, 2, 2, 2, 2);
        show("v10 kat[0] fresh ctx", h2);
        cn_hash_context_free(fresh);
    }

    printf("known-answer test: %s\n",
           cn_slow_hash_known_answer_test() ? "PASS" : "FAIL");

    cn_hash_context_free(ctx);
    return 0;
}
