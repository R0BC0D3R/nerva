/* How much of v8's pad do the sweeps actually write?
 *
 * This decides whether v6's recomputed final pass transfers to v8. In v13 the
 * final pass reads all 8 MB, and every block the VM never wrote is reproducible
 * from the fill's AES chain and the salt, so a miner regenerates it instead of
 * reading it. That was worth +16.8%. On a screened v13 nonce the median number
 * of dirty blocks is 32, which is just the random-value pokes.
 *
 * v8's structure says the same thing should hold, and more strongly, because it
 * needs no screening: consensus draws xx and yy in [4,8] and iters in [0,63],
 * so the sweeps run at most (xx-1)*yy + iters = 119 operations, and each writes
 * two 16-byte slots. That is at most 238 slots of the 65,536 a 1 MB pad holds.
 *
 * Arithmetic is not measurement, so this counts them, over the consensus
 * parameter ranges, using the real cn_slow_hash_v14.
 *
 * Counted here: the sweep stores only. The 32 random-value pokes land outside
 * them and add at most 32 more blocks, which is noted in the output rather than
 * instrumented, because randomize_scratchpad is shared with versions this is
 * not asking about.
 *
 * Not counted, deliberately: the salt XOR that randomize_scratchpad_256k_v8
 * applies to one byte in four across the whole pad. It is deterministic and
 * reproducible from the salt, exactly like v13's folded salt, so it does not
 * make a block irreproducible.
 *
 *   t_v8_dirty [nonces]
 *
 * Local experiment, not kept.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cpuid.h>

#include "hash-ops.h"
#include "cna-vm.h"

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

#define V8_AES_BLOCK  16
#define V8_PAD_BLOCKS (CN_SCRATCHPAD_MEMORY_V8 / (CN_V8_INIT_SIZE_BLK * V8_AES_BLOCK))

static uint32_t dirty_blocks(const uint8_t *map)
{
    static const uint8_t pop[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
    uint32_t set = 0, i;
    for (i = 0; i < V8_PAD_BLOCKS / 8u; i++)
        set += pop[map[i] & 15] + pop[map[i] >> 4];
    return set;
}

static uint64_t rs = 0x243F6A8885A308D3ull;
static uint32_t rnd(void)
{
    rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27;
    return (uint32_t)((rs * 0x2545F4914F6CDD1Dull) >> 32);
}

int main(int argc, char **argv)
{
    const int n = (argc > 1) ? atoi(argv[1]) : 2000;
    cn_hash_context_t *ctx = cn_hash_context_create();
    char blob[76], h[HASH_SIZE];
    uint32_t lo = 0xFFFFFFFFu, hi = 0;
    double sum = 0.0;
    int i;

    if (ctx == NULL) { fprintf(stderr, "no context\n"); return 2; }
    memset(blob, 0x5A, sizeof(blob));

    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14(ctx, blob, sizeof(blob), h, 8, CN_V8_INIT_SIZE_BLK, 4, 4);
    if (ctx->salt == NULL) { fprintf(stderr, "no salt\n"); return 2; }

    if (!cn_vm_dirty_enable(1)) { fprintf(stderr, "no dirty map\n"); return 2; }

    printf("v8 pad %d KB, %d blocks of %d bytes\n",
           CN_SCRATCHPAD_MEMORY_V8 / 1024, (int)V8_PAD_BLOCKS,
           CN_V8_INIT_SIZE_BLK * V8_AES_BLOCK);
    printf("consensus draw: xx,yy in [4,8], iters in [0,63]\n\n");

    for (i = 0; i < n; i++)
    {
        const uint16_t xx = (uint16_t)(4 + rnd() % 5);
        const uint16_t yy = (uint16_t)(4 + rnd() % 5);
        const size_t iters = (size_t)(rnd() % (1 + rnd() % 64));
        uint32_t nd;

        /* fresh salt and values per nonce: the sweeps mutate the salt, and a
         * nonce that starts from a different salt is a different experiment */
        for (size_t k = 0; k < CN_SALT_MEMORY; k += 8)
        {
            uint64_t v = ((uint64_t)rnd() << 32) | rnd();
            memcpy(ctx->salt + k, &v, 8);
        }
        memset(&ctx->random_values, 0, sizeof(ctx->random_values));

        memset(cn_vm_dirty_map(), 0, CN_V13_DIRTY_BYTES);
        cn_slow_hash_v14(ctx, blob, sizeof(blob), h, iters,
                         CN_V8_INIT_SIZE_BLK, xx, yy);
        nd = dirty_blocks(cn_vm_dirty_map());

        sum += nd;
        if (nd < lo) lo = nd;
        if (nd > hi) hi = nd;
    }

    cn_vm_dirty_enable(0);

    printf("  blocks the sweeps wrote, over %d nonces\n", n);
    printf("    min %u   mean %.1f   max %u   of %d\n",
           lo, sum / n, hi, (int)V8_PAD_BLOCKS);
    printf("    mean %.2f%% of the pad written, %.2f%% reproducible\n",
           100.0 * (sum / n) / V8_PAD_BLOCKS,
           100.0 - 100.0 * (sum / n) / V8_PAD_BLOCKS);
    printf("\n  the 32 random-value pokes add at most 32 more blocks,\n");
    printf("  so the reproducible share is at least %.2f%%\n",
           100.0 - 100.0 * (sum / n + 32.0) / V8_PAD_BLOCKS);

    if (hi == 0)
        printf("\nNOTHING WAS COUNTED: the mark never fired\n");

    cn_hash_context_free(ctx);
    return 0;
}
