/* v13 digest harness for the recomputed final pass.
 *
 * Two mining-only switches are meant to change nothing about the digest:
 * --mining-recompute-final regenerates any pad block the VM never wrote rather
 * than reading it, and --mining-nontemporal-fill streams the fill's stores past
 * the caches. Correctness is the whole risk, so this harness runs every case
 * four times, the full 2x2, and compares all of them to the one with neither
 * on, which is the path the daemon has always had. Both AES arms are called
 * explicitly, so the software path is covered on a machine that has AES-NI.
 * The software arm ignores the non-temporal switch, which makes its two
 * streaming variants duplicates of the other two rather than a gap.
 *
 * Two things make a comparison like this vacuous, and both are checked rather
 * than assumed:
 *
 *  1. If the salt is zero, a wrong salt offset still gives the right digest,
 *     because XOR with zero is the identity. The salt is dense and per-seed,
 *     and SALT_ZERO=1 is the control: set it and the digests must change.
 *  2. If every block is dirty, the regeneration path never runs and the
 *     comparison proves nothing. An unscreened nonce does roughly 588,000
 *     writes per hash and leaves the pad effectively fully dirty, which is
 *     exactly the case a miner never hashes. So half the seeds here are drawn
 *     the way a screening miner draws them, by rejecting any seed whose program
 *     costs more than a threshold, and the harness prints the clean-block
 *     percentage it actually exercised. If that number is near zero the run
 *     did not test the thing it claims to test.
 *
 * The random values matter too. An earlier harness zeroed them, which makes
 * every poke "add 0 at index 0": the pad comes out unchanged, so failing to
 * mark the blocks they touch would not have changed a single digest. Here they
 * are dense, spread across the pad, and never write a value back unchanged.
 *
 * argv[1] = screened seeds per arm (default 250)
 * argv[2] = unscreened seeds per arm (default 250)
 * argv[3] = screen threshold for the screened half (default 4)
 * Local experiment, not kept.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "hash-ops.h"
#include "cna-vm.h"
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
    "nerva v13 recomputed final pass A",
    "nerva v13 recomputed final pass B",
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
    if (getenv("SALT_ZERO") != NULL) { memset(salt, 0, CN_SALT_MEMORY); return; }
    for (i = 0; i < (uint32_t)CN_SALT_MEMORY; i += 8)
    {
        uint64_t v;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        v = x * 0x2545F4914F6CDD1Dull;
        memcpy(salt + i, &v, 8);
    }
}

/* Dense pokes spread across the whole pad, so a missed dirty mark lands on a
 * block the final pass would otherwise regenerate and the digest changes. */
static void fill_random_values(cn_random_values_t *rv, uint32_t s)
{
    uint64_t x = 0xA24BAED4963EE407ull ^ ((uint64_t)s * 0x9E3779B97F4A7C15ull);
    int i;
    if (x == 0) x = 1;
    for (i = 0; i < CN_RANDOM_VALUES; i++)
    {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        rv->operators[i] = (uint8_t)(ADD + (x % 7u));           /* ADD..EQ, never NOP */
        rv->indices[i]   = (uint32_t)((x >> 13) % (uint64_t)CN_SCRATCHPAD_MEMORY_V13);
        rv->values[i]    = (int8_t)((x >> 41) | 1u);            /* never 0 */
    }
}

static void make_seed(uint8_t seed[32], uint32_t s)
{
    uint64_t x = 0x2545F4914F6CDD1Dull ^ ((uint64_t)s * 0xBF58476D1CE4E5B9ull);
    int i;
    if (x == 0) x = 1;
    for (i = 0; i < 32; i += 8)
    {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        memcpy(seed + i, &x, 8);
    }
}

/* Dirty blocks, not a percentage. At threshold 4 the count is in the tens out
 * of 65536, and a percentage rounds that to "100% clean" whether the real
 * answer is 40 blocks or 4000. The count is also the number the Amdahl estimate
 * for this change was built on, so it is worth reading directly. */
static uint32_t dirty_blocks(const uint8_t *map)
{
    static const uint8_t pop[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
    uint32_t set = 0, i;
    for (i = 0; i < CN_V13_DIRTY_BYTES; i++)
        set += pop[map[i] & 15] + pop[map[i] >> 4];
    return set;
}

#define CN_V13_PAD_BLOCKS (CN_V13_DIRTY_BYTES * 8u)

struct tally { int digests; int mismatches; uint32_t d_min, d_max; double d_sum; int n; };

static void run(cn_hash_context_t *ctx, const char *tag, int seeds, uint32_t threshold,
                void (*fn)(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *),
                struct tally *t)
{
    char h_off[HASH_SIZE], h_on[HASH_SIZE];
    uint8_t seed[32];
    uint32_t s = 0;
    int got = 0;

    while (got < seeds)
    {
        int k;
        make_seed(seed, s++);
        if (threshold != 0 && cn_vm_screen_cost(seed, threshold) > threshold)
            continue;                                   /* the miner would skip it */
        got++;

        for (k = 0; k < 4; k++)
        {
            /* The full 2x2. Both switches are meant to be pure performance,
             * so all four have to agree with the one that has neither on,
             * which is the code path the daemon has always had. Testing them
             * one at a time would miss an interaction, and there is a real
             * one to miss: the recomputed final pass reads dirty blocks back
             * out of a pad the streaming stores have just written. */
            static const char *variant[4] = { "base", "rec", "nt", "rec+nt" };
            uint32_t nd = 0;
            int v;

            for (v = 0; v < 4; v++)
            {
                char *out = (v == 0) ? h_off : h_on;

                fill_salt(ctx->salt, s);
                fill_random_values(&ctx->random_values, s);

                if (v & 1) { if (!cn_vm_dirty_enable(1)) { fprintf(stderr, "no dirty map\n"); exit(2); } }
                else cn_vm_dirty_enable(0);
                cn_v13_nt_fill_enable((v & 2) ? 1 : 0);

                fn(ctx, inputs[k], strlen(inputs[k]), out, seed);
                if (v == 1) nd = dirty_blocks(cn_vm_dirty_map());

                cn_vm_dirty_enable(0);
                cn_v13_nt_fill_enable(0);

                if (v == 0) continue;

                t->digests++;
                if (memcmp(h_off, h_on, HASH_SIZE) != 0)
                {
                    int i;
                    printf("MISMATCH %s seed=%u k=%d variant=%s dirty=%u\n  base ",
                           tag, s - 1, k, variant[v], nd);
                    for (i = 0; i < HASH_SIZE; i++) printf("%02x", (unsigned char)h_off[i]);
                    printf("\n  got  ");
                    for (i = 0; i < HASH_SIZE; i++) printf("%02x", (unsigned char)h_on[i]);
                    putchar('\n');
                    t->mismatches++;
                }
            }

            t->d_sum += nd; t->n++;
            if (nd < t->d_min) t->d_min = nd;
            if (nd > t->d_max) t->d_max = nd;

            /* printed so two builds can be diffed, not just self-compared */
            {
                int i;
                printf("%s s=%u k=%d dirty=%6u ", tag, s - 1, k, nd);
                for (i = 0; i < HASH_SIZE; i++) printf("%02x", (unsigned char)h_off[i]);
                putchar('\n');
            }
        }
    }
    fprintf(stderr, "  %-18s %4d seeds, %u/%u candidates taken\n", tag, got, (unsigned)got, s);
}

int main(int argc, char **argv)
{
    cn_hash_context_t *ctx = cn_hash_context_create();
    char h[HASH_SIZE];
    uint8_t seed[32];
    int screened = (argc > 1) ? atoi(argv[1]) : 250;
    int plain    = (argc > 2) ? atoi(argv[2]) : 250;
    uint32_t thr = (argc > 3) ? (uint32_t)strtoul(argv[3], NULL, 10) : 4;
    struct tally lo = {0, 0, 0xFFFFFFFFu, 0, 0.0, 0};
    struct tally hi = {0, 0, 0xFFFFFFFFu, 0, 0.0, 0};

    if (ctx == NULL) { fprintf(stderr, "no context\n"); return 2; }

    memset(seed, 0, sizeof(seed));
    cn_slow_hash_v13(ctx, "warm", 4, h, seed);           /* lazy allocation */
    if (ctx->salt == NULL) { fprintf(stderr, "no salt\n"); return 2; }

    fprintf(stderr, "screened half (threshold %u):\n", thr);
    run(ctx, "hw-screened", screened, thr, cn_slow_hash_v13_hw, &lo);
    run(ctx, "sw-screened", screened / 10, thr, cn_slow_hash_v13_sw, &lo);
    fprintf(stderr, "unscreened half:\n");
    run(ctx, "hw-plain", plain, 0, cn_slow_hash_v13_hw, &hi);
    run(ctx, "sw-plain", plain / 10, 0, cn_slow_hash_v13_sw, &hi);

    fprintf(stderr, "\n%d digests, 3 variants per case against the base path\n", lo.digests + hi.digests);
    fprintf(stderr, "  screened   dirty blocks %u to %u of %u, mean %.1f (%.3f%% of the pad)\n",
            lo.d_min, lo.d_max, CN_V13_PAD_BLOCKS, lo.n ? lo.d_sum / lo.n : 0.0,
            lo.n ? lo.d_sum / lo.n * 100.0 / CN_V13_PAD_BLOCKS : 0.0);
    fprintf(stderr, "  unscreened dirty blocks %u to %u of %u, mean %.1f (%.3f%% of the pad)\n",
            hi.d_min, hi.d_max, CN_V13_PAD_BLOCKS, hi.n ? hi.d_sum / hi.n : 0.0,
            hi.n ? hi.d_sum / hi.n * 100.0 / CN_V13_PAD_BLOCKS : 0.0);

    if (lo.d_min >= CN_V13_PAD_BLOCKS)
        fprintf(stderr, "\nNOTHING WAS TESTED: every block was dirty, nothing was regenerated\n");
    if (lo.mismatches + hi.mismatches)
    {
        fprintf(stderr, "\n%d MISMATCHES\n", lo.mismatches + hi.mismatches);
        cn_hash_context_free(ctx);
        return 1;
    }
    fprintf(stderr, "\nall digests identical across the recompute and non-temporal 2x2\n");
    cn_hash_context_free(ctx);
    return 0;
}
