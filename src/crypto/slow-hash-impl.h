// Copyright (c) 2018-2026, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
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
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
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

/* Implementation bodies of cn_slow_hash and its variants. Included by both
 * slow-hash-hw.c and slow-hash-sw.c. The includer is responsible for setting
 * up the function-name macros (e.g. #define cn_slow_hash cn_slow_hash_hw)
 * before pulling this file in, and for arranging which AES path slow-hash.h
 * activates via CN_FORCE_SOFTWARE_AES. */

#include "cna-vm.h"

#if !defined(CN_USE_SOFTWARE_AES)

void cn_slow_hash_v11(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&c;
    for (k = 1; k < xx; k++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
        salt_pad(salt, salt_hash, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
            salt_pad(salt, salt_hash, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v10(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t r2[6] = {xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww};
    uint16_t k = 1, l = 1, m = 1;

    for (k = 1; k < xx; k++)
    {
        r2[0] ^= r2[1];
        r2[1] ^= r2[2];
        r2[2] ^= r2[3];
        r2[3] ^= r2[4];
        r2[4] ^= r2[5];
        r2[5] ^= r2[0];

        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
        salt_pad(salt, salt_hash, r2[0], r2[3], r2[1], r2[4]);
        r2[0] ^= (r2[1] ^ r2[3]);
        r2[1] ^= (r2[0] ^ r2[2]);

        for (l = 1; l < yy; l++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
            salt_pad(salt, salt_hash, r2[1], r2[4], r2[2], r2[5]);
            r2[2] ^= (r2[3] ^ r2[5]);
            r2[3] ^= (r2[2] ^ r2[4]);

            for (m = 1; m < zz; m++)
            {
                pre_aes();
                _c = _mm_aesenc_si128(_c, _a);
                post_aes_variant();
                salt_pad(salt, salt_hash, r2[2], r2[5], r2[3], r2[0]);
                r2[4] ^= (r2[5] ^ r2[1]);
                r2[5] ^= (r2[4] ^ r2[0]);
            }
        }
    }

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v9(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad_4k(context->random_values, salt, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    for(i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v7_8(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad(context->random_values, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();

    if (prehashed)
        memcpy(&state.hs, data, length);
    else
        hash_process(&state.hs, data, length);

    memcpy(text, state.init, init_size_byte);
    const uint64_t tweak1_2 = variant > 0 ? (state.hs.w[24] ^ (*((const uint64_t *)NONCE_POINTER))) : 0;

    aes_expand_key((OAES_CTX *)context->oaes_ctx, state.hs.b, expandedKey);
    for(i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++)
    {
        aes_pseudo_round(text, text, expandedKey, INIT_SIZE_BLK);
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
    }

    xor_u64();

    _b = _mm_load_si128(R128(b));

    if (variant > 0)
    {
        for(i = 0; i < iters; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
        }
    }
    else
    {
        for(i = 0; i < iters; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_novariant();
        }
    }

    finalize_hash();
}

void cn_slow_hash_v13(cn_hash_context_t *context, const void *data, size_t length, char *hash, const uint8_t *seed)
{
    uint8_t * const hp_state = context->cna_scratchpad;
    char * const salt = context->salt;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    const uint32_t init_size_byte = (uint32_t)(init_size_blk * AES_BLOCK_SIZE);

    RDATA_ALIGN16 uint8_t expandedKey[240];
    RDATA_ALIGN16 uint8_t expandedKeyFill[240];
    RDATA_ALIGN16 uint8_t fill_text[INIT_SIZE_BLK * AES_BLOCK_SIZE];
    RDATA_ALIGN16 uint8_t clean_blk[INIT_SIZE_BLK * AES_BLOCK_SIZE];
    uint8_t *text = (uint8_t *)malloc(init_size_byte);
    union cn_slow_hash_state state;
    size_t i;

    /* Non-NULL only on a mining thread that asked for it. See cna-vm.h. */
    uint8_t * const dirty = cn_vm_dirty_map();

    static void (*const extra_hashes[4])(const void *, size_t, char *) = {
        hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein};

    hash_process(&state.hs, data, length);
    memcpy(text, state.init, init_size_byte);
    aes_expand_key((OAES_CTX *)context->oaes_ctx, state.hs.b, expandedKey);
    if (dirty != NULL)
    {
        /* The final pass replays this fill, and by the time it runs the key it
         * was derived from is gone: state.k is XORed with the VM's registers
         * first, and state.k is hs.b[0..64), which covers both this key and the
         * final pass's. Keep the expansion rather than the 32 bytes. */
        memcpy(expandedKeyFill, expandedKey, sizeof(expandedKey));
        memset(dirty, 0, CN_V13_DIRTY_BYTES);
    }
    for (i = 0; i < CN_SCRATCHPAD_MEMORY_V13 / init_size_byte; i++)
    {
        aes_pseudo_round(text, text, expandedKey, init_size_blk);
        {
            /* Salt folded into the fill's store. The separate pass this
             * replaces read and wrote all 8 MB a second time purely to XOR the
             * salt in, so removing it takes 16 MB of traffic off every nonce.
             * The fold is exact: that pass walked the salt offset forward in
             * lockstep with the pad offset and wrapped at CN_SALT_MEMORY, so
             * the salt offset was always the pad offset mod CN_SALT_MEMORY and
             * depended on nothing else. CN_SALT_MEMORY is 2^18 and
             * init_size_byte is 128, which divides it, so a block never
             * straddles the wrap.
             *
             * text is left alone on purpose: the AES round above feeds it
             * back to the next iteration, so it carries the chain. */
            const uint32_t p_off = (uint32_t)(i * init_size_byte);
            const uint8_t * const sp = (const uint8_t *)salt + (p_off & (CN_SALT_MEMORY - 1));
            uint8_t * const dp = &hp_state[p_off];
            uint32_t k;
            for (k = 0; k < init_size_byte; k += 8)
            {
                uint64_t t, sv;
                memcpy(&t, text + k, 8);
                memcpy(&sv, sp + k, 8);
                t ^= sv;
                memcpy(dp + k, &t, 8);
            }
        }
    }

    {
        const cn_random_values_t rv = context->random_values;
        int ri;
        for (ri = 0; ri < CN_RANDOM_VALUES; ri++)
        {
            /* These land on the pad outside the VM, so the final pass must not
             * regenerate the blocks they touch. Marked for every entry,
             * including operators that happen to write the value back
             * unchanged: a bit set on a clean block only costs a read, a bit
             * missed corrupts the hash silently. */
            if (dirty != NULL)
                dirty[rv.indices[ri] >> 10] |= (uint8_t)(1u << ((rv.indices[ri] >> 7) & 7));
            switch (rv.operators[ri])
            {
            case ADD:  hp_state[rv.indices[ri]] += (uint8_t)rv.values[ri]; break;
            case SUB:  hp_state[rv.indices[ri]] -= (uint8_t)rv.values[ri]; break;
            case XOR:  hp_state[rv.indices[ri]] ^= (uint8_t)rv.values[ri]; break;
            case OR:   hp_state[rv.indices[ri]] |= (uint8_t)rv.values[ri]; break;
            case AND:  hp_state[rv.indices[ri]] &= (uint8_t)rv.values[ri]; break;
            case COMP: hp_state[rv.indices[ri]] = ~(uint8_t)rv.values[ri]; break;
            case EQ:   hp_state[rv.indices[ri]] =  (uint8_t)rv.values[ri]; break;
            default: break;
            }
        }
    }

    uint64_t regs[CN_REG_COUNT];
    {
        int r;
        for (r = 0; r < CN_REG_COUNT; r++)
            memcpy(&regs[r], &state.k[r * sizeof(uint64_t)], sizeof(uint64_t));
    }

    cn_vm_program_t prog;
    cn_vm_generate_program(&prog, seed);

    {
        int iter;
        for (iter = 0; iter < CN_VM_ITERATIONS; iter++)
            cn_vm_execute(&prog, hp_state, regs);
    }

    {
        int r;
        for (r = 0; r < CN_REG_COUNT; r++)
        {
            uint64_t tmp;
            memcpy(&tmp, &state.k[r * sizeof(uint64_t)], sizeof(uint64_t));
            tmp ^= regs[r];
            memcpy(&state.k[r * sizeof(uint64_t)], &tmp, sizeof(uint64_t));
        }
    }

    memcpy(text, state.init, init_size_byte);
    aes_expand_key((OAES_CTX *)context->oaes_ctx, &state.hs.b[32], expandedKey);
    if (dirty == NULL)
    {
        for (i = 0; i < CN_SCRATCHPAD_MEMORY_V13 / init_size_byte; i++)
            aes_pseudo_round_xor(text, text, expandedKey, &hp_state[i * init_size_byte], init_size_blk);
    }
    else
    {
        /* Same arithmetic, but a block the VM never wrote is regenerated rather
         * than read. The fill is a chain, so this walks it forward in step: the
         * final pass is already sequential over the same blocks in the same
         * order, which is why no checkpoints are needed. A clean block is
         * exactly what the fill stored, aes_pseudo_round of the running fill
         * text XOR the salt at the same offset.
         *
         * fill_text starts where the fill started. state.init is hs.b[64..192)
         * and the register XOR above only touched hs.b[0..64), so it is still
         * the value the fill began from. */
        memcpy(fill_text, state.init, init_size_byte);
        for (i = 0; i < CN_SCRATCHPAD_MEMORY_V13 / init_size_byte; i++)
        {
            aes_pseudo_round(fill_text, fill_text, expandedKeyFill, init_size_blk);
            if (dirty[i >> 3] & (1u << (i & 7)))
            {
                aes_pseudo_round_xor(text, text, expandedKey, &hp_state[i * init_size_byte], init_size_blk);
            }
            else
            {
                const uint32_t p_off = (uint32_t)(i * init_size_byte);
                const uint8_t * const sp = (const uint8_t *)salt + (p_off & (CN_SALT_MEMORY - 1));
                uint32_t k;
                for (k = 0; k < init_size_byte; k += 8)
                {
                    uint64_t t, sv;
                    memcpy(&t, fill_text + k, 8);
                    memcpy(&sv, sp + k, 8);
                    t ^= sv;
                    memcpy(clean_blk + k, &t, 8);
                }
                aes_pseudo_round_xor(text, text, expandedKey, clean_blk, init_size_blk);
            }
        }
    }
    memcpy(state.init, text, init_size_byte);
    hash_permutation(&state.hs);
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);

    free(text);
}

#else /* CN_USE_SOFTWARE_AES */

void cn_slow_hash_v11(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&b;
    for (k = 1; k < xx; k++)
    {
        aes_sw_variant();
        salt_pad(salt, salt_hash, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant();
            salt_pad(salt, salt_hash, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v10(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t r2[6] = {xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww};
    uint16_t k = 1, l = 1, m = 1;

    for (k = 1; k < xx; k++)
    {
        r2[0] ^= r2[1];
        r2[1] ^= r2[2];
        r2[2] ^= r2[3];
        r2[3] ^= r2[4];
        r2[4] ^= r2[5];
        r2[5] ^= r2[0];

        aes_sw_variant();
        salt_pad(salt, salt_hash, r2[0], r2[3], r2[1], r2[4]);
        r2[0] ^= (r2[1] ^ r2[3]);
        r2[1] ^= (r2[0] ^ r2[2]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant();
            salt_pad(salt, salt_hash, r2[1], r2[4], r2[2], r2[5]);
            r2[2] ^= (r2[3] ^ r2[5]);
            r2[3] ^= (r2[2] ^ r2[4]);

            for (m = 1; m < zz; m++)
            {
                aes_sw_variant();
                salt_pad(salt, salt_hash, r2[2], r2[5], r2[3], r2[0]);
                r2[4] ^= (r2[5] ^ r2[1]);
                r2[5] ^= (r2[4] ^ r2[0]);
            }
        }
    }

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v9(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_4k(context->random_values, salt, hp_state);
    xor_u64();

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v7_8(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad(context->random_values, hp_state);
    xor_u64();

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();

    if (prehashed)
        memcpy(&state.hs, data, length);
    else
        hash_process(&state.hs, data, length);

    memcpy(text, state.init, init_size_byte);
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);

    uint8_t tweak1_2[8] = {0};
    if (variant > 0)
    {
        memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2));
        xor64(tweak1_2, NONCE_POINTER);
    }

    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
    for (i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
        }
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
    }

    xor_u64();

    if (variant > 0) {
        for (i = 0; i < iters; i++) {
            aes_sw_variant();
        }
    } else {
        for (i = 0; i < iters; i++) {
            aes_sw_novariant();
        }
    }

    finalize_hash();
}

void cn_slow_hash_v13(cn_hash_context_t *context, const void *data, size_t length, char *hash, const uint8_t *seed)
{
    uint8_t * const hp_state = context->cna_scratchpad;
    char * const salt = context->salt;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    const uint32_t init_size_byte = (uint32_t)(init_size_blk * AES_BLOCK_SIZE);

    uint8_t *text = (uint8_t *)malloc(init_size_byte);
    union cn_slow_hash_state state;
    uint8_t aes_key[AES_KEY_SIZE];
    oaes_ctx * const aes_ctx = (oaes_ctx *)context->oaes_ctx;
    size_t i, j;

    /* Non-NULL only on a mining thread that asked for it. See cna-vm.h. The
     * software arm is not what anyone mines on; it is here so the recomputed
     * final pass has a second, independent implementation for the digest
     * harness to check the hardware one against. */
    uint8_t *dirty = cn_vm_dirty_map();
    uint8_t fill_exp[256];
    uint8_t fill_text[INIT_SIZE_BLK * AES_BLOCK_SIZE];
    uint8_t clean_blk[INIT_SIZE_BLK * AES_BLOCK_SIZE];

    static void (*const extra_hashes[4])(const void *, size_t, char *) = {
        hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein};

    hash_process(&state.hs, data, length);
    memcpy(text, state.init, init_size_byte);
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);
    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
    if (dirty != NULL)
    {
        /* The final pass imports a different key over this one, so the
         * expansion has to be kept now. 240 bytes for a 32-byte key; the guard
         * is here so a changed expansion falls back to reading the pad rather
         * than overrunning the buffer. */
        if (aes_ctx->key->exp_data_len > sizeof(fill_exp))
            dirty = NULL;
        else
        {
            memcpy(fill_exp, aes_ctx->key->exp_data, aes_ctx->key->exp_data_len);
            memset(dirty, 0, CN_V13_DIRTY_BYTES);
        }
    }
    for (i = 0; i < CN_SCRATCHPAD_MEMORY_V13 / init_size_byte; i++)
    {
        for (j = 0; j < init_size_blk; j++)
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
        {
            /* Salt folded into the fill's store. The separate pass this
             * replaces read and wrote all 8 MB a second time purely to XOR the
             * salt in, so removing it takes 16 MB of traffic off every nonce.
             * The fold is exact: that pass walked the salt offset forward in
             * lockstep with the pad offset and wrapped at CN_SALT_MEMORY, so
             * the salt offset was always the pad offset mod CN_SALT_MEMORY and
             * depended on nothing else. CN_SALT_MEMORY is 2^18 and
             * init_size_byte is 128, which divides it, so a block never
             * straddles the wrap.
             *
             * text is left alone on purpose: the AES round above feeds it
             * back to the next iteration, so it carries the chain. */
            const uint32_t p_off = (uint32_t)(i * init_size_byte);
            const uint8_t * const sp = (const uint8_t *)salt + (p_off & (CN_SALT_MEMORY - 1));
            uint8_t * const dp = &hp_state[p_off];
            uint32_t k;
            for (k = 0; k < init_size_byte; k += 8)
            {
                uint64_t t, sv;
                memcpy(&t, text + k, 8);
                memcpy(&sv, sp + k, 8);
                t ^= sv;
                memcpy(dp + k, &t, 8);
            }
        }
    }

    {
        const cn_random_values_t rv = context->random_values;
        int ri;
        for (ri = 0; ri < CN_RANDOM_VALUES; ri++)
        {
            /* These land on the pad outside the VM, so the final pass must not
             * regenerate the blocks they touch. Marked for every entry,
             * including operators that happen to write the value back
             * unchanged: a bit set on a clean block only costs a read, a bit
             * missed corrupts the hash silently. */
            if (dirty != NULL)
                dirty[rv.indices[ri] >> 10] |= (uint8_t)(1u << ((rv.indices[ri] >> 7) & 7));
            switch (rv.operators[ri])
            {
            case ADD:  hp_state[rv.indices[ri]] += (uint8_t)rv.values[ri]; break;
            case SUB:  hp_state[rv.indices[ri]] -= (uint8_t)rv.values[ri]; break;
            case XOR:  hp_state[rv.indices[ri]] ^= (uint8_t)rv.values[ri]; break;
            case OR:   hp_state[rv.indices[ri]] |= (uint8_t)rv.values[ri]; break;
            case AND:  hp_state[rv.indices[ri]] &= (uint8_t)rv.values[ri]; break;
            case COMP: hp_state[rv.indices[ri]] = ~(uint8_t)rv.values[ri]; break;
            case EQ:   hp_state[rv.indices[ri]] =  (uint8_t)rv.values[ri]; break;
            default: break;
            }
        }
    }

    uint64_t regs[CN_REG_COUNT];
    {
        int r;
        for (r = 0; r < CN_REG_COUNT; r++)
            memcpy(&regs[r], &state.k[r * sizeof(uint64_t)], sizeof(uint64_t));
    }

    cn_vm_program_t prog;
    cn_vm_generate_program(&prog, seed);

    {
        int iter;
        for (iter = 0; iter < CN_VM_ITERATIONS; iter++)
            cn_vm_execute(&prog, hp_state, regs);
    }

    {
        int r;
        for (r = 0; r < CN_REG_COUNT; r++)
        {
            uint64_t tmp;
            memcpy(&tmp, &state.k[r * sizeof(uint64_t)], sizeof(uint64_t));
            tmp ^= regs[r];
            memcpy(&state.k[r * sizeof(uint64_t)], &tmp, sizeof(uint64_t));
        }
    }

    memcpy(text, state.init, init_size_byte);
    oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
    if (dirty != NULL)
        memcpy(fill_text, state.init, init_size_byte);
    for (i = 0; i < CN_SCRATCHPAD_MEMORY_V13 / init_size_byte; i++)
    {
        const uint8_t *src = &hp_state[i * init_size_byte];
        if (dirty != NULL)
        {
            /* Walk the fill's chain forward in step with the final pass, and
             * regenerate any block the VM never wrote instead of reading it.
             * See the hardware arm for why no checkpoints are needed. */
            for (j = 0; j < init_size_blk; j++)
                aesb_pseudo_round(&fill_text[AES_BLOCK_SIZE * j], &fill_text[AES_BLOCK_SIZE * j], fill_exp);
            if ((dirty[i >> 3] & (1u << (i & 7))) == 0)
            {
                const uint32_t p_off = (uint32_t)(i * init_size_byte);
                const uint8_t * const sp = (const uint8_t *)salt + (p_off & (CN_SALT_MEMORY - 1));
                uint32_t k;
                for (k = 0; k < init_size_byte; k += 8)
                {
                    uint64_t t, sv;
                    memcpy(&t, fill_text + k, 8);
                    memcpy(&sv, sp + k, 8);
                    t ^= sv;
                    memcpy(clean_blk + k, &t, 8);
                }
                src = clean_blk;
            }
        }
        for (j = 0; j < init_size_blk; j++)
        {
            xor_blocks(&text[j * AES_BLOCK_SIZE], &src[j * AES_BLOCK_SIZE]);
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
        }
    }
    memcpy(state.init, text, init_size_byte);
    hash_permutation(&state.hs);
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);

    free(text);
}

#endif /* CN_USE_SOFTWARE_AES */
