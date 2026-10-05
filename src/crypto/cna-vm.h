// Copyright (c) 2018-2026, The Nerva Project
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

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "hc128.h"

#ifdef __cplusplus
extern "C" {
#endif

// CryptoNight-Adaptive v6 virtual machine for HF13 (pool-resistant + ASIC/GPU-resistant).
//
// The VM generates a random program per block from a chain-rooted seed,
// then executes it against an 8 MB scratchpad.  Combining random code
// execution (defeats fixed ASIC circuits) with a large scratchpad
// (kills GPU occupancy) while keeping the blockchain-DB seed dependency
// that makes pool mining architecturally impossible.

// Must be a power of 2 so pc wrapping works with a bitmask.
#define CN_PROGRAM_SIZE    512
#define CN_REG_COUNT       8
#define CN_VM_ITERATIONS   2048

// Instruction opcodes — kept small so the opcode byte fits in uint8_t.
typedef enum {
    CN_OP_IADD_RS   = 0,  // r[dst] += r[src] << (shift & 3)
    CN_OP_ISUB      = 1,  // r[dst] -= r[src]
    CN_OP_IMUL      = 2,  // r[dst] *= r[src]  (lower 64 bits)
    CN_OP_IXOR      = 3,  // r[dst] ^= r[src]
    CN_OP_IROR      = 4,  // r[dst] = ror64(r[dst], r[src] & 63)
    CN_OP_CBRANCH   = 5,  // if (r[dst] & (imm|1)) pc = (pc + shift) % SIZE
    CN_OP_SP_READ   = 6,  // r[dst] = scratchpad[(r[src]+imm+chain) & mask] (8B); chain = r[dst]
    CN_OP_SP_WRITE  = 7,  // scratchpad[(r[dst]+imm+chain) & mask] ^= r[src]; chain += prev value
    CN_OP_MIX       = 8,  // r[dst] = mix64(r[dst] ^ r[src], imm)
    CN_OP_COUNT     = 9
} cn_vm_opcode_t;

typedef struct {
    uint8_t  op;    // cn_vm_opcode_t stored as byte
    uint8_t  dst;   // destination register [0, CN_REG_COUNT)
    uint8_t  src;   // source register      [0, CN_REG_COUNT)
    uint8_t  shift; // shift amount / signed branch offset (interpreted as int8_t for CN_OP_CBRANCH)
    uint32_t imm;   // immediate operand
} cn_vm_instruction_t;

typedef struct {
    cn_vm_instruction_t instructions[CN_PROGRAM_SIZE];
} cn_vm_program_t;

// Generate a deterministic random program from a 32-byte seed.
// The seed must embed both per-height chain data and per-nonce blob hash
// so that the program is unique per (height, nonce) tuple.
void cn_vm_generate_program(cn_vm_program_t *prog, const uint8_t seed[32]);

// Execute one pass of prog against scratchpad, mutating both scratchpad
// and regs in place.  Executes exactly CN_PROGRAM_SIZE steps (no infinite
// loops possible).  Call CN_VM_ITERATIONS times with the same prog and
// evolving regs to accumulate scratchpad mutations.
void cn_vm_execute(cn_vm_program_t *prog, uint8_t *scratchpad, uint64_t regs[CN_REG_COUNT]);

/* Cheap estimate of what a nonce's program will cost, without registers, memory
 * or a pad. Mining only: it chooses which nonces to hash and never affects a
 * hash that is computed. Lower is cheaper.
 *
 * Stops early once the count passes `limit` and returns something above it,
 * since the count cannot come back down; the result is then a verdict rather
 * than a measurement. Pass UINT32_MAX for the exact count. See the comment on
 * the definition. */
uint32_t cn_vm_screen_cost(const uint8_t seed[32], uint32_t limit);

/* Same, from an already-initialised HC-128 state, so a caller screening a batch
 * of nonces can run the key schedules eight at a time with HC128_Init_x8. */
uint32_t cn_vm_screen_cost_from_state(HC128_State *rng, uint32_t limit);

/* Dirty-block tracking for the recomputed final pass. Mining only.
 *
 * v13 writes the whole 8 MB pad in the fill and reads the whole 8 MB back in
 * the final pass. A screened nonce barely touches it in between: at threshold 4
 * the VM does at most four memory operations per pass, so under 12% of the
 * blocks are ever written and the final pass can regenerate the rest instead of
 * reading them. Regenerating costs an AES pseudo-round per block, which is the
 * fill's cost again; reading costs 128 bytes off DRAM. On a machine that is
 * memory bound at 30 threads the AES is the cheaper side.
 *
 * It has to be opt-in because cn_vm_execute is also the verification path,
 * where a nonce is not screened and does hundreds of thousands of writes per
 * hash. There the marking is pure overhead and the pad is fully dirty anyway.
 * The map is per thread and NULL means no tracking, which is the behaviour the
 * daemon has always had.
 *
 * One bit per CN_V13_FILL_BLOCK bytes of pad, bit b of byte n covering block
 * n * 8 + b. The caller clears it before the fill and sets the bits for any
 * writes it makes outside the VM; cn_vm_execute sets the rest. */
#define CN_V13_FILL_BLOCK   128    /* INIT_SIZE_BLK * AES_BLOCK_SIZE */
#define CN_V13_DIRTY_BYTES  8192   /* CN_SCRATCHPAD_MEMORY_V13 / CN_V13_FILL_BLOCK / 8 */

/* Turn tracking on or off for the calling thread. Returns 1 on success, 0 if
 * the map could not be allocated, in which case tracking stays off and hashing
 * is still correct. */
int cn_vm_dirty_enable(int on);

/* The calling thread's map, or NULL when tracking is off. */
uint8_t *cn_vm_dirty_map(void);

#ifdef __cplusplus
}
#endif
