// Copyright (c) 2018-2024, The Nerva Project
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
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "cnx_vm.h"
#include "hc128.h"
#include "hash-ops.h"   // CN_SCRATCHPAD_MEMORY_V13

#include <string.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Program generation
// ---------------------------------------------------------------------------

void cnx_generate_program(cnx_program_t *prog, const uint8_t seed[32])
{
    HC128_State rng;
    // Use seed as both key and IV — first 16 bytes key, last 16 bytes IV.
    HC128_Init(&rng, (unsigned char *)seed, (unsigned char *)(seed + 16));

    size_t key_idx = 0;

    for (int i = 0; i < CNX_PROGRAM_SIZE; i++)
    {
        cnx_instruction_t *ins = &prog->instructions[i];

        ins->op    = (uint8_t)HC128_U32(&rng, &key_idx, CNX_OP_COUNT);
        ins->dst   = (uint8_t)HC128_U32(&rng, &key_idx, CNX_REG_COUNT);
        ins->src   = (uint8_t)HC128_U32(&rng, &key_idx, CNX_REG_COUNT);
        // shift doubles as branch offset (interpreted as int8_t for CBRANCH)
        ins->shift = (uint8_t)HC128_U32(&rng, &key_idx, 256);
        // Build a full 32-bit immediate from two 16-bit halves.
        uint32_t lo = HC128_U32(&rng, &key_idx, 0x10000);
        uint32_t hi = HC128_U32(&rng, &key_idx, 0x10000);
        ins->imm = (hi << 16) | lo;
    }
}

// ---------------------------------------------------------------------------
// Execution primitives
// ---------------------------------------------------------------------------

static uint64_t ror64(uint64_t x, uint32_t r)
{
    r &= 63;
    if (r == 0)
        return x;
    return (x >> r) | (x << (64 - r));
}

// High-quality 64-bit mixing function used by CNX_OP_MIX.
// Avalanche effect comparable to an AES round but portable and branchless.
static uint64_t mix64(uint64_t val, uint32_t key_material)
{
    uint64_t k = (uint64_t)key_material * UINT64_C(0x9e3779b97f4a7c15);
    val ^= k;
    val ^= val >> 30;
    val *= UINT64_C(0xbf58476d1ce4e5b9);
    val ^= val >> 27;
    val *= UINT64_C(0x94d049bb133111eb);
    val ^= val >> 31;
    return val;
}

// ---------------------------------------------------------------------------
// cnx_execute
//
// Runs exactly CNX_PROGRAM_SIZE steps through prog, using the for-loop
// counter as the step count and pc as the instruction pointer.  CBRANCH
// changes pc without consuming an extra step, so the total instruction
// count is always deterministic.  CNX_PROGRAM_SIZE is a power of 2 so
// wrapping works with a single bitmask.
// ---------------------------------------------------------------------------

void cnx_execute(cnx_program_t *prog, uint8_t *scratchpad, uint64_t regs[CNX_REG_COUNT])
{
    // Address mask: ensures 8-byte alignment within the 4 MB scratchpad.
    // CN_SCRATCHPAD_MEMORY_V13 must be a multiple of 8.
    const size_t sp_mask = (size_t)(CN_SCRATCHPAD_MEMORY_V13 - 1) & ~(size_t)7;
    const int    pc_mask = CNX_PROGRAM_SIZE - 1;   // CNX_PROGRAM_SIZE is a power of 2

    int pc = 0;

    for (int step = 0; step < CNX_PROGRAM_SIZE; step++)
    {
        const cnx_instruction_t *ins = &prog->instructions[pc & pc_mask];
        int next_pc = pc + 1;

        const uint8_t dst = ins->dst;   // generator bounds these to [0, CNX_REG_COUNT)
        const uint8_t src = ins->src;

        switch ((cnx_opcode_t)ins->op)
        {
        case CNX_OP_IADD_RS:
            regs[dst] += regs[src] << (ins->shift & 3);
            break;

        case CNX_OP_ISUB:
            regs[dst] -= regs[src];
            break;

        case CNX_OP_IMUL:
            regs[dst] *= regs[src];
            break;

        case CNX_OP_IXOR:
            regs[dst] ^= regs[src];
            break;

        case CNX_OP_IROR:
            regs[dst] = ror64(regs[dst], (uint32_t)(regs[src] & 63));
            break;

        case CNX_OP_CBRANCH:
            // Branch if r[dst] has any of the masked bits set (|1 prevents
            // a zero mask that would make the branch unconditional/trivial).
            if (regs[dst] & ((uint64_t)ins->imm | 1))
            {
                // (int8_t)ins->shift gives signed [-128, 127] offset.
                // Wrapping keeps pc in [0, CNX_PROGRAM_SIZE).
                int target = (pc + (int)((int8_t)ins->shift) + CNX_PROGRAM_SIZE) & pc_mask;
                next_pc = target;
            }
            break;

        case CNX_OP_SP_READ:
        {
            size_t addr = ((size_t)((uint64_t)regs[src] + (uint64_t)ins->imm)) & sp_mask;
            memcpy(&regs[dst], &scratchpad[addr], sizeof(uint64_t));
            break;
        }

        case CNX_OP_SP_WRITE:
        {
            size_t addr = ((size_t)((uint64_t)regs[dst] + (uint64_t)ins->imm)) & sp_mask;
            uint64_t tmp;
            memcpy(&tmp, &scratchpad[addr], sizeof(uint64_t));
            tmp ^= regs[src];
            memcpy(&scratchpad[addr], &tmp, sizeof(uint64_t));
            break;
        }

        case CNX_OP_MIX:
            regs[dst] = mix64(regs[dst] ^ regs[src], ins->imm);
            break;

        default:
            // Unknown opcode — treat as NOP to stay deterministic.
            break;
        }

        pc = next_pc;
    }
}
