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

#pragma once

#include <stdint.h>
#include "hc128.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HC128_X8_LANES 8

/* Eight HC-128 key schedules at once.
 *
 * HC128_Init is a 1264-term W recurrence with a dependency distance of two
 * followed by 1024 update steps, so a single schedule is latency bound and
 * leaves most of the machine idle. Eight independent schedules fill it, one per
 * lane of a ymm register, because nothing in the expansion crosses lanes except
 * the h-function table lookups.
 *
 * Mining only, and specifically for nonce screening: v6's VM program seed is
 * readable from the first 64 bytes of the salt, so a miner can estimate a
 * nonce's cost before paying for it, and the estimate costs two key schedules.
 * Nothing on the verification path uses this.
 *
 * Bit-identical to eight HC128_Init calls, checked over hundreds of thousands
 * of schedules by contrib/powbench/t_hc128_x8.c. Falls back to eight scalar
 * HC128_Init calls when AVX2 is unavailable, so callers need no runtime check
 * of their own.
 *
 * keys and ivs are HC128_X8_LANES * 16 bytes, lane L at offset L * 16.
 */
void HC128_Init_x8(HC128_State *states, const unsigned char *keys, const unsigned char *ivs);

/* 1 when the AVX2 path is compiled in and the CPU supports it. Informational:
 * HC128_Init_x8 is correct either way. */
int hc128_x8_hardware(void);

#ifdef __cplusplus
}
#endif
