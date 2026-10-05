#!/bin/sh
# Build the v13 phase-breakdown harness. Run from anywhere:
#
#   sh contrib/powbench/build-v13-phases.sh /tmp/t_v13_phases.exe
#   t_v13_phases 30 20 4
#
# -DCN_V13_PHASE_TIMING=1 is what compiles the rdtsc marks into the real
# cn_slow_hash_v13 rather than into a copy of it. The daemon never defines it,
# so the marks cost nothing there. Only this script sets it.
#
# Read the H/s line first. The harness models the miner's duty cycle, screen
# included, so it should reproduce the daemon's rate at the same thread count.
# If it does not, the breakdown underneath it is not a breakdown of the daemon.
#
# Two notes for Windows. Run this from MSYS2 bash, not Git for Windows bash: the
# latter cannot create a temp file and the compile dies with "Cannot create
# temporary file in C:/WINDOWS/". And the resulting binary needs libwinpthread
# and friends on PATH or it exits 127, which a script parsing its output sees as
# no readings rather than as an error.
set -e

OUT="${1:-t_v13_phases.exe}"

cd "$(dirname "$0")/../.." || exit 1

gcc -O2 -maes -march=x86-64 -fno-strict-aliasing -ffp-contract=off \
    -DSLOW_HASH_HW_AES_BUILT=1 -DCN_V13_PHASE_TIMING=1 \
    -I src -I src/crypto -I contrib/epee/include -I contrib/hf14checks \
    contrib/powbench/t_v13_phases.c \
    src/crypto/slow-hash.c src/crypto/slow-hash-hw.c src/crypto/slow-hash-sw.c \
    src/crypto/slow-hash-v8-hw.c src/crypto/slow-hash-v8-sw.c \
    src/crypto/slow-hash-v8fp-hw.c src/crypto/slow-hash-v8fp-sw.c \
    src/crypto/cna-vm.c src/crypto/hc128.c src/crypto/oaes_lib.c \
    src/crypto/aesb.c src/crypto/keccak.c src/crypto/hash.c \
    src/crypto/blake256.c src/crypto/groestl.c src/crypto/jh.c \
    src/crypto/skein.c \
    src/crypto/hash-extra-blake.c src/crypto/hash-extra-groestl.c \
    src/crypto/hash-extra-jh.c src/crypto/hash-extra-skein.c \
    contrib/epee/src/memwipe.c \
    -pthread -o "$OUT" -lm

echo "built $OUT"
