#!/bin/sh
# Build the v13 digest harness that pins the fused pad init. Run from anywhere:
#
#   sh contrib/powbench/build-v13-fold.sh /tmp/t_v13_fold.exe
#
# Then run it against the unmodified tree and against the change and compare the
# two outputs; they must be identical byte for byte.
#
#   t_v13_fold  2000 v13 digests, 400 seeds x 4 inputs on the hardware arm and
#               100 x 4 on the software arm, with a dense per-seed chain salt.
#
# The salt matters. An earlier harness zeroed it, and XOR with zero is the
# identity, so any wrong salt offset still produced the right digest and the
# check proved nothing. The harness has a SALT_ZERO=1 control for exactly that:
# set it and the digests must change, which proves the salt reaches them.
#
# This links the crypto sources directly rather than the daemon, so it needs no
# Boost and builds in about seven seconds. It must be compiled from the tree
# whose behaviour is being measured, so build it twice, once per side.
#
# Two notes for Windows. Run this from MSYS2 bash, not Git for Windows bash: the
# latter cannot create a temp file and the compile dies with "Cannot create
# temporary file in C:\WINDOWS\". And the resulting binary needs libwinpthread
# and friends on PATH or it exits 127, which a script parsing its output sees as
# no readings rather than as an error.
set -e

OUT="${1:-t_v13_fold.exe}"

cd "$(dirname "$0")/../.." || exit 1

gcc -O2 -maes -march=x86-64 -fno-strict-aliasing -ffp-contract=off \
    -DSLOW_HASH_HW_AES_BUILT=1 \
    -I src -I src/crypto -I contrib/epee/include -I contrib/hf14checks \
    contrib/powbench/t_v13_fold.c \
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
