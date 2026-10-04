# v13 (CNA v6) miner optimization log

Running record of the work, the measurements and the mistakes. Fork branch
only, not proposed for nerva-project. Started 2026-10-04.

## Why this exists

The CNA v8 work in PR #162 is measured but not live, so nobody is mining on it
and no improvement there is visible to anyone. This effort applies the same
class of optimization to **v13 (CNA v6), the algorithm mainnet runs today**, so
the result can be seen in the miner that is actually running.

The second purpose is adversarial. 0xROOTPLS reports 8.5x to 13.4x on v6 and
2.43x on v8 from the same techniques. Everything we find and understand here is
something we can design out of v8 before it ships, so the gap between a stock
miner and a tuned one stays small. Getting near his v6 numbers is what makes
that credible.

## The rig

- Build: `make release-static-win64 -j4`, **run inside MSYS2 bash**, see traps.
- Measurement daemon: offline, mainnet DB copy at `D:\Claude\nerva-dbcheck`,
  height 4,424,749. That is past HF13 (4,320,000) and short of the HF14
  placeholder (4,500,000), so the miner is on v13. The A/B script asserts the
  height; outside that window it would silently be measuring another algorithm.
- Mining started over the `start_mining` RPC at 12 threads.
- Reference point: the same machine mining normally through NervaOne reports
  580 to 640 H/s, and the rig's baseline lands at 597.6, so the rig is
  representative.

## Measurement method

A-B-B-A, with the baseline measured both before and after the change. A-B-A was
tried in earlier work and produced a confident **-5.5% that was pure drift**:
its two baseline runs came back 10.7% apart. A-B-B-A cancels linear drift, and
the A1-to-A2 gap is printed as a gate, with the run treated as void above 2%.

**The gate has now caught two fake results, which is the entire reason it
exists.** See the void run below.

Window sizes come from the measured noise rather than a guess:

- `mining_status.speed` is hashes in the last 2-second merge window
  ([miner.cpp:453](../../src/cryptonote_basic/miner.cpp#L453)), not a moving
  average.
- 25 consecutive settled readings ran 286 to 336, mean 308, so **about ±4%**.
- An early guess of "2x swing" was wrong and had the sampling window set four
  times longer than it needed to be. The settle time, by contrast, is genuinely
  needed: a fresh daemon reads high for the first couple of minutes, then steps
  down and stays down, so sampling early measures a transient.

## Stage 0: fused pad init

### What

v13 filled the 8 MB pad with AES and then made a **second full pass** over all
8 MB purely to XOR the chain salt in. The XOR is now folded into the fill's
store and the second pass is deleted, removing **16 MB of memory traffic per
hash** from a nonce that moves roughly 32 MB.

Both arms changed identically in
[slow-hash-impl.h](../../src/crypto/slow-hash-impl.h).

### Why the fold is exact

- The deleted pass advanced the salt offset in lockstep with the pad offset and
  wrapped at `CN_SALT_MEMORY`, so the salt offset was always the pad offset mod
  `CN_SALT_MEMORY` and depended on nothing else.
- `CN_SALT_MEMORY` is 262144 = 2^18, so the modulo is a mask.
- `init_size_byte` is 128 and divides 262144, so a block never straddles the
  wrap and no split case is needed. The highest byte touched is exactly
  `CN_SALT_MEMORY`, so the bounds are unchanged.
- `text` is deliberately not modified: the AES round feeds it back into the
  next iteration, so it carries the chain.

### Verification

Bit-identical over **2000 digests**: 400 seeds x 4 inputs on the hardware arm,
100 x 4 on the software arm. The known-answer test and the hardware-vs-software
self-test both pass, so the daemon starts and the hashes are the network's.

**The verification nearly tested nothing.** The pre-existing digest harness
zeroed the salt before every call. XOR with zero is the identity, so a
completely wrong salt offset would still have produced the right digest and the
run would have reported a clean pass on a check that proved nothing. The
harness now fills the salt with a dense per-seed pattern, and that is itself
checked: with the salt zeroed, 0 of 12 digests match the salted run.

Lesson: when a change touches how a value is mixed in, make the test data make
that value matter, and prove it by breaking it on purpose.

Harness is [t_v13_fold.c](t_v13_fold.c), built with
[build-v13-fold.sh](build-v13-fold.sh).

### Result: +7.6%

```
A1  baseline   n=12  mean  597.4  min  579  max  610 H/s   [huge pages]
B1  fused      n=12  mean  644.8  min  627  max  669 H/s   [huge pages]
B2  fused      n=12  mean  640.9  min  620  max  660 H/s   [huge pages]
A2  baseline   n=12  mean  597.8  min  577  max  622 H/s   [huge pages]

A drift across the pair: +0.1%   (within tolerance)
baseline mean 597.6 H/s   fused mean 642.9 H/s   delta +7.6%
```

A standalone benchmark of the hash core alone, excluding the chain salt, gave
**+12.1%** on the same change. The two agree: the core is about 23.4 ms of a
roughly 39.6 ms nonce, and 12.1% x (23.4 / 39.6) is 7.1%, against 7.6%
measured. A prediction made before the daemon run, from an independent
measurement, landing within half a point is the strongest evidence here that
the effect is real and not an artifact.

0xROOTPLS measured +7% for this change on an already-optimized miner.

### Confirmed on the live miner

The fused build run through NervaOne against a live synced mainnet daemon
reports **640 to 720 H/s**, against a remembered 580 to 640 before it. That is
about +11% at the midpoint.

**Quote the +7.6%, not the +11%.** The NervaOne comparison is not controlled:
the two ranges overlap at 640, the baseline is from memory rather than a run
made the same day, and it came from a third binary built at a different moment
from either A/B binary. What it does establish is that the effect is real on
the live miner and on a synced daemon rather than only on an offline database
copy, which the controlled rig could not show.

## The void run, and what it cost

The first daemon A-B-B-A came back:

```
A1 baseline  303.2    B1 fused     287.8
B2 fused     591.3    A2 baseline  600.6
A drift +98.1%  ->  void
```

The two baselines were 98% apart. Run as a plain A-B this would have reported
either a **2x speedup** (B2 against A1) or a 5% regression (B1 against A1), and
both would have been pure noise.

**Cause: two daemons running at once, not large pages.** `nervad-base.log` for
that A/B holds **three** daemon startups for the **two** baseline runs it
performed, the extra one beginning 67 seconds into A1. Two daemons sharing the
machine halves each one's reported rate, which is exactly the factor seen, and
it ended partway through, so B2 and A2 read normally. The source was almost
certainly an earlier A/B task that was force-stopped: that killed the
PowerShell loop but not the daemons it had launched with `Start-Process`, which
are detached and outlive it.

**The large-pages explanation written here first was wrong**, and the evidence
against it was already in the logs. `allocate_hugepage` does fall back to
malloc when memory is fragmented
([slow-hash.c:315](../../src/crypto/slow-hash.c#L315)), but the miner warns
loudly when it does: `Mining is running on normal memory pages`, through
`MGUSER_YELLOW` on the `user` category, which `--log-level 0` still shows, and
`CN_PAGES_MALLOC` is well below the `CN_PAGES_THP` threshold that fires it.
That warning appears in none of the logs, and every page-tier line ever
recorded on this machine says huge pages. A tidy mechanism that explained the
magnitude was accepted before checking the one line that would have falsified
it.

Lesson, and the more useful of the two: **a plausible cause that fits the
magnitude is not evidence.** The check that settled it cost one grep.

Every run now logs at level 1 into its own file and the page tier is parsed back
out and printed beside the number. That gating is worth keeping, since a silent
fallback really would be worth about 2x if it ever happened, but it is not what
was wrong here.

What none of this changes is the +7.6%. That run's four logs show exactly one
daemon start each, the same page tier throughout, and +0.1% drift between the
two baselines. The protection came from the A-B-B-A gate, not from page-tier
gating added on a wrong theory.

**Harness fix owed:** before starting a run, assert that no nervad process
exists and that the RPC port is free, and confirm the daemon answering RPC is
the process just started. Stopping a runner must also stop the daemons it
spawned.

Two earlier confusions have the same root: a claimed "plateau" at 620-634 H/s
that was really a startup transient, and an apparent regime mismatch where the
core benchmark looked slower than a whole nonce. Both came from comparing
against a contended run.

## Stage 2: eight-lane AVX2 HC-128 salt

### The eight-lane init works and is faster than the report expected

`HC128_Init` vectorizes cleanly across eight nonces. The salt loop reseeds on a
fixed cadence that does not depend on the data, so eight inits always run in
lockstep, which is what makes this possible at all. The pick loop between
reseeds does **not** run in lockstep, because `HC128_U32` uses rejection
sampling and consumes a data-dependent number of keystream words.

[t_hc128_x8.c](t_hc128_x8.c) builds it and checks it against the scalar
`HC128_Init` from the tree, not against a reimplementation. **Bit-identical
over 320,000 inits**, in both lookup forms.

```
scalar x8            2.06 us per init
x8 scalar lookup     1.36 us per init   1.51x
x8 gather lookup     0.81 us per init   2.55x
```

The h-function table lookups are the hard part, since each lane indexes its own
table with its own byte. The report measured `vpgatherdd` as the *slower* of
the two options on Zen 3 and recommended scalar extraction. **On this Zen 4
machine gather wins decisively, 2.55x against 1.51x.** Worth knowing before
copying his conclusion: the right lookup form is machine-dependent, so both are
built and selected at run time.

The benchmark varies its key every iteration. With a fixed key the whole call is
loop-invariant and the compiler may hoist it, which would time an empty loop and
report a spectacular speedup.

### The Amdahl gate: init is only 38.6% of the salt

[t_salt_profile.c](t_salt_profile.c) reproduces the salt loop faithfully against
a synthetic block cache of the real size (4.42M entries, 236 MB) and puts rdtsc
accumulators around the three components.

```
component   share     cycles/salt       count  cycles each
init        38.6%         2360832         257       9186
picks       19.3%         1183625       16384         72
encrypt     37.4%         2292665        4097        560
unattributed 4.7%          286042
total                     6123164
```

**So a 2.55x init buys only 1.31x on the salt**, and with the salt at roughly
40% of a nonce that is about +10% overall. Real, and more than Stage 0 gave,
but nothing like the 2.9x the report headlines for this work.

The gap is explained by `encrypt`, which is another 37.4% and is almost entirely
`HC128_NextKeys`: 4097 calls per salt, the same sixteen-step update the init
runs sixty-four times. It is vectorizable by the same code. The obstacle is that
lanes consume keystream at different rates, so they cannot share a refill point,
and the way around it is that **generating keystream ahead is free**: the stream
is deterministic and consumed in order, so all eight lanes can be refilled in
lockstep whenever the hungriest one runs dry, and the lanes that did not need it
simply carry a longer buffer.

With init and encrypt both vectorized the salt should reach roughly 1.8x, which
is about +22% on the nonce. That is the real target for this stage.

This check is the reason the stage is worth doing at the size it is, rather
than being abandoned after the init turned out to be a third of the problem. It
cost one harness and ran while the machine was busy.

### Run-ahead: measured +7.6% on the daemon, and a prediction that missed

```
A1  stage 0            n=11  mean  659.4  min  651  max  666 H/s   [huge pages]
B1  + run-ahead salt   n=12  mean  712.5  min  706  max  722 H/s   [huge pages]
B2  + run-ahead salt   n=12  mean  709.5  min  698  max  720 H/s   [huge pages]
A2  stage 0            n=12  mean  662.6  min  655  max  668 H/s   [huge pages]

A drift +0.5%   stage 0 661.0 H/s   with run-ahead 711.0 H/s   delta +7.6%
```

No overlap between the two groups, drift well inside tolerance, every run on
huge pages, one daemon per run enforced.

**The prediction was +17% and the result was +7.6%.** The error was not in the
salt measurement, which stands at 1.57x, but in the share of a nonce the salt
occupies. That was taken as 40%, derived by subtracting a core benchmark from a
daemon nonce time of 39.6 ms. **That 39.6 ms came from the contended run**, the
one where two daemons were splitting the machine. With a correct baseline of
about 660 H/s at twelve threads the nonce is 18.2 ms, and working backwards
from the measured +7.6% the salt is **about 19% of a nonce, not 40%**.

That reconciles independently: the standalone harness puts one salt at 1333 us,
and against a single-threaded nonce of roughly 8 ms that is 17%.

A bad number does not stop being bad when you stop looking at it. The contended
run was identified and corrected hours earlier, but a figure derived from it had
already been written down and kept being used.

### What this does to the rest of stage 2

The eight-lane init would take the salt from 1.57x to about 2.48x. At a 19%
share that is worth:

| | salt | nonce |
|---|---|---|
| run-ahead only (done) | 1.57x | +7.6% measured |
| run-ahead + x8 init | 2.48x | about +12.8% |

So the eight-lane init adds roughly **+5% on top of what is already banked**,
and it is the change that requires the miner to compute eight nonces at once:
a restructuring of the miner loop and `get_block_longhash_v13`, with the
verification path keeping a scalar version. That is the largest integration in
the project for the smallest measured return in it.

**Recommendation: do not build the eight-nonce batching.** The eight-lane init
stays in the tree as a verified harness, and if the salt ever becomes a larger
share of the nonce it is ready.

### Where the time actually is

The salt is 19% of a nonce, so **the hash core is the other 81%**, and that is
where anything further has to come from. It also means the two stages still
unbuilt are better targets than the one that was supposed to be the big one:

- Non-temporal stores on the 8 MB fill, which is core work.
- K-way nonce interleaving of the VM, which targets the dependent pointer
  chase and is core work.

The report's ordering put the salt first because on his already-optimized miner
the salt was 59.5% of the nonce. On a stock miner it is 19%. His proportions
are not ours, and the stage order should follow our profile, not his.

## What has already failed

**Computed-goto dispatch in `cn_vm_execute`: +0.5%, i.e. nothing.** Predicted 5
to 20%. The VM is deliberately memory-latency-bound, 51 to 63% of its work
being scratchpad operations in a dependent chase, so interpreter dispatch work
hides behind the stalls. Do not retry dispatch-level optimization. This miss
stands as a caveat on estimates made here.

## Next stages

1. **Non-temporal stores.** The fill writes 8 MB it never reads first, so
   `movntdq` skips read-for-ownership. The large-page half of this stage needs
   nothing: master already warns on the fallback and ships
   `nervad --setup-large-pages`. Checked, after briefly proposing to build it
   again.
2. **Eight-lane AVX2 HC-128 salt.** The big one, and it applies to **both v13
   and v8**, since both call `get_cna_v6_data`. The salt is roughly 40% of a
   nonce here. HC-128's update is elementwise on 32-bit words, so 8 salts fill
   8 lanes of a ymm register. Known trap already answered in the source report:
   `vpgatherdd` was measured and rejected at 32.9K cycles, use scalar extracts.
3. **K-way nonce interleaving of the VM.** K nonces per thread in lockstep so K
   scratchpad loads are in flight, aimed at the dependent pointer chase that
   computed-goto could not touch.

**Deliberately out of scope: the v6 nonce screening.** It exploits a trace
degeneracy specific to v6, and a 3x screening edge is a weapon. Unpublished it
creates exactly the unfairness this effort exists to remove; published it harms
a live chain that is being replaced anyway.

## Feeding back into v8

- **Stage 0 has no v8 counterpart.** v8 has no second full-pad salt pass to
  fold: the sweep deferral already removed that class of work. Checked, not
  assumed.
- **Stage 2 applies to v8 unchanged**, because `get_cna_v6_data` is shared. If
  an eight-lane salt is worth what the source report claims, it is an
  optimization an outside miner can also make on v8, and that argues for
  either doing it in-tree or changing the salt so it does not vectorize.

## Stage 3: nonce screening

Built deliberately, as defensive research. The weapon is already in use by at
least one miner on a live chain, so the asymmetry exists whether or not we
understand it; what is optional is whether the people designing the successor
understand it as well as the person exploiting it. v13 is being retired, so what
is learned here is worth more than what is lost.

### The mechanism, in one line

The VM program seed is `blob_hash XOR salt[0..32)`, and `salt[0..32)` is written
by **one of the salt's 4096 loop iterations**. A miner can therefore know what a
nonce will cost for about 1/4096 of a salt plus a walk of the program with no
registers, no memory and no pad.

### What was built

- `cn_vm_screen_cost` in [cna-vm.c](../../src/crypto/cna-vm.c): generate lazily,
  walk 512 steps assuming every `CN_OP_CBRANCH` taken, count scratchpad ops.
  Slots come off a sequential HC-128 stream so they cannot be random-accessed;
  lazy means generating in order only as far as the walk reaches, which is about
  67 of 512 slots.
- `get_cna_v6_seed` on the DB: the first 64 bytes of the salt only.
- `--mining-screen-threshold N` on the daemon, default 0 (off).

**The safety property is structural, not empirical.** Screening decides *which*
nonces are hashed, never *how* one is hashed. The verification path never calls
it. A block found this way is an ordinary valid block, and a miner may try
whatever nonces it likes.

### Verification

- The lazy screen matches a full-generation reference walk over 2000 programs.
- Extracting `cn_vm_gen_slot` out of `cn_vm_generate_program` to enable lazy
  generation changed nothing: 2000 v13 digests identical. The draw order is the
  generator's definition and a refactor near it has to be proven inert.

### Standalone measurement, and why it is an upper bound

[t_v13_screenmine.c](t_v13_screenmine.c) records the estimate and the real
measured hash time for each nonce, then sweeps the threshold over the recorded
pairs, so nothing is assumed about how estimate and cost relate.

```
screen         17.9 us      full salt   1356.9 us
estimate       min 4  p50 287  p99 396  max 418

  accept   thr    n    mean hash   effective H/s   vs unscreened
      1%    14    6      5.04 ms       126.8 H/s        3.82x
      2%    37   10      5.50 ms       129.0 H/s        3.88x
      5%   130   25      7.50 ms       108.5 H/s        3.27x
     10%   200   50     12.78 ms        69.9 H/s        2.10x
    100%   418  500     28.75 ms        33.2 H/s        1.00x
```

3.8x brackets the published 3.06x. **It is not yet believed.** This harness
reports 30.1 ms per nonce single-threaded while the daemon does 16.9 ms per
nonce per thread with twelve threads running, and one thread cannot be slower
than one of twelve. Most likely the synthetic 236 MB cache evicts the pad harder
than the real block cache does, which would inflate both the mean and the spread
the screen feeds on. The daemon sweep settles it.

## Lessons for v8

The point of the v6 work. Written as rules, so a future change to v8 can be
checked against them without re-deriving the attack each time.

### 1. Anything that determines a nonce's cost must not be computable more cheaply than the nonce

This is the governing rule, and v6 breaks it in one line. The VM program seed is
`blob_hash XOR salt[0..32)`, and `salt[0..32)` falls out of **one of the salt's
4096 loop iterations**. So a miner can learn what a nonce will cost for about
1/4096 of the salt plus a register-free walk, measured here at **17.9 us**
against a nonce costing milliseconds. That ratio is the entire break.

**v8 already satisfies the rule**, by construction rather than by accident:
`get_cna_v6_data` reseeds its HC-128 state 256 times from bytes it has already
written, so the keystream cannot be fast-forwarded, and `xx`, `yy` and
`init_size_blk` are drawn only afterwards. The cheapest possible oracle costs a
full fill.

**What to check on any future v8 change:** if a per-nonce parameter moves
earlier in the pipeline, or if any value that influences cost becomes derivable
from a prefix of the fill, this rule is broken and the screening attack returns.
The draw ordering is load-bearing and should be commented as such where it is
written, not only here.

### 2. Cost that varies is only safe while it is unpredictable, so prefer cost that does not vary

v6's spread is enormous: the cheap estimate ranges 4 to 418 scratchpad
operations per pass across 500 nonces, and the cheapest 1% hash about 5.7x
faster than the mean. v8 narrows this by pinning `init_size_blk` (F42: that one
axis alone was worth up to 2.24x in time and bought nothing), but `xx` and `yy`
still vary cost by F42's measured 3.7x.

That is currently safe only because of rule 1. **Two defences are better than
one**, and narrowing the spread costs nothing in fairness: a PoW where every
nonce costs the same is strictly easier to reason about, and difficulty then
means what it is assumed to mean.

### 3. Evaluate a defence against an optimised miner, not a stock one

FINDINGS F6b modelled v6 screening at 1.3 to 1.4x; the published miner
attributes 3.06x to it. **Both can be right.** Screening removes a share of the
part of a nonce that varies, so the more the fixed parts have been optimised
away, the larger that share becomes and the more screening is worth.

A design gate run against a stock baseline therefore **systematically
understates** every attack of this shape. v8's gates should be re-run against
the fastest implementation we know how to build, which after this project is a
better implementation than when they were first run.

### 4. Shipping an optimisation is a defensive act

The gap that matters is not between our miner and the theoretical maximum, it
is between a stock miner and a tuned one. Every optimisation that lands in the
stock miner is one nobody can hold privately. This is the whole logic of the
project, and it has a concrete instance: the run-ahead salt is worth +7.6% here
and would be worth far more on v8, because v8's fill is a much larger share of
its nonce.

### 5. Proportions do not transfer between implementations

The salt is **19% of a v13 nonce** and about **55% of a v8 nonce**, because
v8's pad is 1 MB against v13's 8 MB so everything else shrank around it. The
same salt change is therefore worth roughly four times more on v8 than on v13.

The published report orders its work with the salt first because on **its**
pipeline the salt was 59.5% of a nonce. Our stage order should follow our own
profile, and v8's order should follow v8's. Twice now a figure taken from one
context and applied to another has produced a wrong prediction here.

### 6. What dies with the VM, and what does not

Of the published 13.4x on v6, the progression attributes 1.96x to engineering
and the rest to screening (3.06x), trace JIT (1.48x) and virtual pad (1.51x).
**All three of the large multipliers are VM properties and v8 has no VM.** The
GPU hybrid likewise hunts "the ~1 in 950 whose VM never touches the pad", and
v8 has no such nonce: both AES passes and every sweep touch the whole pad on
every nonce.

So v8's exposure to that toolkit is roughly the 1.4x of engineering, which rule
4 says to ship ourselves. **The residual is not screening at all**: it is GPU
offload of the fill, which does not predict cost but pays it elsewhere, so the
draw ordering does nothing against it. See F43, and note `CN_SALT_MEMORY` is
load-bearing there and is not documented as such.

## Environment traps

- **The build must run inside MSYS2 bash.** In Git for Windows bash, `make`
  hands recipes to Git's `sh`, which cannot create a temp file, and CMake's
  `forbid_undefined_symbols()` probe fails first, so the build dies at
  `Undefined symbols test failure` as though the code were broken.
  `MINGW_PREFIX` is also unset there, so `MSYS2_FOLDER` resolves to
  `C:/Program Files/Git`. Wrap it:
  `MSYSTEM=MINGW64 CHERE_INVOKING=1 /c/msys64/usr/bin/bash.exe -lc 'cd ... && make release-static-win64 -j4'`.
- **The `--start-mining` command-line flag silently does not start the miner.**
  The `start_mining` RPC does, and returns a status that can be checked.
- **Never redirect the daemon's stdout.** It reads EOF on stdin and exits
  immediately, which looks exactly like a crash.
- **The version banner does not distinguish builds.** It is stamped from the
  git hash, so a tree with uncommitted changes reports the last commit. Go by
  file, and check the two binaries differ before trusting an A/B.
- **Standalone harnesses need the MinGW DLLs on PATH** or they exit 127, and a
  script parsing their output silently sees empty readings.
- **Bash heredocs mangle backslashes inside string literals.** Write C and
  Python with a file-writing tool, not inline heredocs.
- **In PowerShell, anything written to the output stream inside a function
  becomes part of its return value.** Use `Write-Host` for progress, or the
  caller gets an array and the arithmetic fails.
