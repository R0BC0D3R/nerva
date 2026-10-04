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

### Measured on the daemon: 2.17x

Nine runs, threshold 0 interleaved between every screened run so each one is
compared against its own neighbours. Every run on huge pages, one daemon
enforced, acceptance read back from the daemon's own log.

```
  threshold   acceptance    H/s     local baseline   vs baseline   bracket drift
          0            -    739.1            -             -
         14        1.12%   1392.4          740.0         1.88x           0.3%
         37        2.21%   1605.3          741.1         2.17x           0.1%
        130        3.96%   1397.5          733.1         1.91x           2.1%
        200        9.98%   1098.1          732.4         1.50x           1.9%
```

The five baselines came back 738.8, 741.3, 740.9, 725.3, 739.4, so the machine
was stable throughout and the brackets are tight.

**Peak 2.17x at 2.2% acceptance**, where the estimate's cost and the saving it
buys balance. The curve has a maximum rather than rising forever, because at
tighter thresholds the miner pays `1/q` estimates per accepted nonce: at 1.12%
acceptance the estimate overhead has already pulled the result back down to
1.88x.

**The standalone harness said 3.88x at the same acceptance and was wrong by
1.8x**, exactly as suspected when its single-threaded nonce time came out slower
than the daemon's per-thread time. Its synthetic 236 MB cache evicts the pad
harder than the real block cache does, which inflates both the mean hash time
and the spread the screen feeds on. Recorded because the harness was right about
the shape and wrong about the size, which is the more dangerous kind of wrong.

The published figure for this step is 3.06x. Ours is 2.17x on a less optimised
pipeline, and by rule 3 that is the expected direction: screening removes a
share of what varies, so the less the fixed costs have been cut, the smaller
that share is. Finishing the memory work should move our figure toward his.

### Screening moves the optimal thread count, and that is most of its value

Measured on the offline rig, **a fresh daemon per point on both sides**, every
run on huge pages with no fallback warning.

```
 threads   unscreened    screened   ratio
      12        733.4      1598.8   2.18x
      16        684.6      1706.2   2.49x
      20        641.4      1787.6   2.79x
      24        600.4      1842.7   3.07x
      28        572.7      1860.2   3.25x
      32        564.4      1876.0   3.32x
```

**Unscreened peaks at 12 threads and falls monotonically. Screened climbs all
the way to 32** and is still climbing where the machine runs out of logical
cores.

The mechanism: stock v6 drags an 8 MB pad through the cache hierarchy on every
nonce, so past about twelve threads the extra workers only contend for L3 and
memory bandwidth. At 2.2% acceptance roughly 98% of nonces end at the estimate,
which touches one salt iteration and walks 512 program slots with no registers,
no memory and no pad. Screening converts a bandwidth-bound workload into a
compute-bound one, and compute-bound work scales with cores.

Best against best: **733.4 to 1876.0, 2.56x**, against 2.18x if both are held at
twelve threads. So **roughly a sixth of screening's value is unavailable unless
the thread count is retuned.**

Two independent cross-checks, both clean:

- The 12-thread ratio here is 2.18x; the separate interleaved threshold sweep
  measured 2.17x for the same configuration.
- Live NervaOne on the same machine reported 1.82 to 1.89 kH/s at 24 threads
  and 1.83 to 1.89 at 30; this rig gives 1842.7 at 24 and 1860.2 at 28.

**The rule for v8: measure an attack at the attacker's best configuration, not
the defender's.** An attacker retunes. A design gate that holds thread count
fixed at the stock optimum would have reported 2.18x for an attack worth 2.56x.

#### A method error worth keeping, because it nearly stood

The first version of this sweep changed thread count with
`stop_mining`/`start_mining` inside one daemon, to avoid restart variance. That
introduced a worse bias:

```
unscreened, fresh daemon          709.3 H/s
unscreened, after mining restart  613.1        -13.6%
screened,  fresh daemon          1388.6
screened,  after mining restart  1392.2         -0.3%
```

The penalty lands on pad-heavy work and not on screened work, so the
denominators were depressed and the numerators were not, inflating every ratio.
It also moved the apparent unscreened peak from 12 threads to 16. Both report
huge pages and neither warns, so it is not a page-tier fallback; reallocated
pads simply do not perform like the originals, which is worth knowing
independently.

What exposed it was a 15% disagreement between this sweep's 12-thread baseline
and earlier sweeps' 733 to 739. That gap was within shouting distance of
"drift", and calling it drift would have shipped the wrong table.

**Rule 6: an optimisation to the measurement method is a change that needs
measuring, exactly like a change to the thing being measured.** Removing a
safeguard because it looks unnecessary is the same class of mistake as keeping
a workaround after its cause is gone.

### Early exit in the screen: +21%, mostly by moving the optimum

His section 2 notes "early exit once predicted memops pass the threshold (~40%
fewer slots)". The walk's count only ever rises, so once it passes the caller's
limit the verdict is settled and the rest of the walk, and the lazy slot
generation it drives, is wasted. Rejected nonces are the overwhelming majority,
so that is where the screen's cost lives.

Measured: **screen 11.3 us to 7.9 us, 30% cheaper.**

Verified rather than argued: over 2000 programs, early exit gives the same
accept/reject verdict at every threshold tested and the same exact count
whenever the nonce is accepted.

The throughput gain is larger than the screen saving, because **a cheaper screen
moves the optimum**. Before early exit, tighter thresholds lost on estimate
overhead: threshold 14 scored 1392 against 1599 at threshold 37. After it, the
whole curve shifts left.

Threshold sweep, 30 threads, baseline interleaved between every point:

```
  threshold   acceptance      H/s
          3       0.34%     2274.0
          4       0.41%     2280.2    <- peak
          6       0.56%     2267.4
          8       0.71%     2238.3
         14       1.07%     2137.3
         24       1.63%     2011.7
         37       2.12%     1883.4
         60       2.57%     1774.2
```

**1876 to 2280 H/s, +21%**, from a change that only made the estimate 30%
cheaper. The optimum moved from threshold 37 at 2.1% acceptance to threshold 4
at 0.41%.

The 30-thread cap costs nothing: threshold 8 reads 2238.3 at 30 threads against
2233.8 at 32. The machine is a workstation, not a mining rig, so harnesses are
capped at 30 of 32 logical threads.

#### What this says about where the cost now sits

The curve is flat between thresholds 3 and 6, which means the screen itself has
become the wall. At 0.41% acceptance a miner runs about **244 screens per
accepted nonce**, so at 7.9 us each that is ~1.9 ms of screening against roughly
3 ms for the accepted hash. **Screening is now about 40% of the work.**

That reverses an earlier judgement in this log. When the screen was 5% of the
time, cutting its cost looked worth about 4% and was deprioritised. At 0.41%
acceptance the same work is worth far more, and it compounds, because each
reduction moves the optimum tighter again. The published figures for the screen
path are 43k to 8.6k cycles, about 5x, via four-way AVX2 Keccak, eight-lane
AVX2 HC-128 init, a faster lazy generator and prefetched picks.

**The eight-lane init is already built and verified here at 2.55x**, and
batching the *screen* eight-wide is far less invasive than batching the hash:
the screen is a pure function of the blob and never touches the pad, so the hash
path can stay scalar.

### Eight-wide screening: correct, 2.37x on the part it touches, and worth nothing

A negative result, kept because the reasoning that led to it was sound and the
next person will otherwise redo it.

At 0.41% acceptance the screen is roughly 40% of the work and each screen is two
HC-128 key schedules, so vectorising the schedules looked like the obvious next
move. [hc128-x8.c](../../src/crypto/hc128-x8.c) does eight at a time, in its own
translation unit at AVX2 while the rest of the binary stays at baseline, with a
cpuid plus XGETBV check and a scalar fallback.

**Verified:** bit-identical to eight `HC128_Init` calls over 12,000 schedules,
including the transpose back to ordinary `HC128_State` values and four keystream
blocks drawn from each result. That last part matters: a state can match field
for field and still be unusable if `counter1024` or the keystream buffer is
wrong. **2.37x per schedule**, 1.95 us to 0.83 us.

**Measured on the daemon, threshold 4, 30 threads:**

```
scalar screen                        2280.2 H/s
x8 screen, 64 KB allocated per call  2101.7      -7.8%
x8 screen, thread-local buffer       2260.6      -0.9%
```

So a 2.37x faster key schedule converts to **nothing**. The screen's selection
is provably identical, acceptance reads 0.41% to three digits either way, so
this is not a correctness problem. The transposed per-lane state costs about
what the vectorisation saves: the scalar screen reuses one 4 KB `HC128_State`
that stays hot, while the batched one writes and reads back eight of them twice
per batch, roughly 8 KB per nonce of traffic the scalar path never does.

It is off by default behind `--mining-screen-batch`. Adding it did not cost the
default path anything: A-B-B-A gives pre 2274.7, post 2260.3, delta -0.6%
against a baseline drift of -0.5%, so the difference is not separable from
noise.

**The allocation finding is the useful part.** A 64 KB allocation per call cost
**7% at 30 threads and was invisible single-threaded**, because the
microbenchmark called it in a tight loop where the allocator hands back the same
block every time. A microbenchmark can be correct, repeatable, and still answer
a question nobody asked.

**If it is ever worth revisiting**, the way is the one the published
implementation takes: keep the state lane-interleaved for the whole screen and
run `NextKeys` eight-wide too, so there is no transpose at all. That needs a
per-lane block queue because keystream consumption diverges. The eight-lane init
is also worth far more on **v8**, whose salt is 55% of a nonce against v13's
19%, and there it would serve the salt itself rather than screening, so the
transpose penalty would not land in the same place.

A single run at 8 threads came back +5% for batching, which fits the
cache-pressure explanation, but it was one unrepeated point in an uninterleaved
sequence and 12 threads came back -11% against 30 threads' -0.9%. **Not
believed**, and the flag exists so a low-core machine can be tested properly,
not because it has been shown to help.

### The rig was finding blocks all day

The offline daemon mines against a stale chain copy whose difficulty drifts
down, so it had been finding real blocks: height moved 4424749 to 4424751 over
the day's runs. Each find rebuilds the template and stalls the miner, and it is
what made `start_mining` intermittently return busy.

At roughly a 2% chance per 30-second run the distortion was small, and the drift
gates would have caught a badly affected run, but it was an uncontrolled
variable present in every measurement and it would have grown as difficulty
fell. All harnesses now pass `--fixed-difficulty 100000000`.

**The plan file written at the start of this project said to do exactly that.**
It was not done, and was not noticed for a full day.

### Second machine: an i7-7700HQ laptop, 4 cores, 256 KB L2

Measured live through NervaOne against a synced mainnet node, so a different
CPU, a different generation and a real chain rather than the offline copy.

```
stock v0.3.0.0        2t 47.5   4t 73.0   6t 88.0   7t 93.0
final, threshold 4    2t 144.5  4t 263.5  6t 325.0  7t 373.0   8t 394.0

7 threads, threshold sweep
  thr  0    105.0     (fused pad init + run-ahead salt only)
  thr  2    344.5
  thr  4    373.0
  thr  8    385.5     best of those tested, still rising
  thr  8 + --mining-screen-batch   400.5

8 threads, with --mining-screen-batch
  thr 14    413.5     peak
  thr 24    388.5
```

```
stock, 7 threads                     93.0 H/s
+ fused pad init, run-ahead salt    105.0     1.13x
+ screening (thr 8)                 385.5     4.15x
+ eight-wide screen                 400.5     4.31x
+ thr 14, 8 threads                 413.5     4.45x
```

**The optimum threshold is 14 on the laptop against 4 on the 7950X**, 3.5x
looser, which is the machine dependence the corrected model above predicts: the
screen's four random block-cache reads cost more on a machine with worse latency
and less cache, so screening hard stops paying sooner.

**4.31x on the laptop against 3.82x on the 7950X.** Screening alone is 3.67x
there (105 to 385.5) against 3.11x here.

#### A prediction that was half wrong, and the model it fixes

Written before the data: *the optimum threshold will be tighter than 4 on the
laptop, and screening will be worth more.*

The second half holds. **The first half is wrong: the optimum is looser, 8 or
above.**

The error was treating the screen as pure compute. It is not: the salt prefix
does **four random reads into a 236 MB block cache**, which are DRAM-latency
bound. The laptop has worse latency and far less cache, so the screen is
relatively *more* expensive there, and screening harder stops paying sooner.
The hash's bandwidth sensitivity was modelled correctly and the screen's memory
component was left out of the model entirely.

Consequence worth carrying: **the optimal threshold is a machine property and
has to be swept per machine.** It is not a constant of the algorithm, and the
default in the help text is right only for the machine it was measured on.

#### The eight-wide screen is vindicated on low core counts

`--mining-screen-batch` gives **+3.9%** here (385.5 to 400.5), matching the +5%
at 8 threads measured on the 7950X and dismissed at the time as one
uncontrolled point. Two machines, two generations, same direction.

So the earlier negative result stands as stated but is incomplete: the eight-
wide screen is worth nothing at 30 threads and worth about 4% at 7 to 8. The
transposed per-lane state costs roughly what the vectorisation saves, and which
side wins depends on how much cache pressure the machine is already under. Off
by default remains right for the 7950X and wrong for the laptop, which is what
the flag is for.

### Where this leaves the project

Each row at its own best thread count, which is the only fair way to compare
once the optimum moves:

Each row at its own best configuration, with the thread count stated, because
the optimum moves as the work changes:

```
stock,                     12 threads            597.6 H/s
+ fused pad init,          12 threads              661.0      1.11x
+ run-ahead salt,          12 threads              711.0      1.19x
+ screening (thr 37),      12 threads             1605.3      2.69x
+ retuned,                 32 threads             1876.0      3.14x
+ screen early exit (thr 4), 30 threads           2280.2      3.82x
```

Best unscreened is 733.4 H/s at 12 threads, so screening and its retuning are
worth **3.11x** on their own.

Live through NervaOne on the same machine, 24 to 30 threads: 1.82 to 1.89 kH/s,
which agrees with the rig.

Against the published v6 progression on a comparable machine (his 5900X stock
558 H/s against this 7950X's 597.6), his figure after the same two steps,
memory work and screening, is 976 H/s scaled from a 5600G or about 2233 on the
5900X. The remaining gap is the memory work we have not built, chiefly K-way
nonce interleaving at +23%, plus trace JIT and virtual pad.

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

## Measurement rules

Earned the hard way on this project. Each one is here because ignoring it
produced a confident wrong number.

### Rule 1. When a measurement is invalidated, re-derive everything built on it

Deleting a bad number does not delete what was computed from it. This has now
cost twice in one day:

- A nonce time of 39.6 ms came from a contended run. The run was identified and
  discarded, but the salt's 40% share of a nonce, derived from it, stayed in use
  and produced a prediction of +17% against a measured +7.6%. The true share is
  19%.
- An early daemon appeared to read high and then step down, which was the same
  contention episode. The cause was corrected; the 150-second settle built to
  work around it was not, and silently cost two minutes per run for the rest of
  the day. A calibration run later showed the rate is flat from the first
  sample, 717 to 747 H/s with no trend.

**When a measurement is withdrawn, list what was justified by it and re-check
each one.** The derived belief outlives the number and is harder to see.

### Rule 2. A measurement whose key diagnostic is missing cannot be debugged

The first screening sweep was uninterpretable because the screened-nonce counter
existed but was never logged, so there was no acceptance rate to check the
throughput against. A measurement needs the number being reported *and* the
number that says whether the mechanism did what it claims.

### Rule 3. Measure the settle, do not inherit it

See rule 1. Settle time is a parameter like any other and costs nothing to
calibrate once: one cold run sampled every 10 seconds says what it should be.

### Rule 4. Do not touch the machine during a run, including locking it

Locking a Windows session and unlocking it changes power and scheduling state,
and a run spanning that transition is not comparing like with like. One sweep
here alternated high and low across runs in a way that tracked run order rather
than the parameter being swept, and a lock/unlock during it is the most likely
explanation. The session now stays unlocked for the duration of any
measurement.

### Rule 5. Know the shape the result should have before reading it

Screened throughput is not monotonic in the threshold: a tighter threshold
accepts cheaper nonces but pays the estimate more times per accepted nonce, so
the effective rate has a peak. Calling a non-monotonic result "impossible" was
wrong; what was actually anomalous was one point, not the shape. Predict the
shape first, then the deviations stand out instead of the noise.

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
