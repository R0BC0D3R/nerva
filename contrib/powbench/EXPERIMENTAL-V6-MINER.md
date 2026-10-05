# Experimental v6 miner build

A faster solo miner for Nerva's current proof of work (v13, CryptoNight-Adaptive
v6). On a 16-core Ryzen 9 7950X it finds blocks about **5.3x faster** than the
stock daemon.

This is a research build on a personal branch. It is **not an official Nerva
release**, it is not endorsed by the project, and it is not proposed for merge.

## Why it exists

Someone is already mining v6 with optimizations like these. That is a private
advantage over everyone else, and it is not something anyone can take away by
asking. So the optimizations were rebuilt in the open, measured, and published,
which removes the advantage by making it available to anybody who wants it.

The real purpose is the next algorithm. v6 retires at HF14 and everything
learned here is being used to make CNA v8 harder to optimize, so the same gap
does not open again after the fork. The findings are written up in
[V6-MINER-LOG.md](V6-MINER-LOG.md).

Being honest about what this does and does not do: if a large share of the
network runs it, difficulty rises and rewards normalize. **It does not make
everyone earn more.** It removes an advantage rather than creating one.

## Is it safe to mine with

The blocks it finds are ordinary valid blocks, and it has been checked rather
than assumed:

- **It self-tests at startup.** The daemon runs known-answer vectors for every
  hash version before it will mine, and **refuses to start** if the build does
  not compute the same hashes as the network. A build that would mine invalid
  blocks does not run at all.
- **The hash is bit-identical to stock.** The two switches that change how a
  nonce is hashed were verified against the unmodified code over thousands of
  digests, on both the hardware-AES and software-AES paths.
- **It was run on mainnet overnight.** 13 blocks found, 13 credited, none
  rejected or orphaned.
- **Every switch is off by default.** Without flags, this daemon behaves exactly
  like a stock one.

What it changes is *which* nonces are tried and *how* the hash is computed
internally, never what counts as a valid block.

## Getting a binary

Every push to `perf/v13-fused-pad-init` cross-builds **14 targets** through the
`depends` workflow: Windows x64 and x32, Linux x86_64 and i686 (glibc and musl),
macOS x64 and arm64, FreeBSD x86_64, Android arm64, and ARM v7 and v8. It can
also be run on demand from the Actions tab with "Run workflow", which works on
any branch.

**From Actions artifacts.** Actions tab, newest `depends` run on branch
`perf/v13-fused-pad-init`, then the artifact for your platform. **GitHub
requires a signed-in account to download workflow artifacts**, and they expire
after a while. A free account is enough.

**Building it yourself** trusts nobody, and is the better option if you would
rather not download a binary from a stranger's branch. It builds exactly like
upstream Nerva; see [../../docs/BUILDING.md](../../docs/BUILDING.md).

```
git clone https://github.com/R0BC0D3R/nerva
cd nerva
git checkout perf/v13-fused-pad-init
make release
```

### If you would rather publish a pre-release

Not the plan, kept because it is the only way to hand binaries to someone
without a GitHub account. After a `depends` run finishes:

```
gh run download <run-id> --dir dist
gh release create v6-exp-$(date +%Y%m%d) dist/*/*    --repo R0BC0D3R/nerva    --target perf/v13-fused-pad-init    --prerelease    --title "Experimental v6 miner"    --notes "Research build, not an official Nerva release. See contrib/powbench/EXPERIMENTAL-V6-MINER.md"
```

Marking it a pre-release keeps it out of the "latest release" slot, which
matters because this is not one.

## Running it

Replace your `nervad` with this one and add the flags:

```
nervad --mining-screen-threshold 4 \
       --mining-screen-batch \
       --mining-recompute-final \
       --mining-nontemporal-fill \
       --mining-affinity
```

Then start mining as usual, or add `--start-mining <your address> --mining-threads N`.

Through NervaOne, put the flags in the additional-arguments box and set threads
in the UI. **Check the daemon log says the thread count you expect**: a stale
`--mining-threads` can leave the UI showing one number while the daemon runs
another. The line to look for is `Mining has started with N threads`, and it is
always the truth.

### What each flag does

| flag | effect |
|---|---|
| `--mining-screen-threshold N` | Skips nonces predicted to be expensive before hashing them. **This is where most of the speedup comes from.** 0 disables it. |
| `--mining-screen-batch` | Screens eight nonces at a time using vector registers. |
| `--mining-recompute-final` | Regenerates pad blocks in the final pass instead of reading them from memory. |
| `--mining-nontemporal-fill` | Streams the pad fill past the caches. |
| `--mining-affinity` | Pins one mining thread per physical core. Matters most below the logical CPU count. |

### Tuning

**Sweep the threshold on your own machine.** The best value is a property of
your CPU, not of the algorithm. It was 4 on a 7950X and 14 on an i7-7700HQ.
Try 2, 4, 6, 8, 14 and 20 and keep the best. Too tight and you reject so many
candidates that screening them costs more than hashing; too loose and you hash
expensive nonces.

**Thread count scales linearly up to your physical core count**, then much more
slowly. On a 16-core/32-thread 7950X: 16 threads gave 2277 H/s and 30 gave
3149, so each thread past 16 was worth about 44% of a real core. More threads is
still more hashrate, just with diminishing returns, and on a machine you also
use for other things there is little reason to go far past the core count.

**Memory.** Each thread needs an 8 MB scratchpad, so 16 threads needs 128 MB
plus the daemon's usual footprint. Large pages help; the daemon logs
`Mining scratchpads on huge pages` when it gets them.

### Checking it is working

```
--log-level "*:WARNING,user:INFO,global:INFO,miner.screen:INFO"
```

That prints the active options at startup and an acceptance line while mining:

```
v13 miner options: screen threshold 4 (batched), final pass recomputed, fill stores non-temporal
screen: 4641 hashed, 1111334 skipped, acceptance 0.41%
```

An acceptance figure near 0.4% at threshold 4 is normal. The reported hashrate
counts nonces actually hashed, and it is directly comparable to a stock miner's:
each hashed nonce is one independent chance at a block either way.

## Expected results

```
Ryzen 9 7950X, 16C/32T, 30 threads    597.6 -> 3148.6 H/s     5.27x
same machine, 16 threads                        2277 H/s
Intel i7-7700HQ, 4C/8T, 8 threads      93.0 ->  413.5 H/s     4.45x
```

The laptop figure predates the two newest switches and is probably low now.

Your mileage will vary with core count, cache size and memory speed. The
screening speedup is the largest part and is fairly portable; the memory-related
switches depend on how your cache compares to 8 MB per thread.

## Limitations and known issues

- **v6 only.** These flags do nothing after HF14 at block 4,500,000, when the
  chain moves to CNA v8. This build is useful for roughly the remaining life of
  v6.
- **Solo mining only**, which is a property of v6 itself rather than this build.
- **Not audited by the Nerva project.** It is a personal branch.
- The miner reports the page tier for thread 0 only, so a per-thread fallback to
  small pages would not show up in the log.

## Reporting problems

Open an issue on the fork, not on nerva-project. Include the `v13 miner options`
line, your thread count, and the `screen:` acceptance line if you have it.
