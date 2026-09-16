# QI-Fingerprint

One run, on a synthetic 70-key / 409-signature corpus with the labels hidden:

```
$ docker compose run --rm pipeline sh -c \
    "qi generate --out data/demo --seed 7 && qi run --corpus data/demo --truth"

wrote 70 keys / 409 signatures -> data/demo
screened 70 keys / 409 signatures; r-collisions=43
cracked 6; diagnosed 6; attributed 14
attributed by class:
  short_period_prng: 6
  weak_seed: 6
  truncated_msb: 1
  modular_reduction: 1
accuracy vs ground truth:
  diagnosis    6/6  (100%)
  attribution  14/14  (100%)
  per class    short_period_prng 1/1  weak_seed 3/3  truncated_msb 1/1  modular_reduction 1/1
```

**6 keys cracked → 14 keys attributed, 100% correct, zero clean keys touched.** Every
recovery is gated on `d·G == Q`, so a listed crack is a proof, not a guess. Every
claim below has a repro command next to it.

## What it does

QI-Fingerprint triages an *unlabeled* corpus of ECDSA signatures to answer which
nonce-generation bug is leaking private keys and which other keys share it. It runs
four stages — Screen, Crack, Fingerprint, Propagate — and recovers the key only
when `d·G == Q` holds, so a silent mis-scaled lattice can never emit a wrong answer.
It is validated on **synthetic corpora only**, and ships with adversarial self-audits
that quantify exactly where it works and where it doesn't.

## The four-stage pipeline (two lanes)

```
 Screen ─────────► Crack ─────────► Fingerprint ─────► Propagate
 r-collision       │                reconstruct k,     attribute the
 population stats,  │                classify the       diagnosis across
 cohorts, crack     │                root-cause bug     the cohort
 queue              │
                    ├─ MSB-bias lane      truncated_msb, modular_reduction
                    │                     → HNP lattice (LLL / BKZ)
                    │
                    ├─ repeat lane        short_period_prng → nonce-reuse recovery
                    │                     weak_seed         → seed brute-force
                    │
                    └─ chain lane         any recovered key → its shared-nonce
                       (opt-in, --chain)  neighbours, cascading (§8)
```

The **MSB-bias lane** solves the Hidden Number Problem by lattice reduction on keys
that carry enough biased signatures. The **repeat lane** never touches the lattice:
short-period pools force exact nonce reuse (recovered algebraically from one
r-collision), and weak seeds are brute-forced over a tiny seed space. The **chain
lane** takes any key the other two recovered and walks the cross-key r-collisions
outward from it — two keys sharing a nonce is unsolvable alone, but not once
either end is known. A fifth class, `related_nonce` (linear recurrence
`k_{i+1}=a·k_i+c mod n`), fits **none** of the lanes — it is a documented blind
spot (see Limitations).

## Evidence

### 1 · Stage 3 classifies from nonce data, not the recovery method

Strict mode masks `cracked_by` and generation order, classifying from reconstructed
nonces alone. Per-class accuracy vs truth (20 keys/class):

| class | default | strict |
|---|---|---|
| truncated_msb | 100% | 100% |
| modular_reduction | 100% | 100% |
| short_period_prng | 100% | 100% |
| **weak_seed** | **100%** | **0%** → all collapse to `clean` |
| clean | 100% | 100% |

Only `weak_seed` was method-carried — a single weak-seed key's own nonces are
full-range and distinct, information-theoretically identical to clean. The three
data-driven detections (truncated_msb, modular_reduction, short_period_prng)
survive masking; `clean` is a fallthrough, not a detection.

```
docker compose run --rm pipeline python tools/audit_stage3.py
```

### 2 · Stage 4 attribution never reads ground truth

Running the whole pipeline on the **public-only** corpus (`generator_id`,
`bias_type`, `d`, `true_k`, `gen_index` all stripped) is **byte-identical** to the
with-truth run: `cohorts=True  attributions=True`. Cohort membership comes purely
from shared `r` values — e.g. keys `[52,53,54,55,56,57]` are linked by 6 shared
r-values — and **4/4 observable cohorts are single-generator**. Propagation is
**8/8 = 100%** on the keys it labels.

```
docker compose run --rm pipeline python tools/audit_propagate.py
```

### 3 · Few-signature siblings cannot be linked observably (negative result)

A 4-signature sibling is uncrackable, so its nonces are unavailable; the only public
nonce-derived quantity is `r`, which the curve scrambles. Separation of biased vs
clean, Cohen's d:

| feature | observable (on `r`, no `d`) | oracle (on reconstructed `k`, needs `d`) |
|---|---|---|
| bias_magnitude | **+0.09** | +3.90 |
| range_ratio | −0.09 | −0.62 |
| spectral peak | −0.15 | +2.38 |

Observable PR precision is pinned at the 0.667 base rate (no usable threshold); the
oracle reaches precision 0.99 at recall 1.00. The barrier is nonce reconstruction,
not the features — so the siblings stay **unattributed** rather than guessed.

```
docker compose run --rm pipeline python tools/audit_sibling_linkage.py
```

### 4 · A KS test beats the original MSB classifier (why the `min_lz` gate was removed)

Binary MSB-bias detection on identical reconstructed nonces (228 keys), simple tests
at their max-F1 threshold:

| classifier | precision | recall | F1 | ROC-AUC |
|---|---|---|---|---|
| **ks_msb** | 0.97 | 1.00 | **0.99** | 0.998 |
| fft_peak_floor | 0.96 | 0.88 | 0.92 | 0.967 |
| chi2_msb | 0.77 | 0.99 | 0.87 | 0.929 |
| original model (`min_lz≥4 & bias_mag>0.3`) | 1.00 | 0.56 | **0.71** | — |

The original model's `min_leading_zero_bits ≥ 4` gate was structurally blind to
sub-4-bit bias (recall **0.00** on truncated B=1/2/3), while the KS test catches
down to 1 dead bit at 100% recall. The gate was removed and the MSB branch replaced
with `ks_stat ≥ max(0.5, 1.63/√N)`. `chi2` false-positives 89% on short-period pools,
so it was not adopted.

```
docker compose run --rm pipeline python tools/benchmark_msb_tests.py
```

### 5 · Stage 1 operating window (birthday physics confirmed, prediction refuted)

Sweeping effective entropy `e` × pooled signatures `N`, the r-collision screen's
detection edge sits **exactly on the birthday line** `N ≈ 2^(e/2)` (e=40 crosses 50%
at 2^20.2 vs predicted 2^20.0). But within a 2^24-signature budget the usable window
is ~`(26, 48]`, reliable only to ~40 — **not** the predicted 40–60. Reaching e=60
needs 2^30 pooled signatures (64× the budget); the upper edge is set by the signature
budget, not entropy.

```
# writes tools/stage1_operating_window.png
docker compose run --rm pipeline python tools/stage1_operating_window.py
```

### 6 · `related_nonce` is a genuine blind spot (measured, not assumed)

The ePrint 2023/305 recurrence `k_{i+1}=a·k_i+c mod n` (secret `a`) produces
full-range, distinct nonces. It lands in **`clean` in both default and strict mode**
(150/150). Lag-1 autocorrelation does **not** separate it from clean: Cohen's
d = **−0.10**. An LCG's lag-1 correlation ~`1/a` is only visible for a tiny
multiplier (a≈2² → d=0.86; gone by a≈2⁴), so a secret ~256-bit `a` is invisible.
Recovering it needs the algebraic recurrence attack, not a statistical feature.

```
docker compose run --rm pipeline python tools/audit_related_nonce.py
```

## Limitations

- **`weak_seed` is not nonce-fingerprintable.** A single weak-seed key's nonces are
  full-range and distinct (§1: strict accuracy 0%). Its label is carried entirely by
  a successful small-seed brute force; without that method signal it is
  indistinguishable from clean.
- **Truncated/modular siblings can't be linked observably.** Few-signature siblings
  are uncrackable and carry no observable bias signal (§3: Cohen's d ≤ 0.15 on `r`).
  Grouping them would require reading `generator_id` (ground truth), so they are left
  unattributed.
- **The operating window is bounded by entropy and signature budget.** The
  r-collision screen only fires when `N ≳ 2^(e/2)` (§5), so high-entropy weak
  generators are invisible unless you can pool an infeasible number of signatures.
- **`related_nonce` is undetectable and uncrackable** by every current stage (§6).
- **Classification accuracy is measured on synthetic data only.** The pipeline now
  runs on real Bitcoin (§7), and the *recovery* path is validated against a real
  reused-nonce key. But every diagnosis and attribution number above (§1, §2, §6)
  comes from a corpus the generator made, because scoring a label needs a ground
  truth real data does not have. No real key has yet been fingerprinted: the one
  recovered from mainnet carries two signatures, far too few to classify.
- **Real coverage is P2PKH, P2PK and SegWit v0 P2WPKH** (native and P2SH-wrapped).
  Measured on block 800,000 (4,911 non-coinbase inputs, 89.9% carrying a witness),
  the prevout-free hunt now sees **1,546 inputs (31.5%)**, up from 488 (9.9%) when
  witnesses were skipped outright. So roughly two thirds of a modern block is
  still invisible: P2WSH, bare multisig and P2SH-of-anything-else present a
  different shape and are counted, not guessed at. Taproot is out permanently —
  it is Schnorr, so there is no `(r, s)` to collect at all.
- **P2PK can be ingested but not hunted.** Its public key lives in the output
  being spent, and the cheap scan deliberately never fetches prevouts. That is a
  property of the input, not a gap in the scanner.

### 7 · The pipeline runs on real Bitcoin, and a positive control proves it fires

Real mainnet blocks now ingest into the same `Corpus` the generator produces.
There is no ground truth on real data, so the gate is `ecdsa_verify`: if our
reconstructed sighash `z` is the value the signer committed to, the on-chain
signature verifies against it. A record that fails is dropped; a run below
threshold writes nothing.

```
blocks 250000..250001  (284 txs, 818 inputs)
  verified 813/813 (100.0000%)
    p2pkh/legacy/ht=0x01    813/813  100.000%
  skipped: unsupported_type:p2pk 3, coinbase 2
  corpus: 813 signatures over 461 keys   ·   low-s 51.3%
```

Re-running from cache performs zero network I/O and produces byte-identical
parquets. `qi run` on that corpus reports **0 r-collisions, 0 cracked** — a clean
range, and **zero false positives on 461 real keys**.

A clean result only means something if the pipeline can be shown to fire, so:

```
scanned 1,026 blocks / 719,121 signatures   (Aug 2013)
  same-key  r-collisions : 1
  cross-key r-collisions : 1   (two keys, one nonce -- not recoverable)

  RECOVERED (d·G == Q)   19qnLpn9it7csR9sEay1XrFyfAmUNoXYk4
  f92d4310ccc12bc41d2e51ab17b80c942a9343fce7a63a41e3d2db646fe05661:0 and :1
  block 252,474 · 2013-08-16 · five days after the Android SecureRandom advisory
```

One transaction, two inputs, one nonce. The key is pinned as a permanent
regression fixture (`tests/fixtures_control.py`) and recovered offline on every
test run. It was **discovered by scanning, not looked up** — which is the point:
a control taken on faith is not a control.

**Safety.** Recovered keys in this range may control real funds. The tools
recover, verify against the on-chain public key, and report a count — never a
scalar. Three things are asserted rather than promised:

- `d` is a local that dies with the function. `Confirmation` has no field for it,
  so there is nowhere for it to be carried out to; tests search the rendered
  report and the pinned fixture for the actual recovered key and require its
  absence. Ingested corpora write no ground-truth column, and the site exporter
  omits the key field for any corpus without one.
- **Nothing can be published.** Broadcasting needs a request with a body; a test
  walks the syntax tree of every module and requires each HTTP call site to be a
  bodyless GET. Verification is `d·G == Q`, arithmetic on data already held — no
  balance is ever queried.
- Reporting a vulnerable key to its owner is a disclosure question, not a data
  one, and is out of scope here.

### 8 · One recovered key cascades into its cohort (`--chain`)

Two *different* keys sharing a nonce is two equations in three unknowns — no
recovery from the pair alone. But it collapses the instant either end is known:

```
key A known:   k   = s_A⁻¹ (h_A + r·d_A)      exact, from A's own equation
key B, same r: d_B = (s_B·k' − h_B)·r⁻¹        k' ∈ {k, n−k}, decided by d_B·G == Q_B
```

`d_B` then opens *its* edges, breadth-first, every hop gated by `d·G == Q`. Both
signs must be tried: BIP146 may have normalised one signature and not the other,
and across two keys — plausibly different software, different eras — that is a
coin flip. Trying only `+k` recovers nothing and looks exactly like an empty range.

On the standard synthetic corpus (seed 7), against the same run without the flag:

| | cracked | diagnosed | attribution |
|---|---|---|---|
| `qi run` | 6 | 6/6 = 100% | 14/14 = 100% |
| `qi run --chain` | **14** | 7/7 = 100% | 14/14 = 100% |

Recovery more than doubles at no cost to accuracy. The gap between 14 recovered
and 7 diagnosed is the honest part: **recovering a key is not the same as being
able to fingerprint it.** Seven of the chained keys carry two to six signatures
against a period of six, so their own nonces show zero collisions and a distinct
ratio of 1.00 — `clean` would be a fallthrough, not a finding. Those keys keep
their cohort attribution instead, and the run says so:

```
chain    : 8 recovered (depth 1, 1, 1, 1, 1, 1, 1, 1)
  key 53 via key 52 (depth 1, r=d299e9e551b70f02..)
  ...
  7 recovered but not self-diagnosable (too few nonces); labelled from their cohort
```

The scan side changed to match: cross-key r-collisions used to be counted and
discarded, which left a collision nobody could point at. `ReuseIndex` now retains
the pair — for less memory than the tally cost, since it stores a reference to a
`SigSite` it already holds instead of a fresh tuple.

**Opt-in on purpose.** On a real corpus every hop is a live mainnet spending key,
so cascading is a deliberate act; without the flag the run still reports how many
edges it declined to walk.

```
docker compose run --rm pipeline qi run --corpus data/demo --truth --chain
```

### 9 · A wider net: SegWit coverage and an index that fits

Two limits were structural rather than incidental, and both are measured.

**The hunt was blind to SegWit for no reason.** It computes no sighash — it needs
only `r` and the public key — so a witness input never required BIP143 to be
*found*, only to be *confirmed*. A P2WPKH witness is literally
`[<DER sig>, <pubkey>]`, the same two elements a P2PKH scriptSig pushes. On block
800,000:

| | inputs seen | of 4,911 |
|---|---|---|
| legacy only (before) | 488 | 9.9% |
| + P2WPKH (now) | **1,546** | **31.5%** |

Confirmation then needs the amount, because BIP143 commits to the value of the
output being spent — which `EsploraSource` was already fetching and discarding.
Pinned mainnet known-answer tests cover native P2WPKH, P2SH-wrapped P2WPKH and
P2PK; each is paired with a perturbation that must break it, including a
one-satoshi amount error, so the oracle is not vacuous.

**The in-memory index could not reach the range it was hunting in.** Measured on
the real structure, `ReuseIndex` costs ~682 B per signature:

| layout | B/site | 719k sigs | ~14M sigs (20k blocks) |
|---|---|---|---|
| dataclass + str txid | 682 | 490 MB | **9.55 GB** |
| + `slots=True` | 639 | 459 MB | 8.95 GB |
| numpy record (`rindex.py`) | **24** | **17 MB** | **0.34 GB** |

`slots` buys 6%; the fixed-width record buys 28×. The record stores the top 64
bits of `r`, no txid at all — a site is named by `(height, site_idx)` and
recovered by re-running the pure `scan_block` over a refetched block. **The
prefix is a filter, not a finding:** every hit is re-derived at full 256-bit
width before anything is reported, so the expected 5×10⁻⁶ spurious matches at 14M
signatures cost two block fetches rather than a wrong answer.

The file doubles as the checkpoint. A killed scan resumes from its sidecar and
produces a **byte-identical index** to an uninterrupted run, which is what makes
a multi-day scan survivable at all.

```
docker compose run --rm pipeline python tools/find_reuse.py \
    --start 240000 --end 260000 --index data/hunt.idx --cache-raw --resume
```

## Related work

Most of the lineage below is real-target key *recovery* from a specific leakage
source; QI-Fingerprint sits one layer up — inferring the root-cause bug and
attributing it across a cohort from reconstructed nonces alone, and only on
synthetic data. Two entries sit closer and are called out as such: a feasibility
model our recovery threshold rests on, and a real-world study that did the same
attribution with vendor firmware.

- **Breitner & Heninger, FC 2019 ("Biased Nonce Sense").** Scanned real
  cryptocurrency blockchains and recovered keys from biased/reused nonces with HNP
  lattices. That is the real-corpus validation QI-Fingerprint lacks; its Stage-2
  lattice is the same HNP tool. What is added here — "which bug, and which sibling
  keys" — is demonstrated only synthetically.
- **Minerva (2020)** and **TPM-Fail (2020).** Both *discover* nonce bias through a
  timing side-channel (nonce bit-length / leaked MSBs) and then lattice it.
  QI-Fingerprint does no side-channel measurement; it assumes the bias is already in
  the signatures and asks what *kind* it is.
- **LadderLeak (2020).** Recovered keys from <1 bit of nonce leakage via a
  Bleichenbacher/FFT amplification over ~2⁴⁰ signatures. QI-Fingerprint uses the
  Bleichenbacher spectrum only as a classification *feature*; its lattice lane needs
  several bits, and its Stage-1 study maps where the far cheaper r-collision screen
  fires instead.
- **Cisco ASA entropy failures (ePrint 2023/912) — the nearest neighbour.** Traced
  real ECDSA key/nonce collisions in deployed Cisco ASA devices to flawed DRBG
  plumbing, doing genuine root-cause attribution via certificate-scale statistics
  *plus firmware analysis*. The distinction is narrow and worth stating plainly:
  their root cause came from **reading the vendor firmware**; QI-Fingerprint infers
  it from **reconstructed nonces alone, with no vendor access**. Attribution without
  ground truth is the whole bet — which is exactly why the audits above exist.
- **"Estimating the Effectiveness of Lattice Attacks" (ePrint 2021/1489) —
  complementary, not competing.** A feasibility model relating key size, leakage
  bits and BKZ behaviour to whether an HNP recovery will succeed. It takes leakage
  strength as an *input* and predicts success; it does not find biased keys. It
  answers "will recovery work at this bias?" while QI-Fingerprint asks "which keys
  are biased, and why" — and it is the proper basis for the recovery threshold
  Stage 2 assumes when it decides a key has enough biased signatures to lattice.

## Run it

Everything runs in a Linux container (fpylll/fastecdsa have no usable native-Windows
build):

```
docker compose build
# 322 tests; every recovery path asserts d·G == Q
docker compose run --rm pipeline pytest -q
docker compose run --rm pipeline qi run --corpus data/demo --truth
```

The dashboard is the static site in `site/`. Its numbers are pre-computed by the
container, so the site itself needs no Python at run time and ships as plain HTML:

```
# freeze seeds 7/11/23
docker compose run --rm pipeline python tools/export_site_data.py
cd site && npm install
npm run dev                                           # http://localhost:3000
# static export -> site/out/
npm run build
```

Real Bitcoin (read-only; no node required, no new dependencies):

```
# ingest a block range -> the corpus the pipeline already reads
docker compose run --rm pipeline python tools/ingest_bitcoin.py \
    --start 250000 --end 250001 --out data/btc-250000
docker compose run --rm pipeline qi run --corpus data/btc-250000 --canonical-nonces

# hunt a range for nonce reuse, then verify each hit through the full gate
docker compose run --rm pipeline python tools/find_reuse.py --start 252474 --end 252474
```

`--canonical-nonces` folds reconstructed nonces to `min(k, n−k)`. BIP146 low-s
normalisation rewrites `s → n−s`, which is exactly `k → −k`; without the fold,
half a real key's nonces land just below `n` and an MSB bias reads as two clumps
instead of one. The synthetic generator never normalises, so the flag is off by
default and every number above is unaffected.
