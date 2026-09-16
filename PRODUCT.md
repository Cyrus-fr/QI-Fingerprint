# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

**Primary: security researchers and applied cryptographers**, arriving skeptical and
deciding whether the method is real.

They do not read top to bottom. They skim for rigour, pick the one section that would
expose the work if it were shallow, and dig there. What they want before the headline
is the reproduction command, the negative results, and the stated limits. A number
without a way to regenerate it reads as a claim; a blind spot stated plainly reads as
competence.

They already know the domain. Nonce reuse, the Hidden Number Problem, lattice
reduction and `d·G == Q` need no introduction, and explaining them would cost
credibility rather than build it.

## Product Purpose

QI-Fingerprint triages an **unlabeled** corpus of ECDSA signatures to answer two
questions: which nonce-generation bug is leaking private keys, and which other keys
share it. Four stages — Screen → Crack → Fingerprint → Propagate.

**Success is conviction, not adoption.** The win condition is an expert reviewer coming
away satisfied that the work is real, careful, and well beyond tutorial depth. Nobody
needs to run it, cite it, or deploy it for the project to have succeeded. This makes
credibility the deliverable and honesty the strategy: the fastest way to fail is a claim
that does not survive the reviewer checking it.

## Positioning

**The unit of analysis is the population, not the key.**

Recovering one key from a reused nonce is well-trodden. The claim here sits one layer
up: infer the *root-cause generator bug* from reconstructed nonces alone, then attribute
it across a collision-linked cohort — including keys that carry too few signatures to
ever be cracked themselves. A chain lane extends this to recovery, turning one recovered
key into its shared-nonce neighbours.

Two things a neighbouring tool could not truthfully copy without doing the same work:

- **Cohort attribution from public data only.** Membership comes from shared `r` values,
  never from ground truth or vendor metadata, and the keys with no observable link are
  left unlabelled rather than guessed. The refusal is part of the claim.
- **The gate as a design principle.** Every recovery path returns a key only after
  `d·G == Q`, so a mis-scaled lattice fails to recover rather than emitting a wrong
  answer. A listed crack is a proof, not a guess.

## Operating Context

- **Everything runs in a Linux container.** `docker compose run --rm pipeline …` is the
  form every documented command takes.
- **CLI first:** `qi generate`, `qi run --corpus … [--truth] [--strict]
  [--canonical-nonces] [--chain]`. Supporting tools in `tools/` handle real-chain ingest,
  the reuse hunt, the self-audits, and freezing the site's data.
- **The web surface is a static export** (`site/`, Next.js) built from a frozen pipeline
  run. It carries no live compute; the numbers on it were produced by
  `tools/export_site_data.py` and are inlined at build time.
- **How a reviewer evaluates:** read a claim, run the command printed beside it, compare.
  The site is read on a laptop, usually once, often skimmed.
- **Real-chain access is read-only** over the Esplora HTTP API, with a local block cache
  so a published finding can be re-derived offline.

## Capabilities and Constraints

**Confirmed functionality**

- Four stages, three crack lanes: MSB-bias (HNP lattice, LLL/BKZ), repeat (nonce-reuse
  recovery, weak-seed brute force), and chain (cascade across shared-nonce edges,
  opt-in behind `--chain`).
- Five synthetic bias classes: `truncated_msb`, `modular_reduction`, `short_period_prng`,
  `weak_seed`, `clean`.
- Real Bitcoin ingest and a prevout-free reuse hunt with a resumable on-disk r-index.
- 322 tests, all passing.

**Technical constraints**

- **Docker-only.** `fpylll`, `fastecdsa` and `cysignals` have no usable native-Windows
  build, so nothing in the docs runs on the host.
- Real coverage is P2PKH, P2PK and SegWit v0 P2WPKH (native and P2SH-wrapped). Measured
  on block 800,000 that is 1,546 of 4,911 inputs — about two thirds of a modern block
  stays invisible.
- **Taproot is out permanently**, not deferred: it is Schnorr, so there is no `(r, s)`
  pair to collect at all.
- P2PK can be ingested but never hunted — its public key lives in the output being spent,
  which the prevout-free scan deliberately never fetches.
- Blockstream's Esplora rate-limits hard (HTTP 429); mempool.space refused connections
  from the container. A wide scan is rate-limit bound, not compute bound.

**Terminology is fixed by the domain** and is not ours to soften: nonce, r-collision,
cohort, sighash, `d·G == Q`, BIP143, BIP146, low-s.

**Explicitly undecided**

- No licence file exists.
- No deploy target for the site has been chosen; it is served locally.
- Disclosure of a recovered real key to its owner is a disclosure question, not a data
  one, and is deliberately out of scope.

## Brand Commitments

- **Name:** QI-Fingerprint.
- **Voice:** plain, measured, numbers first. Negative results are reported as negative
  results. No hedging and no salesmanship — this audience reads both as weakness.
- **`README.md` is the source of truth for site copy.** `site/content/site-content.ts`
  is transcribed from it; when they disagree, the README wins and the site changes.

## Evidence on Hand

**Real, and available to future work**

- **A genuine mainnet positive control.** A reused-nonce key from block 252,474
  (2013-08-16, five days after the Android `SecureRandom` advisory), **discovered by
  scanning rather than looked up**, recovering with `d·G == Q`. Address
  `19qnLpn9it7csR9sEay1XrFyfAmUNoXYk4`, txid
  `f92d4310ccc12bc41d2e51ab17b80c942a9343fce7a63a41e3d2db646fe05661` inputs 0 and 1.
  Pinned offline at `tests/fixtures_control.py`; recovered on every test run.
- **Hunt totals:** 1,026 blocks / 719,121 signatures / 1 same-key r-collision / 1
  cross-key.
- **Ingest:** 813/813 inputs verified (100%) on blocks 250,000–250,001, byte-identical on
  cache replay; `qi run` on that corpus finds 0 collisions and 0 cracks — zero false
  positives on 461 real keys.
- **Eight adversarial self-audits**, each with the command that reproduces it, in
  `tools/audit_*.py` and `tools/benchmark_msb_tests.py`.
- **Frozen run data** for seeds 7 / 11 / 23 at `site/public/data/run-*.json`, regenerated
  by `tools/export_site_data.py`.
- `tools/stage1_operating_window.png` — the measured operating-window study.

**Absences that future work must not paper over**

- **No users, no adoption, no testimonials, no customers, no press.** Nothing has been
  run by anyone else.
- **No benchmark against another tool.** None was performed.
- **All classification accuracy is synthetic.** Scoring a label needs a ground truth real
  data does not have. This qualifies every accuracy figure on every surface.
- **No real key has been fingerprinted.** The one recovered from mainnet carries two
  signatures — far too few to classify.
- No licence, no deployment, no funding, no institutional affiliation.

## Product Principles

1. **The gate is the product.** Nothing is claimed that `d·G == Q` has not confirmed. A
   wrong hypothesis must fail to recover, never emit a wrong key.
2. **Report the negative result as a result.** For this audience a blind spot stated
   plainly — `related_nonce` is undetectable; `weak_seed` is not nonce-fingerprintable;
   few-signature siblings cannot be linked — buys more credibility than another number.
3. **Every claim ships with its reproduction.** A figure with no command beside it is a
   claim; with one, it is an invitation.
4. **Recovered keys never escape.** Recover, verify against the on-chain public key,
   report the count, the `(txid, vin)` provenance and the derived address. Never the
   scalar, never a balance query, never a code path that can spend. Every new recovery
   path joins that check in the same change that adds it.
5. **Measure; do not assert.** This project has repeatedly overturned its own
   predictions — the operating window, the low-s era assumption, the memory arithmetic.
   A number that was reasoned to rather than measured is a liability.

## Accessibility & Inclusion

`prefers-reduced-motion: reduce` is treated as a hard switch, not a dial: the resolved
end state renders immediately and completely. It must never resolve to a hidden state —
a reader who asked for less motion is owed the finished picture, not an empty panel.
Visible keyboard focus and a skip link are in place. No further product-specific standard
has been established.
