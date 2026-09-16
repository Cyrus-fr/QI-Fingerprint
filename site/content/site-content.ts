/**
 * Site copy, transcribed verbatim from README.md.
 *
 * Every figure here is load-bearing: the audits are what make the headline claim
 * credible, and the negative results are reported as negative results. Do not
 * soften, round, or drop a number to make a layout cleaner. If the README
 * changes, change this file to match -- README.md is the source of truth.
 */

export interface TableSpec {
  columns: string[];
  /** `mono: true` renders the row's value cells in the cryptographic mono face. */
  rows: { cells: string[]; emphasis?: boolean }[];
  caption?: string;
}

export interface EvidenceCard {
  index: string;
  title: string;
  /** The single number this audit exists to establish. */
  headline: { value: string; label: string };
  body: string[];
  table?: TableSpec;
  command: string;
}

export const HERO = {
  name: "QI-Fingerprint",
  statement:
    "One recovered key diagnoses the population. Four stages infer which nonce-generation bug is leaking private keys — and which other keys share it — from public ECDSA signatures alone.",
  scope: "Validated on synthetic corpora only.",
  headlineRun:
    "6 keys cracked → 14 keys attributed, 100% correct, zero clean keys touched. Walk the shared-nonce edges and the same corpus yields 14 keys recovered outright.",
  gate:
    "Every recovery is gated on d·G == Q, so a listed crack is a proof, not a guess. Every claim below has a repro command next to it.",
  command:
    'docker compose run --rm pipeline sh -c \\\n    "qi generate --out data/demo --seed 7 && qi run --corpus data/demo --truth"',
};

export const PROBLEM = {
  index: "001",
  title: "The problem",
  statement:
    "QI-Fingerprint triages an unlabeled corpus of ECDSA signatures to answer which nonce-generation bug is leaking private keys and which other keys share it.",
  body: [
    "An ECDSA signature leaks its private key the moment its nonce stops being uniform and unpredictable. Reuse one nonce across two signatures and the key falls out algebraically. Shave a few bits off the top and it falls out of a lattice. The key itself was never the weak part — the randomness was.",
    "Recovering one key is the well-trodden part. The question that actually matters to whoever has to fix it is the next one: which bug caused this, and which of the other keys in front of me have the same bug? Answering that per key does not scale — most keys in a real corpus carry too few signatures to crack at all.",
    "So QI-Fingerprint inverts the unit of analysis. It runs four stages — Screen, Crack, Fingerprint, Propagate — and recovers the key only when d·G == Q holds, so a silent mis-scaled lattice can never emit a wrong answer. It is validated on synthetic corpora only, and ships with adversarial self-audits that quantify exactly where it works and where it doesn't.",
  ],
};

export interface PipelineStage {
  no: string;
  name: string;
  line: string;
  detail: string;
}

export const PIPELINE: {
  index: string;
  title: string;
  statement: string;
  stages: PipelineStage[];
  lanes: { name: string; classes: string; method: string; detail: string }[];
  blindSpot: string;
} = {
  index: "002",
  title: "The pipeline",
  statement:
    "Four stages, two lanes. The MSB-bias lane solves the Hidden Number Problem by lattice reduction on keys that carry enough biased signatures. The repeat lane never touches the lattice.",
  stages: [
    {
      no: "01",
      name: "Screen",
      line: "r-collision population stats, cohorts, crack queue",
      detail:
        "Population statistics over the unlabeled corpus. No private key needed. Intra-key r-collisions mean a reused nonce; cross-key r-collisions link keys into a cohort; high signature counts become speculative lattice candidates.",
    },
    {
      no: "02",
      name: "Crack",
      line: "two lanes — recover d, gated on d·G == Q",
      detail:
        "The cheapest certain recovery per key, cheap first: reuse, then seed brute force, then lattice. Every path returns a key only after d·G == Q, so a wrong bias hypothesis simply fails to recover rather than emitting a wrong key.",
    },
    {
      no: "03",
      name: "Fingerprint",
      line: "reconstruct k, classify the root-cause bug",
      detail:
        "With d known, every nonce is k_i = (h_i + r_i·d)·s_i⁻¹ mod n. The population of reconstructed nonces fixes the root cause: a KS test on the MSB distribution, the Bleichenbacher spectrum, lag-1 autocorrelation, and value-repeat structure.",
    },
    {
      no: "04",
      name: "Propagate",
      line: "attribute the diagnosis across the cohort",
      detail:
        "One cracked and fingerprinted member colours its whole collision-linked cohort. Keys with no observable link are left unattributed rather than guessed — the refusal is the point.",
    },
  ],
  lanes: [
    {
      name: "MSB-bias lane",
      classes: "truncated_msb, modular_reduction",
      method: "→ HNP lattice (LLL / BKZ)",
      detail:
        "Solves the Hidden Number Problem by lattice reduction on keys that carry enough biased signatures.",
    },
    {
      name: "repeat lane",
      classes: "short_period_prng, weak_seed",
      method: "→ nonce-reuse recovery / seed brute-force",
      detail:
        "Never touches the lattice. Short-period pools force exact nonce reuse (recovered algebraically from one r-collision), and weak seeds are brute-forced over a tiny seed space.",
    },
    {
      name: "chain lane",
      classes: "any recovered key → its shared-nonce neighbours",
      method: "→ cascade, opt-in behind --chain",
      detail:
        "Two different keys sharing a nonce is two equations in three unknowns — unsolvable on its own. Known either end and it collapses: k falls out of the known key's equation, then the neighbour's d falls out of k. Every hop is gated the same way.",
    },
  ],
  blindSpot:
    "A fifth class, related_nonce (linear recurrence k_{i+1}=a·k_i+c mod n), fits neither lane — it is a documented blind spot.",
};

export const EVIDENCE: EvidenceCard[] = [
  {
    index: "1",
    title: "Stage 3 classifies from nonce data, not the recovery method",
    headline: { value: "0%", label: "weak_seed strict accuracy" },
    body: [
      "Strict mode masks cracked_by and generation order, classifying from reconstructed nonces alone. Per-class accuracy vs truth (20 keys/class):",
      "Only weak_seed was method-carried — a single weak-seed key's own nonces are full-range and distinct, information-theoretically identical to clean. The three data-driven detections (truncated_msb, modular_reduction, short_period_prng) survive masking; clean is a fallthrough, not a detection.",
    ],
    table: {
      columns: ["class", "default", "strict"],
      rows: [
        { cells: ["truncated_msb", "100%", "100%"] },
        { cells: ["modular_reduction", "100%", "100%"] },
        { cells: ["short_period_prng", "100%", "100%"] },
        { cells: ["weak_seed", "100%", "0% → all collapse to clean"], emphasis: true },
        { cells: ["clean", "100%", "100%"] },
      ],
    },
    command: "docker compose run --rm pipeline python tools/audit_stage3.py",
  },
  {
    index: "2",
    title: "Stage 4 attribution never reads ground truth",
    headline: { value: "8/8", label: "propagation accuracy, 100%" },
    body: [
      "Running the whole pipeline on the public-only corpus (generator_id, bias_type, d, true_k, gen_index all stripped) is byte-identical to the with-truth run: cohorts=True  attributions=True.",
      "Cohort membership comes purely from shared r values — e.g. keys [52,53,54,55,56,57] are linked by 6 shared r-values — and 4/4 observable cohorts are single-generator. Propagation is 8/8 = 100% on the keys it labels.",
    ],
    command: "docker compose run --rm pipeline python tools/audit_propagate.py",
  },
  {
    index: "3",
    title: "Few-signature siblings cannot be linked observably",
    headline: { value: "+0.09", label: "Cohen's d, observable — a negative result" },
    body: [
      "A 4-signature sibling is uncrackable, so its nonces are unavailable; the only public nonce-derived quantity is r, which the curve scrambles. Separation of biased vs clean, Cohen's d:",
      "Observable PR precision is pinned at the 0.667 base rate (no usable threshold); the oracle reaches precision 0.99 at recall 1.00. The barrier is nonce reconstruction, not the features — so the siblings stay unattributed rather than guessed.",
    ],
    table: {
      columns: ["feature", "observable (on r, no d)", "oracle (on reconstructed k, needs d)"],
      rows: [
        { cells: ["bias_magnitude", "+0.09", "+3.90"], emphasis: true },
        { cells: ["range_ratio", "−0.09", "−0.62"] },
        { cells: ["spectral peak", "−0.15", "+2.38"] },
      ],
    },
    command: "docker compose run --rm pipeline python tools/audit_sibling_linkage.py",
  },
  {
    index: "4",
    title: "A KS test beats the original MSB classifier",
    headline: { value: "0.99 vs 0.71", label: "F1 — ks_msb over the original model" },
    body: [
      "Binary MSB-bias detection on identical reconstructed nonces (228 keys), simple tests at their max-F1 threshold:",
      "The original model's min_leading_zero_bits ≥ 4 gate was structurally blind to sub-4-bit bias (recall 0.00 on truncated B=1/2/3), while the KS test catches down to 1 dead bit at 100% recall. The gate was removed and the MSB branch replaced with ks_stat ≥ max(0.5, 1.63/√N). chi2 false-positives 89% on short-period pools, so it was not adopted.",
    ],
    table: {
      columns: ["classifier", "precision", "recall", "F1", "ROC-AUC"],
      rows: [
        { cells: ["ks_msb", "0.97", "1.00", "0.99", "0.998"], emphasis: true },
        { cells: ["fft_peak_floor", "0.96", "0.88", "0.92", "0.967"] },
        { cells: ["chi2_msb", "0.77", "0.99", "0.87", "0.929"] },
        { cells: ["original model (min_lz≥4 & bias_mag>0.3)", "1.00", "0.56", "0.71", "—"], emphasis: true },
      ],
    },
    command: "docker compose run --rm pipeline python tools/benchmark_msb_tests.py",
  },
  {
    index: "5",
    title: "Stage 1 operating window — birthday physics confirmed, prediction refuted",
    headline: { value: "2^20.2", label: "measured detection edge at e=40 (predicted 2^20.0)" },
    body: [
      "Sweeping effective entropy e × pooled signatures N, the r-collision screen's detection edge sits exactly on the birthday line N ≈ 2^(e/2) (e=40 crosses 50% at 2^20.2 vs predicted 2^20.0).",
      "But within a 2^24-signature budget the usable window is ~(26, 48], reliable only to ~40 — not the predicted 40–60. Reaching e=60 needs 2^30 pooled signatures (64× the budget); the upper edge is set by the signature budget, not entropy.",
    ],
    command:
      "docker compose run --rm pipeline python tools/stage1_operating_window.py   # writes tools/stage1_operating_window.png",
  },
  {
    index: "6",
    title: "related_nonce is a genuine blind spot",
    headline: { value: "150/150", label: "land in clean — Cohen's d = −0.10" },
    body: [
      "The ePrint 2023/305 recurrence k_{i+1}=a·k_i+c mod n (secret a) produces full-range, distinct nonces. It lands in clean in both default and strict mode (150/150).",
      "Lag-1 autocorrelation does not separate it from clean: Cohen's d = −0.10. An LCG's lag-1 correlation ~1/a is only visible for a tiny multiplier (a≈2² → d=0.86; gone by a≈2⁴), so a secret ~256-bit a is invisible. Recovering it needs the algebraic recurrence attack, not a statistical feature.",
    ],
    command: "docker compose run --rm pipeline python tools/audit_related_nonce.py",
  },
  {
    index: "8",
    title: "One recovered key cascades into its cohort",
    headline: { value: "6 → 14", label: "keys recovered on the same corpus" },
    body: [
      "A cross-key r-collision used to be counted and discarded as unsolvable. It is — on its own. Known either endpoint and the system collapses: k = s⁻¹(h + r·d) comes exactly out of the known key's own equation, then the neighbour's d = (s·k′ − h)·r⁻¹ falls out of that. Every hop is gated on d·G == Q, so a wrong branch fails rather than returning a wrong key.",
      "Both signs of k′ must be tried. BIP146 may have normalised one signature and not the other, and across two keys — plausibly different software, different eras — that is a coin flip. Trying only +k recovers nothing and looks exactly like an empty range.",
      "Recovery more than doubles at no cost to accuracy. The gap between 14 recovered and 7 diagnosed is the honest part: recovering a key is not the same as being able to fingerprint it. Seven of the chained keys carry two to six signatures against a period of six, so their own nonces show zero collisions — clean would be a fallthrough, not a finding, and those keys keep their cohort attribution instead.",
    ],
    table: {
      columns: ["run", "cracked", "diagnosed", "attribution"],
      rows: [
        { cells: ["qi run", "6", "6/6 = 100%", "14/14 = 100%"] },
        { cells: ["qi run --chain", "14", "7/7 = 100%", "14/14 = 100%"], emphasis: true },
      ],
    },
    command: "docker compose run --rm pipeline qi run --corpus data/demo --truth --chain",
  },
  {
    index: "9",
    title: "A wider net: SegWit coverage and an index that fits",
    headline: { value: "31.5%", label: "of a modern block now visible, from 9.9%" },
    body: [
      "The hunt computes no sighash — it needs only r and the public key — so a witness input never required BIP143 to be found, only to be confirmed. A P2WPKH witness is literally [DER sig, pubkey], the same two elements a P2PKH scriptSig pushes. On block 800,000 that takes the prevout-free scan from 488 of 4,911 inputs to 1,546.",
      "The in-memory index could not reach the range it was hunting in. Measured on the real structure it costs 682 bytes per signature — 9.55 GB for the ~14M signatures in the 20k-block Android SecureRandom window. Adding slots saves 6%; a fixed-width 24-byte record saves 28×.",
      "The record keeps the top 64 bits of r and no txid at all: a site is named by (height, site index) and recovered by re-running the pure block scan. The prefix is a filter, not a finding — every hit is re-derived at full 256-bit width before anything is reported, so the expected 5×10⁻⁶ spurious matches cost two block fetches rather than a wrong answer. The file doubles as the checkpoint, and a killed scan resumes to a byte-identical index.",
    ],
    table: {
      columns: ["index layout", "bytes/sig", "719k sigs", "~14M sigs"],
      rows: [
        { cells: ["dataclass + str txid", "682", "490 MB", "9.55 GB"] },
        { cells: ["+ slots=True", "639", "459 MB", "8.95 GB"] },
        { cells: ["numpy record", "24", "17 MB", "0.34 GB"], emphasis: true },
      ],
    },
    command:
      "docker compose run --rm pipeline python tools/find_reuse.py --start 240000 --end 260000 --index data/hunt.idx --cache-raw --resume",
  },
];

export interface Limitation {
  index: string;
  title: string;
  body: string;
  /** The synthetic-only limit is the one that qualifies every other claim. */
  primary?: boolean;
}

export const LIMITATIONS: Limitation[] = [
  {
    index: "1",
    title: "weak_seed is not nonce-fingerprintable.",
    body: "A single weak-seed key's nonces are full-range and distinct (§1: strict accuracy 0%). Its label is carried entirely by a successful small-seed brute force; without that method signal it is indistinguishable from clean.",
  },
  {
    index: "2",
    title: "Truncated/modular siblings can't be linked observably.",
    body: "Few-signature siblings are uncrackable and carry no observable bias signal (§3: Cohen's d ≤ 0.15 on r). Grouping them would require reading generator_id (ground truth), so they are left unattributed.",
  },
  {
    index: "3",
    title: "The operating window is bounded by entropy and signature budget.",
    body: "The r-collision screen only fires when N ≳ 2^(e/2) (§5), so high-entropy weak generators are invisible unless you can pool an infeasible number of signatures.",
  },
  {
    index: "4",
    title: "related_nonce is undetectable and uncrackable",
    body: "by every current stage (§6).",
  },
  {
    index: "5",
    title: "Classification accuracy is measured on synthetic data only.",
    body: "The pipeline runs on real Bitcoin, and the recovery path is validated against a real reused-nonce key recovered from block 252,474 with d·G == Q. But every diagnosis and attribution figure on this page comes from a corpus the generator made, because scoring a label needs a ground truth real data does not have. No real key has been fingerprinted yet: the one recovered from mainnet carries two signatures, far too few to classify.",
    primary: true,
  },
  {
    index: "6",
    title: "Two thirds of a modern block is still invisible.",
    body: "Real coverage is P2PKH, P2PK and SegWit v0 P2WPKH, native and P2SH-wrapped. Measured on block 800,000 — 4,911 non-coinbase inputs, 89.9% carrying a witness — the prevout-free hunt sees 1,546 of them (31.5%), up from 488 (9.9%). P2WSH, bare multisig and P2SH-of-anything-else present a different shape and are counted, not guessed at. Taproot is out permanently: it is Schnorr, so there is no (r, s) pair to collect at all.",
  },
  {
    index: "7",
    title: "P2PK can be ingested but never hunted.",
    body: "Its public key lives in the output being spent, and the cheap prevout-free scan deliberately never fetches prevouts. That is a property of the input, not a gap in the scanner — and it is why the coverage figure above is a scan figure, not an ingest one.",
  },
];

export interface PriorArtLink {
  href: string;
  label: string;
}

export interface PriorArtEntry {
  name: string;
  year: string;
  body: string;
  /** Every URL here was checked to resolve 200 to the paper it claims to be. */
  links?: PriorArtLink[];
  /** Entries that sit closest to this work, called out as such in the README. */
  nearest?: boolean;
}

export const PRIOR_ART_INTRO =
  "Most of the lineage below is real-target key recovery from a specific leakage source; QI-Fingerprint sits one layer up — inferring the root-cause bug and attributing it across a cohort from reconstructed nonces alone, and only on synthetic data. Two entries sit closer and are called out as such: a feasibility model our recovery threshold rests on, and a real-world study that did the same attribution with vendor firmware.";

export const PRIOR_ART: PriorArtEntry[] = [
  {
    name: "Breitner & Heninger — “Biased Nonce Sense”",
    year: "FC 2019",
    links: [{ href: "https://eprint.iacr.org/2019/023", label: "eprint 2019/023" }],
    body: "Scanned real cryptocurrency blockchains and recovered keys from biased/reused nonces with HNP lattices. That is the real-corpus validation QI-Fingerprint lacks; its Stage-2 lattice is the same HNP tool. What is added here — “which bug, and which sibling keys” — is demonstrated only synthetically.",
  },
  {
    name: "Minerva and TPM-Fail",
    year: "2020",
    links: [
      { href: "https://eprint.iacr.org/2020/728", label: "Minerva — eprint 2020/728" },
      {
        href: "https://www.usenix.org/conference/usenixsecurity20/presentation/moghimi-tpm",
        label: "TPM-Fail — USENIX Security 20",
      },
    ],
    body: "Both discover nonce bias through a timing side-channel (nonce bit-length / leaked MSBs) and then lattice it. QI-Fingerprint does no side-channel measurement; it assumes the bias is already in the signatures and asks what kind it is.",
  },
  {
    name: "LadderLeak",
    year: "2020",
    links: [{ href: "https://eprint.iacr.org/2020/615", label: "eprint 2020/615" }],
    body: "Recovered keys from <1 bit of nonce leakage via a Bleichenbacher/FFT amplification over ~2⁴⁰ signatures. QI-Fingerprint uses the Bleichenbacher spectrum only as a classification feature; its lattice lane needs several bits, and its Stage-1 study maps where the far cheaper r-collision screen fires instead.",
  },
  {
    name: "Cisco ASA entropy failures — the nearest neighbour",
    year: "ePrint 2023/912",
    body: "Traced real ECDSA key/nonce collisions in deployed Cisco ASA devices to flawed DRBG plumbing, doing genuine root-cause attribution via certificate-scale statistics plus firmware analysis. The distinction is narrow and worth stating plainly: their root cause came from reading the vendor firmware; QI-Fingerprint infers it from reconstructed nonces alone, with no vendor access. Attribution without ground truth is the whole bet — which is exactly why the audits above exist.",
    links: [{ href: "https://eprint.iacr.org/2023/912", label: "eprint 2023/912" }],
    nearest: true,
  },
  {
    name: "“Estimating the Effectiveness of Lattice Attacks” — complementary, not competing",
    year: "ePrint 2021/1489",
    body: "A feasibility model relating key size, leakage bits and BKZ behaviour to whether an HNP recovery will succeed. It takes leakage strength as an input and predicts success; it does not find biased keys. It answers “will recovery work at this bias?” while QI-Fingerprint asks “which keys are biased, and why” — and it is the proper basis for the recovery threshold Stage 2 assumes when it decides a key has enough biased signatures to lattice.",
    links: [{ href: "https://eprint.iacr.org/2021/1489", label: "eprint 2021/1489" }],
    nearest: true,
  },
];

export const RUN_IT = {
  intro:
    "Everything runs in a Linux container (fpylll/fastecdsa have no usable native-Windows build):",
  commands: [
    { cmd: "docker compose build", note: "" },
    {
      cmd: "docker compose run --rm pipeline pytest -q",
      note: "322 tests (every recovery path asserts d·G == Q)",
    },
    { cmd: "docker compose run --rm pipeline qi run --corpus data/demo --truth", note: "" },
    {
      cmd: "docker compose run --rm pipeline qi run --corpus data/demo --truth --chain",
      note: "cascade across shared-nonce edges — 6 keys become 14",
    },
    {
      cmd: "docker compose run --rm pipeline python tools/ingest_bitcoin.py --start 250000 --end 250001 --out data/btc-250000",
      note: "real mainnet blocks, read-only",
    },
  ],
  siteData: {
    intro: "The data on this page is a frozen run of that same pipeline:",
    cmd: "docker compose run --rm pipeline python tools/export_site_data.py",
  },
};
