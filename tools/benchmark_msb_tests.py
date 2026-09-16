"""Benchmark MSB-bias detectors on identical reconstructed-nonce data.

Binary task: is a key's nonce set MSB-biased?
  positive = truncated_msb (B in {1,2,3,4,6,8}) or modular_reduction (headroom {2,4,8})
  negative = clean, short_period_prng, weak_seed   (all full-range MSBs)

Four classifiers, every one scoring the SAME reconstructed nonces k:
  chi2_msb        per-bit chi-square of the top-b bits vs uniform (sum of z^2)
  ks_msb          Kolmogorov-Smirnov of the phase k/2^L vs Uniform[0,1)
  fft_peak_floor  Bleichenbacher spectrum peak / uniform noise floor (peak * sqrt N)
  current_model   diagnose(strict).label in {truncated_msb, modular_reduction}

The three simple tests are reported at their max-F1 threshold (best case for them);
the model is a fixed decision (min_leading_zero_bits >= 4 AND bias_magnitude > 0.3).
"""

import random

from qi_fingerprint.curves import get_curve
from qi_fingerprint.features import chi2_msb_stat, fft_peak_to_floor, ks_uniform_stat
from qi_fingerprint.fingerprint import diagnose, reconstruct_nonces
from qi_fingerprint.generator import (
    _fold_modulus,
    clean_source,
    generate_signatures,
    modular_reduction_source,
    short_period_source,
    truncated_msb_source,
    weak_seed_source,
)

CURVE = get_curve("secp256k1")
L, Nn, M = CURVE.L, CURVE.n, 1 << CURVE.L
NSIG = 30
PER = 12
CHI_BITS = 16
rng = random.Random(20260829)


def nonces_for(kind, param):
    d = rng.randrange(1, Nn)
    if kind == "trunc":
        src = truncated_msb_source(CURVE, param, random.Random(rng.randrange(1 << 30)))
    elif kind == "mod":
        m = _fold_modulus(L, param, random.Random(rng.randrange(1 << 30)))
        src = modular_reduction_source(CURVE, m, random.Random(rng.randrange(1 << 30)))
    elif kind == "short":
        pool = [random.Random(rng.randrange(1 << 30)).randrange(1, Nn) for _ in range(6)]
        src = short_period_source(pool)
    elif kind == "weak":
        src = weak_seed_source(CURVE, rng.randrange(0, 1 << 12), 12)
    else:
        src = clean_source(CURVE, random.Random(rng.randrange(1 << 30)))
    sigs = generate_signatures(CURVE, 0, d, src, NSIG, random.Random(rng.randrange(1 << 30)))
    return reconstruct_nonces(CURVE, sigs, d)


# ---- the three simple tests, now first-class in qi_fingerprint.features ----
def chi2_msb(k):
    return chi2_msb_stat(k, L, CHI_BITS)


def ks_msb(k):
    return ks_uniform_stat(k, L)


def fft_peak_floor(k):
    return fft_peak_to_floor(k, L, 32)


def model_positive(k):
    return diagnose(k, L, Nn, strict=True).label in ("truncated_msb", "modular_reduction")


# ---- identical dataset -----------------------------------------------------
POS = [("trunc", b) for b in (1, 2, 3, 4, 6, 8)] + [("mod", h) for h in (2, 4, 8)]
NEG = [("clean", None)] * 4 + [("short", None)] * 3 + [("weak", None)] * 3

data = []  # (is_biased, tag, nonces)
for kind, p in POS:
    tag = f"{kind}{p}"
    for _ in range(PER):
        data.append((True, tag, nonces_for(kind, p)))
for kind, p in NEG:
    for _ in range(PER):
        data.append((False, kind, nonces_for(kind, p)))

base = sum(1 for d in data if d[0]) / len(data)


# ---- metrics ---------------------------------------------------------------
def metrics(preds):  # preds: list of (pred_bool, truth_bool)
    tp = sum(1 for p, y in preds if p and y)
    fp = sum(1 for p, y in preds if p and not y)
    fn = sum(1 for p, y in preds if (not p) and y)
    tn = sum(1 for p, y in preds if (not p) and not y)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / len(preds)
    return prec, rec, f1, acc


def roc_auc(scored):  # Mann-Whitney: P(score_pos > score_neg)
    pos = [s for s, y in scored if y]
    neg = [s for s, y in scored if not y]
    wins = sum((s > t) + 0.5 * (s == t) for s in pos for t in neg)
    return wins / (len(pos) * len(neg))


def best_f1(scored):  # sweep threshold; return (prec, rec, f1, acc, thr, auc)
    best = (0, 0, -1, 0, None)
    for thr in sorted({s for s, _ in scored}):
        m = metrics([(s >= thr, y) for s, y in scored])
        if m[2] > best[2]:
            best = m + (thr,)
    return best, roc_auc(scored)


chi = [(chi2_msb(k), y) for y, _, k in data]
ks = [(ks_msb(k), y) for y, _, k in data]
fft = [(fft_peak_floor(k), y) for y, _, k in data]
model_preds = [(model_positive(k), y) for y, _, k in data]

print(f"Identical data: {len(data)} keys ({NSIG} sigs each), base rate biased = {base:.2f}\n")
print("classifier        precision  recall    F1     accuracy   ROC-AUC   operating point")
for name, scored in (("chi2_msb", chi), ("ks_msb", ks), ("fft_peak_floor", fft)):
    (p, r, f, a, thr), auc = best_f1(scored)
    print(f"  {name:15s}   {p:.2f}      {r:.2f}    {f:.2f}    {a:.2f}      {auc:.3f}    max-F1 @ thr={thr:.2f}")
p, r, f, a = metrics(model_preds)
print(f"  {'current_model':15s}   {p:.2f}      {r:.2f}    {f:.2f}    {a:.2f}        -      fixed (min_lz>=4 & bias_mag>0.3)")

# ---- recall by bias strength (where do the simple tests win?) --------------
chosen = {}
for name, scored in (("chi2", chi), ("ks", ks), ("fft", fft)):
    (_, _, _, _, thr), _ = best_f1(scored)
    chosen[name] = thr
tags = [f"{k}{p}" for k, p in POS]
print("\nrecall by bias strength (positives only):")
print(f"  {'strength':10s}  chi2   ks    fft   model")
for tag in tags:
    idx = [i for i, (_, t, _) in enumerate(data) if t == tag]
    rc = sum(chi[i][0] >= chosen["chi2"] for i in idx) / len(idx)
    rk = sum(ks[i][0] >= chosen["ks"] for i in idx) / len(idx)
    rf = sum(fft[i][0] >= chosen["fft"] for i in idx) / len(idx)
    rm = sum(model_preds[i][0] for i in idx) / len(idx)
    print(f"  {tag:10s}  {rc:.2f}  {rk:.2f}  {rf:.2f}  {rm:.2f}")

# ---- false positives on the non-MSB negatives ------------------------------
print("\nfalse-positive rate on negatives (should be 0):")
print(f"  {'negative':10s}  chi2   ks    fft   model")
for neg in ("clean", "short", "weak"):
    idx = [i for i, (yb, t, _) in enumerate(data) if (not yb) and t == neg]
    fc = sum(chi[i][0] >= chosen["chi2"] for i in idx) / len(idx)
    fk = sum(ks[i][0] >= chosen["ks"] for i in idx) / len(idx)
    ff = sum(fft[i][0] >= chosen["fft"] for i in idx) / len(idx)
    fm = sum(model_preds[i][0] for i in idx) / len(idx)
    print(f"  {neg:10s}  {fc:.2f}  {fk:.2f}  {ff:.2f}  {fm:.2f}")
