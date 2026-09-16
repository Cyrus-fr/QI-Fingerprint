"""Can truncated/modular siblings (few sigs, uncracked) be linked by OBSERVABLE
features alone -- shared bias magnitude / range_ratio / spectral shape -- without
reading generator_id or the private key?

The features are defined on nonces k = (h + r*d) s^-1 mod n, which need d. A
few-signature sibling can't be cracked, so its nonces are unavailable; the only
public nonce-derived quantity is r = (k*G).x, which the curve scrambles. We
measure, with precision/recall for the task "flag a few-sig key as biased
(truncated/modular) vs clean":

  OBSERVABLE : the named features computed on the public r-values (no d).
  ORACLE     : the same features on reconstructed k (needs d -- NOT deployable),
               an upper bound isolating whether the features themselves separate.
"""

import random
import statistics

from qi_fingerprint.curves import get_curve
from qi_fingerprint.features import bias_magnitude, spectrum
from qi_fingerprint.fingerprint import _range_ratio, reconstruct_nonces
from qi_fingerprint.generator import (
    _fold_modulus,
    clean_source,
    generate_signatures,
    modular_reduction_source,
    truncated_msb_source,
)
from qi_fingerprint.lattice import recover_d

CURVE = get_curve("secp256k1")
N, M = CURVE.n, 1 << CURVE.L
SIBLING_SIGS = 4
PER_CLASS = 60
rng = random.Random(20260829)


def gen_key(kind):
    d = rng.randrange(1, N)
    if kind == "truncated":
        src = truncated_msb_source(CURVE, 12, random.Random(rng.randrange(1 << 30)))
    elif kind == "modular":
        m = _fold_modulus(CURVE.L, 8, random.Random(rng.randrange(1 << 30)))
        src = modular_reduction_source(CURVE, m, random.Random(rng.randrange(1 << 30)))
    else:
        src = clean_source(CURVE, random.Random(rng.randrange(1 << 30)))
    sigs = generate_signatures(CURVE, 0, d, src, SIBLING_SIGS, random.Random(rng.randrange(1 << 30)))
    return d, sigs


def feats(values):
    return {
        "bias_mag": bias_magnitude(values, M),
        "range_ratio": _range_ratio(values),
        "spec_peak": float(spectrum(values, M, 16).max()),
    }


def cohens_d(pos, neg):
    sp, sn = statistics.pstdev(pos), statistics.pstdev(neg)
    pooled = (((sp ** 2) + (sn ** 2)) / 2) ** 0.5 or 1e-9
    return (statistics.mean(pos) - statistics.mean(neg)) / pooled


def pr(scored, thresholds):
    P = sum(1 for _, y in scored if y)
    out = []
    for t in thresholds:
        tp = sum(1 for s, y in scored if y and s >= t)
        fp = sum(1 for s, y in scored if (not y) and s >= t)
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        out.append((t, prec, tp / P))
    return out


# 0) Confirm a few-signature sibling is uncrackable -> no nonces observably.
d, sigs = gen_key("truncated")
Q = CURVE.pubkey(d)
uncrackable = recover_d(CURVE, sigs, 12, Q) is None
print(f"4-signature truncated sibling crackable? {'no' if uncrackable else 'YES'} "
      f"(lattice needs ~L/bias_bits sigs) -> nonces unavailable observably\n")

# 1) Build population and features.
rows = []  # (biased, obs_feats, oracle_feats)
for kind in ("truncated", "modular", "clean"):
    for _ in range(PER_CLASS):
        dd, ss = gen_key(kind)
        r_vals = [s.r for s in ss]
        k_vals = reconstruct_nonces(CURVE, ss, dd)
        rows.append((kind != "clean", feats(r_vals), feats(k_vals)))

base = sum(1 for r in rows if r[0]) / len(rows)
print(f"Population: {PER_CLASS} each truncated/modular/clean, {SIBLING_SIGS} sigs/key; "
      f"base rate biased = {base:.3f}\n")

print("Separation of biased vs clean (mean +/- sd, Cohen's d):")
for feat in ("bias_mag", "range_ratio", "spec_peak"):
    for label, idx in (("OBSERVABLE r ", 1), ("ORACLE k    ", 2)):
        pos = [r[idx][feat] for r in rows if r[0]]
        neg = [r[idx][feat] for r in rows if not r[0]]
        print(f"  {feat:11s} {label} biased {statistics.mean(pos):.3f}+/-{statistics.pstdev(pos):.3f}"
              f"  clean {statistics.mean(neg):.3f}+/-{statistics.pstdev(neg):.3f}  d={cohens_d(pos, neg):+.2f}")
    print()

thr = [i / 20 for i in range(21)]
show = {0.00, 0.30, 0.50, 0.60, 0.70, 0.80, 0.90, 1.00}
for label, idx in (("OBSERVABLE  bias_mag(r-values, no d)", 1), ("ORACLE  bias_mag(reconstructed k, needs d)", 2)):
    print(f"PR curve -- flag biased -- {label}:")
    print("   thr  precision  recall")
    for t, p, rec in pr([(r[idx]["bias_mag"], r[0]) for r in rows], thr):
        if round(t, 2) in show:
            print(f"   {t:.2f}    {p:.2f}      {rec:.2f}")
    print()
