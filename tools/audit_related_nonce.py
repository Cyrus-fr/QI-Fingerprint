"""Where does a related-nonce (ePrint 2023/305) key land in Stage 3, and can lag-1
autocorrelation separate it from clean?

Recurrence k_{i+1} = a*k_i + c (mod n), secret a,c. Nonces are full-range and
distinct: no MSB bias, no repeats. We (1) run reconstructed nonces through
diagnose() in default and strict mode, and (2) measure lag-1 separation (Cohen's d,
PR) vs clean for the FAITHFUL random-a model, plus a sweep over multiplier size --
because an LCG's lag-1 serial correlation is ~1/a and vanishes for a large secret
multiplier. Measurement only: NO classifier branch is added.
"""

import random
import statistics
from collections import Counter

from qi_fingerprint.curves import get_curve
from qi_fingerprint.features import (
    collision_pairs,
    distinct_ratio,
    ks_uniform_stat,
    lag1_autocorrelation,
)
from qi_fingerprint.fingerprint import diagnose
from qi_fingerprint.generator import clean_source, related_nonce_source, sample_nonces

CURVE = get_curve("secp256k1")
N, M, L = CURVE.n, 1 << CURVE.L, CURVE.L
N_SIG, PER = 64, 150
rng = random.Random(20230305)


def related_ks(count, a=None):
    src = related_nonce_source(CURVE, a=a, rng=random.Random(rng.randrange(1 << 40)))
    return sample_nonces(src, count)[1]


def clean_ks(count):
    return sample_nonces(clean_source(CURVE, random.Random(rng.randrange(1 << 40))), count)[1]


def cohens_d(x, y):
    sx, sy = statistics.pstdev(x), statistics.pstdev(y)
    pooled = (((sx ** 2) + (sy ** 2)) / 2) ** 0.5 or 1e-9
    return (statistics.mean(x) - statistics.mean(y)) / pooled


# 1. Stage 3 landing (default + strict)
print("STAGE 3 -- where related_nonce lands (reconstructed nonces, random secret a):")
for mode in ("default", "strict"):
    labels = Counter()
    for _ in range(PER):
        dg = diagnose(related_ks(N_SIG), L, N, cracked_by=None, strict=(mode == "strict"))
        labels[dg.label] += 1
    print(f"  {mode:8}: " + ", ".join(f"{k}:{v}" for k, v in labels.most_common()))

# 2. lag-1 separation on the faithful random-a model
rel = [lag1_autocorrelation(related_ks(N_SIG), M) for _ in range(PER)]
cln = [lag1_autocorrelation(clean_ks(N_SIG), M) for _ in range(PER)]
rel_abs, cln_abs = [abs(x) for x in rel], [abs(x) for x in cln]
print(f"\nLAG-1 SEPARATION (random secret a ~ 2^256, N={N_SIG} nonces, {PER} keys/class):")
print(f"  |lag1| mean -- related {statistics.mean(rel_abs):.4f}  clean {statistics.mean(cln_abs):.4f}")
print(f"  Cohen's d (signed lag1): {cohens_d(rel, cln):+.3f}")
print(f"  Cohen's d (|lag1|):      {cohens_d(rel_abs, cln_abs):+.3f}")
print(f"  sanity (related): distinct_ratio={distinct_ratio(related_ks(N_SIG)):.2f}, "
      f"collision_pairs={collision_pairs(related_ks(N_SIG))}, ks_stat={ks_uniform_stat(related_ks(N_SIG), L):.3f}")

scored = [(x, True) for x in rel_abs] + [(x, False) for x in cln_abs]
P = sum(1 for _, y in scored if y)
print("  PR (flag related via |lag1| threshold):")
for t in (0.1, 0.2, 0.3, 0.4, 0.5):
    tp = sum(1 for s, y in scored if y and s >= t)
    fp = sum(1 for s, y in scored if (not y) and s >= t)
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    print(f"    thr={t:.2f}  precision={prec:.2f}  recall={tp / P:.2f}")

# 3. sensitivity: lag-1 vs multiplier size (why a random large a is invisible)
print("\nLAG-1 vs MULTIPLIER SIZE (a ~ 2^b, 60 keys/point):")
print("  b     related|lag1|   Cohen's d vs clean")
for b in (2, 4, 8, 16, 32, 64, 128, 255):
    lo = max(2, 1 << (b - 1))
    rl = [lag1_autocorrelation(related_ks(N_SIG, a=rng.randrange(lo, 1 << b)), M) for _ in range(60)]
    cl = [lag1_autocorrelation(clean_ks(N_SIG), M) for _ in range(60)]
    rl_abs, cl_abs = [abs(x) for x in rl], [abs(x) for x in cl]
    print(f"  2^{b:<3d}  {statistics.mean(rl_abs):.4f}          d={cohens_d(rl_abs, cl_abs):+.2f}")
