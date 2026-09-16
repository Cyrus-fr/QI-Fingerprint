"""Audit Stage 3: does the diagnosis come from the recovery method or the nonces?

Generates many labelled keys per class, reconstructs each key's nonces from its
known d (no cracking needed for the audit), and classifies each in BOTH modes:
  * default -- recovery method admissible (cracked_by passed, as the pipeline does);
  * strict  -- recovery path + generation order masked, nonce features only.
Reports per-class accuracy for each mode; the gap is the method's contribution.
"""

import random
from collections import defaultdict

from qi_fingerprint.curves import get_curve
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
CLASSES = ["truncated_msb", "modular_reduction", "short_period_prng", "weak_seed", "clean"]
K = 20  # keys per class


def cases(rng):
    """Yield (truth, cracked_by, source, n_sigs) -- cracked_by is what the pipeline would use."""
    for i in range(K):
        s = rng.randrange(1, 1 << 30)
        yield "truncated_msb", "lattice", truncated_msb_source(CURVE, 12, random.Random(s)), 60
        m = _fold_modulus(CURVE.L, 8, random.Random(s + 7))
        yield "modular_reduction", "lattice", modular_reduction_source(CURVE, m, random.Random(s + 1)), 60
        pool = [random.Random(s + 100 + j).randrange(1, CURVE.n) for j in range(6)]
        yield "short_period_prng", "reuse", short_period_source(pool), 18
        yield "weak_seed", "seed", weak_seed_source(CURVE, rng.randrange(0, 1 << 12), 12), 8
        yield "clean", None, clean_source(CURVE, random.Random(s + 3)), 60


def run():
    rng = random.Random(2026)
    normal = defaultdict(lambda: [0, 0])  # class -> [correct, n]
    strict = defaultdict(lambda: [0, 0])
    confusion = defaultdict(lambda: defaultdict(int))  # strict: truth -> predicted counts
    for truth, method, src, m in cases(rng):
        d = rng.randrange(1, CURVE.n)
        sigs = generate_signatures(CURVE, 0, d, src, m, random.Random(rng.randrange(1 << 30)))
        nonces = reconstruct_nonces(CURVE, sigs, d)
        default = diagnose(nonces, CURVE.L, CURVE.n, cracked_by=method, strict=False)
        masked = diagnose(nonces, CURVE.L, CURVE.n, strict=True)
        normal[truth][1] += 1
        normal[truth][0] += int(default.label == truth)
        strict[truth][1] += 1
        strict[truth][0] += int(masked.label == truth)
        confusion[truth][masked.label] += 1
    return normal, strict, confusion


def fmt(table):
    lines = []
    for cls in CLASSES:
        correct, n = table[cls]
        lines.append(f"  {cls:20s} {correct:3d}/{n:<3d}  {100 * correct / n:6.1f}%")
    tc = sum(v[0] for v in table.values())
    tn = sum(v[1] for v in table.values())
    lines.append(f"  {'OVERALL':20s} {tc:3d}/{tn:<3d}  {100 * tc / tn:6.1f}%")
    return "\n".join(lines)


if __name__ == "__main__":
    normal, strict, confusion = run()
    print("=== Stage 3 per-class accuracy vs truth ===\n")
    print("DEFAULT (recovery method admissible -- cracked_by passed):")
    print(fmt(normal))
    print("\nSTRICT (nonce features only -- recovery path + gen order masked):")
    print(fmt(strict))
    print("\nSTRICT confusion (truth -> predicted):")
    for t in CLASSES:
        preds = ", ".join(f"{p}:{confusion[t][p]}" for p in CLASSES if confusion[t][p])
        print(f"  {t:20s} -> {preds}")
