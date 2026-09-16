"""M4 gate: reconstructed nonces + crack method yield the correct root-cause label."""

import random

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


def _key_and_nonces(source, m, seed):
    d = random.Random(seed).randrange(1, CURVE.n)
    sigs = generate_signatures(CURVE, 0, d, source, m, random.Random(seed + 1))
    nonces = reconstruct_nonces(CURVE, sigs, d)
    gen_indices = [s.gen_index for s in sigs]
    return d, sigs, nonces, gen_indices


def test_reconstruct_matches_ground_truth():
    _, sigs, nonces, _ = _key_and_nonces(truncated_msb_source(CURVE, 12, random.Random(0)), 30, 0)
    assert nonces == [s.true_k for s in sigs]


def test_diagnose_truncated_msb():
    _, _, nonces, gi = _key_and_nonces(truncated_msb_source(CURVE, 12, random.Random(1)), 70, 1)
    dg = diagnose(nonces, CURVE.L, CURVE.n, gen_indices=gi, cracked_by="lattice")
    assert dg.label == "truncated_msb"


def test_diagnose_modular_reduction():
    m = _fold_modulus(CURVE.L, 8, random.Random(2))
    src = modular_reduction_source(CURVE, m, random.Random(3))
    _, _, nonces, gi = _key_and_nonces(src, 90, 2)
    dg = diagnose(nonces, CURVE.L, CURVE.n, gen_indices=gi, cracked_by="lattice")
    assert dg.label == "modular_reduction"


def test_diagnose_short_period():
    pool = [random.Random(50 + i).randrange(1, CURVE.n) for i in range(5)]
    _, _, nonces, gi = _key_and_nonces(short_period_source(pool), 15, 3)
    dg = diagnose(nonces, CURVE.L, CURVE.n, gen_indices=gi, cracked_by="reuse")
    assert dg.label == "short_period_prng"
    assert dg.evidence.get("period") == 5


def test_diagnose_weak_seed():
    _, _, nonces, gi = _key_and_nonces(weak_seed_source(CURVE, 1234, 14), 8, 4)
    dg = diagnose(nonces, CURVE.L, CURVE.n, gen_indices=gi, cracked_by="seed")
    assert dg.label == "weak_seed"


def test_diagnose_clean():
    _, _, nonces, gi = _key_and_nonces(clean_source(CURVE, random.Random(5)), 40, 5)
    dg = diagnose(nonces, CURVE.L, CURVE.n, gen_indices=gi, cracked_by=None)
    assert dg.label == "clean"


def test_collision_check_precedes_ks_branch():
    # Regression: a short-period pool whose values are ALSO MSB-biased trips BOTH
    # the collision check and the KS bias test. The ordering must resolve it as
    # short_period_prng (collisions first) -- never truncated_msb.
    from qi_fingerprint.features import collision_pairs, ks_uniform_stat

    L = CURVE.L
    biased_pool = [random.Random(90 + i).getrandbits(L - 16) | 1 for i in range(5)]
    _, _, nonces, _ = _key_and_nonces(short_period_source(biased_pool), 20, 11)

    assert collision_pairs(nonces) > 0          # repeats present
    assert ks_uniform_stat(nonces, L) > 0.5     # KS would ALSO flag MSB bias
    assert diagnose(nonces, L, CURVE.n, strict=True).label == "short_period_prng"


def test_related_nonce_falls_through_to_clean():
    # ePrint 2023/305 linear recurrence k_{i+1}=a*k_i+c mod n, random secret a:
    # full-range, distinct nonces -> no MSB bias, no repeats, and (large a) no lag-1
    # signal. A KNOWN blind spot -- it lands in 'clean' in BOTH modes (measured,
    # not a designed target; recovery would need the algebraic attack).
    from qi_fingerprint.generator import related_nonce_source, sample_nonces

    _, ks = sample_nonces(related_nonce_source(CURVE, rng=random.Random(7)), 64)
    assert diagnose(ks, CURVE.L, CURVE.n, cracked_by=None, strict=False).label == "clean"
    assert diagnose(ks, CURVE.L, CURVE.n, strict=True).label == "clean"
