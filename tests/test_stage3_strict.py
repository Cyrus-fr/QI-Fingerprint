"""Audit gate: strict-mode Fingerprint uses only reconstructed-nonce features.

Confirms the one method-dependent branch (weak_seed) collapses when the recovery
path is masked, while the data-driven classes survive."""

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


def _nonces(source, m, seed):
    d = random.Random(seed).randrange(1, CURVE.n)
    sigs = generate_signatures(CURVE, 0, d, source, m, random.Random(seed + 1))
    return reconstruct_nonces(CURVE, sigs, d)


def test_strict_ignores_cracked_by():
    # Even handed cracked_by="seed", strict mode must NOT return weak_seed --
    # proof the recovery path is truly masked.
    nonces = _nonces(weak_seed_source(CURVE, 1234, 12), 8, 4)
    assert diagnose(nonces, CURVE.L, CURVE.n, cracked_by="seed", strict=True).label != "weak_seed"


def test_strict_weak_seed_collapses_to_clean():
    # A weak-seed key's own nonces are full-range + distinct -> looks clean.
    nonces = _nonces(weak_seed_source(CURVE, 777, 12), 8, 9)
    assert diagnose(nonces, CURVE.L, CURVE.n, strict=True).label == "clean"


def test_default_weak_seed_uses_method():
    # In default mode the method still names it (the leak we are auditing).
    nonces = _nonces(weak_seed_source(CURVE, 777, 12), 8, 9)
    assert diagnose(nonces, CURVE.L, CURVE.n, cracked_by="seed", strict=False).label == "weak_seed"


def test_strict_preserves_data_driven_classes():
    truncated = _nonces(truncated_msb_source(CURVE, 12, random.Random(1)), 60, 1)
    assert diagnose(truncated, CURVE.L, CURVE.n, strict=True).label == "truncated_msb"

    m = _fold_modulus(CURVE.L, 8, random.Random(2))
    modular = _nonces(modular_reduction_source(CURVE, m, random.Random(3)), 60, 2)
    assert diagnose(modular, CURVE.L, CURVE.n, strict=True).label == "modular_reduction"

    pool = [random.Random(50 + i).randrange(1, CURVE.n) for i in range(6)]
    short = _nonces(short_period_source(pool), 18, 3)
    assert diagnose(short, CURVE.L, CURVE.n, strict=True).label == "short_period_prng"

    clean = _nonces(clean_source(CURVE, random.Random(5)), 60, 5)
    assert diagnose(clean, CURVE.L, CURVE.n, strict=True).label == "clean"
