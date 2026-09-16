"""The statistical bias tests are first-class and separate biased from clean --
including the shallow (sub-4-bit) MSB bias the model's leading-zero gate misses."""

import random

from qi_fingerprint.curves import get_curve
from qi_fingerprint.features import chi2_msb_stat, fft_peak_to_floor, ks_uniform_stat
from qi_fingerprint.fingerprint import diagnose, reconstruct_nonces
from qi_fingerprint.generator import clean_source, generate_signatures, truncated_msb_source

CURVE = get_curve("secp256k1")
L = CURVE.L


def _nonces(source, m, seed):
    d = random.Random(seed).randrange(1, CURVE.n)
    sigs = generate_signatures(CURVE, 0, d, source, m, random.Random(seed + 1))
    return reconstruct_nonces(CURVE, sigs, d)


def test_tests_separate_strong_bias_from_clean():
    biased = _nonces(truncated_msb_source(CURVE, 12, random.Random(1)), 40, 1)
    clean = _nonces(clean_source(CURVE, random.Random(2)), 40, 2)

    assert chi2_msb_stat(biased, L) > chi2_msb_stat(clean, L)
    assert ks_uniform_stat(biased, L) > 0.9 and ks_uniform_stat(clean, L) < 0.4
    assert fft_peak_to_floor(biased, L) > fft_peak_to_floor(clean, L)


def test_model_now_catches_weak_bias_via_ks():
    # 2 dead top bits -- below the OLD min_leading_zero_bits>=4 gate, which scored
    # this "clean". The KS branch now flags it as truncated_msb.
    weak = _nonces(truncated_msb_source(CURVE, 2, random.Random(3)), 40, 3)
    assert ks_uniform_stat(weak, L) > 0.5
    assert diagnose(weak, L, CURVE.n, strict=True).label == "truncated_msb"
