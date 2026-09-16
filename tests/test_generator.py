"""M1 gate: every planted bias is statistically CONFIRMED present in the raw
nonces before any downstream stage trusts the corpus (spec build-order step 2)."""

import random

from qi_fingerprint import features as F
from qi_fingerprint.corpus import Corpus
from qi_fingerprint.curves import get_curve
from qi_fingerprint.generator import (
    BIAS_TYPES,
    _fold_modulus,
    build_corpus,
    clean_source,
    modular_reduction_source,
    sample_nonces,
    short_period_source,
    truncated_msb_source,
    weak_seed_source,
)

CURVE = get_curve("secp256k1")
L = CURVE.L
M = 1 << L


def _nonces(source, n=2000):
    _, ks = sample_nonces(source, n)
    return ks


def test_clean_shows_no_bias():
    ks = _nonces(clean_source(CURVE, random.Random(1)))
    assert F.min_leading_zero_bits(ks, L) <= 3
    assert F.bias_magnitude(ks, M) < 0.1
    assert F.distinct_ratio(ks) > 0.99
    assert F.exact_period(ks[:200]) is None


def test_truncated_msb_confirmed():
    B = 12
    ks = _nonces(truncated_msb_source(CURVE, B, random.Random(2)))
    assert F.min_leading_zero_bits(ks, L) >= B - 1
    assert F.bias_magnitude(ks, M) > 0.9
    # Top B bits are hard zero -> the fingerprint of a power-of-two truncation.
    assert F.msb_bit_means(ks, L, B).max() < 1e-9


def test_modular_reduction_confirmed():
    headroom = 8
    m = _fold_modulus(L, headroom, random.Random(3))
    ks = _nonces(modular_reduction_source(CURVE, m, random.Random(4)))
    assert F.bias_magnitude(ks, M) > 0.5          # clear bias present
    assert m.bit_length() == L - headroom
    assert (m & (m - 1)) != 0                     # non-power-of-two: distinct from truncation
    assert max(ks) < m                            # confined below the fold modulus


def test_short_period_confirmed():
    P = 6
    pool = [random.Random(10 + i).randrange(1, CURVE.n) for i in range(P)]
    _, ks = sample_nonces(short_period_source(pool), 60)
    assert F.exact_period(ks) == P                # periodicity -> autocorrelation signal
    assert F.collision_pairs(ks) > 0             # repeats -> nonce reuse -> crackable
    assert F.distinct_ratio(ks) < 0.2


def test_weak_seed_cross_key_collisions():
    # Same tiny-space seed on two different keys -> identical nonce streams,
    # i.e. cross-key r-collisions (the Screen cohort signal).
    _, ka = sample_nonces(weak_seed_source(CURVE, seed=42, seed_bits=16), 5)
    _, kb = sample_nonces(weak_seed_source(CURVE, seed=42, seed_bits=16), 5)
    _, kc = sample_nonces(weak_seed_source(CURVE, seed=43, seed_bits=16), 5)
    assert ka == kb
    assert ka != kc


def test_build_corpus_structure_and_ground_truth_roundtrip(tmp_path):
    corpus = build_corpus("secp256k1", seed=7)
    assert set(BIAS_TYPES) <= {k.bias_type for k in corpus.keys}

    out = tmp_path / "corpus"
    corpus.save(str(out))

    # Public load must NOT leak ground truth.
    pub = Corpus.load(str(out))
    assert all(k.bias_type is None for k in pub.keys)
    assert all(s.true_k is None and s.gen_index is None for s in pub.signatures)

    # Truth load must preserve true_k AND gen_index, in order (guards load() bug).
    gt = Corpus.load(str(out), with_truth=True)
    assert any(s.gen_index is not None for s in gt.signatures)
    assert len(gt.signatures) == len(corpus.signatures)
    for original, loaded in zip(corpus.signatures, gt.signatures):
        assert loaded.key_id == original.key_id
        assert loaded.true_k == original.true_k
        assert loaded.gen_index == original.gen_index
