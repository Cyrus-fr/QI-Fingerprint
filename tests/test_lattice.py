"""M2 gate: the lattice recovers a KNOWN-biased key and proves it via d*G == Q.

This is the highest-risk stage. The smoke test uses a large bias margin where
success is mandatory if the basis is correct; the sweep maps the boundary; the
last test guarantees we never return a wrong key (silent-garbage failure mode).
"""

import random

import pytest

from qi_fingerprint.curves import get_curve
from qi_fingerprint.generator import generate_signatures, truncated_msb_source
from qi_fingerprint.lattice import recover_d
from qi_fingerprint.verify import recovers_key

CURVE = get_curve("secp256k1")


def make_biased_key(bias_bits: int, m: int, seed: int):
    rng = random.Random(seed)
    d = rng.randrange(1, CURVE.n)
    Q = CURVE.pubkey(d)
    src = truncated_msb_source(CURVE, bias_bits, random.Random(seed + 1))
    sigs = generate_signatures(CURVE, 0, d, src, m, random.Random(seed + 2))
    return d, Q, sigs


def test_smoke_strong_bias_must_recover():
    # Maximal margin: 64 dead MSBs, few signatures. If the basis is right, this
    # MUST succeed -- it is the oracle for basis correctness.
    d, Q, sigs = make_biased_key(bias_bits=64, m=12, seed=1)
    rec = recover_d(CURVE, sigs, bias_bits=64, Q=Q)
    assert rec is not None, "strong-bias recovery failed => basis is wrong"
    assert recovers_key(rec, Q, CURVE)
    assert rec == d


def test_realistic_8bit_bias():
    d, Q, sigs = make_biased_key(bias_bits=8, m=60, seed=2)
    rec = recover_d(CURVE, sigs, bias_bits=8, Q=Q, method="auto")
    assert rec == d


@pytest.mark.parametrize(
    "bias_bits,m,seed",
    [
        (64, 8, 10),   # very easy
        (32, 12, 11),  # comfortable margin
        (16, 24, 12),  # tighter
    ],
)
def test_boundary_sweep(bias_bits, m, seed):
    d, Q, sigs = make_biased_key(bias_bits, m, seed)
    rec = recover_d(CURVE, sigs, bias_bits, Q=Q)
    assert rec == d


def test_insufficient_never_returns_wrong_key():
    # One bit of bias, far too few signatures: uncrackable. The gate must ensure
    # we return None rather than a plausible-looking wrong key.
    d, Q, sigs = make_biased_key(bias_bits=1, m=4, seed=3)
    rec = recover_d(CURVE, sigs, bias_bits=1, Q=Q, method="lll")
    assert rec is None or rec == d


def test_lattice_alone_cannot_recover_short_period():
    # Short-period nonces are full-range (no MSB bias), so the HNP lattice cannot
    # recover them across any bias hypothesis -- short-period keys are exclusively
    # the reuse path's job. (Confirms the separation of concerns.)
    from qi_fingerprint.generator import short_period_source
    from qi_fingerprint.reuse import recover_by_reuse

    rng = random.Random(21)
    d = rng.randrange(1, CURVE.n)
    Q = CURVE.pubkey(d)
    pool = [random.Random(200 + i).randrange(1, CURVE.n) for i in range(6)]  # full-range
    sigs = generate_signatures(CURVE, 0, d, short_period_source(pool), 30, random.Random(22))

    for bias_bits in (4, 8, 12, 16):
        assert recover_d(CURVE, sigs, bias_bits, Q) is None  # lattice fails
    assert recover_by_reuse(CURVE, sigs, Q) == d             # reuse recovers it
