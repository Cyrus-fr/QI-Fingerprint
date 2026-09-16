"""M2 gate: non-lattice cracks (nonce reuse, short-period PRNG, weak seed)."""

import random

from qi_fingerprint.corpus import Signature
from qi_fingerprint.curves import get_curve, sign_with_nonce
from qi_fingerprint.generator import (
    generate_signatures,
    short_period_source,
    weak_seed_source,
)
from qi_fingerprint.reuse import (
    recover_by_reuse,
    recover_by_seed_bruteforce,
    recover_from_reuse,
)

CURVE = get_curve("secp256k1")


def test_direct_nonce_reuse():
    rng = random.Random(1)
    d = rng.randrange(1, CURVE.n)
    Q = CURVE.pubkey(d)
    k = rng.randrange(1, CURVE.n)
    h1, h2 = rng.randrange(1, CURVE.n), rng.randrange(1, CURVE.n)
    r1, s1 = sign_with_nonce(CURVE, h1, d, k)
    r2, s2 = sign_with_nonce(CURVE, h2, d, k)
    assert r1 == r2  # same nonce -> same r
    rec = recover_from_reuse(CURVE, Signature(0, h1, r1, s1), Signature(0, h2, r2, s2), Q)
    assert rec == d


def test_short_period_prng_cracked_by_reuse():
    rng = random.Random(2)
    d = rng.randrange(1, CURVE.n)
    Q = CURVE.pubkey(d)
    pool = [random.Random(100 + i).randrange(1, CURVE.n) for i in range(5)]
    sigs = generate_signatures(CURVE, 0, d, short_period_source(pool), 12, random.Random(3))
    rec = recover_by_reuse(CURVE, sigs, Q)  # period 5 < 12 sigs -> guaranteed repeat
    assert rec == d


def test_weak_seed_bruteforce():
    seed_bits = 12  # small for test speed
    rng = random.Random(4)
    d = rng.randrange(1, CURVE.n)
    Q = CURVE.pubkey(d)
    seed = random.Random(5).getrandbits(seed_bits)
    sigs = generate_signatures(CURVE, 0, d, weak_seed_source(CURVE, seed, seed_bits), 3, random.Random(6))
    rec = recover_by_seed_bruteforce(CURVE, sigs, Q, seed_bits)
    assert rec == d
