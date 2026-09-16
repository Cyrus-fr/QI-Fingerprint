"""BIP146 low-s normalisation, which is exactly ``k -> -k``.

Bitcoin Core has enforced ``s <= n/2`` since 2016, rewriting ``s -> n-s`` where
needed; ~46% of the 2013 range is affected too (measured: block 250,000 is 53.8%
low-s, i.e. a coin flip, so normalisation was not yet applied there and either
sign occurs naturally). Because ``x(kG) == x(-kG)``, ``r`` never changes -- so
Screen still fires on a reuse pair, and every downstream stage that assumes the
reconstructed nonce is the *signed* one is silently wrong half the time.

This file pins all three consequences: recovery from a mixed-sign reuse pair,
sign-blind seed brute force, and the canonical-nonce fold that Fingerprint needs.
The dangerous failure is the first: without it Screen reports a real compromise
that Crack declines to recover, which on real data is indistinguishable from
"nothing found".
"""

import random

import pytest

from qi_fingerprint.corpus import Corpus, KeyRecord, Signature
from qi_fingerprint.curves import get_curve, sign_with_nonce
from qi_fingerprint.features import ks_uniform_stat
from qi_fingerprint.fingerprint import (
    canonical_bound,
    diagnose,
    nonce_features,
    reconstruct_nonces,
)
from qi_fingerprint.generator import (
    _fold_modulus,
    clean_source,
    generate_signatures,
    modular_reduction_source,
    short_period_source,
    truncated_msb_source,
    weak_seed_source,
)
from qi_fingerprint.pipeline import run
from qi_fingerprint.reuse import (
    recover_by_reuse,
    recover_by_seed_bruteforce,
    recover_from_reuse,
)
from qi_fingerprint.screen import screen
from qi_fingerprint.verify import ecdsa_verify, recovers_key

CURVE = get_curve("secp256k1")
N = CURVE.n
HALF_N = N // 2


def normalise(sig: Signature) -> Signature:
    """Apply BIP146: force ``s`` into the lower half, as a Bitcoin signer would."""
    if sig.s <= HALF_N:
        return sig
    return Signature(sig.key_id, sig.h, sig.r, N - sig.s, sig.true_k, sig.gen_index)


def flip(sig: Signature) -> Signature:
    """Unconditionally rewrite ``s -> n-s`` -- used to force a known mixed pair."""
    return Signature(sig.key_id, sig.h, sig.r, N - sig.s, sig.true_k, sig.gen_index)


def _reuse_pair(seed: int):
    """One key, two messages, one shared nonce. The catastrophic case."""
    rng = random.Random(seed)
    d = rng.randrange(1, N)
    Q = CURVE.pubkey(d)
    k = rng.randrange(1, N)
    h1, h2 = rng.randrange(1, N), rng.randrange(1, N)
    r1, s1 = sign_with_nonce(CURVE, h1, d, k)
    r2, s2 = sign_with_nonce(CURVE, h2, d, k)
    assert r1 == r2
    return d, Q, Signature(0, h1, r1, s1), Signature(0, h2, r2, s2)


# --------------------------------------------------------------------------- #
# The invariant itself
# --------------------------------------------------------------------------- #


def test_flipping_s_keeps_the_signature_valid_and_r_unchanged():
    """Why low-s is invisible to Screen: the rewrite is a re-signature under -k."""
    d, Q, sig, _ = _reuse_pair(1)
    flipped = flip(sig)
    assert flipped.s != sig.s
    assert flipped.r == sig.r
    assert ecdsa_verify(flipped.h, flipped.r, flipped.s, Q, CURVE)


def test_flipping_s_negates_the_reconstructed_nonce():
    """``s -> n-s`` is ``k -> -k``: the arithmetic behind every test below."""
    d, _Q, sig, _ = _reuse_pair(2)
    k = reconstruct_nonces(CURVE, [sig], d)[0]
    assert reconstruct_nonces(CURVE, [flip(sig)], d)[0] == (N - k) % N


def test_screen_still_sees_the_collision_after_normalisation():
    """Screen fires either way -- which is precisely what makes a Crack failure
    here look like a clean corpus rather than a bug."""
    d, Q, sig1, sig2 = _reuse_pair(3)
    corpus = Corpus(curve="secp256k1")
    corpus.keys.append(KeyRecord(key_id=0, curve="secp256k1", Qx=Q.x, Qy=Q.y))
    corpus.signatures.extend([sig1, flip(sig2)])
    assert screen(corpus).n_r_collisions >= 1


# --------------------------------------------------------------------------- #
# Reuse recovery across a sign flip -- the test that matters
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("which", [0, 1], ids=["flip-first", "flip-second"])
def test_mixed_sign_reuse_pair_recovers(which):
    """A genuine mixed-sign pair: one signature signed with k, one with -k.

    Not a same-sign pair that already worked -- exactly one of the two is
    rewritten, so ``s1 - s2`` carries no usable relation and only the ``s1 + s2``
    branch closes.
    """
    d, Q, sig1, sig2 = _reuse_pair(4 + which)
    pair = [sig1, sig2]
    pair[which] = flip(pair[which])
    a, b = pair

    # Genuinely mixed: the reconstructed nonces are negatives of one another.
    k_a, k_b = reconstruct_nonces(CURVE, [a], d)[0], reconstruct_nonces(CURVE, [b], d)[0]
    assert k_a == (N - k_b) % N and k_a != k_b

    assert recover_from_reuse(CURVE, a, b, Q) == d
    assert recover_from_reuse(CURVE, b, a, Q) == d  # order must not matter


def test_same_sign_formula_alone_would_miss_the_mixed_pair():
    """Guards the guard: proves the ``s1 + s2`` branch is load-bearing, not
    a redundant second attempt at something the first branch already solved."""
    d, Q, sig1, sig2 = _reuse_pair(6)
    a, b = sig1, flip(sig2)

    k_wrong = ((a.h - b.h) * CURVE.inv(a.s - b.s)) % N
    d_wrong = ((a.s * k_wrong - a.h) * CURVE.inv(a.r)) % N
    assert d_wrong != d
    assert not recovers_key(d_wrong, Q, CURVE)  # the gate catches it, silently

    assert recover_from_reuse(CURVE, a, b, Q) == d  # the new branch does not


def test_same_sign_pair_still_recovers():
    """The path that already worked must keep working."""
    d, Q, sig1, sig2 = _reuse_pair(7)
    assert recover_from_reuse(CURVE, sig1, sig2, Q) == d
    assert recover_from_reuse(CURVE, flip(sig1), flip(sig2), Q) == d  # both flipped


def test_identical_message_still_yields_nothing():
    """h1 == h2 carries no information in either branch."""
    d, Q, sig1, _ = _reuse_pair(8)
    twin = Signature(0, sig1.h, sig1.r, sig1.s)
    assert recover_from_reuse(CURVE, sig1, twin, Q) is None
    assert recover_from_reuse(CURVE, sig1, flip(twin), Q) is None


def test_non_colliding_pair_still_yields_nothing():
    d, Q, sig1, _ = _reuse_pair(9)
    other = Signature(0, sig1.h ^ 1, (sig1.r + 1) % N, sig1.s)
    assert recover_from_reuse(CURVE, sig1, other, Q) is None


def test_short_period_key_cracks_through_bip146_normalisation():
    """End-to-end through ``recover_by_reuse`` on a corpus normalised the way a
    real Bitcoin signer would: every s forced into the lower half."""
    rng = random.Random(10)
    d = rng.randrange(1, N)
    Q = CURVE.pubkey(d)
    pool = [random.Random(200 + i).randrange(1, N) for i in range(5)]
    sigs = generate_signatures(CURVE, 0, d, short_period_source(pool), 12, random.Random(11))

    normalised = [normalise(s) for s in sigs]
    assert any(s.s != o.s for s, o in zip(normalised, sigs))  # some were rewritten
    assert all(s.s <= HALF_N for s in normalised)
    assert recover_by_reuse(CURVE, normalised, Q) == d


# --------------------------------------------------------------------------- #
# Seed brute force
# --------------------------------------------------------------------------- #


def test_seed_bruteforce_survives_normalisation():
    """The brute-forcer reproduces k from the PRNG model; if the on-chain
    signature was normalised the true nonce is -k, so both signs must be tried."""
    seed_bits = 12
    rng = random.Random(12)
    d = rng.randrange(1, N)
    Q = CURVE.pubkey(d)
    seed = random.Random(13).getrandbits(seed_bits)
    sigs = generate_signatures(
        CURVE, 0, d, weak_seed_source(CURVE, seed, seed_bits), 3, random.Random(14)
    )

    assert recover_by_seed_bruteforce(CURVE, [flip(sigs[0])], Q, seed_bits) == d
    assert recover_by_seed_bruteforce(CURVE, [normalise(sigs[0])], Q, seed_bits) == d


# --------------------------------------------------------------------------- #
# Canonical nonces + the shifted uniformity reference
# --------------------------------------------------------------------------- #


def _biased_key(source, m, seed, normalise_fraction=0.5):
    """A key whose signatures are partly low-s normalised, as real data is."""
    rng = random.Random(seed)
    d = rng.randrange(1, N)
    sigs = generate_signatures(CURVE, 0, d, source, m, random.Random(seed + 1))
    picker = random.Random(seed + 2)
    mixed = [flip(s) if picker.random() < normalise_fraction else s for s in sigs]
    return d, mixed


def test_canonical_nonces_against_the_unshifted_reference_look_biased():
    """Why the KS reference must move with the fold: a canonical phase can never
    exceed 0.5, so measured against the full width every key reads as biased."""
    d, sigs = _biased_key(clean_source(CURVE, random.Random(20)), 60, 20)
    canon = reconstruct_nonces(CURVE, sigs, d, canonical=True)

    assert ks_uniform_stat(canon, CURVE.L) > 0.45  # full-width reference: false alarm
    assert ks_uniform_stat(canon, CURVE.L, bound=canonical_bound(N)) < 0.25
    assert nonce_features(canon, CURVE.L, bound=canonical_bound(N))["ks_stat"] < 0.25


def test_canonical_fold_costs_exactly_one_msb_bit():
    """Documented cost of the fold: every canonical nonce has a leading zero."""
    d, sigs = _biased_key(clean_source(CURVE, random.Random(21)), 40, 21)
    raw = reconstruct_nonces(CURVE, sigs, d)
    canon = reconstruct_nonces(CURVE, sigs, d, canonical=True)
    assert max(raw) > HALF_N  # some nonces were negated by normalisation
    assert max(canon) < HALF_N
    assert nonce_features(canon, CURVE.L, bound=canonical_bound(N))["min_leading_zero_bits"] >= 1


def test_clean_key_stays_clean_under_the_fold():
    """The false-positive guard: canonicalising must not invent a bias."""
    d, sigs = _biased_key(clean_source(CURVE, random.Random(22)), 60, 22)
    canon = reconstruct_nonces(CURVE, sigs, d, canonical=True)
    dg = diagnose(canon, CURVE.L, N, strict=True, bound=canonical_bound(N))
    assert dg.label == "clean"


def test_modular_fold_is_misdiagnosed_without_canonicalisation():
    """The concrete misdiagnosis low-s causes.

    Half the reconstructed nonces land just below n, so ``max(k)`` sits at the
    top of the 256-bit range and ``range_ratio`` says "power-of-two truncation" --
    turning a modular fold into ``truncated_msb``. The fold restores it.
    """
    m = _fold_modulus(CURVE.L, 8, random.Random(23))
    src = modular_reduction_source(CURVE, m, random.Random(24))
    d, sigs = _biased_key(src, 90, 23)

    raw = reconstruct_nonces(CURVE, sigs, d)
    wrong = diagnose(raw, CURVE.L, N, strict=True)
    assert wrong.label == "truncated_msb"  # the wrong root cause

    canon = reconstruct_nonces(CURVE, sigs, d, canonical=True)
    right = diagnose(canon, CURVE.L, N, strict=True, bound=canonical_bound(N))
    assert right.label == "modular_reduction"


def test_truncated_msb_survives_the_fold():
    """A power-of-two truncation is well below n/2, so the fold leaves it alone."""
    src = truncated_msb_source(CURVE, 12, random.Random(25))
    d, sigs = _biased_key(src, 70, 25)
    canon = reconstruct_nonces(CURVE, sigs, d, canonical=True)
    dg = diagnose(canon, CURVE.L, N, strict=True, bound=canonical_bound(N))
    assert dg.label == "truncated_msb"


def test_fold_is_a_noop_on_an_unnormalised_corpus():
    """Synthetic runs never normalise, so enabling the flag must not move them."""
    src = truncated_msb_source(CURVE, 12, random.Random(26))
    d, sigs = _biased_key(src, 70, 26, normalise_fraction=0.0)
    assert reconstruct_nonces(CURVE, sigs, d) == reconstruct_nonces(
        CURVE, sigs, d, canonical=True
    )


# --------------------------------------------------------------------------- #
# The whole pipeline, on a normalised corpus
# --------------------------------------------------------------------------- #


def test_pipeline_cracks_and_diagnoses_a_normalised_corpus():
    """Screen -> Crack -> Fingerprint end to end with every s in the lower half."""
    rng = random.Random(30)
    d = rng.randrange(1, N)
    Q = CURVE.pubkey(d)
    pool = [random.Random(300 + i).randrange(1, N) for i in range(5)]
    sigs = generate_signatures(CURVE, 0, d, short_period_source(pool), 14, random.Random(31))

    corpus = Corpus(curve="secp256k1")
    corpus.keys.append(KeyRecord(key_id=0, curve="secp256k1", Qx=Q.x, Qy=Q.y))
    corpus.signatures.extend(normalise(s) for s in sigs)
    assert all(s.s <= HALF_N for s in corpus.signatures)

    result = run(corpus, canonical=True)
    assert result.cracks[0][0] == d
    assert result.diagnoses[0].label == "short_period_prng"
