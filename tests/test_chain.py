"""C gate: a known key unlocks its shared-nonce neighbours, and a cascade follows.

The test that matters here is the **mixed-sign** one. A shared ``r`` says two
signatures share a nonce *up to sign*, and across two different keys -- plausibly
different software, different eras -- one may be BIP146 low-s normalised while
the other is not. Trying only ``+k`` then recovers nothing, and on real data that
is indistinguishable from "there was nothing to find". So every mixed-sign test
below also asserts that the ``k``-only formula **fails** on the same pair; without
that second assertion the first could pass for the wrong reason.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from qi_fingerprint.chain import propagate_keys, shared_r_index, unwalked_edges
from qi_fingerprint.corpus import Corpus, KeyRecord, Signature
from qi_fingerprint.curves import get_curve, sign_with_nonce
from qi_fingerprint.generator import generate_signatures, short_period_source
from qi_fingerprint.pipeline import run
from qi_fingerprint.reuse import nonce_from_signature, recover_from_shared_nonce
from qi_fingerprint.verify import recovers_key

CURVE = get_curve("secp256k1")
N = CURVE.n


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Edge:
    """One shared-nonce edge between two genuinely different keys."""

    k: int
    d_a: int
    Q_a: object
    sig_a: Signature
    d_b: int
    Q_b: object
    sig_b: Signature


def _cross_key_edge(seed: int, negate_b: bool = False) -> _Edge:
    """Two DIFFERENT keys signing with the same nonce -- or with ``k`` and ``-k``.

    When ``negate_b`` is set, key B really signs with ``n - k``; the nonce is
    negated at signing time rather than a same-sign pair being relabelled
    afterwards, so the test exercises the case that actually occurs on chain.
    """
    rng = random.Random(seed)
    d_a = rng.randrange(1, N)
    d_b = rng.randrange(1, N)
    assert d_a != d_b, "fixture must be cross-key, not one key signing twice"

    k = rng.randrange(1, N)
    k_b = (N - k) if negate_b else k
    h_a, h_b = rng.randrange(1, N), rng.randrange(1, N)

    r_a, s_a = sign_with_nonce(CURVE, h_a, d_a, k)
    r_b, s_b = sign_with_nonce(CURVE, h_b, d_b, k_b)
    assert r_a == r_b, "x(kG) == x(-kG): the edge must exist for either sign"

    return _Edge(
        k=k,
        d_a=d_a,
        Q_a=CURVE.pubkey(d_a),
        sig_a=Signature(0, h_a, r_a, s_a),
        d_b=d_b,
        Q_b=CURVE.pubkey(d_b),
        sig_b=Signature(1, h_b, r_b, s_b),
    )


def _k_only_recovery(k: int, sig: Signature, Q):
    """The pre-fix formula: try ``k`` and never ``n - k``. Returns d or None.

    This is what `recover_from_shared_nonce` would be without its sign loop, kept
    here so the mixed-sign tests can prove the loop is load-bearing rather than
    incidental.
    """
    d = ((sig.s * k - sig.h) * CURVE.inv(sig.r)) % N
    return d if recovers_key(d, Q, CURVE) else None


def _chain_corpus(n_keys: int, seed: int, negate: frozenset = frozenset()):
    """A path of keys linked by shared nonces, with key 0 directly crackable.

    Key 0 reuses one nonce across two of its own messages, so the ordinary crack
    loop recovers it and the chain has a seed. Edge ``i`` then links key ``i`` to
    key ``i+1`` through one distinct shared nonce. Naming ``i`` in ``negate``
    makes the right-hand key of that edge sign with ``-k``.
    """
    rng = random.Random(seed)
    ds = [rng.randrange(1, N) for _ in range(n_keys)]

    corpus = Corpus(curve="secp256k1")
    for kid, d in enumerate(ds):
        Q = CURVE.pubkey(d)
        corpus.keys.append(KeyRecord(key_id=kid, curve="secp256k1", Qx=Q.x, Qy=Q.y))

    # Key 0's own nonce reuse -- the entry point for the whole cascade.
    k0 = rng.randrange(1, N)
    for h in (rng.randrange(1, N), rng.randrange(1, N)):
        r, s = sign_with_nonce(CURVE, h, ds[0], k0)
        corpus.signatures.append(Signature(0, h, r, s))

    for i in range(n_keys - 1):
        k = rng.randrange(1, N)
        k_right = (N - k) if i in negate else k
        h_l, h_r = rng.randrange(1, N), rng.randrange(1, N)
        r_l, s_l = sign_with_nonce(CURVE, h_l, ds[i], k)
        r_r, s_r = sign_with_nonce(CURVE, h_r, ds[i + 1], k_right)
        assert r_l == r_r
        corpus.signatures.append(Signature(i, h_l, r_l, s_l))
        corpus.signatures.append(Signature(i + 1, h_r, r_r, s_r))

    return corpus, ds


# --------------------------------------------------------------------------- #
# The nonce primitive
# --------------------------------------------------------------------------- #


def test_nonce_from_signature_round_trips_against_sign_with_nonce():
    """Recovering k from (sig, d) must return the very nonce that was signed with."""
    rng = random.Random(4)
    for _ in range(20):
        d = rng.randrange(1, N)
        k = rng.randrange(1, N)
        h = rng.randrange(1, N)
        r, s = sign_with_nonce(CURVE, h, d, k)
        assert nonce_from_signature(CURVE, Signature(0, h, r, s), d) == k


def test_nonce_from_signature_is_exact_not_up_to_sign():
    """Signing with -k must yield -k back, not k.

    The whole design rests on the source side being exact so the ambiguity lives
    only on the far side of the edge, where the gate resolves it.
    """
    rng = random.Random(5)
    d = rng.randrange(1, N)
    k = rng.randrange(1, N)
    h = rng.randrange(1, N)
    r, s = sign_with_nonce(CURVE, h, d, N - k)
    assert nonce_from_signature(CURVE, Signature(0, h, r, s), d) == N - k


# --------------------------------------------------------------------------- #
# One edge: the easy case, then the case that matters
# --------------------------------------------------------------------------- #


def test_same_sign_cross_key_edge_recovers():
    """The easy half. Passes with or without the sign loop, so it proves little
    on its own -- it is here to show the arithmetic itself is right."""
    edge = _cross_key_edge(10)
    k = nonce_from_signature(CURVE, edge.sig_a, edge.d_a)
    assert k == edge.k
    assert recover_from_shared_nonce(CURVE, k, edge.sig_b, edge.Q_b) == edge.d_b


def test_mixed_sign_cross_key_edge_recovers_and_k_only_would_miss_it():
    """THE test: key A signed with k, key B with -k. Both assertions required.

    Without the second, the first could pass for the wrong reason and the mixed
    case would still read as "nothing found" on a real corpus.
    """
    edge = _cross_key_edge(11, negate_b=True)
    k = nonce_from_signature(CURVE, edge.sig_a, edge.d_a)
    assert k == edge.k

    # 1. the sign loop closes it
    assert recover_from_shared_nonce(CURVE, k, edge.sig_b, edge.Q_b) == edge.d_b
    # 2. and the k-only formula demonstrably does NOT
    assert _k_only_recovery(k, edge.sig_b, edge.Q_b) is None


def test_the_mixed_sign_edge_is_symmetric_in_its_endpoints():
    """Walking B -> A must work as well as A -> B; the fix is not orientation-
    dependent, and a real cascade arrives from an arbitrary direction."""
    edge = _cross_key_edge(12, negate_b=True)
    k_b = nonce_from_signature(CURVE, edge.sig_b, edge.d_b)
    assert k_b == (N - edge.k) % N
    assert recover_from_shared_nonce(CURVE, k_b, edge.sig_a, edge.Q_a) == edge.d_a
    assert _k_only_recovery(k_b, edge.sig_a, edge.Q_a) is None


def test_a_forged_edge_is_refused_by_the_gate():
    """An r shared by two signatures that were not made with the same nonce.

    Genuine coincidence is ~2^-256, so this stands in for a corrupt feed or a
    manufactured claim: the gate, not the graph, decides what counts.
    """
    rng = random.Random(13)
    d_a, d_b = rng.randrange(1, N), rng.randrange(1, N)
    k, j = rng.randrange(1, N), rng.randrange(1, N)
    h_a, h_b = rng.randrange(1, N), rng.randrange(1, N)
    r_a, s_a = sign_with_nonce(CURVE, h_a, d_a, k)
    _r_b, s_b = sign_with_nonce(CURVE, h_b, d_b, j)

    forged = Signature(1, h_b, r_a, s_b)  # B's signature, A's r bolted on
    k_a = nonce_from_signature(CURVE, Signature(0, h_a, r_a, s_a), d_a)
    assert recover_from_shared_nonce(CURVE, k_a, forged, CURVE.pubkey(d_b)) is None


# --------------------------------------------------------------------------- #
# The cascade
# --------------------------------------------------------------------------- #


def test_a_four_key_chain_recovers_every_hop_with_increasing_depth():
    corpus, ds = _chain_corpus(4, seed=20)
    chained = propagate_keys(CURVE, corpus, {0: ds[0]})

    assert sorted(chained) == [1, 2, 3]
    for kid in (1, 2, 3):
        assert chained[kid].d == ds[kid]
        assert chained[kid].depth == kid
        assert chained[kid].via_key_id == kid - 1
    # The seed key is not echoed back as a chained result.
    assert 0 not in chained


def test_a_mixed_sign_hop_mid_cascade_does_not_stop_the_chain():
    """Edge 1 (key 1 -> key 2) is mixed-sign, so the cascade must survive a sign
    flip it meets *after* the first hop -- the variant a one-edge test misses."""
    corpus, ds = _chain_corpus(4, seed=21, negate=frozenset({1}))
    chained = propagate_keys(CURVE, corpus, {0: ds[0]})

    assert sorted(chained) == [1, 2, 3]
    assert chained[2].depth == 2 and chained[2].d == ds[2]
    assert chained[3].depth == 3 and chained[3].d == ds[3]


def test_every_hop_of_a_mixed_sign_chain_satisfies_d_times_G_equals_Q():
    """The universal gate, restated at the cascade level: no hop may drift."""
    corpus, ds = _chain_corpus(5, seed=22, negate=frozenset({0, 2, 3}))
    keys = corpus.key_index()
    chained = propagate_keys(CURVE, corpus, {0: ds[0]})

    assert len(chained) == 4
    for kid, hop in chained.items():
        Q = CURVE.point(keys[kid].Qx, keys[kid].Qy)
        assert recovers_key(hop.d, Q, CURVE)


def test_no_known_key_recovers_nothing_however_dense_the_cohort():
    """Two equations, three unknowns still holds. This upgrade is not a claim
    that a cross-key collision alone is solvable -- it is not."""
    corpus, _ds = _chain_corpus(5, seed=23)
    assert propagate_keys(CURVE, corpus, {}) == {}


def test_a_key_outside_any_cohort_contributes_no_edges():
    rng = random.Random(24)
    corpus = Corpus(curve="secp256k1")
    d = rng.randrange(1, N)
    Q = CURVE.pubkey(d)
    corpus.keys.append(KeyRecord(key_id=0, curve="secp256k1", Qx=Q.x, Qy=Q.y))
    for _ in range(3):
        h, k = rng.randrange(1, N), rng.randrange(1, N)
        r, s = sign_with_nonce(CURVE, h, d, k)
        corpus.signatures.append(Signature(0, h, r, s))

    assert shared_r_index(corpus) == {}
    assert propagate_keys(CURVE, corpus, {0: d}) == {}


# --------------------------------------------------------------------------- #
# The index and the unwalked-edge count
# --------------------------------------------------------------------------- #


def test_shared_r_index_keeps_only_r_values_signed_by_two_or_more_keys():
    corpus, _ds = _chain_corpus(3, seed=25)
    index = shared_r_index(corpus)

    # Two edges in a 3-key path; key 0's own reuse is one key, so it is excluded.
    assert len(index) == 2
    for _r, peers in index.items():
        assert len({kid for kid, _sig in peers}) == 2


def test_unwalked_edges_counts_what_declining_to_chain_leaves_behind():
    corpus, ds = _chain_corpus(4, seed=26)
    # Only key 0 is known, and it touches exactly one edge.
    assert unwalked_edges(corpus, {0: ds[0]}) == 1
    # With every key known, all three edges are reachable.
    assert unwalked_edges(corpus, dict(enumerate(ds))) == 3
    # Nothing known -> nothing reachable.
    assert unwalked_edges(corpus, {}) == 0


# --------------------------------------------------------------------------- #
# End to end through the pipeline
# --------------------------------------------------------------------------- #


def test_pipeline_with_chain_recovers_keys_the_crack_loop_cannot():
    corpus, ds = _chain_corpus(4, seed=27, negate=frozenset({0, 2}))

    baseline = run(corpus)
    chained = run(corpus, chain=True)

    # The crack loop finds key 0 by its own reuse and nothing else: the cohort
    # skip is what it is for.
    assert set(baseline.cracks) == {0}
    assert baseline.chained == {}
    assert baseline.unwalked_edges == 1

    assert set(chained.cracks) == {0, 1, 2, 3}
    assert all(chained.cracks[kid][0] == ds[kid] for kid in range(4))
    assert all(chained.cracks[kid][1] == "chain" for kid in (1, 2, 3))
    assert chained.unwalked_edges == 0


# --------------------------------------------------------------------------- #
# Recovering a key is not the same as being able to fingerprint it
# --------------------------------------------------------------------------- #


def _sibling_cohort():
    """A short-period cohort with two well-sampled members and two thin ones.

    The real shape of a compromised cohort. Key 0 is cracked directly by its own
    reuse; key 1 is reached by the chain and has enough nonces to diagnose itself;
    keys 2 and 3 have two signatures each -- too few to say anything, but sharing
    the pool means they share an ``r`` and are chainable all the same.
    """
    rng = random.Random(40)
    pool = [random.Random(200 + i).randrange(1, N) for i in range(4)]
    corpus = Corpus(curve="secp256k1")
    ds = []

    for kid, n_sigs in enumerate((12, 12, 2, 2)):
        d = rng.randrange(1, N)
        ds.append(d)
        Q = CURVE.pubkey(d)
        corpus.keys.append(KeyRecord(key_id=kid, curve="secp256k1", Qx=Q.x, Qy=Q.y))
        corpus.signatures.extend(
            generate_signatures(
                CURVE, kid, d, short_period_source(pool), n_sigs, random.Random(50 + kid)
            )
        )
    return corpus, ds


def test_a_well_sampled_chained_key_is_diagnosed_from_its_own_nonces():
    """Key 1 is reached by the chain, not the crack loop -- the cohort skip means
    it is never attempted there -- and it still earns a real diagnosis."""
    corpus, ds = _sibling_cohort()
    result = run(corpus, chain=True)

    assert result.cracks[1] == (ds[1], "chain")
    assert result.diagnoses[1].label == "short_period_prng"
    assert result.attributions[1].source == "cracked"


def test_a_thin_sibling_is_recovered_but_not_diagnosed_from_its_own_nonces():
    """Two signatures cannot carry a short-period signal, so `clean` would be a
    fallthrough rather than a finding -- the key is left for Propagate instead."""
    corpus, ds = _sibling_cohort()
    result = run(corpus, chain=True)

    assert set(result.cracks) == {0, 1, 2, 3}  # all four recovered
    assert result.undiagnosable == [2, 3]
    for kid in (2, 3):
        assert kid not in result.diagnoses
        assert result.cracks[kid][0] == ds[kid]


def test_the_deferred_siblings_still_get_the_cohort_label():
    corpus, _ds = _sibling_cohort()
    result = run(corpus, chain=True)

    assert result.diagnoses[0].label == "short_period_prng"
    for kid in (2, 3):
        attribution = result.attributions[kid]
        assert attribution.label == "short_period_prng"
        assert attribution.source == "propagated"


def test_chaining_never_costs_attribution_accuracy():
    """The regression this deferral exists to prevent: asserting `clean` on a key
    with no evidence would overwrite a correct cohort label with a wrong one."""
    corpus, _ds = _sibling_cohort()
    baseline = run(corpus)
    chained = run(corpus, chain=True)

    assert len(chained.cracks) > len(baseline.cracks)
    for kid, attribution in baseline.attributions.items():
        assert chained.attributions[kid].label == attribution.label
    for kid in chained.chained:
        if kid in chained.diagnoses:
            assert chained.diagnoses[kid].label != "clean"
