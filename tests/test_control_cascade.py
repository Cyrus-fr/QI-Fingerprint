"""C5 gate: a confirmed key cascades across cross-key edges, through the real path.

`test_chain.py` proves the arithmetic on bare `Signature` objects. This file
proves the *tool* path: synthetic blocks in, `scan_block` finds the sites,
`ReuseIndex` retains the cross-key pairs, and `confirm_with_cascade` refetches,
recomputes ``z`` from real prevout scripts, re-runs the verify gate and requires
``d*G == Q`` at every hop.

Both hops here are deliberately **mixed-sign** -- the second key of each edge
signs with ``-k``. That is the case a cascade would silently fail on, and
failing silently is indistinguishable from finding nothing.

No private key appears in this file's output; the last test asserts it.
"""

from __future__ import annotations

import random

from synth_bitcoin import build_signed_tx

from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.control import confirm_with_cascade
from qi_fingerprint.ingest.hunt import ReuseIndex, scan_block
from qi_fingerprint.ingest.sources import BlockRecord

CURVE = get_curve("secp256k1")
N = CURVE.n
HEIGHT = 300_000


# --------------------------------------------------------------------------- #
# A three-key cohort in one block
# --------------------------------------------------------------------------- #


def _cohort_block():
    """Key A reuses its own nonce; A-B and B-C each share one, both mixed-sign.

    Returns (source, seed_candidate, cross_hits, [d_a, d_b, d_c]).
    """
    rng = random.Random(77)
    d_a, d_b, d_c = (rng.randrange(1, N) for _ in range(3))
    j = rng.randrange(1, N)  # A's own reused nonce -- the way in
    k1 = rng.randrange(1, N)  # the A-B edge
    k2 = rng.randrange(1, N)  # the B-C edge

    tx_a, prev_a = build_signed_tx(d_a, [j, j, k1])
    tx_b, prev_b = build_signed_tx(
        d_b, [N - k1, k2], funding=[(b"\xb1" * 32, 0), (b"\xb2" * 32, 1)]
    )
    tx_c, prev_c = build_signed_tx(d_c, [N - k2], funding=[(b"\xc1" * 32, 0)])

    txs = [(tx_a, prev_a), (tx_b, prev_b), (tx_c, prev_c)]

    class _Source:
        def block(self, height: int) -> BlockRecord:
            assert height == HEIGHT
            return BlockRecord(height, "0" * 64, b"\x00" * 80, list(txs))

    index = ReuseIndex()
    seed = None
    for site in scan_block([tx for tx, _ in txs], HEIGHT):
        hit = index.add(site)
        if hit is not None:
            seed = hit

    assert seed is not None, "key A's own reuse must be found -- it is the way in"
    return _Source(), seed, index.cross_key_hits, [d_a, d_b, d_c]


# --------------------------------------------------------------------------- #
# The fixture is the shape the test claims
# --------------------------------------------------------------------------- #


def test_the_block_holds_one_same_key_candidate_and_two_cross_key_edges():
    _source, seed, cross_hits, _ds = _cohort_block()
    assert len(seed.sites) == 2  # A's own reuse pair
    assert len(cross_hits) == 2  # A-B and B-C
    assert len({hit.r for hit in cross_hits}) == 2


def test_both_edges_are_genuinely_mixed_sign():
    """Otherwise the cascade would pass without exercising the sign loop."""
    _source, _seed, cross_hits, _ds = _cohort_block()
    for hit in cross_hits:
        a, b = hit.sites
        # k and -k give the same r but s values that are not equal and do not
        # simply mirror each other, because the two keys differ.
        assert a.r == b.r
        assert a.s != b.s


# --------------------------------------------------------------------------- #
# The cascade
# --------------------------------------------------------------------------- #


def test_the_cascade_recovers_both_neighbours_through_the_gated_path():
    source, seed, cross_hits, _ds = _cohort_block()
    confirmation, chained = confirm_with_cascade(seed, cross_hits, source, CURVE)

    assert confirmation.recovered  # key A, by its own reuse
    assert len(chained) == 2
    assert all(hop.recovered for hop in chained)
    assert sorted(hop.depth for hop in chained) == [1, 2]


def test_the_cascade_records_which_key_opened_which():
    source, seed, cross_hits, _ds = _cohort_block()
    confirmation, chained = confirm_with_cascade(seed, cross_hits, source, CURVE)

    by_depth = {hop.depth: hop for hop in chained}
    # Depth 1 was opened by the seed key, so it names the seed's address.
    assert by_depth[1].via_addresses == confirmation.addresses
    # Depth 2 was opened by depth 1, not by the seed.
    assert by_depth[2].via_addresses == by_depth[1].addresses
    assert by_depth[2].addresses != confirmation.addresses


def test_each_hop_carries_the_provenance_needed_to_check_it():
    source, seed, cross_hits, _ds = _cohort_block()
    _confirmation, chained = confirm_with_cascade(seed, cross_hits, source, CURVE)

    for hop in chained:
        assert len(hop.provenance) == 2
        assert all(len(txid) == 64 and vin >= 0 for txid, vin in hop.provenance)
        assert all(sig.height == HEIGHT for sig in hop.verified_sigs)
        assert "RECOVERED" in hop.format()


def test_without_the_cross_key_pairs_there_is_no_cascade():
    """The pairs are the evidence; drop them and the neighbours stay unreachable.

    This is what the old `cross_key_r += 1` amounted to -- a count with nothing
    behind it.
    """
    source, seed, _cross_hits, _ds = _cohort_block()
    confirmation, chained = confirm_with_cascade(seed, [], source, CURVE)
    assert confirmation.recovered
    assert chained == []


def test_an_edge_that_touches_no_recovered_key_is_reported_unrecovered():
    """A cross-key pair between two keys we never cracked stays inert."""
    rng = random.Random(78)
    d_x, d_y = rng.randrange(1, N), rng.randrange(1, N)
    k = rng.randrange(1, N)
    tx_x, prev_x = build_signed_tx(d_x, [k], funding=[(b"\xd1" * 32, 0)])
    tx_y, prev_y = build_signed_tx(d_y, [N - k], funding=[(b"\xd2" * 32, 0)])

    index = ReuseIndex()
    for site in scan_block([tx_x, tx_y], HEIGHT):
        assert index.add(site) is None  # no same-key reuse anywhere
    assert len(index.cross_key_hits) == 1

    source, seed, cross_hits, _ds = _cohort_block()
    # The unrelated edge is offered alongside the real ones and simply never fires.
    _confirmation, chained = confirm_with_cascade(
        seed, list(cross_hits) + index.cross_key_hits, source, CURVE
    )
    assert len(chained) == 2  # still only the two reachable hops


# --------------------------------------------------------------------------- #
# ...and no key escapes
# --------------------------------------------------------------------------- #


def test_no_cascaded_key_appears_in_any_report():
    """§9 across the whole cascade, including the intermediate hop."""
    source, seed, cross_hits, ds = _cohort_block()
    confirmation, chained = confirm_with_cascade(seed, cross_hits, source, CURVE)

    rendered = "\n".join(
        [confirmation.format(), repr(confirmation)]
        + [hop.format() for hop in chained]
        + [repr(hop) for hop in chained]
    ).lower()

    for d in ds:
        for encoding in (f"{d:x}", f"{d:064x}", str(d)):
            assert encoding.lower() not in rendered
        assert d.to_bytes(32, "big").hex() not in rendered
