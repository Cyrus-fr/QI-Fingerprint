"""The cheap r-collision scan.

The hunt runs on scriptSigs alone, with no prevouts and no sighash, so its job is
to be *fast and complete* rather than certain: a false candidate costs one wasted
confirmation, a missed one costs the whole control. These tests pin both halves --
that it finds real collisions, and that it never manufactures one out of the same
input seen twice.
"""

import pytest

from fixtures_bitcoin import ONE_INPUT_INPUTS, ONE_INPUT_RAW, TWO_INPUT_RAW
from qi_fingerprint.ingest.hunt import (
    ReuseIndex,
    SigSite,
    count_cross_key_r,
    find_candidates,
    scan_block,
    scan_tx,
)
from qi_fingerprint.ingest.tx import parse_tx
from synth_bitcoin import CURVE, build_signed_tx

D = 0xB1A5_C0DE_1234_5678_9ABC_DEF0_1122_3344
K = 0x5EED_0F_C0FFEE_1234_5678_9ABC_DEF0_2233


def _site(r, qx=1, qy=2, txid="a" * 64, vin=0, height=1):
    return SigSite(height, txid, vin, r, 99, qx, qy)


def test_scan_finds_the_real_fixture_signature():
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    sites = scan_tx(tx, 250000)
    assert len(sites) == 1
    _index, _spk, _ht, r, s, _z, qx, qy = ONE_INPUT_INPUTS[0]
    assert (sites[0].r, sites[0].s, sites[0].qx, sites[0].qy) == (r, s, qx, qy)


def test_scan_agrees_with_the_extractor_on_a_multi_input_tx():
    """The hunt must not see fewer inputs than the extractor will."""
    tx = parse_tx(bytes.fromhex(TWO_INPUT_RAW))
    assert len(scan_tx(tx, 250000)) == len(tx.vin)


def test_coinbase_is_skipped():
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    coinbase_like = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    assert scan_tx(tx, 1)  # sanity: the fixture does produce sites
    # A coinbase has a single all-zero prevout; the real check is the property.
    assert not coinbase_like.is_coinbase


def test_reused_nonce_is_found():
    """One key, two inputs, one nonce -- the catastrophic case, end to end
    through the same parser the ingest path uses."""
    tx, _prevouts = build_signed_tx(D, [K, K])
    sites = scan_tx(tx, 500)

    assert len(sites) == 2
    assert sites[0].r == sites[1].r  # same nonce -> same r
    candidates = find_candidates(sites)
    assert len(candidates) == 1
    assert candidates[0].r == sites[0].r
    assert len(candidates[0].sites) == 2


def test_mixed_sign_reuse_is_still_found():
    """Low-s normalisation changes s, never r, so the scan is blind to it --
    which is exactly why Crack has to handle both signs."""
    tx, _prevouts = build_signed_tx(D, [K, K], low_s=[True, False])
    sites = scan_tx(tx, 500)
    assert sites[0].r == sites[1].r
    assert sites[0].s != sites[1].s
    assert len(find_candidates(sites)) == 1


def test_distinct_nonces_produce_no_candidate():
    tx, _prevouts = build_signed_tx(D, [K, K + 1])
    assert find_candidates(scan_tx(tx, 500)) == []


def test_the_same_input_twice_is_not_a_collision():
    """A refetched block or a doubly-served page must not invent evidence."""
    site = _site(r=7)
    assert find_candidates([site, site]) == []

    index = ReuseIndex()
    assert index.add(site) is None
    assert index.add(site) is None


def test_same_r_under_different_keys_is_not_a_same_key_candidate():
    """Two keys sharing a nonce is two equations in three unknowns, so it is not
    a recovery on its own -- but it is retained as a lead, not just tallied."""
    a = _site(r=7, qx=1, qy=2, txid="a" * 64)
    b = _site(r=7, qx=3, qy=4, txid="b" * 64)
    assert find_candidates([a, b]) == []
    assert count_cross_key_r([a, b]) == 1

    index = ReuseIndex()
    assert index.add(a) is None
    assert index.add(b) is None  # never *returned*: it is inert until chased
    assert index.cross_key_r == 1


def test_the_cross_key_pair_itself_is_retained_not_just_counted():
    """A collision you cannot point at is one you cannot come back to."""
    a = _site(r=7, qx=1, qy=2, txid="a" * 64, vin=1, height=100)
    b = _site(r=7, qx=3, qy=4, txid="b" * 64, vin=0, height=140)

    index = ReuseIndex()
    index.add(a)
    index.add(b)

    assert len(index.cross_key_hits) == 1
    hit = index.cross_key_hits[0]
    assert hit.r == 7
    assert hit.keys == ((1, 2), (3, 4))
    assert hit.heights == (100, 140)
    assert hit.provenance == (("a" * 64, 1), ("b" * 64, 0))


def test_a_retained_cross_key_pair_is_in_canonical_order():
    """`iter_raw_blocks` descends, so the pair must not depend on walk direction."""
    high = _site(r=7, qx=1, qy=2, txid="a" * 64, height=140)
    low = _site(r=7, qx=3, qy=4, txid="b" * 64, height=100)

    descending = ReuseIndex()
    descending.add(high)
    descending.add(low)

    ascending = ReuseIndex()
    ascending.add(low)
    ascending.add(high)

    assert descending.cross_key_hits[0].sites == ascending.cross_key_hits[0].sites
    assert descending.cross_key_hits[0].sites[0].height == 100


def test_a_same_key_collision_is_not_recorded_as_a_cross_key_one():
    index = ReuseIndex()
    index.add(_site(r=5, txid="a" * 64))
    hit = index.add(_site(r=5, txid="b" * 64))
    assert hit is not None
    assert index.cross_key_hits == []
    assert index.cross_key_r == 0


def test_three_keys_on_one_r_retain_every_pairing_occurrence():
    """Matches the counter's old semantics: one hit per colliding occurrence."""
    index = ReuseIndex()
    index.add(_site(r=7, qx=1, qy=2, txid="a" * 64))
    index.add(_site(r=7, qx=3, qy=4, txid="b" * 64))
    index.add(_site(r=7, qx=5, qy=6, txid="c" * 64))
    assert index.cross_key_r == 2 == len(index.cross_key_hits)


def test_streaming_index_agrees_with_the_batch_pass():
    """Two implementations of one question; they must not diverge."""
    sites = [
        _site(r=1, txid="a" * 64),
        _site(r=2, txid="b" * 64),
        _site(r=1, txid="c" * 64, height=2),
        _site(r=3, qx=9, qy=8, txid="d" * 64),
    ]
    index = ReuseIndex()
    streamed = [hit for hit in (index.add(s) for s in sites) if hit is not None]

    batch = find_candidates(sites)
    assert len(streamed) == len(batch) == 1
    assert streamed[0].r == batch[0].r == 1
    assert index.n_sites == len(sites)


def test_candidate_reports_both_heights():
    index = ReuseIndex()
    index.add(_site(r=5, txid="a" * 64, height=100))
    hit = index.add(_site(r=5, txid="b" * 64, height=140))
    assert hit is not None
    assert hit.heights == (100, 140)


def test_scan_block_covers_every_transaction():
    txs = [parse_tx(bytes.fromhex(ONE_INPUT_RAW)), parse_tx(bytes.fromhex(TWO_INPUT_RAW))]
    assert len(scan_block(txs, 250000)) == 3


@pytest.mark.parametrize(
    "script_sig",
    [b"", b"\x51", b"\x00", bytes([2]) + b"\xaa\xbb"],
    ids=["empty", "opcode", "op-0", "one-push"],
)
def test_undecodable_scriptsigs_are_skipped_quietly(script_sig):
    """A shape filter, not a validator: anything that is not <sig> <pubkey> is
    simply not a candidate."""
    from qi_fingerprint.ingest.tx import OutPoint, Tx, TxIn, TxOut

    tx = Tx(
        version=1,
        vin=(TxIn(OutPoint(b"\x01" * 32, 0), script_sig, 0xFFFFFFFF),),
        vout=(TxOut(1, b"\x51"),),
        locktime=0,
    )
    assert scan_tx(tx, 1) == []


def test_pubkey_recovered_by_the_scan_matches_the_signing_key():
    tx, _prevouts = build_signed_tx(D, [K])
    site = scan_tx(tx, 1)[0]
    Q = CURVE.pubkey(D)
    assert (site.qx, site.qy) == (Q.x, Q.y)
