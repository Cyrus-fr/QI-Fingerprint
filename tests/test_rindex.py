"""D gate: the on-disk r-index is exact, resumable, and small enough to matter.

`ReuseIndex` cannot reach the window it hunts in -- measured at ~682 bytes per
signature, the ~14M signatures in the 20k-block Android `SecureRandom` range come
to 9.5 GB. The record here is 24 bytes.

The property that must not be lost in the shrink: **a prefix match is a filter,
not a finding.** Every test below that asserts a collision also asserts the
exact recheck happened, and `test_a_forged_prefix_collision_is_rejected` proves
the recheck can say no.
"""

from __future__ import annotations

import random

from synth_bitcoin import build_signed_tx

from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.hunt import ReuseIndex, scan_block
from qi_fingerprint.ingest.rindex import (
    RECORD,
    IndexState,
    PrefixHit,
    RIndexWriter,
    confirm_hit,
    find_prefix_hits,
    load_records,
    prefix,
    read_state,
    resolve_hit,
    scan_to_index,
)
from qi_fingerprint.ingest.sources import RawBlock, SourceError
from qi_fingerprint.ingest.tx import block_hash, check_pow, merkle_root

CURVE = get_curve("secp256k1")
N = CURVE.n
BITS_EASY = 0x207FFFFF
BASE = 1000


# --------------------------------------------------------------------------- #
# A short mined chain we control the nonces of
# --------------------------------------------------------------------------- #


def _header(merkle: bytes, prev: bytes, nonce: int) -> bytes:
    return (
        (1).to_bytes(4, "little")
        + prev
        + merkle
        + (1375531783).to_bytes(4, "little")
        + BITS_EASY.to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )


def _mine(height: int, txs, prev: bytes) -> RawBlock:
    merkle = merkle_root([tx.txid for tx in txs])
    for nonce in range(1 << 16):
        header = _header(merkle, prev, nonce)
        if check_pow(header):
            return RawBlock(height, block_hash(header)[::-1].hex(), header, list(txs))
    raise AssertionError("could not mine a regtest-difficulty header")


class _StubSource:
    """Addressable by height or by block id, like Esplora."""

    def __init__(self, blocks):
        self.blocks = {b.height: b for b in blocks}
        self.by_hash = {b.block_hash: b for b in blocks}
        self.fetches = 0
        self.fail_after = None

    def raw_block(self, height: int, block_hash_: str | None = None) -> RawBlock:
        if self.fail_after is not None and self.fetches >= self.fail_after:
            raise SourceError("stub source: deliberate failure")
        self.fetches += 1
        record = (
            self.blocks[height]
            if block_hash_ is None
            else self.by_hash.get(block_hash_)
        )
        if record is None:
            raise SourceError(f"unknown block {block_hash_}")
        return RawBlock(height, block_hash_ or record.block_hash, record.header, record.txs)


def _chain():
    """Three blocks: a same-key reuse in one, a cross-key edge across two others.

    Returns (source, {"j": r_j, "k": r_k}).
    """
    rng = random.Random(64)
    d_a, d_b, d_c = (rng.randrange(1, N) for _ in range(3))
    j, k = rng.randrange(1, N), rng.randrange(1, N)

    tx_a, _ = build_signed_tx(d_a, [j, j])  # same key, one nonce twice
    tx_b, _ = build_signed_tx(d_b, [k], funding=[(b"\xb0" * 32, 0)])
    tx_c, _ = build_signed_tx(d_c, [N - k], funding=[(b"\xc0" * 32, 0)])

    blocks = []
    prev = b"\x00" * 32
    for offset, txs in enumerate(([tx_a], [tx_b], [tx_c])):
        record = _mine(BASE + offset, txs, prev)
        blocks.append(record)
        prev = block_hash(record.header)

    r_j = scan_block([tx_a], BASE)[0].r
    r_k = scan_block([tx_b], BASE + 1)[0].r
    return _StubSource(blocks), {"j": r_j, "k": r_k}


# --------------------------------------------------------------------------- #
# The record
# --------------------------------------------------------------------------- #


def test_the_record_is_twenty_four_bytes_with_no_padding():
    """The whole point of the module; a silent pad would undo the arithmetic."""
    assert RECORD.itemsize == 24
    assert sum(RECORD[name].itemsize for name in RECORD.names) == 24


def test_the_prefix_is_the_top_sixty_four_bits():
    value = 0xDEADBEEF_CAFEBABE << 192 | 0x1234
    assert prefix(value) == 0xDEADBEEF_CAFEBABE
    assert prefix(0) == 0


def test_writing_and_reading_round_trips(tmp_path):
    path = str(tmp_path / "hunt.idx")
    source, _rs = _chain()
    with RIndexWriter(path, BASE, BASE + 2) as writer:
        for height in (BASE + 2, BASE + 1, BASE):
            record = source.raw_block(height)
            writer.add_block(height, scan_block(record.txs, height))

    records = load_records(path)
    assert len(records) == 4  # 2 inputs + 1 + 1
    assert set(int(r["height"]) for r in records) == {BASE, BASE + 1, BASE + 2}


# --------------------------------------------------------------------------- #
# Collision detection, and the exact recheck behind it
# --------------------------------------------------------------------------- #


def test_the_index_finds_both_the_same_key_and_cross_key_collisions(tmp_path):
    path = str(tmp_path / "hunt.idx")
    source, rs = _chain()
    scan_to_index(source, path, BASE, BASE + 2)

    hits = find_prefix_hits(load_records(path))
    assert len(hits) == 2

    confirmed = {}
    for hit in hits:
        sites = confirm_hit(hit, source)
        assert sites is not None, "a real collision must survive the exact recheck"
        confirmed[sites[0].r] = sites

    assert set(confirmed) == {rs["j"], rs["k"]}
    # The same-key pair shares a public key; the cross-key pair does not.
    same_key = confirmed[rs["j"]]
    cross_key = confirmed[rs["k"]]
    assert len({(s.qx, s.qy) for s in same_key}) == 1
    assert len({(s.qx, s.qy) for s in cross_key}) == 2


def test_a_forged_prefix_collision_is_rejected(tmp_path):
    """Two records can share 64 bits of r without sharing r.

    That is the price of a 24-byte record, and it is paid in two block fetches
    rather than in a false finding. Here the prefix match is fabricated outright.
    """
    source, _rs = _chain()
    # Block BASE carries key A's r; BASE+1 carries key B's. BASE+1 and BASE+2
    # would NOT do -- those two are the cross-key edge and share r by design.
    forged = PrefixHit(
        r_hi=0,
        same_key_prefix=False,
        locations=((BASE, 0), (BASE + 1, 0)),
    )
    sites = resolve_hit(forged, source)
    assert len({s.r for s in sites}) == 2  # the fixture really is two distinct r
    assert confirm_hit(forged, source) is None


def test_the_index_agrees_with_the_in_memory_reuse_index(tmp_path):
    """Two implementations of one question; they must not diverge."""
    path = str(tmp_path / "hunt.idx")
    source, _rs = _chain()
    scan_to_index(source, path, BASE, BASE + 2)

    memory = ReuseIndex()
    for height in (BASE + 2, BASE + 1, BASE):
        record = source.raw_block(height)
        for site in scan_block(record.txs, height):
            memory.add(site)

    hits = find_prefix_hits(load_records(path))
    confirmed = [confirm_hit(hit, source) for hit in hits]
    same_key = [s for s in confirmed if s and len({(x.qx, x.qy) for x in s}) == 1]
    cross_key = [s for s in confirmed if s and len({(x.qx, x.qy) for x in s}) == 2]

    assert len(same_key) == 1  # the one ReuseIndex returned as a candidate
    assert len(cross_key) == memory.cross_key_r == 1


# --------------------------------------------------------------------------- #
# Resumability -- the reason a wide scan is possible at all
# --------------------------------------------------------------------------- #


def test_a_resumed_scan_is_byte_identical_to_an_uninterrupted_one(tmp_path):
    whole = str(tmp_path / "whole.idx")
    source, _rs = _chain()
    scan_to_index(source, whole, BASE, BASE + 2)

    partial = str(tmp_path / "partial.idx")
    interrupted, _rs2 = _chain()
    interrupted.fail_after = 2  # dies after two blocks
    try:
        scan_to_index(interrupted, partial, BASE, BASE + 2)
    except SourceError:
        pass

    state = read_state(partial, BASE, BASE + 2)
    assert state is not None and not state.complete
    assert state.lowest_done == BASE + 1

    resumed, _rs3 = _chain()
    final = scan_to_index(resumed, partial, BASE, BASE + 2, resume=True)
    assert final.complete

    with open(whole, "rb") as a, open(partial, "rb") as b:
        assert a.read() == b.read()


def test_resuming_a_complete_scan_refetches_nothing(tmp_path):
    path = str(tmp_path / "hunt.idx")
    source, _rs = _chain()
    scan_to_index(source, path, BASE, BASE + 2)
    before = source.fetches

    scan_to_index(source, path, BASE, BASE + 2, resume=True)
    assert source.fetches == before


def test_a_sidecar_for_a_different_range_is_not_a_checkpoint(tmp_path):
    """Grafting two scans together would invent collisions between them."""
    path = str(tmp_path / "hunt.idx")
    source, _rs = _chain()
    scan_to_index(source, path, BASE, BASE + 2)

    assert read_state(path, BASE, BASE + 2) is not None
    assert read_state(path, BASE, BASE + 99) is None
    assert read_state(path, BASE - 5, BASE + 2) is None


def test_starting_over_does_not_append_to_a_stale_index(tmp_path):
    path = str(tmp_path / "hunt.idx")
    source, _rs = _chain()
    scan_to_index(source, path, BASE, BASE + 2)
    first = len(load_records(path))

    scan_to_index(source, path, BASE, BASE + 2)  # no resume: start over
    assert len(load_records(path)) == first


def test_index_state_reports_where_to_pick_up():
    state = IndexState(start=100, end=200, lowest_done=150, n_sites=9)
    assert state.resume_from == 149
    assert not state.complete
    assert IndexState(100, 200, 100, 9).complete
    assert IndexState(100, 200, None, 0).resume_from == 200
