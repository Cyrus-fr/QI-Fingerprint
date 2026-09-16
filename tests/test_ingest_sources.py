"""Block sources: self-authentication, the raw cache, and range contiguity.

`RawBlock` exists so the hunt can read scriptSigs without paying for prevouts.
It is a *smaller* record, not a laxer one -- it goes through the same header
hash, proof-of-work and merkle checks, because those are what make a third
party's bytes usable at all. These tests pin that the shared check really is
shared, and that each of its three limbs can fail.

The fixtures are genuinely mined, at a regtest-style difficulty that costs a
couple of nonce increments. That is not a detail: the cache re-verifies proof of
work on *read*, so an unmined fixture cannot round-trip -- and a test that
worked around it by relaxing the check would be testing a different program.
"""

import gzip
import json

import pytest

from fixtures_bitcoin import BLOCK_HEADER_HEX
from qi_fingerprint.ingest.sources import (
    RAW_CACHE_SCHEMA,
    RawBlock,
    RawCachedSource,
    SourceError,
    _cache_path,
    iter_raw_blocks,
)
from qi_fingerprint.ingest.tx import block_hash, check_pow, merkle_root, parse_tx
from synth_bitcoin import build_signed_tx

D = 0xB1A5_C0DE_1234_5678_9ABC_DEF0_1122_3344
K = 0x5EED_0F_C0FFEE_1234_5678_9ABC_DEF0_2233

#: Regtest difficulty: target ~2^255, so roughly every other nonce works.
BITS_EASY = 0x207FFFFF
#: Block 250,000's real difficulty -- unreachable by grinding here, which is
#: what makes it useful for the negative test. Note every multi-byte header
#: field is little-endian: written big-endian this decodes as exponent 0x3d
#: instead of 0x1a, a target so large that any hash clears it and the proof-of-
#: work check silently passes.
BITS_HARD = 0x1A01AA3D


def _header(merkle: bytes, prev: bytes, bits: int, nonce: int) -> bytes:
    return (
        (1).to_bytes(4, "little")
        + prev
        + merkle
        + (1375531783).to_bytes(4, "little")
        + bits.to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )


def _raw_block(
    height: int, *, prev: bytes = b"\x00" * 32, mined: bool = True
) -> RawBlock:
    """A block whose header really commits to its transactions.

    With ``mined=False`` the header carries mainnet difficulty and no work, so
    `check()` rejects it -- the negative case for the proof-of-work limb.
    """
    tx, _prevouts = build_signed_tx(D, [K], funding=[(bytes([height & 0xFF]) * 32, 0)])
    merkle = merkle_root([tx.txid])

    if not mined:
        header = _header(merkle, prev, BITS_HARD, 0)
        return RawBlock(height, block_hash(header)[::-1].hex(), header, [tx])

    for nonce in range(1 << 16):
        header = _header(merkle, prev, BITS_EASY, nonce)
        if check_pow(header):
            return RawBlock(height, block_hash(header)[::-1].hex(), header, [tx])
    raise AssertionError("could not mine a regtest-difficulty header")


def test_a_well_formed_raw_block_passes():
    _raw_block(500).check()


def test_a_wrong_block_hash_is_caught():
    record = _raw_block(500)
    bad = RawBlock(record.height, "0" * 64, record.header, record.txs)
    with pytest.raises(SourceError, match="hash to its own id"):
        bad.check()


def test_a_mutated_transaction_breaks_the_merkle_root():
    """The check that stops a source substituting a transaction: the header
    commits to the set, and we recompute it rather than trusting the feed."""
    record = _raw_block(500)
    other, _prevouts = build_signed_tx(D, [K + 1], funding=[(b"\x99" * 32, 0)])
    swapped = RawBlock(record.height, record.block_hash, record.header, [other])
    with pytest.raises(SourceError, match="merkle root mismatch"):
        swapped.check()


def test_proof_of_work_is_checked_by_default():
    """A header with mainnet difficulty and no work behind it must be rejected."""
    record = _raw_block(500, mined=False)
    with pytest.raises(SourceError, match="proof of work"):
        record.check()
    record.check(verify_pow=False)  # ...and the opt-out really does skip it


def test_a_real_header_passes_proof_of_work():
    """The other side of the same check, on a header that really was mined."""
    assert check_pow(bytes.fromhex(BLOCK_HEADER_HEX))


def test_an_empty_block_is_refused():
    """No transaction list at all -- caught before the merkle root, which has
    no meaningful value to compare against."""
    header = _header(b"\x00" * 32, b"\x00" * 32, BITS_HARD, 0)
    empty = RawBlock(1, block_hash(header)[::-1].hex(), header, [])
    with pytest.raises(SourceError, match="no transactions"):
        empty.check(verify_pow=False)


# --------------------------------------------------------------------------- #
# The raw cache
# --------------------------------------------------------------------------- #


class StubRawSource:
    """Mimics Esplora: addressable by height *or* by block id, and -- like the
    real source -- it labels what it returns with the id that was asked for, so
    a wrong answer is caught by `RawBlock.check()` rather than by the stub."""

    def __init__(self, blocks):
        self.blocks = blocks
        self.by_hash = {record.block_hash: record for record in blocks.values()}
        self.fetches = 0

    def raw_block(self, height: int, block_hash: str | None = None) -> RawBlock:
        self.fetches += 1
        if block_hash is None:
            record = self.blocks[height]
        else:
            record = self.by_hash.get(block_hash)
            if record is None:
                raise SourceError(f"unknown block {block_hash}")
        labelled = RawBlock(
            height, block_hash or record.block_hash, record.header, record.txs
        )
        labelled.check()
        return labelled


def test_cache_round_trips_and_then_serves_offline(tmp_path):
    record = _raw_block(700)
    inner = StubRawSource({700: record})
    cache = RawCachedSource(inner, str(tmp_path))

    first = cache.raw_block(700)
    assert inner.fetches == 1
    assert [tx.txid_hex for tx in first.txs] == [tx.txid_hex for tx in record.txs]

    # A fresh instance with no inner source must still serve it.
    offline = RawCachedSource(None, str(tmp_path))
    second = offline.raw_block(700)
    assert second.header == record.header
    assert [tx.serialize() for tx in second.txs] == [tx.serialize() for tx in record.txs]
    assert inner.fetches == 1  # nothing refetched


def test_offline_only_source_says_so(tmp_path):
    with pytest.raises(SourceError, match="offline-only"):
        RawCachedSource(None, str(tmp_path)).raw_block(12345)


def test_a_corrupt_entry_is_discarded_and_refetched(tmp_path):
    record = _raw_block(700)
    inner = StubRawSource({700: record})
    cache = RawCachedSource(inner, str(tmp_path))
    cache.raw_block(700)

    path = _cache_path(str(tmp_path), 700)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("{not json")

    assert cache.raw_block(700).block_hash == record.block_hash
    assert inner.fetches == 2  # refetched, not trusted


def test_a_stale_schema_is_ignored(tmp_path):
    record = _raw_block(700)
    inner = StubRawSource({700: record})
    cache = RawCachedSource(inner, str(tmp_path))
    cache.raw_block(700)

    path = _cache_path(str(tmp_path), 700)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload["schema"] = RAW_CACHE_SCHEMA + 1
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)

    cache.raw_block(700)
    assert inner.fetches == 2


def test_a_tampered_cache_entry_fails_its_own_merkle_check(tmp_path):
    """The cache is not a trusted store either -- it is re-checked on read."""
    record = _raw_block(700)
    inner = StubRawSource({700: record})
    cache = RawCachedSource(inner, str(tmp_path))
    cache.raw_block(700)

    other, _prevouts = build_signed_tx(D, [K + 5], funding=[(b"\x77" * 32, 0)])
    path = _cache_path(str(tmp_path), 700)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload["txs"] = [other.serialize().hex()]
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)

    cache.raw_block(700)
    assert inner.fetches == 2  # the swap was caught and the entry refetched


# --------------------------------------------------------------------------- #
# Ranges
# --------------------------------------------------------------------------- #


def test_iter_raw_blocks_walks_backwards_one_request_per_block():
    """The optimisation: only the top block is resolved by height, and every
    other is fetched by the id its successor's header already gave us."""
    first = _raw_block(100)
    chained = _raw_block(101, prev=block_hash(first.header))

    source = StubRawSource({100: first, 101: chained})
    walked = list(iter_raw_blocks(source, 100, 101))

    assert [r.height for r in walked] == [101, 100]  # descending, by design
    assert source.fetches == 2  # not 4: no height lookups after the first


def test_a_range_that_does_not_chain_cannot_be_walked_at_all():
    """Contiguity is structural now. A block is fetched *because* its successor
    named it, so a detached predecessor is not a mismatch we notice afterwards --
    it is a block the source was never asked for and cannot supply."""
    detached = _raw_block(101)  # prev_hash points at all-zeroes, not block 100

    broken = StubRawSource({100: _raw_block(100), 101: detached})
    with pytest.raises(SourceError, match="unknown block"):
        list(iter_raw_blocks(broken, 100, 101))


def test_a_source_answering_with_the_wrong_block_is_caught():
    """The saving is not bought with trust: the record carries the id we asked
    for, and `check()` requires the header to hash to it."""
    first = _raw_block(100)
    chained = _raw_block(101, prev=block_hash(first.header))
    impostor = _raw_block(55)

    source = StubRawSource({100: first, 101: chained})
    source.by_hash[first.block_hash] = impostor  # same id, different block

    with pytest.raises(SourceError, match="hash to its own id"):
        list(iter_raw_blocks(source, 100, 101))


def test_prev_hash_is_reported_in_display_order():
    """The header stores it internal-order; fetching needs it reversed."""
    first = _raw_block(100)
    chained = _raw_block(101, prev=block_hash(first.header))
    assert chained.prev_hash == first.block_hash


def test_cached_blocks_reparse_identically(tmp_path):
    """Byte-level: what comes out of the cache serialises to what went in."""
    record = _raw_block(800)
    cache = RawCachedSource(StubRawSource({800: record}), str(tmp_path))
    cache.raw_block(800)

    reloaded = RawCachedSource(None, str(tmp_path)).raw_block(800)
    for original, restored in zip(record.txs, reloaded.txs):
        raw = original.serialize()
        assert restored.serialize() == raw
        assert parse_tx(raw).txid_hex == restored.txid_hex
