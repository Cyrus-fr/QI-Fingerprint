"""Transaction and block structure: round-trip, txid, merkle root, proof of work."""

import pytest

from fixtures_bitcoin import (
    BLOCK_HASH,
    BLOCK_HEADER_HEX,
    ONE_INPUT_RAW,
    ONE_INPUT_TXID,
    TWO_INPUT_RAW,
    TWO_INPUT_TXID,
)
from qi_fingerprint.ingest.tx import (
    block_hash,
    check_pow,
    header_fields,
    merkle_root,
    parse_tx,
    sha256d,
    target_from_bits,
)

CASES = [(ONE_INPUT_RAW, ONE_INPUT_TXID), (TWO_INPUT_RAW, TWO_INPUT_TXID)]


@pytest.mark.parametrize("raw_hex,txid", CASES)
def test_parse_serialize_roundtrip(raw_hex, txid):
    """The invariant the whole untrusted-source model rests on."""
    raw = bytes.fromhex(raw_hex)
    assert parse_tx(raw).serialize() == raw


@pytest.mark.parametrize("raw_hex,txid", CASES)
def test_recomputed_txid_matches(raw_hex, txid):
    assert parse_tx(bytes.fromhex(raw_hex)).txid_hex == txid


def test_trailing_bytes_rejected():
    from qi_fingerprint.ingest.codec import ParseError

    with pytest.raises(ParseError):
        parse_tx(bytes.fromhex(ONE_INPUT_RAW) + b"\x00")


def test_header_hashes_to_its_block_id():
    header = bytes.fromhex(BLOCK_HEADER_HEX)
    assert block_hash(header)[::-1].hex() == BLOCK_HASH


def test_header_meets_its_own_target():
    assert check_pow(bytes.fromhex(BLOCK_HEADER_HEX))


def test_mutated_header_fails_pow():
    """PoW is what makes a third-party block feed self-authenticating."""
    header = bytearray(bytes.fromhex(BLOCK_HEADER_HEX))
    header[-1] ^= 0xFF  # perturb the nonce
    assert not check_pow(bytes(header))


def test_target_from_bits_matches_known_encoding():
    # 0x1d00ffff is the genesis/max-difficulty target.
    assert target_from_bits(0x1D00FFFF) == 0x00FFFF * 256 ** (0x1D - 3)


def test_merkle_root_of_single_tx_is_that_tx():
    txid = sha256d(b"only")
    assert merkle_root([txid]) == txid


def test_merkle_root_duplicates_last_on_odd_count():
    a, b, c = sha256d(b"a"), sha256d(b"b"), sha256d(b"c")
    expected = sha256d(sha256d(a + b) + sha256d(c + c))
    assert merkle_root([a, b, c]) == expected


def test_header_fields_are_sane():
    fields = header_fields(bytes.fromhex(BLOCK_HEADER_HEX))
    assert len(fields["prev_hash"]) == 32
    assert len(fields["merkle_root"]) == 32
    assert fields["time"] > 1_300_000_000  # block 250,000 is well after 2011
