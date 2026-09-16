"""P2PKH address derivation.

The §9 safety rule reports a recovered key as an *address*, never as a scalar,
so a wrong address here would make a real finding uncheckable -- or point a
reader at somebody else's coins. Two independent anchors:

  * the genesis coinbase key, whose address is the most widely published
    constant in Bitcoin;
  * every P2PKH input in the pinned block-250,000 fixtures, where the pubkey in
    the scriptSig must hash to the pubkey-hash inside the output it spends.
    That one needs no external constant at all -- the chain checks itself.
"""

import pytest

from fixtures_bitcoin import ONE_INPUT_INPUTS, ONE_INPUT_RAW, TWO_INPUT_INPUTS, TWO_INPUT_RAW
from qi_fingerprint.ingest.address import (
    address_from_pubkey_len,
    b58encode,
    base58check,
    hash160,
    p2pkh_address,
    serialize_pubkey,
)
from qi_fingerprint.ingest.codec import script_pushes
from qi_fingerprint.ingest.tx import parse_tx

# The genesis block's coinbase output pays this key; the address is 1A1zP1eP...
GENESIS_QX = 0x678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB6
GENESIS_QY = 0x49F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5F
GENESIS_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

CASES = [
    pytest.param(ONE_INPUT_RAW, ONE_INPUT_INPUTS, id="one-input"),
    pytest.param(TWO_INPUT_RAW, TWO_INPUT_INPUTS, id="two-input"),
]


def test_ripemd160_is_available():
    """Guards the build: RIPEMD-160 is an OpenSSL legacy-provider algorithm."""
    assert len(hash160(b"")) == 20


def test_genesis_pubkey_gives_the_genesis_address():
    assert p2pkh_address(GENESIS_QX, GENESIS_QY, compressed=False) == GENESIS_ADDRESS


@pytest.mark.parametrize("raw_hex,inputs", CASES)
def test_pubkey_hashes_to_the_output_it_spends(raw_hex, inputs):
    """Self-authenticating: no memorised constant, just the chain agreeing with
    itself. A P2PKH scriptPubKey embeds hash160(pubkey) at bytes 3..23."""
    tx = parse_tx(bytes.fromhex(raw_hex))
    for index, spk_hex, _ht, _r, _s, _z, qx, qy in inputs:
        pubkey = script_pushes(tx.vin[index].script_sig)[1]
        assert hash160(pubkey) == bytes.fromhex(spk_hex)[3:23]
        # and our own serialisation reproduces those exact bytes
        assert serialize_pubkey(qx, qy, compressed=len(pubkey) == 33) == pubkey


@pytest.mark.parametrize("raw_hex,inputs", CASES)
def test_address_from_pubkey_len_matches_the_spent_output(raw_hex, inputs):
    tx = parse_tx(bytes.fromhex(raw_hex))
    for index, spk_hex, _ht, _r, _s, _z, qx, qy in inputs:
        pubkey = script_pushes(tx.vin[index].script_sig)[1]
        address = address_from_pubkey_len(qx, qy, len(pubkey))
        assert address == base58check(0x00, bytes.fromhex(spk_hex)[3:23])
        assert address[0] == "1"


def test_the_two_encodings_of_one_key_give_two_addresses():
    """Why `Confirmation` reports a tuple: the corpus groups by point, but a
    reader checking the finding on an explorer needs the right address."""
    compressed = p2pkh_address(GENESIS_QX, GENESIS_QY, compressed=True)
    assert compressed != GENESIS_ADDRESS
    assert compressed[0] == "1"


def test_leading_zero_bytes_become_ones():
    """The base58 convention that a naive integer encoding silently drops."""
    assert b58encode(b"\x00\x00\x01") == "11" + b58encode(b"\x01")
    assert base58check(0x00, bytes(20)).startswith("1" * 2)


def test_checksum_is_load_bearing():
    """A one-bit change to the payload must change the encoded address."""
    payload = bytearray(bytes.fromhex(ONE_INPUT_INPUTS[0][1])[3:23])
    good = base58check(0x00, bytes(payload))
    payload[7] ^= 0x01
    assert base58check(0x00, bytes(payload)) != good


def test_unexpected_pubkey_length_is_refused():
    with pytest.raises(ValueError):
        address_from_pubkey_len(GENESIS_QX, GENESIS_QY, 64)
