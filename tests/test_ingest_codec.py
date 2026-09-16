"""Byte-level decoding: varints, script pushes, DER signatures, public keys."""

import pytest

from fixtures_bitcoin import ONE_INPUT_INPUTS, ONE_INPUT_RAW
from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.codec import (
    ByteReader,
    DerError,
    ParseError,
    PubkeyError,
    parse_der_sig,
    parse_pubkey,
    push_data,
    script_has_op,
    script_pushes,
    write_varint,
)
from qi_fingerprint.ingest.tx import parse_tx


def test_varint_roundtrip():
    for value in (0, 1, 0xFC, 0xFD, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000):
        assert ByteReader(write_varint(value)).varint() == value


def test_reader_refuses_to_overrun():
    with pytest.raises(ParseError):
        ByteReader(b"\x01\x02").read(3)


def test_push_data_uses_minimal_encoding():
    assert push_data(b"\xaa" * 10)[0] == 10
    assert push_data(b"\xaa" * 0x4C)[0] == 0x4C  # OP_PUSHDATA1
    assert push_data(b"\xaa" * 0x100)[0] == 0x4D  # OP_PUSHDATA2


def test_script_pushes_rejects_non_push_scripts():
    # A P2PKH scriptPubKey starts with OP_DUP -- an opcode, not a push.
    spk = bytes.fromhex(ONE_INPUT_INPUTS[0][1])
    assert script_pushes(spk) is None


def test_script_has_op_ignores_pushed_data():
    # 0xab inside a pushed blob is data, not OP_CODESEPARATOR.
    assert not script_has_op(push_data(b"\xab" * 4), 0xAB)
    assert script_has_op(b"\xab", 0xAB)


def test_real_scriptsig_splits_into_signature_and_pubkey():
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    pushes = script_pushes(tx.vin[0].script_sig)
    assert pushes is not None and len(pushes) == 2

    _, _, hashtype, r, s, _, qx, qy = ONE_INPUT_INPUTS[0]
    assert parse_der_sig(pushes[0]) == (r, s, hashtype)
    assert parse_pubkey(pushes[1]) == (qx, qy)


def test_der_hashtype_is_the_final_byte():
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    element = script_pushes(tx.vin[0].script_sig)[0]
    assert parse_der_sig(element)[2] == element[-1]


@pytest.mark.parametrize(
    "element",
    [b"", b"\x30\x06\x02\x01\x01\x02\x01\x01", b"\x99" * 40],
)
def test_bad_der_raises(element):
    with pytest.raises(DerError):
        parse_der_sig(element)


def test_der_rejects_r_or_s_outside_range():
    n = get_curve("secp256k1").n
    # r = n is out of [1, n) and must be refused rather than passed downstream.
    body = b"\x02\x21\x00" + n.to_bytes(32, "big") + b"\x02\x01\x01"
    with pytest.raises(DerError):
        parse_der_sig(b"\x30" + bytes([len(body)]) + body + b"\x01")


def test_compressed_and_uncompressed_agree():
    """The whole reason grouping is by POINT and not by pubkey bytes."""
    curve = get_curve("secp256k1")
    point = curve.pubkey(0xC0FFEE)
    x, y = point.x, point.y

    uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    compressed = bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")

    assert parse_pubkey(uncompressed) == (x, y)
    assert parse_pubkey(compressed) == (x, y)


def test_generator_point_decompresses():
    curve = get_curve("secp256k1")
    G = curve.G
    compressed = bytes([0x02 | (G.y & 1)]) + G.x.to_bytes(32, "big")
    assert parse_pubkey(compressed) == (G.x, G.y)


def _off_curve_x() -> int:
    """Smallest x with no y, i.e. x**3 + 7 is a quadratic non-residue mod p.

    Computed rather than hardcoded: roughly HALF of all x values are valid curve
    points, so picking an arbitrary x and assuming it is off-curve is how you get
    a test that passes for the wrong reason.
    """
    from qi_fingerprint.ingest.codec import FIELD_P

    for x in range(1, 500):
        alpha = (pow(x, 3, FIELD_P) + 7) % FIELD_P
        if pow(alpha, (FIELD_P - 1) // 2, FIELD_P) != 1:  # Euler's criterion
            return x
    raise AssertionError("no off-curve x found in range")


def test_off_curve_x_is_rejected():
    x = _off_curve_x()
    with pytest.raises(PubkeyError):
        parse_pubkey(bytes([0x02]) + x.to_bytes(32, "big"))


def test_on_curve_x_is_accepted():
    """The complement of the above: an x that IS on the curve must decode."""
    curve = get_curve("secp256k1")
    G = curve.G
    assert parse_pubkey(bytes([0x02 | (G.y & 1)]) + G.x.to_bytes(32, "big")) == (G.x, G.y)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        bytes([0x04]) + bytes(64),
        bytes([0x02]) + bytes(20),
        bytes([0x05]) + bytes(32),
    ],
    ids=["empty", "zero-point", "wrong-length", "bad-prefix"],
)
def test_malformed_pubkey_raises(data):
    with pytest.raises(PubkeyError):
        parse_pubkey(data)
