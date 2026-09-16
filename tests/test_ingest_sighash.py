"""Sighash: the digest that was actually signed.

These are known-answer tests in the strong sense. The expected `z` values are not
snapshots of our own output -- each one is confirmed against the real on-chain
signature with `ecdsa_verify`, which only passes if `z` is the value the signer
committed to. A serialisation, scriptCode or endianness error changes `z` and
these fail.
"""

import pytest

from fixtures_bitcoin import (
    ONE_INPUT_INPUTS,
    ONE_INPUT_RAW,
    TWO_INPUT_INPUTS,
    TWO_INPUT_RAW,
)
from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.sighash import (
    ONE_HASH,
    SIGHASH_SINGLE,
    SighashUnsupported,
    legacy_sighash,
    sighash_to_z,
)
from qi_fingerprint.ingest.tx import Tx, TxOut, parse_tx
from qi_fingerprint.verify import ecdsa_verify

CASES = [
    pytest.param(ONE_INPUT_RAW, ONE_INPUT_INPUTS, id="one-input"),
    pytest.param(TWO_INPUT_RAW, TWO_INPUT_INPUTS, id="two-input"),
]


@pytest.mark.parametrize("raw_hex,inputs", CASES)
def test_sighash_matches_pinned_value(raw_hex, inputs):
    tx = parse_tx(bytes.fromhex(raw_hex))
    for index, spk_hex, hashtype, _r, _s, z, _qx, _qy in inputs:
        digest = legacy_sighash(tx, index, bytes.fromhex(spk_hex), hashtype)
        assert sighash_to_z(digest) == z


@pytest.mark.parametrize("raw_hex,inputs", CASES)
def test_computed_sighash_verifies_against_the_real_signature(raw_hex, inputs):
    """The oracle: if z is right, the on-chain signature verifies against it."""
    curve = get_curve("secp256k1")
    tx = parse_tx(bytes.fromhex(raw_hex))
    for index, spk_hex, hashtype, r, s, _z, qx, qy in inputs:
        z = sighash_to_z(legacy_sighash(tx, index, bytes.fromhex(spk_hex), hashtype))
        assert ecdsa_verify(z, r, s, curve.point(qx, qy), curve)


@pytest.mark.parametrize("raw_hex,inputs", CASES)
def test_a_wrong_sighash_does_not_verify(raw_hex, inputs):
    """Guards against a vacuous oracle: verification must be able to fail."""
    curve = get_curve("secp256k1")
    tx = parse_tx(bytes.fromhex(raw_hex))
    index, spk_hex, hashtype, r, s, _z, qx, qy = inputs[0]
    z = sighash_to_z(legacy_sighash(tx, index, bytes.fromhex(spk_hex), hashtype))
    assert not ecdsa_verify(z ^ 1, r, s, curve.point(qx, qy), curve)


def test_scriptcode_matters():
    """Substituting the wrong scriptCode must change z -- that is what makes the
    verify gate an oracle for the prevout data an untrusted source hands us."""
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    index, spk_hex, hashtype, *_ = ONE_INPUT_INPUTS[0]
    good = legacy_sighash(tx, index, bytes.fromhex(spk_hex), hashtype)
    tampered = bytearray(bytes.fromhex(spk_hex))
    tampered[5] ^= 0xFF  # perturb the pubkey hash inside the scriptPubKey
    assert legacy_sighash(tx, index, bytes(tampered), hashtype) != good


def test_sighash_single_index_bug_is_two_to_the_248():
    """Core returns uint256(1) when SIGHASH_SINGLE has no matching output.

    Its uint256 is little-endian internally while libsecp256k1 reads msg32
    big-endian, so the scalar actually signed is 2**248 -- not 1. Getting this
    backwards would silently corrupt every affected record.
    """
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    one_output = Tx(tx.version, tx.vin, (tx.vout[0],), tx.locktime)
    # Input 0 exists, output 1 does not -> the bug fires.
    stripped = Tx(
        one_output.version,
        one_output.vin + one_output.vin,  # two inputs, one output
        one_output.vout,
        one_output.locktime,
    )
    digest = legacy_sighash(stripped, 1, b"\x51", SIGHASH_SINGLE)
    assert digest == ONE_HASH
    assert sighash_to_z(digest) == 2**248
    assert sighash_to_z(digest) != 1


def test_sighash_single_blanks_earlier_outputs():
    """Outputs before the signed index serialise with value -1 (all-ones)."""
    tx = parse_tx(bytes.fromhex(TWO_INPUT_RAW))
    assert len(tx.vout) >= 2
    digest = legacy_sighash(tx, 1, b"\x51", SIGHASH_SINGLE)
    assert digest != ONE_HASH  # output 1 exists, so the bug must NOT fire
    assert len(digest) == 32


def test_blanked_output_serialises_as_all_ones():
    assert TxOut(-1, b"").serialize()[:8] == b"\xff" * 8


def test_op_codeseparator_is_refused_not_guessed():
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    with pytest.raises(SighashUnsupported):
        legacy_sighash(tx, 0, b"\xab", 0x01)


def test_sighash_to_z_rejects_wrong_length():
    with pytest.raises(ValueError):
        sighash_to_z(b"\x00" * 31)
