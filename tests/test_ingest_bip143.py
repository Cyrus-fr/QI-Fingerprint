"""E gate (structure): BIP143 differs from legacy in ways that must be exercised.

A synthetic SegWit signature cannot validate this module. Signing a digest we
computed ourselves and then verifying against it passes whatever the digest was
-- the arithmetic is consistent with itself. Only a *real* signature made by
someone else pins the algorithm, and those live in `tests/fixtures_segwit.py`.

What this file covers is the structure: the places BIP143 deliberately departs
from the legacy rules, each of which is a way to be silently wrong.
"""

from __future__ import annotations

import pytest

from qi_fingerprint.ingest.codec import OP_CODESEPARATOR
from qi_fingerprint.ingest.sighash import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SighashUnsupported,
    bip143_sighash,
    legacy_sighash,
    p2wpkh_script_code,
    sighash_to_z,
)
from qi_fingerprint.ingest.tx import OutPoint, Tx, TxIn, TxOut

KEYHASH = bytes(range(20))
SCRIPT_CODE = p2wpkh_script_code(KEYHASH)
AMOUNT = 600_000_000


def _tx(n_in: int = 2, n_out: int = 2) -> Tx:
    return Tx(
        version=1,
        vin=tuple(
            TxIn(OutPoint(bytes([i + 1]) * 32, i), b"", 0xFFFFFFFE) for i in range(n_in)
        ),
        vout=tuple(TxOut(50_000 * (i + 1), b"\x51") for i in range(n_out)),
        locktime=17,
        has_witness=True,
    )


# --------------------------------------------------------------------------- #
# The scriptCode
# --------------------------------------------------------------------------- #


def test_the_script_code_is_the_bare_script_without_its_length_byte():
    """The spec writes it 0x1976a914..88ac; that 0x19 is the length prefix the
    preimage adds. Carrying it inside the value hashes 26 bytes where 25 were
    meant, and the result verifies against nothing."""
    assert len(SCRIPT_CODE) == 25
    assert SCRIPT_CODE[:3] == b"\x76\xa9\x14"
    assert SCRIPT_CODE[-2:] == b"\x88\xac"
    assert SCRIPT_CODE[3:23] == KEYHASH


@pytest.mark.parametrize("length", [0, 19, 21, 32])
def test_a_key_hash_of_the_wrong_length_is_refused(length):
    with pytest.raises(ValueError):
        p2wpkh_script_code(bytes(length))


# --------------------------------------------------------------------------- #
# The amount -- the defining difference from legacy
# --------------------------------------------------------------------------- #


def test_only_the_segwit_digest_depends_on_the_input_amount():
    """*The* BIP143 change, and the reason a source without prevout values cannot
    support SegWit at all.

    Legacy takes no amount argument -- there is nothing to vary, which is exactly
    the point -- so the contrast is drawn against the pair of BIP143 digests: two
    amounts give two different digests, and the single legacy digest over the
    same transaction is neither of them.
    """
    tx = _tx()
    cheap = bip143_sighash(tx, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL)
    dear = bip143_sighash(tx, 0, SCRIPT_CODE, AMOUNT * 2, SIGHASH_ALL)
    legacy = legacy_sighash(tx, 0, SCRIPT_CODE, SIGHASH_ALL)

    assert cheap != dear
    assert legacy != cheap and legacy != dear


def test_a_negative_amount_is_refused():
    with pytest.raises(ValueError):
        bip143_sighash(_tx(), 0, SCRIPT_CODE, -1, SIGHASH_ALL)


# --------------------------------------------------------------------------- #
# No SIGHASH_SINGLE index bug
# --------------------------------------------------------------------------- #


def test_single_past_the_last_output_has_no_index_bug():
    """Legacy returns the constant 1 (as 2**248 once read big-endian). BIP143
    just zeroes hashOutputs, so a short-circuit here would be wrong."""
    tx = _tx(n_in=3, n_out=1)
    digest = bip143_sighash(tx, 2, SCRIPT_CODE, AMOUNT, SIGHASH_SINGLE)
    z = sighash_to_z(digest)
    assert z != 2**248
    assert z != 1


def test_the_legacy_index_bug_still_fires_where_it_should():
    """Guards the contrast: the legacy quirk must not be 'fixed' by accident."""
    tx = _tx(n_in=3, n_out=1)
    assert sighash_to_z(legacy_sighash(tx, 2, SCRIPT_CODE, SIGHASH_SINGLE)) == 2**248


def test_single_within_range_commits_to_only_its_own_output():
    tx = _tx(n_in=2, n_out=2)
    first = bip143_sighash(tx, 0, SCRIPT_CODE, AMOUNT, SIGHASH_SINGLE)
    second = bip143_sighash(tx, 1, SCRIPT_CODE, AMOUNT, SIGHASH_SINGLE)
    assert first != second


# --------------------------------------------------------------------------- #
# The three midstates
# --------------------------------------------------------------------------- #


def test_anyonecanpay_changes_the_digest():
    """It zeroes hashPrevouts and hashSequence, so the other inputs stop being
    committed to."""
    tx = _tx()
    plain = bip143_sighash(tx, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL)
    acp = bip143_sighash(tx, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL | SIGHASH_ANYONECANPAY)
    assert plain != acp


def test_anyonecanpay_ignores_the_other_inputs():
    """The property that makes it useful, and a check that the zeroing is real."""
    one = _tx(n_in=2)
    other = Tx(
        version=one.version,
        vin=(one.vin[0], TxIn(OutPoint(b"\x09" * 32, 7), b"", 0x11111111)),
        vout=one.vout,
        locktime=one.locktime,
        has_witness=True,
    )
    ht = SIGHASH_ALL | SIGHASH_ANYONECANPAY
    assert bip143_sighash(one, 0, SCRIPT_CODE, AMOUNT, ht) == bip143_sighash(
        other, 0, SCRIPT_CODE, AMOUNT, ht
    )
    # ...and without ACP the same change *is* committed to, or the test above
    # would pass for a digest that ignores the inputs entirely.
    assert bip143_sighash(one, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL) != bip143_sighash(
        other, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL
    )


def test_none_and_single_free_the_other_inputs_sequences():
    """Both zero hashSequence, so a changed nSequence elsewhere is not committed."""
    one = _tx(n_in=2)
    other = Tx(
        version=one.version,
        vin=(one.vin[0], TxIn(one.vin[1].prevout, b"", 0x00000001)),
        vout=one.vout,
        locktime=one.locktime,
        has_witness=True,
    )
    for base in (SIGHASH_NONE, SIGHASH_SINGLE):
        assert bip143_sighash(one, 0, SCRIPT_CODE, AMOUNT, base) == bip143_sighash(
            other, 0, SCRIPT_CODE, AMOUNT, base
        )
    # ALL does commit to them, which is what makes the above a real result.
    assert bip143_sighash(one, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL) != bip143_sighash(
        other, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL
    )


def test_none_does_not_commit_to_outputs():
    one = _tx(n_out=2)
    other = Tx(
        version=one.version,
        vin=one.vin,
        vout=(TxOut(999, b"\x52"),),
        locktime=one.locktime,
        has_witness=True,
    )
    assert bip143_sighash(one, 0, SCRIPT_CODE, AMOUNT, SIGHASH_NONE) == bip143_sighash(
        other, 0, SCRIPT_CODE, AMOUNT, SIGHASH_NONE
    )
    # ALL commits to the outputs; otherwise the equality above says nothing.
    assert bip143_sighash(one, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL) != bip143_sighash(
        other, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL
    )


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


def test_op_codeseparator_is_refused_rather_than_guessed_at():
    tainted = SCRIPT_CODE + bytes([OP_CODESEPARATOR])
    with pytest.raises(SighashUnsupported):
        bip143_sighash(_tx(), 0, tainted, AMOUNT, SIGHASH_ALL)


@pytest.mark.parametrize("index", [-1, 2, 99])
def test_an_out_of_range_input_index_raises(index):
    with pytest.raises(IndexError):
        bip143_sighash(_tx(n_in=2), index, SCRIPT_CODE, AMOUNT, SIGHASH_ALL)


def test_the_two_algorithms_do_not_agree():
    """A trivial-looking guard with a real purpose: if `bip143_sighash` ever fell
    through to the legacy preimage, every other test here would still pass."""
    tx = _tx()
    assert bip143_sighash(tx, 0, SCRIPT_CODE, AMOUNT, SIGHASH_ALL) != legacy_sighash(
        tx, 0, SCRIPT_CODE, SIGHASH_ALL
    )
