"""The positive control, as a permanent regression test.

Everything else in this suite proves the pipeline is internally consistent. This
one proves it *fires* -- on a real key, from real chain data, with no synthetic
step anywhere in the path. Without it, a clean run on any range is ambiguous: it
could mean the range is clean, or it could mean recovery is broken.

The whole path runs offline from the pinned transaction: parse -> classify ->
recompute the sighash from the prevout script -> ECDSA verify -> recover -> the
`d*G == Q` gate. A regression in any one of those turns this red.

**No private key appears in this file, and none is printed by these tests.** The
scalar is a local; what is asserted about it is that it reproduces the on-chain
public key, and that it never reaches a report. See `ingest/control.py` §9.
"""

import pytest

from fixtures_control import (
    ADDRESS,
    BLOCK_HEIGHT,
    PREVOUT_SCRIPTS,
    RAW_TX,
    REUSE_INPUTS,
    SHARED_R,
    TXID,
)
from qi_fingerprint.corpus import Signature
from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.address import address_from_pubkey_len
from qi_fingerprint.ingest.control import confirm_candidate
from qi_fingerprint.ingest.extract import PrevOut, extract_tx
from qi_fingerprint.ingest.hunt import find_candidates, scan_tx
from qi_fingerprint.ingest.sighash import legacy_sighash, sighash_to_z
from qi_fingerprint.ingest.sources import BlockRecord
from qi_fingerprint.ingest.tx import parse_tx
from qi_fingerprint.ingest.validate import assert_gate, validate
from qi_fingerprint.reuse import recover_by_reuse, recover_from_reuse
from qi_fingerprint.screen import screen
from qi_fingerprint.verify import ecdsa_verify, recovers_key

CURVE = get_curve("secp256k1")
QX, QY = REUSE_INPUTS[0][5], REUSE_INPUTS[0][6]


def _tx():
    return parse_tx(bytes.fromhex(RAW_TX))


def _prevouts():
    return [PrevOut(0, bytes.fromhex(spk)) for spk in PREVOUT_SCRIPTS]


def _extracted():
    sigs, skips = extract_tx(_tx(), _prevouts(), BLOCK_HEIGHT)
    assert skips == []
    return sigs


class _OneBlock:
    """A source holding just the pinned transaction."""

    def block(self, height: int) -> BlockRecord:
        assert height == BLOCK_HEIGHT
        return BlockRecord(
            height, "0" * 64, b"\x00" * 80, [(_tx(), _prevouts())]
        )


# --------------------------------------------------------------------------- #
# The chain data is what it claims to be
# --------------------------------------------------------------------------- #


def test_the_transaction_hashes_to_its_pinned_txid():
    assert _tx().txid_hex == TXID


def test_both_inputs_share_one_r():
    """The finding itself: one nonce, two signatures, one key."""
    sigs = _extracted()
    assert len(sigs) == 2
    assert sigs[0].r == sigs[1].r == SHARED_R
    assert sigs[0].s != sigs[1].s
    assert (sigs[0].qx, sigs[0].qy) == (sigs[1].qx, sigs[1].qy) == (QX, QY)


def test_the_sighashes_are_distinct():
    """Two different messages under one nonce -- without that there is no
    information to recover from."""
    sigs = _extracted()
    assert sigs[0].z != sigs[1].z


@pytest.mark.parametrize("index,hashtype,r,s,z,qx,qy,pubkey_len,low_s", REUSE_INPUTS)
def test_each_signature_verifies_against_its_recomputed_sighash(
    index, hashtype, r, s, z, qx, qy, pubkey_len, low_s
):
    """The oracle: z is right only if the on-chain signature verifies against it."""
    computed = sighash_to_z(
        legacy_sighash(_tx(), index, bytes.fromhex(PREVOUT_SCRIPTS[index]), hashtype)
    )
    assert computed == z
    assert ecdsa_verify(z, r, s, CURVE.point(qx, qy), CURVE)


def test_the_address_matches_the_one_that_was_spent_from():
    assert address_from_pubkey_len(QX, QY, 65) == ADDRESS


# --------------------------------------------------------------------------- #
# The pipeline fires
# --------------------------------------------------------------------------- #


def test_the_scan_finds_it():
    candidates = find_candidates(scan_tx(_tx(), BLOCK_HEIGHT))
    assert len(candidates) == 1
    assert candidates[0].r == SHARED_R
    assert [s.vin for s in candidates[0].sites] == [0, 1]


def test_screen_flags_the_collision():
    from qi_fingerprint.corpus import Corpus, KeyRecord

    sigs = _extracted()
    corpus = Corpus(curve="secp256k1")
    corpus.keys.append(KeyRecord(key_id=0, curve="secp256k1", Qx=QX, Qy=QY))
    corpus.signatures.extend(Signature(0, s.z, s.r, s.s) for s in sigs)
    assert screen(corpus).n_r_collisions >= 1


def test_the_gate_passes_on_both_inputs():
    verified, report = validate(_extracted(), CURVE)
    assert report.pass_rate == 1.0
    assert len(verified) == 2
    assert_gate(report)


def test_the_key_is_recovered_and_satisfies_d_times_G_equals_Q():
    """The control. A real private key, recomputed from public data alone."""
    a, b = _extracted()
    Q = CURVE.point(QX, QY)

    d = recover_from_reuse(
        CURVE, Signature(0, a.z, a.r, a.s), Signature(0, b.z, b.r, b.s), Q
    )
    assert d is not None
    assert recovers_key(d, Q, CURVE)  # d*G == Q, against the on-chain public key
    assert CURVE.pubkey(d) == Q


def test_recover_by_reuse_finds_it_without_being_told_which_pair():
    sigs = [Signature(0, s.z, s.r, s.s) for s in _extracted()]
    Q = CURVE.point(QX, QY)
    assert recovers_key(recover_by_reuse(CURVE, sigs, Q), Q, CURVE)


def test_confirm_candidate_reports_it_end_to_end():
    candidate = find_candidates(scan_tx(_tx(), BLOCK_HEIGHT))[0]
    result = confirm_candidate(candidate, _OneBlock(), CURVE)

    assert result.recovered
    assert result.addresses == (ADDRESS,)
    assert result.provenance == ((TXID, 0), (TXID, 1))
    assert result.detail == "same-sign pair"  # both signatures are low-s here


# --------------------------------------------------------------------------- #
# ...and the key does not escape
# --------------------------------------------------------------------------- #


def test_the_recovered_key_appears_in_no_report():
    """§9 checked against the real key rather than a synthetic stand-in."""
    a, b = _extracted()
    Q = CURVE.point(QX, QY)
    d = recover_from_reuse(
        CURVE, Signature(0, a.z, a.r, a.s), Signature(0, b.z, b.r, b.s), Q
    )
    assert d is not None

    candidate = find_candidates(scan_tx(_tx(), BLOCK_HEIGHT))[0]
    rendered = "\n".join(
        [confirm_candidate(candidate, _OneBlock(), CURVE).format(), repr(candidate)]
    )
    for encoding in (f"{d:x}", f"{d:064x}", str(d)):
        assert encoding.lower() not in rendered.lower()


def test_the_pinned_fixture_contains_no_private_key():
    """A fixture is committed, indexed and mirrored forever. This one holds only
    what the chain already publishes -- if that ever stops being true, fail."""
    import pathlib

    import fixtures_control

    a, b = _extracted()
    Q = CURVE.point(QX, QY)
    d = recover_from_reuse(
        CURVE, Signature(0, a.z, a.r, a.s), Signature(0, b.z, b.r, b.s), Q
    )
    body = pathlib.Path(fixtures_control.__file__).read_text(encoding="utf-8").lower()
    for encoding in (f"{d:x}", f"{d:064x}", str(d)):
        assert encoding not in body
