"""E gate (known answers): SegWit v0 and P2PK extraction, on real chain data.

`test_ingest_bip143.py` covers the structure. This file is the part that can
actually be wrong in a way structure cannot catch: whether the digest we compute
is the digest somebody else signed. The oracle is `ecdsa_verify` -- if the
serialisation, the scriptCode, the amount or the endianness is off, ``z`` changes
and a real signature stops verifying.

That oracle is only meaningful if it can fail, so every case here is paired with
a perturbation that must break it.
"""

from __future__ import annotations

import pytest

from fixtures_segwit import (
    P2PK_HEIGHT,
    P2PK_PREVOUT_SPK,
    P2PK_RAW,
    P2PK_TXID,
    P2SH_P2WPKH_AMOUNT,
    P2SH_P2WPKH_HEIGHT,
    P2SH_P2WPKH_PREVOUT_SPK,
    P2SH_P2WPKH_RAW,
    P2SH_P2WPKH_REDEEM,
    P2SH_P2WPKH_TXID,
    P2SH_P2WPKH_Z,
    P2WPKH_AMOUNT,
    P2WPKH_HEIGHT,
    P2WPKH_PREVOUT_SPK,
    P2WPKH_RAW,
    P2WPKH_TXID,
    P2WPKH_Z,
)
from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.address import hash160
from qi_fingerprint.ingest.extract import PrevOut, classify_input, extract_tx
from qi_fingerprint.ingest.hunt import scan_tx
from qi_fingerprint.ingest.tx import parse_tx
from qi_fingerprint.ingest.validate import assert_gate, validate
from qi_fingerprint.verify import ecdsa_verify

CURVE = get_curve("secp256k1")

#: (name, raw, prevout spk, amount, height, expected script_type, expected sigversion)
CASES = [
    ("p2wpkh", P2WPKH_RAW, P2WPKH_PREVOUT_SPK, P2WPKH_AMOUNT, P2WPKH_HEIGHT,
     "v0_p2wpkh", "witness_v0"),
    ("p2sh_p2wpkh", P2SH_P2WPKH_RAW, P2SH_P2WPKH_PREVOUT_SPK, P2SH_P2WPKH_AMOUNT,
     P2SH_P2WPKH_HEIGHT, "p2sh_p2wpkh", "witness_v0"),
    ("p2pk", P2PK_RAW, P2PK_PREVOUT_SPK, 0, P2PK_HEIGHT, "p2pk", "legacy"),
]
IDS = [case[0] for case in CASES]


def _extract(raw: str, spk: str, amount: int, height: int):
    tx = parse_tx(bytes.fromhex(raw))
    sigs, skips = extract_tx(tx, [PrevOut(amount, bytes.fromhex(spk))], height)
    return tx, sigs, skips


# --------------------------------------------------------------------------- #
# The fixtures are what they claim to be
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name,raw,spk,amount,height,_st,_sv", CASES, ids=IDS)
def test_the_transaction_round_trips_and_hashes_to_its_pinned_txid(
    name, raw, spk, amount, height, _st, _sv
):
    tx = parse_tx(bytes.fromhex(raw))
    assert tx.serialize(witness=True) == bytes.fromhex(raw)
    expected = {"p2wpkh": P2WPKH_TXID, "p2sh_p2wpkh": P2SH_P2WPKH_TXID, "p2pk": P2PK_TXID}
    assert tx.txid_hex == expected[name]


@pytest.mark.parametrize("name,raw,spk,amount,height,script_type,_sv", CASES, ids=IDS)
def test_the_input_is_classified_correctly(
    name, raw, spk, amount, height, script_type, _sv
):
    tx = parse_tx(bytes.fromhex(raw))
    txin = tx.vin[0]
    assert classify_input(bytes.fromhex(spk), txin.script_sig, txin.witness) == script_type


def test_the_wrapped_redeem_script_hashes_to_the_p2sh_it_opens():
    """A P2SH-P2WPKH scriptSig claims to open a specific script; if it does not,
    the key hash we would build the scriptCode from is not the right one."""
    redeem = bytes.fromhex(P2SH_P2WPKH_REDEEM)
    spk = bytes.fromhex(P2SH_P2WPKH_PREVOUT_SPK)
    assert hash160(redeem) == spk[2:22]


# --------------------------------------------------------------------------- #
# The digests -- known answers, confirmed by a signature we did not make
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name,raw,spk,amount,height,script_type,sigversion", CASES, ids=IDS)
def test_every_signature_verifies_against_its_recomputed_digest(
    name, raw, spk, amount, height, script_type, sigversion
):
    _tx, sigs, skips = _extract(raw, spk, amount, height)
    assert skips == [], f"{name}: {[s.reason for s in skips]}"
    assert len(sigs) == 1

    sig = sigs[0]
    assert sig.script_type == script_type
    assert sig.sigversion == sigversion
    Q = CURVE.point(sig.qx, sig.qy)
    assert ecdsa_verify(sig.z, sig.r, sig.s, Q, CURVE)


@pytest.mark.parametrize(
    "raw,spk,amount,height,expected_z",
    [
        (P2WPKH_RAW, P2WPKH_PREVOUT_SPK, P2WPKH_AMOUNT, P2WPKH_HEIGHT, P2WPKH_Z),
        (P2SH_P2WPKH_RAW, P2SH_P2WPKH_PREVOUT_SPK, P2SH_P2WPKH_AMOUNT,
         P2SH_P2WPKH_HEIGHT, P2SH_P2WPKH_Z),
    ],
    ids=["p2wpkh", "p2sh_p2wpkh"],
)
def test_the_digest_matches_the_pinned_value(raw, spk, amount, height, expected_z):
    _tx, sigs, _skips = _extract(raw, spk, amount, height)
    assert sigs[0].z == expected_z


@pytest.mark.parametrize("name,raw,spk,amount,height,_st,_sv", CASES, ids=IDS)
def test_a_tampered_digest_does_not_verify(name, raw, spk, amount, height, _st, _sv):
    """Without this the oracle could be vacuous -- a verifier that always says
    yes would make every case above pass."""
    _tx, sigs, _skips = _extract(raw, spk, amount, height)
    sig = sigs[0]
    Q = CURVE.point(sig.qx, sig.qy)
    assert not ecdsa_verify(sig.z ^ 1, sig.r, sig.s, Q, CURVE)


@pytest.mark.parametrize(
    "raw,spk,amount,height",
    [
        (P2WPKH_RAW, P2WPKH_PREVOUT_SPK, P2WPKH_AMOUNT, P2WPKH_HEIGHT),
        (P2SH_P2WPKH_RAW, P2SH_P2WPKH_PREVOUT_SPK, P2SH_P2WPKH_AMOUNT, P2SH_P2WPKH_HEIGHT),
    ],
    ids=["p2wpkh", "p2sh_p2wpkh"],
)
def test_one_satoshi_of_amount_error_breaks_verification(raw, spk, amount, height):
    """BIP143's defining property, on real data: the digest commits to the value
    of the output being spent. This is also why the legacy path never needed
    prevout *values* and the witness path cannot work without them."""
    _tx, sigs, _skips = _extract(raw, spk, amount + 1, height)
    sig = sigs[0]
    Q = CURVE.point(sig.qx, sig.qy)
    assert not ecdsa_verify(sig.z, sig.r, sig.s, Q, CURVE)


# --------------------------------------------------------------------------- #
# Through the gate, and through the hunt
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name,raw,spk,amount,height,_st,_sv", CASES, ids=IDS)
def test_the_ingest_gate_passes_on_each_new_input_type(
    name, raw, spk, amount, height, _st, _sv
):
    _tx, sigs, _skips = _extract(raw, spk, amount, height)
    verified, report = validate(sigs, CURVE)
    assert_gate(report)
    assert len(verified) == 1
    assert report.pass_rate == 1.0


def test_a_corrupted_amount_makes_the_gate_refuse_to_write():
    """The gate is what turns a wrong z into a refusal rather than a corpus."""
    from qi_fingerprint.ingest.validate import IngestGateError

    _tx, sigs, _skips = _extract(
        P2WPKH_RAW, P2WPKH_PREVOUT_SPK, P2WPKH_AMOUNT + 1, P2WPKH_HEIGHT
    )
    _verified, report = validate(sigs, CURVE)
    with pytest.raises(IngestGateError):
        assert_gate(report)


@pytest.mark.parametrize(
    "name,raw,height,findable",
    [
        ("p2wpkh", P2WPKH_RAW, P2WPKH_HEIGHT, True),
        ("p2sh_p2wpkh", P2SH_P2WPKH_RAW, P2SH_P2WPKH_HEIGHT, True),
        # P2PK keeps its public key in the PREVOUT, which the hunt never fetches.
        # Not an oversight -- a property of the input, and the reason P2PK is an
        # ingest-only type.
        ("p2pk", P2PK_RAW, P2PK_HEIGHT, False),
    ],
    ids=["p2wpkh", "p2sh_p2wpkh", "p2pk"],
)
def test_the_prevout_free_hunt_sees_witness_inputs_but_not_p2pk(
    name, raw, height, findable
):
    sites = scan_tx(parse_tx(bytes.fromhex(raw)), height)
    assert bool(sites) is findable


def test_the_hunt_and_the_extractor_agree_on_the_witness_signature():
    """The scan reads (r, s, Q) straight from the witness; the extractor derives
    the same values the long way, through the prevout. They must not diverge, or
    a candidate would not survive its own confirmation."""
    tx, sigs, _skips = _extract(
        P2WPKH_RAW, P2WPKH_PREVOUT_SPK, P2WPKH_AMOUNT, P2WPKH_HEIGHT
    )
    site = scan_tx(tx, P2WPKH_HEIGHT)[0]
    sig = sigs[0]
    assert (site.r, site.s, site.qx, site.qy) == (sig.r, sig.s, sig.qx, sig.qy)
