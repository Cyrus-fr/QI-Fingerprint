"""The ingest gate.

This is the test that matters most. On real data there is no ground truth, so
`ecdsa_verify` is the only oracle we have -- and an oracle that cannot fail is
worse than none, because it makes a broken extractor look perfect. These tests
prove the gate can fail, does fail on corrupted input, and refuses to hand back a
corpus when it does.
"""

import pytest

from fixtures_bitcoin import ONE_INPUT_INPUTS, ONE_INPUT_RAW, TWO_INPUT_INPUTS, TWO_INPUT_RAW
from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.extract import ExtractedSig, PrevOut, extract_tx
from qi_fingerprint.ingest.tx import parse_tx
from qi_fingerprint.ingest.validate import (
    IngestGateError,
    Stratum,
    assert_gate,
    gate_self_test,
    stratum_of,
    validate,
)


def _sig(z, *, hashtype=0x01, script_type="p2pkh", src=ONE_INPUT_INPUTS[0]):
    index, _spk, _ht, r, s, _z, qx, qy = src
    return ExtractedSig(
        height=250000,
        txid="f" * 64,
        vin=index,
        script_type=script_type,
        sigversion="legacy",
        hashtype=hashtype,
        r=r,
        s=s,
        z=z,
        qx=qx,
        qy=qy,
        pubkey_len=65,
        low_s=False,
    )


def test_self_test_passes_on_a_working_verifier():
    gate_self_test(get_curve("secp256k1"))


def test_extracting_the_real_fixture_gives_a_perfect_rate():
    tx = parse_tx(bytes.fromhex(TWO_INPUT_RAW))
    prevouts = [
        PrevOut(0, bytes.fromhex(spk)) for _i, spk, _ht, _r, _s, _z, _qx, _qy in TWO_INPUT_INPUTS
    ]
    sigs, skips = extract_tx(tx, prevouts, 250000)

    assert len(sigs) == len(TWO_INPUT_INPUTS)
    assert skips == []

    kept, report = validate(sigs)
    assert report.attempted == len(sigs)
    assert report.pass_rate == 1.0
    assert len(kept) == len(sigs)
    assert_gate(report)  # must not raise


def test_a_wrong_z_is_dropped_not_written():
    good = _sig(ONE_INPUT_INPUTS[0][5])
    bad = _sig(ONE_INPUT_INPUTS[0][5] ^ 1)

    kept, report = validate([good, bad])

    assert report.attempted == 2
    assert report.passed == 1
    assert kept == [good]  # the bad record never reaches the corpus
    assert report.failures  # and it is reported, not silently swallowed


def test_gate_raises_below_the_threshold():
    _kept, report = validate([_sig(ONE_INPUT_INPUTS[0][5] ^ 1)])
    with pytest.raises(IngestGateError, match="pass rate"):
        assert_gate(report)


def test_gate_denominator_is_attempted_not_total_inputs():
    """Skips must not dilute the rate -- a large skip count would otherwise let a
    genuinely broken stratum hide behind it."""
    _kept, report = validate([_sig(ONE_INPUT_INPUTS[0][5])])
    report.skipped = {"unsupported_type:v1_p2tr": 10_000}
    assert report.pass_rate == 1.0
    assert_gate(report)


def test_a_failing_stratum_fails_even_at_high_global_rate():
    """The reason per-stratum gating exists: '99.8% global' conceals
    'every SIGHASH_NONE input failed'."""
    good_z = ONE_INPUT_INPUTS[0][5]
    good = [_sig(good_z) for _ in range(1000)]
    # 25 records in their own stratum, all wrong.
    bad = [_sig(good_z ^ 1, hashtype=0x02) for _ in range(25)]

    _kept, report = validate(good + bad)

    assert report.pass_rate > 0.97  # global looks healthy
    none_stratum = Stratum("p2pkh", "legacy", 0x02, False)
    assert report.per_stratum[none_stratum].rate == 0.0

    with pytest.raises(IngestGateError, match="stratum"):
        assert_gate(report, min_rate=0.95)


def test_small_strata_are_not_gated_alone():
    """One odd record in a 3-record bucket should not fail the whole run; the
    global gate still catches it."""
    good_z = ONE_INPUT_INPUTS[0][5]
    records = [_sig(good_z) for _ in range(100)] + [_sig(good_z ^ 1, hashtype=0x03)]
    _kept, report = validate(records)
    with pytest.raises(IngestGateError, match="pass rate"):
        assert_gate(report)  # fails globally...
    assert_gate(report, min_rate=0.9, min_stratum_n=20)  # ...but not per-stratum


def test_empty_run_is_a_failure_not_a_pass():
    _kept, report = validate([])
    with pytest.raises(IngestGateError, match="no inputs"):
        assert_gate(report)


def test_stratum_buckets_split_on_sighash_type_and_anyonecanpay():
    assert stratum_of(_sig(1, hashtype=0x01)) != stratum_of(_sig(1, hashtype=0x02))
    assert stratum_of(_sig(1, hashtype=0x01)) != stratum_of(_sig(1, hashtype=0x81))


def test_corrupted_prevout_script_breaks_the_gate():
    """End-to-end: a tampered prevout scriptPubKey -- exactly what a hostile or
    buggy data source would supply -- changes the scriptCode, changes z, and the
    gate refuses the run."""
    tx = parse_tx(bytes.fromhex(ONE_INPUT_RAW))
    spk = bytearray(bytes.fromhex(ONE_INPUT_INPUTS[0][1]))
    spk[5] ^= 0xFF

    sigs, _skips = extract_tx(tx, [PrevOut(0, bytes(spk))], 250000)
    _kept, report = validate(sigs)

    assert report.pass_rate == 0.0
    with pytest.raises(IngestGateError):
        assert_gate(report)
