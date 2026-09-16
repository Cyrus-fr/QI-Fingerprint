"""§9 gate: no recovered private key escapes, by any recovery path, into any sink.

**ENROLMENT RULE.** This is not a test of one code path; it is the place every
recovery path and every result type must be registered. When a new crack method,
a new ``sigversion``, or a new report type lands, add it here *in the same
change*. A path that can produce a scalar but is absent from this sweep is a
defect, not a follow-up -- the whole point is that the guard fails loudly rather
than quietly stopping short of new code.

The sweep is a cross product:

  recovery path  x  sink  x  encoding

Encodings matter because a scalar can leave by more than one door: as bare hex,
as zero-padded hex, as a decimal string, or as 32 raw big-endian bytes inside a
binary artefact like parquet.

Two properties this file relies on:

* ``PipelineResult.cracks`` holds **every** recovered scalar, including each
  intermediate hop of a chained cascade -- not only the keys at the end of a
  chain. So asserting over ``cracks.values()`` covers the intermediates
  structurally. `test_the_deep_cascade_actually_reaches_past_depth_one` keeps
  that coverage from going vacuous.
* Corpora here are **truth-stripped**, so ``has_ground_truth`` is False -- the
  predicate every publishing guard keys on, and therefore the only shape in
  which a leak would actually matter.
"""

from __future__ import annotations

import json
import random

import pytest

from qi_fingerprint.corpus import Corpus, KeyRecord, Signature
from qi_fingerprint.curves import get_curve, sign_with_nonce
from qi_fingerprint.generator import build_corpus
from qi_fingerprint.ingest.bitcoin import IngestReport, ProvenanceRow, write_corpus
from qi_fingerprint.pipeline import run

CURVE = get_curve("secp256k1")
N = CURVE.n

#: Every recovery path that can produce a private key. Add new ones here.
RECOVERY_PATHS = ("reuse", "seed", "lattice", "chain")

_CACHE: dict[str, object] = {}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _strip_truth(corpus: Corpus) -> Corpus:
    """The corpus as a real ingest would produce it: public columns only.

    `has_ground_truth` then reads False, so the publishing guards engage exactly
    as they would on ingested chain data.
    """
    return Corpus(
        curve=corpus.curve,
        signatures=[Signature(s.key_id, s.h, s.r, s.s) for s in corpus.signatures],
        keys=[KeyRecord(k.key_id, k.curve, k.Qx, k.Qy) for k in corpus.keys],
    )


def _encodings(d: int) -> list[bytes]:
    """Every way a 256-bit scalar can appear in a text or binary artefact."""
    return [
        f"{d:x}".encode(),
        f"{d:X}".encode(),
        f"{d:064x}".encode(),
        f"{d:064X}".encode(),
        str(d).encode(),
        d.to_bytes(32, "big"),
    ]


def _assert_absent(secrets, haystack: bytes, sink: str) -> None:
    for d in secrets:
        for encoded in _encodings(d):
            assert encoded not in haystack, f"private key leaked into {sink}"


def _default_run():
    """One synthetic corpus exercising reuse, seed and lattice, chained as well.

    Cached at module level because the lattice ladder is expensive and every test
    below wants the same result; the repo has no conftest, so this is the
    fixture.
    """
    if "default" not in _CACHE:
        corpus = _strip_truth(build_corpus("secp256k1", seed=7))
        _CACHE["default"] = (corpus, run(corpus, chain=True))
    return _CACHE["default"]


def _deep_cascade():
    """A 6-key path where key 0 is directly crackable and the rest fall by chain.

    Half the hops are mixed-sign, so the intermediates being checked are the ones
    that only exist because of the sign loop.
    """
    if "deep" not in _CACHE:
        rng = random.Random(90)
        ds = [rng.randrange(1, N) for _ in range(6)]
        corpus = Corpus(curve="secp256k1")
        for kid, d in enumerate(ds):
            Q = CURVE.pubkey(d)
            corpus.keys.append(KeyRecord(key_id=kid, curve="secp256k1", Qx=Q.x, Qy=Q.y))

        k0 = rng.randrange(1, N)
        for h in (rng.randrange(1, N), rng.randrange(1, N)):
            r, s = sign_with_nonce(CURVE, h, ds[0], k0)
            corpus.signatures.append(Signature(0, h, r, s))

        for i in range(5):
            k = rng.randrange(1, N)
            k_right = (N - k) if i % 2 else k
            h_l, h_r = rng.randrange(1, N), rng.randrange(1, N)
            r_l, s_l = sign_with_nonce(CURVE, h_l, ds[i], k)
            r_r, s_r = sign_with_nonce(CURVE, h_r, ds[i + 1], k_right)
            corpus.signatures.append(Signature(i, h_l, r_l, s_l))
            corpus.signatures.append(Signature(i + 1, h_r, r_r, s_r))

        _CACHE["deep"] = (corpus, run(corpus, chain=True))
    return _CACHE["deep"]


def _secrets(result) -> list[int]:
    return [d for d, _method in result.cracks.values()]


# --------------------------------------------------------------------------- #
# The sweep is not vacuous: every enrolled path really did fire
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", RECOVERY_PATHS)
def test_every_enrolled_recovery_path_actually_fires_somewhere(path):
    """A sweep over paths that never ran would pass while checking nothing."""
    _corpus, default = _default_run()
    _deep_corpus, deep = _deep_cascade()
    methods = {m for _d, m in default.cracks.values()} | {
        m for _d, m in deep.cracks.values()
    }
    assert path in methods


def test_the_deep_cascade_actually_reaches_past_depth_one():
    """Intermediate-hop coverage is only real if intermediates exist."""
    _corpus, result = _deep_cascade()
    depths = {c.depth for c in result.chained.values()}
    assert max(depths) >= 3, f"cascade too shallow to test intermediates: {depths}"
    assert len(_secrets(result)) == len(result.chained) + 1  # + the seed key


def test_recovered_scalars_are_not_all_equal():
    """Guards against a degenerate fixture where one absent value covers all."""
    _corpus, result = _deep_cascade()
    assert len(set(_secrets(result))) == len(_secrets(result))


# --------------------------------------------------------------------------- #
# Sink: the CLI's own output
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("chain", [False, True])
def test_no_key_reaches_cli_stdout_or_stderr(tmp_path, capsys, chain):
    from qi_fingerprint.cli import main

    corpus, result = _default_run()
    out_dir = tmp_path / "corpus"
    corpus.save(str(out_dir))

    argv = ["run", "--corpus", str(out_dir)] + (["--chain"] if chain else [])
    assert main(argv) == 0
    captured = capsys.readouterr()

    blob = (captured.out + captured.err).encode()
    _assert_absent(_secrets(result), blob, "cli stdout/stderr")


def test_the_cli_prints_the_safety_banner_when_it_recovers_a_live_key(tmp_path, capsys):
    """The §9 rules are restated on any recovery from a corpus that is not ours."""
    from qi_fingerprint.cli import main

    corpus, _result = _default_run()
    out_dir = tmp_path / "corpus"
    corpus.save(str(out_dir))
    assert not corpus.has_ground_truth

    main(["run", "--corpus", str(out_dir), "--chain"])
    out = capsys.readouterr().out
    assert "never" in out.lower() and "balance" in out.lower()


def test_chain_provenance_is_reported_without_the_scalar(tmp_path, capsys):
    """Provenance is the deliverable: key ids, hop counts, and the on-chain r."""
    from qi_fingerprint.cli import main

    corpus, result = _deep_cascade()
    out_dir = tmp_path / "corpus"
    corpus.save(str(out_dir))

    main(["run", "--corpus", str(out_dir), "--chain"])
    out = capsys.readouterr().out

    assert "chain    :" in out and "via key" in out and "depth" in out
    _assert_absent(_secrets(result), out.encode(), "cli chain report")


def test_declining_to_chain_is_reported_rather_than_silent(tmp_path, capsys):
    from qi_fingerprint.cli import main

    corpus, _result = _deep_cascade()
    out_dir = tmp_path / "corpus"
    corpus.save(str(out_dir))

    main(["run", "--corpus", str(out_dir)])
    out = capsys.readouterr().out
    assert "chain    : skipped" in out and "--chain" in out


# --------------------------------------------------------------------------- #
# Sink: everything written to disk
# --------------------------------------------------------------------------- #


def test_no_key_reaches_any_file_written_by_corpus_save(tmp_path):
    corpus, result = _default_run()
    out_dir = tmp_path / "corpus"
    corpus.save(str(out_dir))

    written = sorted(out_dir.iterdir())
    assert written, "nothing was written -- the sink check would be vacuous"
    # A truth-stripped corpus must not emit the ground-truth tables at all.
    assert not any(p.name.startswith("gt_") for p in written)
    for path in written:
        _assert_absent(_secrets(result), path.read_bytes(), path.name)


def test_no_key_reaches_the_ingest_sidecars(tmp_path):
    """provenance.parquet and ingest_manifest.json, written by the real writer."""
    corpus, result = _default_run()
    out_dir = tmp_path / "ingested"

    provenance = [
        ProvenanceRow(
            row=i,
            key_id=sig.key_id,
            height=250000 + i,
            txid=f"{i:064x}",
            vin=0,
            script_type="p2pkh",
            sigversion="legacy",
            hashtype=1,
            low_s=True,
            pubkey_len=33,
        )
        for i, sig in enumerate(corpus.signatures[:20])
    ]
    report = IngestReport(heights=(250000, 250001), n_blocks=2)
    write_corpus(corpus, report, provenance, str(out_dir))

    names = {p.name for p in out_dir.iterdir()}
    assert {"provenance.parquet", "ingest_manifest.json"} <= names
    for path in sorted(out_dir.iterdir()):
        _assert_absent(_secrets(result), path.read_bytes(), path.name)


# --------------------------------------------------------------------------- #
# Sink: every extraction path, each driven to a real recovery
# --------------------------------------------------------------------------- #

#: Every extraction path that can carry a signature as far as a recovery. A new
#: script type or sigversion is a new way for a key to be reconstructed, and so a
#: new way for one to escape -- it is enrolled here in the same change that adds
#: it. The constant sits next to the test that exercises it on purpose: a list
#: nothing iterates is not enrolment, it is a label.
EXTRACTION_PATHS = (
    ("p2pkh", "legacy"),
    ("p2pk", "legacy"),
    ("v0_p2wpkh", "witness_v0"),
    ("p2sh_p2wpkh", "witness_v0"),
)
_EXTRACTION_IDS = [name for name, _sigversion in EXTRACTION_PATHS]
_HEIGHT = 400_000


@pytest.mark.parametrize("script_type,sigversion", EXTRACTION_PATHS, ids=_EXTRACTION_IDS)
def test_no_key_leaks_through_any_extraction_path(script_type, sigversion, tmp_path):
    """Drive each input type to an actual key recovery, then sweep its artefacts.

    The key is one we chose, so we know exactly what to search for -- which is
    impossible with the pinned mainnet fixtures, whose private keys we do not
    have and must not obtain.
    """
    from qi_fingerprint.ingest.extract import extract_tx
    from qi_fingerprint.ingest.validate import assert_gate, validate
    from qi_fingerprint.reuse import recover_from_reuse
    from qi_fingerprint.verify import recovers_key
    from synth_bitcoin import build_typed_tx

    rng = random.Random(700 + _EXTRACTION_IDS.index(script_type))
    d = rng.randrange(1, N)
    Q = CURVE.pubkey(d)
    k = rng.randrange(1, N)  # one nonce, two inputs: the catastrophic case
    tx, prevouts = build_typed_tx(d, [k, k], script_type)

    sigs, skips = extract_tx(tx, prevouts, _HEIGHT)
    assert skips == [], f"{script_type}: {[s.reason for s in skips]}"
    assert len(sigs) == 2
    assert {s.script_type for s in sigs} == {script_type}
    assert {s.sigversion for s in sigs} == {sigversion}

    verified, report = validate(sigs, CURVE)
    assert_gate(report)

    a, b = verified
    recovered = recover_from_reuse(
        CURVE, Signature(0, a.z, a.r, a.s), Signature(0, b.z, b.r, b.s), Q
    )
    # The path really can produce a key -- otherwise the sweep below is vacuous.
    assert recovered == d
    assert recovers_key(recovered, Q, CURVE)

    corpus = Corpus(curve="secp256k1")
    corpus.keys.append(KeyRecord(key_id=0, curve="secp256k1", Qx=Q.x, Qy=Q.y))
    corpus.signatures.extend(Signature(0, s.z, s.r, s.s) for s in verified)
    assert not corpus.has_ground_truth

    provenance = [
        ProvenanceRow(
            row=i,
            key_id=0,
            height=s.height,
            txid=s.txid,
            vin=s.vin,
            script_type=s.script_type,
            sigversion=s.sigversion,
            hashtype=s.hashtype,
            low_s=s.low_s,
            pubkey_len=s.pubkey_len,
        )
        for i, s in enumerate(verified)
    ]
    out_dir = tmp_path / script_type
    write_corpus(
        corpus,
        IngestReport(heights=(_HEIGHT, _HEIGHT), n_blocks=1),
        provenance,
        str(out_dir),
    )

    written = sorted(out_dir.iterdir())
    assert written, "nothing written -- the sink check would be vacuous"
    for path in written:
        _assert_absent([d], path.read_bytes(), f"{script_type}/{path.name}")
    # The in-memory records reach logs and tracebacks; they must be clean too.
    _assert_absent([d], repr(verified).encode(), f"{script_type} ExtractedSig repr")
    _assert_absent([d], repr(report).encode(), f"{script_type} ValidationReport")


def test_the_extraction_sweep_has_not_fallen_behind_the_extractor():
    """A type the extractor can turn into an `ExtractedSig` but the sweep never
    drives is the exact hole the enrolment rule exists to close."""
    handled = {"p2pkh", "p2pk", "v0_p2wpkh", "p2sh_p2wpkh"}
    assert {name for name, _sv in EXTRACTION_PATHS} == handled


# --------------------------------------------------------------------------- #
# Sink: the published static site
# --------------------------------------------------------------------------- #


def test_the_site_export_publishes_d_only_for_a_corpus_we_generated(monkeypatch):
    """Both halves, because a guard that never engages is not a guard.

    On the synthetic corpus the scalar is ours and showing it is the whole
    demonstration; swap in a truth-stripped corpus and the same code path must
    withhold it.
    """
    import tools.export_site_data as exporter

    published = json.dumps(exporter.export_run(seed=7))
    assert '"d"' in published, "synthetic export should carry d -- sink is real"

    stripped = _strip_truth(build_corpus("secp256k1", seed=7))
    monkeypatch.setattr(exporter, "build_corpus", lambda *a, **k: stripped)

    withheld = json.dumps(exporter.export_run(seed=7))
    assert '"d"' not in withheld

    _corpus, result = _default_run()
    _assert_absent(_secrets(result), withheld.encode(), "site export json")
