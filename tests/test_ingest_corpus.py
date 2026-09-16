"""Corpus assembly: grouping by public key, and the round trip through parquet."""

from fixtures_bitcoin import ONE_INPUT_INPUTS, ONE_INPUT_RAW, TWO_INPUT_INPUTS, TWO_INPUT_RAW
from qi_fingerprint.corpus import Corpus
from qi_fingerprint.ingest.bitcoin import build_corpus
from qi_fingerprint.ingest.extract import PrevOut, extract_tx
from qi_fingerprint.ingest.tx import parse_tx
from qi_fingerprint.ingest.validate import validate
from qi_fingerprint.screen import screen


def _extract(raw_hex, inputs, height=250000):
    tx = parse_tx(bytes.fromhex(raw_hex))
    prevouts = [PrevOut(0, bytes.fromhex(spk)) for _i, spk, *_rest in inputs]
    sigs, _skips = extract_tx(tx, prevouts, height)
    kept, _report = validate(sigs)
    return kept


def test_build_corpus_produces_a_loadable_corpus(tmp_path):
    sigs = _extract(ONE_INPUT_RAW, ONE_INPUT_INPUTS) + _extract(
        TWO_INPUT_RAW, TWO_INPUT_INPUTS
    )
    corpus, provenance = build_corpus(sigs)

    out = str(tmp_path / "corpus")
    corpus.save(out)
    reloaded = Corpus.load(out, with_truth=False)

    assert len(reloaded.signatures) == len(sigs)
    assert len(reloaded.keys) == len(corpus.keys)
    assert reloaded.curve == "secp256k1"
    # No ground truth exists for real data, and none must be invented.
    assert all(k.bias_type is None for k in reloaded.keys)
    assert all(s.true_k is None for s in reloaded.signatures)


def test_no_ground_truth_files_are_written(tmp_path):
    corpus, _ = build_corpus(_extract(ONE_INPUT_RAW, ONE_INPUT_INPUTS))
    out = tmp_path / "corpus"
    corpus.save(str(out))
    assert (out / "signatures.parquet").exists()
    assert (out / "keys.parquet").exists()
    assert not (out / "gt_keys.parquet").exists()
    assert not (out / "gt_signatures.parquet").exists()


def test_h_column_is_the_sighash():
    sigs = _extract(ONE_INPUT_RAW, ONE_INPUT_INPUTS)
    corpus, _ = build_corpus(sigs)
    assert corpus.signatures[0].h == ONE_INPUT_INPUTS[0][5]


def test_provenance_is_row_parallel_to_signatures():
    """Any future 'we cracked a real key' claim has to be traceable to a txid."""
    sigs = _extract(ONE_INPUT_RAW, ONE_INPUT_INPUTS) + _extract(
        TWO_INPUT_RAW, TWO_INPUT_INPUTS
    )
    corpus, provenance = build_corpus(sigs)

    assert len(provenance) == len(corpus.signatures)
    for i, (row, sig) in enumerate(zip(provenance, corpus.signatures)):
        assert row.row == i
        assert row.key_id == sig.key_id
        assert len(row.txid) == 64


def test_grouping_is_by_point_so_encodings_collapse():
    """A key that appears compressed in one input and uncompressed in another is
    ONE key. Grouping by the serialised bytes -- or by address -- would split it."""
    sigs = _extract(TWO_INPUT_RAW, TWO_INPUT_INPUTS)
    points = {(s.qx, s.qy) for s in sigs}
    corpus, _ = build_corpus(sigs)
    assert len(corpus.keys) == len(points)


def test_key_ids_are_contiguous_and_reproducible():
    sigs = _extract(TWO_INPUT_RAW, TWO_INPUT_INPUTS)
    first, _ = build_corpus(sigs)
    second, _ = build_corpus(list(reversed(sigs)))

    assert [k.key_id for k in first.keys] == list(range(len(first.keys)))
    # Canonical ordering means input order cannot change the assignment.
    assert [(k.Qx, k.Qy) for k in first.keys] == [(k.Qx, k.Qy) for k in second.keys]


def test_min_sigs_filters_keys():
    sigs = _extract(TWO_INPUT_RAW, TWO_INPUT_INPUTS)
    corpus, _ = build_corpus(sigs, min_sigs=2)
    for key in corpus.keys:
        assert sum(1 for s in corpus.signatures if s.key_id == key.key_id) >= 2


def test_screen_runs_on_a_real_corpus():
    """The point of the whole exercise: Screen accepts real data unchanged."""
    sigs = _extract(ONE_INPUT_RAW, ONE_INPUT_INPUTS) + _extract(
        TWO_INPUT_RAW, TWO_INPUT_INPUTS
    )
    corpus, _ = build_corpus(sigs)
    report = screen(corpus)

    assert report.n_signatures == len(corpus.signatures)
    assert report.n_keys == len(corpus.keys)
    # These fixtures are ordinary spends; no reuse is expected.
    assert report.n_r_collisions == 0
