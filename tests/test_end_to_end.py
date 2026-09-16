"""M5 gate (end-to-end): the whole thesis on an unlabeled corpus.

Screen -> Crack one member per cohort -> Fingerprint -> Propagate, then score
against hidden ground truth: every diagnosis correct, no clean key ever touched,
and propagation attributes strictly more keys than were cracked.
"""

from qi_fingerprint.generator import build_corpus
from qi_fingerprint.pipeline import evaluate, run


def test_end_to_end_one_crack_diagnoses_the_population():
    corpus = build_corpus("secp256k1", seed=7)
    result = run(corpus)
    gt = {k.key_id: k.bias_type for k in corpus.keys}

    # One crack per cohort type surfaces all four bug classes.
    cracked_types = {gt[kid] for kid in result.cracks}
    assert {"truncated_msb", "modular_reduction", "short_period_prng", "weak_seed"} <= cracked_types

    # Every crack+fingerprint diagnosis is correct.
    assert result.diagnoses
    for kid, dg in result.diagnoses.items():
        assert dg.label == gt[kid], (kid, gt[kid], dg.label)

    # No benign key is ever cracked or attributed.
    assert all(gt[kid] != "clean" for kid in result.cracks)
    assert all(gt[kid] != "clean" for kid in result.attributions)

    metrics = evaluate(result, corpus)
    assert metrics["diagnosis_accuracy"] == 1.0
    assert metrics["attribution_accuracy"] >= 0.95

    # The payoff: propagation labels strictly more keys than were cracked.
    assert metrics["n_attributed"] > metrics["n_cracked"]
