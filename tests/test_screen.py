"""M3 gate: Screen flags low-entropy cohorts and routes each to the right crack,
while leaving the benign background untouched."""

from qi_fingerprint.generator import build_corpus
from qi_fingerprint.screen import screen


def test_screen_flags_and_routes():
    corpus = build_corpus("secp256k1", seed=7)
    bias = {k.key_id: k.bias_type for k in corpus.keys}
    report = screen(corpus)

    # Anomaly: collisions exist and dwarf the birthday-bound expectation.
    assert report.n_r_collisions > 0
    assert report.expected_random_collisions < 1e-30

    route = {t.key_id: t.method for t in report.crack_queue()}

    # Lattice candidates are exactly the well-sampled MSB-bias keys -- never clean.
    assert report.lattice_candidates
    for kid in report.lattice_candidates:
        assert route[kid] == "lattice"
        assert bias[kid] in ("truncated_msb", "modular_reduction")

    # Short-period keys reuse nonces -> routed to the cheap reuse crack.
    short_period = [kid for kid in report.intra_key_reuse if bias[kid] == "short_period_prng"]
    assert short_period
    assert all(route[kid] == "reuse" for kid in short_period)

    # Weak-seed cohort surfaces as cross-key collisions -> routed to the seed crack.
    weak_seed = [
        t.key_id for t in report.crack_queue()
        if t.method == "seed" and bias[t.key_id] == "weak_seed"
    ]
    assert weak_seed

    # No benign/clean key is ever queued for cracking.
    assert all(bias[t.key_id] != "clean" for t in report.crack_queue())

    # Cheap-first ordering (reuse < seed < lattice).
    priorities = [t.priority for t in report.crack_queue()]
    assert priorities == sorted(priorities)
