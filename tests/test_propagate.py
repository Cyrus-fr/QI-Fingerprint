"""M5 gate (unit): a single diagnosed member labels its whole cohort."""

from qi_fingerprint.fingerprint import Diagnosis
from qi_fingerprint.propagate import propagate
from qi_fingerprint.screen import ScreenReport


def _report(cohorts):
    return ScreenReport(
        n_keys=0, n_signatures=0, intra_key_reuse=[], cross_key_groups=[],
        cohorts=cohorts, lattice_candidates=[], n_r_collisions=0,
        expected_random_collisions=0.0,
    )


def test_propagate_labels_whole_cohort():
    report = _report([[1, 2, 3]])
    diagnoses = {1: Diagnosis("short_period_prng", 0.9)}
    attr = propagate(report, diagnoses)

    assert attr[1].label == "short_period_prng" and attr[1].source == "cracked"
    assert attr[2].label == "short_period_prng" and attr[2].source == "propagated"
    assert attr[3].label == "short_period_prng" and attr[3].source == "propagated"
    assert attr[2].confidence < attr[1].confidence  # propagated is less certain


def test_undiagnosed_cohort_is_untouched():
    report = _report([[10, 11]])
    attr = propagate(report, diagnoses={})
    assert attr == {}
