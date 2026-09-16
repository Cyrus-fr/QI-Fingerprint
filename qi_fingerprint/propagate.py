"""Stage 4: Propagate -- attribute one key's diagnosis across its cohort.

The payoff of the whole pipeline: a cohort is identified at Screen time (keys
linked by shared r-collisions), one member is cracked and fingerprinted, and that
diagnosis is attributed to every other member. One recovered key diagnoses the
population.

Honest scope: propagation spans the collision-linked cohorts. A pure MSB-bias key
with no cohort link (invisible to Screen) is attributed on its own -- a cohort of
one -- because nothing observable ties the few-signature stragglers to it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import Diagnosis
from .screen import ScreenReport


@dataclass
class Attribution:
    key_id: int
    label: str
    confidence: float
    source: str  # "cracked" | "propagated"


def propagate(
    report: ScreenReport, diagnoses: dict[int, Diagnosis]
) -> dict[int, Attribution]:
    attributions: dict[int, Attribution] = {}

    # Directly diagnosed (cracked + fingerprinted) keys.
    for kid, dg in diagnoses.items():
        attributions[kid] = Attribution(kid, dg.label, dg.confidence, "cracked")

    # Attribute across each cohort from its highest-confidence diagnosed member.
    for cohort in report.cohorts:
        diagnosed = [diagnoses[k] for k in cohort if k in diagnoses]
        if not diagnosed:
            continue
        best = max(diagnosed, key=lambda d: d.confidence)
        for kid in cohort:
            if kid not in attributions:
                attributions[kid] = Attribution(
                    kid, best.label, round(best.confidence * 0.8, 3), "propagated"
                )

    return attributions
