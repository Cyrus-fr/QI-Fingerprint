"""Orchestrate the full triage: Screen -> Crack -> Fingerprint -> Propagate.

Cohort-aware: once a representative of a collision cohort is cracked and
diagnosed, the remaining members are skipped for cracking and picked up by
Propagate instead -- this is the "one crack diagnoses the population" thesis made
operational (and it keeps the expensive brute-force / lattice work to one key per
cohort).

With ``chain=True`` a second pass runs after the crack loop and walks the
shared-nonce edges outward from every key already recovered, so the cohort-mates
that the skip above deliberately never attempts are *recovered* rather than
merely labelled. It is opt-in: on a real corpus every hop is a live mainnet
spending key, so cascading is a deliberate act rather than a side effect of a
normal run.

Recovering a key is not the same as being able to fingerprint it. The chain
reaches every cohort member, including siblings with two or three signatures
whose own nonces carry no measurable signal; those keep a cohort attribution
rather than a fabricated one. See ``record_recovery``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .chain import ChainedKey, propagate_keys, unwalked_edges
from .corpus import Corpus
from .crack import crack_key
from .curves import get_curve
from .fingerprint import Diagnosis, canonical_bound, diagnose, reconstruct_nonces
from .propagate import Attribution, propagate
from .screen import ScreenReport, screen


@dataclass
class PipelineResult:
    report: ScreenReport
    cracks: dict[int, tuple]  # key_id -> (d, method); method is "chain" for chained keys
    diagnoses: dict[int, Diagnosis]  # key_id -> Diagnosis (cracked keys)
    attributions: dict[int, Attribution]  # key_id -> Attribution (cracked + propagated)
    chained: dict[int, ChainedKey] = field(default_factory=dict)  # key_id -> provenance
    unwalked_edges: int = 0  # shared-r edges left unwalked because --chain was off
    #: Recovered by the chain but with too few nonces to diagnose on their own.
    #: Left to Propagate for a cohort label rather than asserted `clean`.
    undiagnosable: list[int] = field(default_factory=list)


def run(
    corpus: Corpus,
    strict: bool = False,
    canonical: bool = False,
    chain: bool = False,
) -> PipelineResult:
    """Run the full triage.

    ``canonical`` folds reconstructed nonces to ``min(k, n-k)`` and moves the
    uniformity reference with them -- required for any corpus that may contain
    BIP146 low-s normalised signatures (i.e. real Bitcoin), and a no-op for the
    synthetic generator, which never normalises.

    ``chain`` walks shared-nonce edges outward from every recovered key. Off by
    default; when off, the number of edges left unwalked is still reported, so
    declining to chase them is visible rather than silent.
    """
    curve = get_curve(corpus.curve)
    bound = canonical_bound(curve.n) if canonical else None
    report = screen(corpus)
    keys = corpus.key_index()
    sigs_by_key = corpus.sigs_by_key()

    cohort_of: dict[int, int] = {}
    for idx, cohort in enumerate(report.cohorts):
        for kid in cohort:
            cohort_of[kid] = idx
    diagnosed_cohorts: set[int] = set()

    cracks: dict[int, tuple] = {}
    diagnoses: dict[int, Diagnosis] = {}
    undiagnosable: list[int] = []

    def record_recovery(
        kid: int, d: int, method: str, defer_unlabelled: bool = False
    ) -> None:
        """Fingerprint one recovered key. Shared by the crack loop and the chain.

        ``defer_unlabelled`` leaves a key out of ``diagnoses`` when its own nonces
        yield only the ``clean`` fallthrough. `clean` is what
        `_classify_from_features` returns when *nothing* fired, so recording it
        would assert "no bias" on the strength of "no evidence" -- and it would
        also stop Propagate from supplying the cohort label, which for a key with
        two or three signatures is the better-supported answer.

        Only the chain passes it. The crack loop attempts one well-sampled
        representative per cohort by design; the chain reaches every member,
        including the few-signature siblings that were never diagnosable.
        """
        cracks[kid] = (d, method)
        nonces = reconstruct_nonces(curve, sigs_by_key[kid], d, canonical=canonical)
        dg = diagnose(
            nonces,
            curve.L,
            curve.n,
            gen_indices=None,
            cracked_by=method,
            strict=strict,
            bound=bound,
        )
        if defer_unlabelled and dg.label == "clean":
            undiagnosable.append(kid)
            return
        diagnoses[kid] = dg

    for target in report.crack_queue():
        kid = target.key_id
        cohort = cohort_of.get(kid)
        if cohort is not None and cohort in diagnosed_cohorts:
            continue  # a cohort-mate already told us the diagnosis

        record = keys[kid]
        Q = curve.point(record.Qx, record.Qy)
        d, method = crack_key(curve, sigs_by_key[kid], Q, target.method)
        if d is None:
            continue

        record_recovery(kid, d, method)
        if cohort is not None:
            diagnosed_cohorts.add(cohort)

    # Stage 2c. Seeded from whatever the crack loop recovered; every hop is gated
    # by d*G == Q inside `propagate_keys`, so nothing unverified enters `cracks`.
    seeds = {kid: d for kid, (d, _method) in cracks.items()}
    chained: dict[int, ChainedKey] = {}
    n_unwalked = 0
    if chain:
        chained = propagate_keys(curve, corpus, seeds)
        for kid, chained_key in chained.items():
            # "chain" carries no bias signal of its own -- how a key was reached
            # says nothing about its generator -- so these classify from nonce
            # features alone, and defer to the cohort when they have none.
            record_recovery(kid, chained_key.d, "chain", defer_unlabelled=True)
    else:
        n_unwalked = unwalked_edges(corpus, seeds)

    attributions = propagate(report, diagnoses)
    return PipelineResult(
        report=report,
        cracks=cracks,
        diagnoses=diagnoses,
        attributions=attributions,
        chained=chained,
        unwalked_edges=n_unwalked,
        undiagnosable=undiagnosable,
    )


def evaluate(result: PipelineResult, corpus_with_truth: Corpus) -> dict:
    """Score the run against ground truth (evaluation only), with a per-class break-down."""
    gt = {k.key_id: k.bias_type for k in corpus_with_truth.keys}

    per_class: dict[str, dict] = {}
    for kid, dg in result.diagnoses.items():
        cls = gt[kid]
        stats = per_class.setdefault(cls, {"n": 0, "correct": 0})
        stats["n"] += 1
        stats["correct"] += int(dg.label == cls)
    for stats in per_class.values():
        stats["accuracy"] = stats["correct"] / stats["n"] if stats["n"] else 0.0

    diag_correct = sum(s["correct"] for s in per_class.values())
    n_diag = sum(s["n"] for s in per_class.values())
    attr_correct = sum(1 for kid, a in result.attributions.items() if a.label == gt[kid])
    return {
        "n_cracked": len(result.cracks),
        "n_diagnosed": n_diag,
        "diagnosis_accuracy": diag_correct / n_diag if n_diag else 0.0,
        "per_class_diagnosis": per_class,
        "n_attributed": len(result.attributions),
        "attribution_accuracy": attr_correct / len(result.attributions) if result.attributions else 0.0,
    }
