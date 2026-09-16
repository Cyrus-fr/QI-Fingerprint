"""Export pre-computed pipeline results as JSON for the static site.

The site is a static export with no backend: a cold pipeline run takes ~75s, which
is far too slow to sit between the hero and the first data. So we run the real
pipeline here, at a few seeds, and freeze everything the site needs into
``site/public/data/run-<seed>.json``.

Nothing is synthesised for presentation. Every number in the output comes from the
same ``screen -> crack -> fingerprint -> propagate`` run the CLI performs, and every
listed crack has already passed the ``d*G == Q`` gate inside ``crack_key`` (the
pipeline drops anything that fails, so an exported crack is a proof, not a guess).

Run it in the container -- fpylll/fastecdsa have no usable native-Windows build:

    docker compose run --rm pipeline python tools/export_site_data.py
"""

from __future__ import annotations

import argparse
import json
import math
import os
from collections import Counter, deque

from qi_fingerprint.curves import get_curve
from qi_fingerprint.features import msb_bit_means, spectrum
from qi_fingerprint.fingerprint import reconstruct_nonces
from qi_fingerprint.generator import build_corpus
from qi_fingerprint.pipeline import evaluate, run

DEFAULT_SEEDS = (7, 11, 23)
MSB_BITS = 32  # top bits shown in the MSB histogram
SPECTRUM_W = 64  # Bleichenbacher scan frequencies w = 1..64
NONCE_SAMPLES = 8  # reconstructed nonces surfaced verbatim per cracked key
HEX_WIDTH = 64  # 256-bit values as fixed-width hex


def _hex(x: int) -> str:
    return format(int(x), f"0{HEX_WIDTH}x")


def _round(xs, places: int = 6) -> list[float]:
    """Round a float sequence so the JSON stays small and diffs stay stable."""
    return [round(float(x), places) for x in xs]


def _dead_msb_bits(means: list[float]) -> int:
    """Leading MSB positions that are never 1 -- the visible truncation signature."""
    dead = 0
    for m in means:
        if m > 0.0:
            break
        dead += 1
    return dead


def _cohort_edges(group: list[int]) -> list[tuple[int, int]]:
    """Consecutive-pair path over one shared-r group.

    A group of k keys sharing an r is mutually linked, but drawing all C(k,2) edges
    buries the graph. The Streamlit dashboard already draws the consecutive path, so
    we keep the same convention and the two UIs stay comparable.
    """
    return [(group[i], group[i + 1]) for i in range(len(group) - 1)]


def _build_edges(report, attributions) -> list[dict]:
    seen: set[tuple[int, int]] = set()
    edges: list[dict] = []
    for group in report.cross_key_groups:
        for a, b in _cohort_edges(sorted(group)):
            edge = (min(a, b), max(a, b))
            if edge in seen or a not in attributions or b not in attributions:
                continue
            seen.add(edge)
            edges.append({"source": edge[0], "target": edge[1]})
    return edges


def _propagation(report, diagnoses, edges) -> list[dict]:
    """Per-cohort BFS from the cracked member outward -- the scrubber's timeline.

    The centrepiece animation replays attribution edge by edge, so the traversal
    order has to be fixed here rather than recomputed (differently) in the browser.
    """
    adjacency: dict[int, list[int]] = {}
    for e in edges:
        adjacency.setdefault(e["source"], []).append(e["target"])
        adjacency.setdefault(e["target"], []).append(e["source"])
    for kid in adjacency:
        adjacency[kid].sort()

    out: list[dict] = []
    for index, cohort in enumerate(report.cohorts):
        diagnosed = [(k, diagnoses[k]) for k in cohort if k in diagnoses]
        if not diagnosed:
            continue
        root, best = max(diagnosed, key=lambda kv: kv[1].confidence)

        steps: list[dict] = []
        visited = {root}
        queue = deque([root])
        while queue:
            node = queue.popleft()
            for neighbour in adjacency.get(node, []):
                if neighbour in visited or neighbour not in cohort:
                    continue
                visited.add(neighbour)
                steps.append({"step": len(steps), "from": node, "to": neighbour})
                queue.append(neighbour)

        out.append(
            {
                "cohort": index,
                "root": root,
                "label": best.label,
                "members": sorted(cohort),
                "steps": steps,
            }
        )
    return out


# The unit box maps onto the SVG's inner area (888 x 374 px), so a cluster only
# looks circular if its x radius is divided by that aspect ratio.
_ASPECT = 888 / 374
# Vertical bands: cohorts above the divider, unaffiliated keys below it.
_COHORT_BAND_Y = 0.34
_SINGLETON_BAND_Y = 0.86
_BAND_DIVIDER_Y = 0.63


def _layout(report, attributions, labels) -> tuple[dict[int, dict], list[dict], list[int]]:
    """Deterministic node positions in a unit box, plus cluster metadata.

    Precomputed so the graph paints instantly and identically on every load -- a
    force simulation would settle differently each time and shift under the reader.

    Two things the earlier version got wrong, both visible once rendered:
      * every cohort got an equal-width slot, so a six-key cohort was crammed into
        the same width as a two-key pair;
      * keys belonging to no cohort were scattered across the full width with
        nothing to say so, which read as an unexplained second row.

    Cohorts now get horizontal space proportional to membership and sit in one
    band; unaffiliated keys sit together in a labelled band beneath a divider.
    """
    cohorts = [sorted(c) for c in report.cohorts]
    in_cohort = {kid for c in cohorts for kid in c}
    singletons = sorted(k for k in attributions if k not in in_cohort)

    positions: dict[int, dict] = {}
    clusters: list[dict] = []

    # Pack by VISUAL extent, not by slot width. Proportional slots leave a big
    # cohort centred in a wide but mostly-empty slot, which reads as a gap; what
    # should be even is the space between what you can actually see.
    node_hw = 19 / 888  # node radius + cracked ring, in unit-x

    radii = [min(0.19, 0.05 + 0.021 * len(c)) for c in cohorts]
    # A 2-member cohort sits at +/-90deg, so it has no horizontal extent at all.
    half_extents = [
        (radii[ci] / _ASPECT if len(c) > 2 else 0.0) + node_hw
        for ci, c in enumerate(cohorts)
    ]
    occupied = sum(2 * h for h in half_extents)
    gap = max(0.04, (1.0 - occupied) / (len(cohorts) + 1)) if cohorts else 0.0

    cursor = gap
    for ci, cohort in enumerate(cohorts):
        cx = cursor + half_extents[ci]
        cursor += 2 * half_extents[ci] + gap
        n = len(cohort)
        r = radii[ci]

        for mi, kid in enumerate(cohort):
            if n == 1:
                x, y = cx, _COHORT_BAND_Y
            else:
                angle = 2 * math.pi * mi / n - math.pi / 2
                x = cx + (r / _ASPECT) * math.cos(angle)
                y = _COHORT_BAND_Y + r * math.sin(angle)
            positions[kid] = {"x": round(x, 6), "y": round(y, 6), "cohort": ci}

        member_labels = {labels[k] for k in cohort if k in labels}
        clusters.append(
            {
                "cohort": ci,
                "x": round(cx, 6),
                "y": round(_COHORT_BAND_Y, 6),
                "r": round(r, 6),
                "size": n,
                "members": cohort,
                # A cohort is single-generator, so this is one label in practice.
                "label": sorted(member_labels)[0] if member_labels else None,
            }
        )

    # Unaffiliated keys: a tight, centred row so they read as one set rather than
    # as scattered strays.
    spacing = 0.062
    start = 0.5 - spacing * (len(singletons) - 1) / 2
    for si, kid in enumerate(singletons):
        positions[kid] = {
            "x": round(start + si * spacing, 6),
            "y": round(_SINGLETON_BAND_Y, 6),
            "cohort": None,
        }

    return positions, clusters, singletons


def export_run(seed: int, curve_name: str = "secp256k1") -> dict:
    curve = get_curve(curve_name)
    corpus = build_corpus(curve_name, seed=seed)
    result = run(corpus)
    metrics = evaluate(result, corpus)

    # Stage 2c, exported alongside rather than instead of the baseline. The page
    # shows the cascade as a transition between two real states -- what the crack
    # loop alone recovers, and what walking the shared-nonce edges adds -- so the
    # README's headline numbers stay visible next to what chaining does to them.
    chained_result = run(corpus, chain=True)
    chained_metrics = evaluate(chained_result, corpus)

    report = result.report
    truth = {k.key_id: k.bias_type for k in corpus.keys}
    sigs_by_key = corpus.sigs_by_key()

    # This page is published. A recovered scalar belongs on it only when the
    # corpus is one we generated -- there the key is ours, and showing it is the
    # demonstration. For a corpus ingested from a real chain the same field would
    # be a live spending key on a static site, so it is omitted and `verified`
    # carries the claim instead. The site types both `d` fields as optional.
    publishable_d = corpus.has_ground_truth

    cracks: list[dict] = []
    keys: dict[str, dict] = {}
    for kid, (d, method) in sorted(result.cracks.items()):
        diagnosis = result.diagnoses[kid]
        nonces = reconstruct_nonces(curve, sigs_by_key[kid], d)
        means = _round(msb_bit_means(nonces, curve.L, MSB_BITS))
        evidence = {
            k: (round(float(v), 6) if isinstance(v, float) else v)
            for k, v in diagnosis.evidence.items()
            if not isinstance(v, str)
        }

        # Spread in place rather than appended, so a synthetic export stays
        # byte-identical to what the site already ships.
        recovered = {"d": _hex(d)} if publishable_d else {}

        cracks.append(
            {
                "keyId": kid,
                "method": method,
                # crack_key only returns d after d*G == Q; a listed row is verified.
                "verified": True,
                **recovered,
                "diagnosis": diagnosis.label,
                "confidence": round(diagnosis.confidence, 3),
                "truth": truth[kid],
                "correct": diagnosis.label == truth[kid],
                "nSignatures": len(sigs_by_key[kid]),
            }
        )
        keys[str(kid)] = {
            "keyId": kid,
            **recovered,
            "diagnosis": diagnosis.label,
            "confidence": round(diagnosis.confidence, 3),
            "nNonces": len(nonces),
            "msbBitMeans": means,
            "deadMsbBits": _dead_msb_bits(means),
            "spectrum": _round(spectrum(nonces, 1 << curve.L, SPECTRUM_W)),
            "nonceSamples": [_hex(k) for k in nonces[:NONCE_SAMPLES]],
            "evidence": evidence,
        }

    attributions = [
        {
            "keyId": kid,
            "diagnosis": a.label,
            "source": a.source,
            "confidence": round(a.confidence, 3),
            "truth": truth[kid],
            "correct": a.label == truth[kid],
        }
        for kid, a in sorted(result.attributions.items())
    ]

    edges = _build_edges(report, result.attributions)
    positions, clusters, singletons = _layout(
        report,
        result.attributions,
        {kid: a.label for kid, a in result.attributions.items()},
    )
    nodes = [
        {
            "id": kid,
            "label": a.label,
            "source": a.source,
            "confidence": round(a.confidence, 3),
            "correct": a.label == truth[kid],
            **positions.get(kid, {"x": 0.5, "y": 0.5, "cohort": None}),
        }
        for kid, a in sorted(result.attributions.items())
    ]

    attributed_ids = set(result.attributions)
    clean_touched = sum(1 for kid in attributed_ids if truth[kid] == "clean")

    return {
        "seed": seed,
        "curve": curve.name,
        "stats": {
            "nKeys": report.n_keys,
            "nSignatures": report.n_signatures,
            "rCollisions": report.n_r_collisions,
            "expectedRandomCollisions": report.expected_random_collisions,
            "nIntraKeyReuse": len(report.intra_key_reuse),
            "nLatticeCandidates": len(report.lattice_candidates),
            "nCohorts": len(report.cohorts),
            "nCracked": metrics["n_cracked"],
            "nDiagnosed": metrics["n_diagnosed"],
            "nAttributed": metrics["n_attributed"],
            "diagnosisAccuracy": round(metrics["diagnosis_accuracy"], 6),
            "attributionAccuracy": round(metrics["attribution_accuracy"], 6),
            "cleanKeysAttributed": clean_touched,
        },
        "attributedByClass": dict(
            Counter(a.label for a in result.attributions.values()).most_common()
        ),
        "perClassDiagnosis": {
            label: {
                "n": s["n"],
                "correct": s["correct"],
                "accuracy": round(s["accuracy"], 6),
            }
            for label, s in sorted(metrics["per_class_diagnosis"].items())
        },
        "cracks": cracks,
        "keys": keys,
        "attributions": attributions,
        "cohortGraph": {
            "nodes": nodes,
            "edges": edges,
            "clusters": clusters,
            "singletons": singletons,
            "bandDividerY": _BAND_DIVIDER_Y,
        },
        "propagation": _propagation(report, result.diagnoses, edges),
        # The cored section: one lamina per key in the corpus, in key order.
        # Every field is measured, because the page draws this column as its
        # first viewport and a fabricated density curve would contradict the one
        # principle the whole artifact rests on.
        "section": [
            {
                "keyId": kid,
                "nSignatures": len(sigs_by_key.get(kid, [])),
                # The label the pipeline assigned, or null where it refused to
                # guess. Null is a reading, not a gap.
                "label": (
                    result.attributions[kid].label
                    if kid in result.attributions
                    else None
                ),
                "source": (
                    result.attributions[kid].source
                    if kid in result.attributions
                    else None
                ),
                "cracked": kid in result.cracks,
            }
            for kid in sorted(sigs_by_key)
        ],
        "chain": {
            "nCracked": chained_metrics["n_cracked"],
            "nDiagnosed": chained_metrics["n_diagnosed"],
            "nAttributed": chained_metrics["n_attributed"],
            "diagnosisAccuracy": round(chained_metrics["diagnosis_accuracy"], 6),
            "attributionAccuracy": round(chained_metrics["attribution_accuracy"], 6),
            "nUndiagnosable": len(chained_result.undiagnosable),
            "unwalkedEdges": result.unwalked_edges,
            # One row per hop: which key opened which, over which r, how far from
            # the seed. No scalar -- `ChainedKey.d` is deliberately not read here.
            "hops": [
                {
                    "keyId": kid,
                    "viaKeyId": hop.via_key_id,
                    "r": _hex(hop.via_r),
                    "depth": hop.depth,
                    "truth": truth[kid],
                    "selfDiagnosable": kid not in chained_result.undiagnosable,
                }
                for kid, hop in sorted(chained_result.chained.items())
            ],
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="export_site_data",
        description="Freeze real pipeline runs into JSON for the static site.",
    )
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=list(DEFAULT_SEEDS),
        help=f"corpus seeds to run (default: {' '.join(map(str, DEFAULT_SEEDS))})",
    )
    parser.add_argument("--curve", default="secp256k1")
    parser.add_argument("--out", default="site/public/data", help="output directory")
    args = parser.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    manifest = []

    for seed in args.seeds:
        print(f"running seed {seed} ...", flush=True)
        payload = export_run(seed, args.curve)
        path = os.path.join(args.out, f"run-{seed}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")

        s = payload["stats"]
        print(
            f"  seed {seed}: {s['nKeys']} keys / {s['nSignatures']} sigs; "
            f"r-collisions={s['rCollisions']}; cracked {s['nCracked']}; "
            f"attributed {s['nAttributed']}; "
            f"diagnosis {s['diagnosisAccuracy'] * 100:.0f}%; "
            f"attribution {s['attributionAccuracy'] * 100:.0f}% "
            f"-> {path} ({os.path.getsize(path)} bytes)",
            flush=True,
        )
        manifest.append(
            {
                "seed": seed,
                "curve": payload["curve"],
                "file": f"run-{seed}.json",
                "nKeys": s["nKeys"],
                "nSignatures": s["nSignatures"],
                "nCracked": s["nCracked"],
                "nAttributed": s["nAttributed"],
            }
        )

    index_path = os.path.join(args.out, "index.json")
    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump({"defaultSeed": args.seeds[0], "runs": manifest}, fh, indent=2)
        fh.write("\n")
    print(f"wrote manifest -> {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
