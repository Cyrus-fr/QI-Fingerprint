"""qi command-line interface: generate | run."""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from qi_fingerprint.ingest.control import SAFETY_BANNER

from .corpus import Corpus
from .generator import build_corpus
from .pipeline import PipelineResult, evaluate, run

# A cascade can be large; list this many hops before summarising the rest.
_MAX_CHAIN_LINES = 10


def _print_chain(result: PipelineResult, chain: bool) -> None:
    """Report Stage 2c: what the chain recovered, or what was left unwalked.

    SAFETY (plan §9): every field printed here is public -- key ids, hop counts
    and the on-chain ``r``. The recovered scalar is deliberately absent, and must
    stay that way: on a real corpus each of these is a live spending key.
    """
    if not chain:
        n = result.unwalked_edges
        if n:
            plural = "edge" if n == 1 else "edges"
            print(f"chain    : skipped (pass --chain to walk {n} shared-r {plural})")
        else:
            print("chain    : skipped (no shared-r edges to walk)")
        return

    chained = result.chained
    if not chained:
        print("chain    : 0 recovered")
        return

    hops = sorted(chained.values(), key=lambda c: (c.depth, c.key_id))
    depths = ", ".join(str(c.depth) for c in hops)
    print(f"chain    : {len(hops)} recovered (depth {depths})")
    for hop in hops[:_MAX_CHAIN_LINES]:
        r_short = f"{hop.via_r:064x}"[:16]  # same truncation style as find_reuse.py
        print(
            f"  key {hop.key_id} via key {hop.via_key_id} "
            f"(depth {hop.depth}, r={r_short}..)"
        )
    if len(hops) > _MAX_CHAIN_LINES:
        print(f"  .. and {len(hops) - _MAX_CHAIN_LINES} more")
    if result.undiagnosable:
        # Recovered is not the same as fingerprintable. Say so, rather than
        # letting a `clean` fallthrough pass for a finding.
        print(
            f"  {len(result.undiagnosable)} recovered but not self-diagnosable "
            f"(too few nonces); labelled from their cohort"
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="qi", description="QI-Fingerprint: ECDSA nonce-bias triage"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="build a synthetic signature corpus")
    gen.add_argument("--out", required=True, help="output corpus directory")
    gen.add_argument("--seed", type=int, default=0)
    gen.add_argument("--curve", default="secp256k1")

    runner = sub.add_parser("run", help="run the full triage pipeline on a corpus")
    runner.add_argument("--corpus", required=True, help="corpus directory")
    runner.add_argument("--truth", action="store_true", help="load ground truth and print accuracy")
    runner.add_argument("--strict", action="store_true", help="classify from nonce features only (mask recovery path)")
    runner.add_argument(
        "--canonical-nonces",
        action="store_true",
        help="fold reconstructed nonces to min(k, n-k); required for corpora that "
        "may contain BIP146 low-s normalised signatures (real Bitcoin)",
    )
    runner.add_argument(
        "--chain",
        action="store_true",
        help="walk shared-nonce edges outward from each recovered key, cascading "
        "through the cohort; opt-in because on a real corpus every hop is a live "
        "spending key",
    )

    args = parser.parse_args(argv)

    if args.cmd == "generate":
        corpus = build_corpus(args.curve, seed=args.seed)
        corpus.save(args.out)
        print(f"wrote {len(corpus.keys)} keys / {len(corpus.signatures)} signatures -> {args.out}")
        return 0

    if args.cmd == "run":
        corpus = Corpus.load(args.corpus, with_truth=args.truth)
        result = run(
            corpus,
            strict=args.strict,
            canonical=args.canonical_nonces,
            chain=args.chain,
        )
        r = result.report
        print(f"screened {r.n_keys} keys / {r.n_signatures} signatures; r-collisions={r.n_r_collisions}")
        print(f"cracked {len(result.cracks)}; diagnosed {len(result.diagnoses)}; attributed {len(result.attributions)}")
        _print_chain(result, args.chain)
        # A recovered key on a corpus with no ground truth is a live key -- it was
        # never ours. Restate the §9 rules whenever that happens, by any method.
        if result.cracks and not corpus.has_ground_truth:
            print(SAFETY_BANNER)
        print("attributed by class:")
        for label, count in Counter(a.label for a in result.attributions.values()).most_common():
            print(f"  {label}: {count}")
        if args.truth:
            m = evaluate(result, corpus)
            dc = round(m["diagnosis_accuracy"] * m["n_diagnosed"])
            ac = round(m["attribution_accuracy"] * m["n_attributed"])
            print("accuracy vs ground truth:")
            print(f"  diagnosis    {dc}/{m['n_diagnosed']}  ({m['diagnosis_accuracy'] * 100:.0f}%)")
            print(f"  attribution  {ac}/{m['n_attributed']}  ({m['attribution_accuracy'] * 100:.0f}%)")
            per_class = "  ".join(
                f"{label} {s['correct']}/{s['n']}"
                for label, s in m["per_class_diagnosis"].items()
            )
            print(f"  per class    {per_class}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
