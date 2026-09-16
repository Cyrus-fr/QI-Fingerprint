"""Build a QI-Fingerprint corpus from real Bitcoin blocks.

Fetches a bounded block range, extracts legacy P2PKH ECDSA signatures, computes
the sighash each one actually signed, and writes the two parquets the pipeline
reads. Every extracted signature must pass `ecdsa_verify` -- that is the only
correctness oracle available without ground truth, so it is a hard gate: below
threshold the run writes nothing and exits 2.

Read-only. This tool fetches public block data and recovers no keys.

Run it in the container -- fpylll/fastecdsa have no usable native-Windows build:

    docker compose run --rm pipeline python tools/ingest_bitcoin.py \\
        --start 250000 --end 250001 --out data/btc-250000

    docker compose run --rm pipeline qi run --corpus data/btc-250000
"""

from __future__ import annotations

import argparse
import sys

from qi_fingerprint.ingest.bitcoin import IngestConfig, ingest, write_corpus
from qi_fingerprint.ingest.sources import (
    CachedSource,
    EsploraSource,
    FileSource,
    SourceError,
)
from qi_fingerprint.ingest.validate import IngestGateError

DEFAULT_ESPLORA = "https://blockstream.info/api"
DEFAULT_CACHE = "data/cache/bitcoin"


def build_source(args):
    if args.source == "cache":
        return FileSource(args.cache_dir)
    return CachedSource(EsploraSource(args.esplora_url, rate_hz=args.rate), args.cache_dir)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ingest_bitcoin",
        description="Real Bitcoin blocks -> QI-Fingerprint corpus (legacy P2PKH).",
    )
    parser.add_argument("--start", type=int, required=True, help="first block height")
    parser.add_argument("--end", type=int, required=True, help="last height (inclusive)")
    parser.add_argument("--out", help="corpus directory (default data/btc-<start>-<end>)")
    parser.add_argument("--source", choices=["esplora", "cache"], default="esplora")
    parser.add_argument("--esplora-url", default=DEFAULT_ESPLORA)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE)
    parser.add_argument("--rate", type=float, default=5.0, help="max requests/second")
    parser.add_argument("--min-sigs", type=int, default=1)
    parser.add_argument("--max-sigs", type=int, default=None)
    parser.add_argument("--only-sighash-all", action="store_true")
    parser.add_argument("--min-verify-rate", type=float, default=1.0)
    parser.add_argument("--min-stratum-n", type=int, default=20)
    parser.add_argument(
        "--dry-run", action="store_true", help="fetch, validate and report; write nothing"
    )
    args = parser.parse_args(argv)

    if args.end < args.start:
        parser.error("--end must be >= --start")

    out_dir = args.out or f"data/btc-{args.start}-{args.end}"
    cfg = IngestConfig(
        start_height=args.start,
        end_height=args.end,
        min_sigs=args.min_sigs,
        max_sigs=args.max_sigs,
        only_sighash_all=args.only_sighash_all,
        min_verify_rate=args.min_verify_rate,
        min_stratum_n=args.min_stratum_n,
    )

    try:
        corpus, report, provenance = ingest(cfg, build_source(args))
    except IngestGateError as exc:
        print("INGEST GATE FAILED -- nothing written", file=sys.stderr)
        print(exc, file=sys.stderr)
        return 2
    except SourceError as exc:
        print(f"source error: {exc}", file=sys.stderr)
        return 1

    print(report.format())

    if args.dry_run:
        print("\ndry run -- no corpus written")
        return 0

    write_corpus(corpus, report, provenance, out_dir)
    print(f"\nwrote {out_dir}/  (signatures.parquet, keys.parquet, provenance.parquet)")
    # Real signatures may be BIP146 low-s normalised, which is k -> -k. Fingerprint
    # has to fold the reconstructed nonces to match, or an MSB bias reads as two
    # clumps at opposite ends of the range. The synthetic generator never
    # normalises, so the flag is off by default and named here instead.
    print(f"next: qi run --corpus {out_dir} --canonical-nonces")
    print(f"      ({report.low_s_fraction * 100:.1f}% of these signatures are low-s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
