"""Hunt a block range for ECDSA nonce reuse, then confirm each hit properly.

Phase B of the real-data plan: the pipeline's *positive control*. A clean run on
a range where recovery has never been demonstrated is indistinguishable from a
broken run, so before any "nothing found" result is reportable we need one real
mainnet key that recovery must succeed on.

Two passes, for cost reasons:

  scan     raw blocks only -- scriptSigs carry (r, pubkey), which is all a
           candidate needs. ~4x cheaper per block than fetching prevouts.
  confirm  for each candidate, refetch the implicated blocks in full, recompute
           z from the real prevouts, run the verify gate, and require d*G == Q.

A confirmed key then *cascades*: the scan also retains every cross-key
r-collision it saw, and each one becomes solvable the moment either of its two
keys is known. Those hops are confirmed to the same standard -- refetched,
re-derived, gated -- so a chain of findings is as checkable as a single one.

**Two scan modes.** The default keeps the index in memory, which is fine for a
few thousand blocks. ``--index PATH`` writes a 24-byte record per signature to
disk instead: the in-memory index costs ~682 bytes per signature, which is 9.5 GB
across the ~20k-block Android `SecureRandom` window and simply will not run. The
on-disk index also *resumes* (``--resume``), so a multi-day scan survives being
interrupted. Pair it with ``--cache-raw`` -- confirmation refetches the blocks a
hit implicates, and a cache turns that into a disk read.

**Safety.** Read-only, and recovery stops at the mathematical check. No private
key is printed, logged or written to disk -- not for the seed key and not for any
key reached by cascade; this package cannot construct, sign or broadcast a
transaction, and no balance is ever queried. What a confirmed hit reports is the
(txid, vin) provenance and the derived address -- enough to check the finding on
any block explorer, and not enough to move a coin.

    docker compose run --rm pipeline python tools/find_reuse.py \\
        --start 250000 --end 250200

    docker compose run --rm pipeline python tools/find_reuse.py \\
        --start 240000 --end 260000 --index data/hunt.idx --cache-raw --resume
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from qi_fingerprint.curves import get_curve
from qi_fingerprint.ingest.control import (
    SAFETY_BANNER,
    ControlError,
    confirm_with_cascade,
)
from qi_fingerprint.ingest.hunt import ReuseIndex, scan_block
from qi_fingerprint.ingest.rindex import (
    confirm_hit,
    find_prefix_hits,
    load_records,
    scan_to_index,
)
from qi_fingerprint.ingest.sources import (
    CachedSource,
    EsploraSource,
    FileSource,
    RawCachedSource,
    SourceError,
    iter_raw_blocks,
)
from qi_fingerprint.ingest.validate import IngestGateError

DEFAULT_ESPLORA = "https://blockstream.info/api"
DEFAULT_CACHE = "data/cache/bitcoin"
DEFAULT_RAW_CACHE = "data/cache/bitcoin-raw"


def scan(source, start: int, end: int, *, quiet: bool = False):
    """Stream the range in memory, returning (candidates, index, n_scanned)."""
    index = ReuseIndex()
    candidates = []
    began = time.monotonic()
    done = 0

    # `iter_raw_blocks` walks the range DOWNWARDS -- each header names its
    # predecessor, which is what makes it one request per block -- so progress
    # has to be counted, not derived from the height.
    for record in iter_raw_blocks(source, start, end):
        done += 1
        for site in scan_block(record.txs, record.height):
            hit = index.add(site)
            if hit is not None:
                candidates.append(hit)
                if not quiet:
                    first, second = hit.sites[0], hit.sites[1]
                    print(
                        f"  candidate @ {record.height}: "
                        f"{first.txid[:16]}..:{first.vin} <-> "
                        f"{second.txid[:16]}..:{second.vin}",
                        flush=True,
                    )
        if not quiet and done % 25 == 0:
            elapsed = max(time.monotonic() - began, 1e-9)
            remaining = (end - start + 1) - done
            print(
                f"  ..{record.height}  {done} blocks, {index.n_sites} sigs, "
                f"{len(candidates)} candidates, {done / elapsed:.2f} blk/s, "
                f"~{remaining / max(done / elapsed, 1e-9) / 60:.0f} min left",
                flush=True,
            )

    return candidates, index, index.n_sites


def scan_indexed(source, path: str, start: int, end: int, *, resume: bool, quiet: bool):
    """Wide-scan path: 24 bytes per signature to disk, then an exact recheck.

    The index narrows millions of signatures to a handful of prefix hits; those
    are re-derived from refetched blocks, and only the survivors go through the
    ordinary in-memory `ReuseIndex`. So the classification logic -- same-key
    candidate vs retained cross-key pair -- is the same code in both modes, run
    over a set small enough to hold trivially.
    """
    began = time.monotonic()
    counter = {"blocks": 0}

    def progress(height: int, _n_block_sites: int, total: int) -> None:
        counter["blocks"] += 1
        if quiet or counter["blocks"] % 25:
            return
        elapsed = max(time.monotonic() - began, 1e-9)
        rate = counter["blocks"] / elapsed
        remaining = (end - start + 1) - counter["blocks"]
        print(
            f"  ..{height}  {counter['blocks']} blocks, {total} sigs, "
            f"{rate:.2f} blk/s, ~{remaining / max(rate, 1e-9) / 60:.0f} min left",
            flush=True,
        )

    state = scan_to_index(
        source, path, start, end, resume=resume, on_block=progress
    )

    hits = find_prefix_hits(load_records(path))
    if not quiet:
        print(f"\n{len(hits)} prefix hit(s); rechecking each against the full r")

    index = ReuseIndex()
    candidates = []
    for hit in hits:
        sites = confirm_hit(hit, source)
        if sites is None:
            if not quiet:
                print(f"  prefix hit at {hit.locations[0][0]} was not a real collision")
            continue
        for site in sites:
            found = index.add(site)
            if found is not None:
                candidates.append(found)

    return candidates, index, state.n_sites


def _report_cross_key(index: ReuseIndex) -> None:
    """Name the cross-key pairs rather than only counting them.

    A collision you cannot point at is a collision you cannot come back to. These
    are inert on their own -- two equations, three unknowns -- but each one is a
    lead the cascade can take up the moment either of its keys falls.
    """
    if not index.cross_key_hits:
        return
    print("\ncross-key r-collisions (one nonce, two keys):")
    for hit in index.cross_key_hits:
        first, second = hit.sites
        print(
            f"  r {hit.r:064x}\n"
            f"    {first.txid}:{first.vin}  height {first.height}\n"
            f"    {second.txid}:{second.vin}  height {second.height}"
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="find_reuse",
        description="Find and verify real ECDSA nonce reuse in a Bitcoin block range.",
    )
    parser.add_argument("--start", type=int, required=True, help="first block height")
    parser.add_argument("--end", type=int, required=True, help="last height (inclusive)")
    parser.add_argument(
        "--source",
        choices=["esplora", "cache"],
        default="esplora",
        help="'cache' replays an earlier scan from disk with zero network I/O",
    )
    parser.add_argument("--esplora-url", default=DEFAULT_ESPLORA)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE, help="full-block cache")
    parser.add_argument("--raw-cache-dir", default=DEFAULT_RAW_CACHE)
    parser.add_argument("--rate", type=float, default=2.0, help="max requests/second")
    parser.add_argument(
        "--retries",
        type=int,
        default=8,
        help="retries per request; a wide scan needs to ride out rate limiting",
    )
    parser.add_argument(
        "--cache-raw",
        action="store_true",
        help="cache scanned blocks to disk (fast re-scan, but ~300MB per 1000 blocks)",
    )
    parser.add_argument(
        "--index",
        help="write a 24-byte record per signature here instead of indexing in "
        "memory; required for ranges of more than a few thousand blocks",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="continue an interrupted --index scan from where it stopped",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="report candidates; do not attempt recovery",
    )
    parser.add_argument(
        "--no-cascade",
        action="store_true",
        help="confirm same-key candidates only; do not walk cross-key edges",
    )
    parser.add_argument("--out", help="write the findings as JSON to this path")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.end < args.start:
        parser.error("--end must be >= --start")
    if args.resume and not args.index:
        parser.error("--resume needs --index: the index file is the checkpoint")

    if args.source == "cache":
        # Offline replay: both the scan and the confirmation come off disk, so a
        # published finding can be re-derived without trusting -- or troubling --
        # a third-party API.
        raw_source = RawCachedSource(None, args.raw_cache_dir)
        full_source = FileSource(args.cache_dir)
    else:
        esplora = EsploraSource(args.esplora_url, rate_hz=args.rate, retries=args.retries)
        raw_source = (
            RawCachedSource(esplora, args.raw_cache_dir) if args.cache_raw else esplora
        )
        full_source = CachedSource(esplora, args.cache_dir)
    curve = get_curve("secp256k1")

    print(f"scanning blocks {args.start}..{args.end} for r-collisions", flush=True)
    try:
        if args.index:
            candidates, index, n_scanned = scan_indexed(
                raw_source,
                args.index,
                args.start,
                args.end,
                resume=args.resume,
                quiet=args.quiet,
            )
        else:
            candidates, index, n_scanned = scan(
                raw_source, args.start, args.end, quiet=args.quiet
            )
    except SourceError as exc:
        print(f"source error: {exc}", file=sys.stderr)
        if args.index:
            print(
                f"the index at {args.index} is a checkpoint -- rerun with --resume",
                file=sys.stderr,
            )
        return 1

    print(
        f"\nscanned {args.end - args.start + 1} blocks, {n_scanned} signatures\n"
        f"  same-key r-collisions : {len(candidates)}\n"
        f"  cross-key r-collisions: {index.cross_key_r}  "
        f"(inert alone; chased once a key in the pair is known)"
    )
    if not args.quiet:
        _report_cross_key(index)

    if not candidates:
        print(
            "\nNo nonce reuse in this range. That is a result, not a control --\n"
            "the pipeline has still not been shown to fire. Widen the range."
        )
        return 3

    if args.scan_only:
        print("\nscan only -- no recovery attempted")
        return 0

    cross_hits = [] if args.no_cascade else index.cross_key_hits
    print(f"\nconfirming {len(candidates)} candidate(s) through the full gated path")
    confirmations = []
    chain_results = []
    for candidate in candidates:
        try:
            confirmation, chained = confirm_with_cascade(
                candidate, cross_hits, full_source, curve
            )
        except (ControlError, IngestGateError, SourceError) as exc:
            height = candidate.sites[0].height
            print(f"  candidate at height {height} not confirmable: {exc}")
            continue
        confirmations.append(confirmation)
        chain_results.extend(chained)

    recovered = [c for c in confirmations if c.recovered]
    chained_recovered = [c for c in chain_results if c.recovered]
    if recovered or chained_recovered:
        print(SAFETY_BANNER)
    for confirmation in confirmations:
        print(confirmation.format())
        print()

    print(f"confirmed {len(recovered)}/{len(confirmations)} candidate(s) with d*G == Q")

    if chain_results:
        print(
            f"\ncascaded across {len(chain_results)} cross-key edge(s); "
            f"{len(chained_recovered)} further key(s) recovered"
        )
        for chained in chain_results:
            print(chained.format())
            print()
    elif cross_hits:
        print("\nno cross-key edge touched a recovered key")

    if args.out:
        payload = {
            "range": [args.start, args.end],
            "n_signatures_scanned": n_scanned,
            "cross_key_r_collisions": index.cross_key_r,
            "findings": [
                {
                    "recovered": c.recovered,
                    "addresses": list(c.addresses),
                    "r": f"{c.candidate.r:064x}",
                    "detail": c.detail,
                    "inputs": [
                        {
                            "txid": s.txid,
                            "vin": s.vin,
                            "height": s.height,
                            "low_s": s.low_s,
                        }
                        for s in c.verified_sigs
                    ],
                }
                for c in confirmations
            ],
            # Every cross-key pair the scan retained, whether or not it was
            # walked -- an unchased lead is still evidence, and stays checkable.
            "cross_key_edges": [
                {
                    "r": f"{hit.r:064x}",
                    "inputs": [
                        {"txid": s.txid, "vin": s.vin, "height": s.height}
                        for s in hit.sites
                    ],
                }
                for hit in index.cross_key_hits
            ],
            "chained": [
                {
                    "recovered": c.recovered,
                    "addresses": list(c.addresses),
                    "via_addresses": list(c.via_addresses),
                    "r": f"{c.r:064x}",
                    "depth": c.depth,
                    "detail": c.detail,
                    "inputs": [
                        {
                            "txid": s.txid,
                            "vin": s.vin,
                            "height": s.height,
                            "low_s": s.low_s,
                        }
                        for s in c.verified_sigs
                    ],
                }
                for c in chain_results
            ],
        }
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        print(f"wrote {args.out}")

    return 0 if (recovered or chained_recovered) else 4


if __name__ == "__main__":
    raise SystemExit(main())
