"""Orchestration: a block range in, a `Corpus` the pipeline can read out.

This is the only module that writes to disk, and it writes nothing at all unless
the verify gate passes. The corpus it emits is the same shape the synthetic
generator produces, minus the ground-truth tables -- because on real data there
is no `bias_type` to score against. What survives is `d·G == Q`, which is
self-verifying: a recovered key needs no oracle to be believed.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

import pandas as pd

from ..corpus import Corpus, KeyRecord, Signature
from ..curves import Curve, get_curve
from .extract import ExtractedSig, SkippedInput, extract_tx
from .sources import BlockSource, iter_blocks
from .validate import ValidationReport, assert_gate, validate


@dataclass(frozen=True)
class IngestConfig:
    start_height: int
    end_height: int  # inclusive
    min_sigs: int = 1
    min_verify_rate: float = 1.0
    min_stratum_n: int = 20
    min_stratum_rate: float = 1.0
    max_sigs: int | None = None
    only_sighash_all: bool = False


@dataclass(frozen=True)
class ProvenanceRow:
    """Row-parallel to signatures.parquet, so any future 'we cracked a real key'
    claim is traceable back to a specific transaction input."""

    row: int
    key_id: int
    height: int
    txid: str
    vin: int
    script_type: str
    sigversion: str
    hashtype: int
    low_s: bool
    pubkey_len: int


@dataclass
class IngestReport:
    heights: tuple[int, int] = (0, 0)
    n_blocks: int = 0
    n_txs: int = 0
    n_inputs: int = 0
    validation: ValidationReport = field(default_factory=ValidationReport)
    n_keys: int = 0
    n_signatures: int = 0
    script_type_counts: dict[str, int] = field(default_factory=dict)
    hashtype_counts: dict[int, int] = field(default_factory=dict)
    low_s_fraction: float = 0.0
    sigs_per_key_hist: dict[int, int] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "heights": list(self.heights),
            "n_blocks": self.n_blocks,
            "n_txs": self.n_txs,
            "n_inputs": self.n_inputs,
            "n_keys": self.n_keys,
            "n_signatures": self.n_signatures,
            "verify": {
                "attempted": self.validation.attempted,
                "passed": self.validation.passed,
                "pass_rate": self.validation.pass_rate,
                "per_stratum": {
                    str(k): {"attempted": v.attempted, "passed": v.passed}
                    for k, v in self.validation.per_stratum.items()
                },
                "skipped": self.validation.skipped,
            },
            "script_type_counts": self.script_type_counts,
            "hashtype_counts": {str(k): v for k, v in self.hashtype_counts.items()},
            "low_s_fraction": self.low_s_fraction,
            "sigs_per_key_hist": {str(k): v for k, v in self.sigs_per_key_hist.items()},
        }

    def format(self) -> str:
        lo, hi = self.heights
        lines = [
            f"blocks {lo}..{hi}  ({self.n_blocks} blocks, {self.n_txs} txs, "
            f"{self.n_inputs} inputs)",
            self.validation.format_table(),
            f"  corpus: {self.n_signatures} signatures over {self.n_keys} keys",
            f"  low-s : {self.low_s_fraction * 100:.1f}%",
        ]
        multi = {k: v for k, v in self.sigs_per_key_hist.items() if k > 1}
        if multi:
            lines.append(
                "  keys with >1 signature: "
                + ", ".join(f"{n}x:{c}" for n, c in sorted(multi.items()))
            )
        else:
            lines.append("  keys with >1 signature: none")
        return "\n".join(lines)


def extract_range(
    source: BlockSource, cfg: IngestConfig
) -> tuple[list[ExtractedSig], list[SkippedInput], dict]:
    """Walk the block range, extracting every supported input."""
    sigs: list[ExtractedSig] = []
    skips: list[SkippedInput] = []
    stats = {"n_blocks": 0, "n_txs": 0, "n_inputs": 0}
    seen: set[tuple[str, int]] = set()  # (txid, vin) -- guards double pagination

    for record in iter_blocks(source, cfg.start_height, cfg.end_height):
        stats["n_blocks"] += 1
        for tx, prevouts in record.txs:
            stats["n_txs"] += 1
            stats["n_inputs"] += len(tx.vin)
            found, missed = extract_tx(tx, prevouts, record.height)
            skips.extend(missed)
            for sig in found:
                identity = (sig.txid, sig.vin)
                if identity in seen:
                    continue
                seen.add(identity)
                if cfg.only_sighash_all and sig.hashtype != 0x01:
                    skips.append(
                        SkippedInput(sig.height, sig.txid, sig.vin, "not_sighash_all")
                    )
                    continue
                sigs.append(sig)
        if cfg.max_sigs is not None and len(sigs) >= cfg.max_sigs:
            sigs = sigs[: cfg.max_sigs]
            break
    return sigs, skips, stats


def build_corpus(
    sigs: Iterable[ExtractedSig], min_sigs: int = 1
) -> tuple[Corpus, list[ProvenanceRow]]:
    """Group verified signatures by public key and assemble a `Corpus`.

    Grouping is by the POINT `(Qx, Qy)`, never by address and never by the
    serialised pubkey bytes -- that is what collapses the compressed and
    uncompressed encodings of one private key into a single `key_id`.
    """
    ordered = sorted(sigs, key=lambda s: (s.height, s.txid, s.vin))

    by_point: dict[tuple[int, int], list[ExtractedSig]] = {}
    for sig in ordered:
        by_point.setdefault((sig.qx, sig.qy), []).append(sig)

    kept = {pt: rows for pt, rows in by_point.items() if len(rows) >= min_sigs}

    corpus = Corpus(curve="secp256k1")
    provenance: list[ProvenanceRow] = []
    row = 0
    # key_id assigned first-seen in canonical order, so runs are reproducible.
    for key_id, (point, rows) in enumerate(
        sorted(kept.items(), key=lambda kv: (kv[1][0].height, kv[1][0].txid, kv[1][0].vin))
    ):
        qx, qy = point
        corpus.keys.append(KeyRecord(key_id=key_id, curve="secp256k1", Qx=qx, Qy=qy))
        for sig in rows:
            corpus.signatures.append(
                Signature(key_id=key_id, h=sig.z, r=sig.r, s=sig.s)
            )
            provenance.append(
                ProvenanceRow(
                    row=row,
                    key_id=key_id,
                    height=sig.height,
                    txid=sig.txid,
                    vin=sig.vin,
                    script_type=sig.script_type,
                    sigversion=sig.sigversion,
                    hashtype=sig.hashtype,
                    low_s=sig.low_s,
                    pubkey_len=sig.pubkey_len,
                )
            )
            row += 1
    return corpus, provenance


def ingest(
    cfg: IngestConfig, source: BlockSource, curve: Curve | None = None
) -> tuple[Corpus, IngestReport, list[ProvenanceRow]]:
    """Fetch, extract, gate, and assemble. Raises `IngestGateError` on a bad gate."""
    curve = curve or get_curve("secp256k1")

    sigs, skips, stats = extract_range(source, cfg)
    verified, validation = validate(sigs, curve)
    validation.skipped = dict(Counter(s.reason for s in skips))

    # Hard gate: below threshold, the caller gets an exception and no corpus.
    assert_gate(
        validation,
        min_rate=cfg.min_verify_rate,
        min_stratum_n=cfg.min_stratum_n,
        min_stratum_rate=cfg.min_stratum_rate,
    )

    corpus, provenance = build_corpus(verified, cfg.min_sigs)

    per_key = Counter(s.key_id for s in corpus.signatures)
    report = IngestReport(
        heights=(cfg.start_height, cfg.end_height),
        n_blocks=stats["n_blocks"],
        n_txs=stats["n_txs"],
        n_inputs=stats["n_inputs"],
        validation=validation,
        n_keys=len(corpus.keys),
        n_signatures=len(corpus.signatures),
        script_type_counts=dict(Counter(s.script_type for s in verified)),
        hashtype_counts=dict(Counter(s.hashtype for s in verified)),
        low_s_fraction=(
            sum(1 for s in verified if s.low_s) / len(verified) if verified else 0.0
        ),
        sigs_per_key_hist=dict(Counter(per_key.values())),
    )
    return corpus, report, provenance


def write_corpus(
    corpus: Corpus,
    report: IngestReport,
    provenance: list[ProvenanceRow],
    out_dir: str,
) -> None:
    """Write the corpus plus two inert sidecars.

    `Corpus.load` reads only signatures/keys/gt_* parquets, so the extra files
    sit alongside without affecting it.
    """
    corpus.save(out_dir)

    pd.DataFrame([p.__dict__ for p in provenance]).to_parquet(
        os.path.join(out_dir, "provenance.parquet"), index=False
    )
    with open(os.path.join(out_dir, "ingest_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(report.to_json(), fh, indent=2)
        fh.write("\n")
