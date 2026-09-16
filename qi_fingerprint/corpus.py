"""Corpus data model and on-disk format.

A corpus is stored as up to four parquet tables in a directory:

  Public (what the pipeline is allowed to see):
    signatures.parquet    (key_id, h, r, s)
    keys.parquet          (key_id, curve, Qx, Qy)

  Ground truth (evaluation ONLY -- the pipeline must never load these to make a
  decision; ``load`` omits them unless ``with_truth=True``):
    gt_keys.parquet       (key_id, bias_type, generator_id, d)
    gt_signatures.parquet (key_id, gen_index, true_k)

``gt_signatures`` is written parallel to ``signatures`` (one row per signature,
same order), so it round-trips both the reconstructed-nonce ground truth
(``true_k``) and the generator's sequence position (``gen_index``) -- the latter
is what the Fingerprint stage needs to order nonces for short-period-PRNG
autocorrelation. Losing it would blind that detector.

Big integers are serialised as fixed-width hex strings so 256-bit values survive
parquet's numeric columns intact.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

_HEX_WIDTH = 64  # 256 bits


def to_hex(x: int) -> str:
    return format(int(x), f"0{_HEX_WIDTH}x")


def from_hex(s: str) -> int:
    return int(s, 16)


@dataclass
class Signature:
    key_id: int
    h: int
    r: int
    s: int
    true_k: Optional[int] = None  # ground truth (eval only)
    gen_index: Optional[int] = None  # position in the generator's output stream


@dataclass
class KeyRecord:
    key_id: int
    curve: str
    Qx: int
    Qy: int
    bias_type: Optional[str] = None  # ground truth (eval only)
    generator_id: Optional[int] = None  # which weak generator produced this key
    d: Optional[int] = None  # ground-truth private key (eval only)


@dataclass
class Corpus:
    """In-memory corpus: signatures + keys, optionally carrying ground truth."""

    curve: str = "secp256k1"
    signatures: list[Signature] = field(default_factory=list)
    keys: list[KeyRecord] = field(default_factory=list)

    # -- convenience -----------------------------------------------------------

    def sigs_by_key(self) -> dict[int, list[Signature]]:
        out: dict[int, list[Signature]] = {}
        for sig in self.signatures:
            out.setdefault(sig.key_id, []).append(sig)
        return out

    def key_index(self) -> dict[int, KeyRecord]:
        return {k.key_id: k for k in self.keys}

    @property
    def has_ground_truth(self) -> bool:
        """True only for a corpus the generator made, and we hold its keys already.

        This is the safety predicate for displaying a recovered ``d``. On
        synthetic data the scalar is ours and showing it is the whole point; on
        an ingested Bitcoin corpus it is a live spending key, and there is no
        ``bias_type`` to compare against either. One condition covers both.
        """
        return any(k.d is not None or k.bias_type is not None for k in self.keys)

    # -- io --------------------------------------------------------------------

    def save(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)

        pd.DataFrame(
            {
                "key_id": [s.key_id for s in self.signatures],
                "h": [to_hex(s.h) for s in self.signatures],
                "r": [to_hex(s.r) for s in self.signatures],
                "s": [to_hex(s.s) for s in self.signatures],
            }
        ).to_parquet(os.path.join(path, "signatures.parquet"), index=False)

        pd.DataFrame(
            {
                "key_id": [k.key_id for k in self.keys],
                "curve": [k.curve for k in self.keys],
                "Qx": [to_hex(k.Qx) for k in self.keys],
                "Qy": [to_hex(k.Qy) for k in self.keys],
            }
        ).to_parquet(os.path.join(path, "keys.parquet"), index=False)

        # Ground truth written to separate files, loaded only for evaluation.
        if any(k.bias_type is not None for k in self.keys):
            pd.DataFrame(
                {
                    "key_id": [k.key_id for k in self.keys],
                    "bias_type": [k.bias_type for k in self.keys],
                    "generator_id": [
                        k.generator_id if k.generator_id is not None else -1
                        for k in self.keys
                    ],
                    "d": [to_hex(k.d) if k.d is not None else "" for k in self.keys],
                }
            ).to_parquet(os.path.join(path, "gt_keys.parquet"), index=False)

        # Parallel to signatures.parquet: one row per signature, same order.
        if any(
            s.true_k is not None or s.gen_index is not None for s in self.signatures
        ):
            pd.DataFrame(
                {
                    "key_id": [s.key_id for s in self.signatures],
                    "gen_index": [
                        s.gen_index if s.gen_index is not None else -1
                        for s in self.signatures
                    ],
                    "true_k": [
                        to_hex(s.true_k) if s.true_k is not None else ""
                        for s in self.signatures
                    ],
                }
            ).to_parquet(os.path.join(path, "gt_signatures.parquet"), index=False)

    @classmethod
    def load(cls, path: str, with_truth: bool = False) -> "Corpus":
        sig_df = pd.read_parquet(os.path.join(path, "signatures.parquet"))
        key_df = pd.read_parquet(os.path.join(path, "keys.parquet"))

        gt_key: dict[int, tuple] = {}
        # Keyed by global row position i, which is the join key between
        # signatures.parquet and gt_signatures.parquet (written in lockstep).
        gt_sig: dict[int, tuple[Optional[int], Optional[int]]] = {}  # i -> (true_k, gen_index)
        if with_truth:
            gk_path = os.path.join(path, "gt_keys.parquet")
            gs_path = os.path.join(path, "gt_signatures.parquet")
            if os.path.exists(gk_path):
                for _, row in pd.read_parquet(gk_path).iterrows():
                    d_val = from_hex(row["d"]) if row["d"] else None
                    gid = int(row["generator_id"])
                    gt_key[int(row["key_id"])] = (
                        row["bias_type"],
                        gid if gid >= 0 else None,
                        d_val,
                    )
            if os.path.exists(gs_path):
                gs_df = pd.read_parquet(gs_path).reset_index(drop=True)
                for i, row in gs_df.iterrows():
                    true_k = from_hex(row["true_k"]) if row["true_k"] else None
                    gi_raw = int(row["gen_index"])
                    gen_index = gi_raw if gi_raw >= 0 else None
                    gt_sig[i] = (true_k, gen_index)

        curve = str(key_df["curve"].iloc[0]) if len(key_df) else cls.curve

        keys = []
        for _, row in key_df.iterrows():
            kid = int(row["key_id"])
            bias_type = generator_id = d_val = None
            if kid in gt_key:
                bias_type, generator_id, d_val = gt_key[kid]
            keys.append(
                KeyRecord(
                    key_id=kid,
                    curve=str(row["curve"]),
                    Qx=from_hex(row["Qx"]),
                    Qy=from_hex(row["Qy"]),
                    bias_type=bias_type,
                    generator_id=generator_id,
                    d=d_val,
                )
            )

        signatures = []
        for i, row in sig_df.reset_index(drop=True).iterrows():
            true_k, gen_index = gt_sig.get(i, (None, None))
            signatures.append(
                Signature(
                    key_id=int(row["key_id"]),
                    h=from_hex(row["h"]),
                    r=from_hex(row["r"]),
                    s=from_hex(row["s"]),
                    true_k=true_k,
                    gen_index=gen_index,
                )
            )

        return cls(curve=curve, signatures=signatures, keys=keys)
