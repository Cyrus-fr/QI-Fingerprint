"""Stage 3: Fingerprint -- reconstruct nonces off a cracked key, classify the bug.

With ``d`` known, every nonce is ``k_i = (h_i + r_i*d) * s_i^-1 mod n``. The
population of reconstructed nonces fixes the root cause:

    truncated_msb      MSB bias, range boundary is a power of two
    modular_reduction  MSB bias, range boundary is a modular fold (not a power of two)
    short_period_prng  repeated nonces (finite value pool) / serial correlation
    weak_seed          nonces are full-range and distinct -- indistinguishable from
                       clean in isolation; only the recovery method (a tiny seed
                       space reproduced them) names it
    clean              no bias

On a corpus that may carry BIP146 low-s normalised signatures -- real Bitcoin --
reconstruct with ``canonical=True`` and pass ``bound=canonical_bound(n)``, which
folds ``k`` and ``-k`` onto one representative and moves the uniform reference
to match. The two go together; either alone is wrong.

Two modes:
  * default -- the recovery method is admissible evidence: ``cracked_by == "seed"``
    names weak_seed directly, since its nonces carry no per-key signal.
  * strict  -- classify ONLY from features of the reconstructed nonces (a KS test
    on the MSB distribution, Bleichenbacher spectrum, lag-1 autocorrelation,
    value-repeat structure); the recovery path (``cracked_by``) and generation order
    (``gen_indices``) are masked. Use this to measure how much a class leans on
    the method rather than the data.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .curves import Curve
from .features import (
    bias_magnitude,
    collision_pairs,
    distinct_ratio,
    exact_period,
    ks_uniform_stat,
    lag1_autocorrelation,
    min_leading_zero_bits,
    spectrum,
)


@dataclass
class Diagnosis:
    label: str
    confidence: float
    evidence: dict = field(default_factory=dict)


def canonical_bound(n: int) -> int:
    """Width of the canonicalised nonce range: ``min(k, n-k)`` lies in [0, n/2)."""
    return n // 2


def reconstruct_nonces(curve: Curve, sigs, d: int, canonical: bool = False) -> list[int]:
    """k_i = (h_i + r_i*d) * s_i^-1 mod n for each signature of a recovered key.

    ``canonical`` folds each nonce to ``min(k, n-k)``. Set it for any corpus that
    may contain BIP146 low-s normalised signatures -- all real Bitcoin from 2016
    on, and about half of the 2013 range. Normalisation rewrites ``s -> n-s``,
    so the reconstructed nonce comes back as ``-k``: without folding, half the
    population lands just below ``n`` and an MSB bias reads as two clumps at
    opposite ends of the range instead of one at the bottom.

    The fold is invariant under normalisation, which is the point, and it costs
    exactly one bit of headroom: every canonical nonce has at least one leading
    zero, so ``min_leading_zero_bits`` reads 1 rather than 0 on unbiased nonces.
    The distribution reference must move with it -- pass
    ``bound=canonical_bound(n)`` to ``nonce_features`` / ``diagnose``, or every
    key looks biased.

    Default off, so synthetic runs (which never normalise) stay bit-for-bit
    reproducible.
    """
    n = curve.n
    ks = [((sig.h + sig.r * d) * curve.inv(sig.s)) % n for sig in sigs]
    return [min(k, n - k) for k in ks] if canonical else ks


def _range_ratio(nonces: list[int]) -> float:
    """max(nonce) / next-power-of-two-above-it. ~1 for a power-of-two truncation,
    well below 1 for a modular fold whose boundary is not a power of two."""
    mx = max(nonces)
    return mx / (1 << mx.bit_length()) if mx > 0 else 0.0


def _ordered_by_gen(nonces: list[int], gen_indices) -> list[int]:
    order = sorted(range(len(nonces)), key=lambda i: gen_indices[i])
    return [nonces[i] for i in order]


def nonce_features(
    nonces: list[int], L: int, gen_indices=None, bound: int | None = None
) -> dict:
    """Classifier features -- every one derived purely from the reconstructed k.

    ``bound`` is the width of the range the nonces are expected to fill, and
    defaults to 2^L. Every phase-based feature (KS, bias magnitude, spectrum,
    lag-1) is scaled by it, so it must be ``canonical_bound(n)`` whenever the
    nonces were canonicalised. ``min_leading_zero_bits`` stays on the raw width
    L, where a canonical population reads one bit rather than zero.
    """
    M = bound if bound is not None else (1 << L)
    feats = {
        "n_nonces": len(nonces),
        "min_leading_zero_bits": min_leading_zero_bits(nonces, L),
        "bias_magnitude": bias_magnitude(nonces, M),
        "range_ratio": _range_ratio(nonces),
        "distinct_ratio": distinct_ratio(nonces),
        "collision_pairs": collision_pairs(nonces),
        "lag1_autocorr": lag1_autocorrelation(nonces, M),
        "spectrum_peak": float(spectrum(nonces, M, 32).max()),
        "ks_stat": ks_uniform_stat(nonces, L, bound=M),
    }
    if gen_indices is not None:  # generation-order feature (masked in strict mode)
        feats["period"] = exact_period(_ordered_by_gen(nonces, gen_indices))
    return feats


def _classify_from_features(f: dict, ks_threshold: float) -> tuple[str, float]:
    """Feature-only decision, identical in both modes.

    The collision / short-period check runs BEFORE the KS MSB test on purpose: a
    small nonce pool can also trip KS, but repeated values name it here first.
    """
    n = max(f["n_nonces"], 1)
    # Short-period PRNG: repeated values (orderless) or serial correlation that
    # clears the lag-1 noise floor (~1/sqrt(N)) -- so tiny samples do not false-fire.
    lag1_significant = abs(f["lag1_autocorr"]) > max(0.4, 2.5 / math.sqrt(n))
    if f["collision_pairs"] > 0 or f["distinct_ratio"] < 0.8 or lag1_significant:
        return "short_period_prng", 0.9
    # MSB bias via a KS test on the nonce phase (replaces the leading-zero gate --
    # it wins the benchmark, catching sub-4-bit bias the old gate was blind to).
    # N-aware floor (KS ~ 1.63/sqrt(N) under uniformity) keeps tiny samples from
    # false-firing while still catching shallow bias when well sampled.
    if f["ks_stat"] >= max(ks_threshold, 1.63 / math.sqrt(n)):
        label = "truncated_msb" if f["range_ratio"] >= 0.9 else "modular_reduction"
        return label, min(0.95, 0.5 + f["ks_stat"] / 2)
    return "clean", 0.8


def diagnose(
    nonces: list[int],
    L: int,
    n: int,
    gen_indices=None,
    cracked_by: str | None = None,
    strict: bool = False,
    ks_threshold: float = 0.5,
    bound: int | None = None,
) -> Diagnosis:
    """Classify the root-cause bias of a recovered key's nonce population.

    In strict mode the recovery path (``cracked_by``) and generation order
    (``gen_indices``) are ignored; classification uses reconstructed-nonce
    features only.

    ``bound`` must be ``canonical_bound(n)`` if the nonces were reconstructed
    with ``canonical=True``; see ``reconstruct_nonces``.
    """
    feats = nonce_features(nonces, L, None if strict else gen_indices, bound=bound)
    evidence = dict(feats)

    # The ONLY use of the recovery path (disabled in strict mode): a weak-seed key
    # has no per-key nonce signal, so a successful small-seed brute force names it.
    if not strict and cracked_by == "seed":
        return Diagnosis(
            "weak_seed", 0.95, {**evidence, "reason": "recovered by small-seed brute force"}
        )

    label, confidence = _classify_from_features(feats, ks_threshold)
    return Diagnosis(label, confidence, evidence)
