"""Statistical nonce-bias features.

Shared by two callers:
  * the M1 generator gate, to *confirm a planted bias is actually present* in the
    raw nonces before any downstream stage trusts the corpus;
  * the Fingerprint stage (M4), to classify the root cause from nonces
    reconstructed off a cracked key.

Nonces are full-width Python ints (up to 2^256). Bit-oriented features use exact
integer ops; the spectral (Bleichenbacher) feature maps each nonce to a phase in
[0, 1) via correctly-rounded int division, which preserves ~53 bits of the ratio
-- ample to separate gross bias from uniform at demo sample sizes.
"""

from __future__ import annotations

import numpy as np


def _nonzero(ks: list[int]) -> list[int]:
    return [int(k) for k in ks if int(k) != 0]


def min_leading_zero_bits(ks: list[int], L: int) -> int:
    """Fewest leading zero bits across the sample (relative to width L).

    truncated_msb with B dead top bits -> ~B (every nonce has >=B leading zeros).
    Uniform nonces -> ~0 (some nonce sets the top bit).
    """
    vals = _nonzero(ks)
    if not vals:
        return 0
    return min(L - v.bit_length() for v in vals)


def msb_bit_means(ks: list[int], L: int, b: int) -> np.ndarray:
    """Mean of each of the top ``b`` bits. ~0.5 uniform; hard 0 for dead bits."""
    vals = _nonzero(ks)
    if not vals:
        return np.zeros(b)
    acc = np.zeros(b)
    for v in vals:
        for j in range(b):
            acc[j] += (v >> (L - 1 - j)) & 1
    return acc / len(vals)


def bias_magnitude(ks: list[int], M: int) -> float:
    """|mean(exp(2*pi*i*k/M))|.

    ~1/sqrt(N) for uniform k over [0, M); approaches 1 as nonces concentrate
    (e.g., MSB truncation pins the phase near 0). This is the sample form of the
    Bleichenbacher bias functional.
    """
    vals = _nonzero(ks)
    if not vals:
        return 0.0
    phases = np.array([(v % M) / M for v in vals], dtype=np.float64)
    z = np.exp(2j * np.pi * phases)
    return float(np.abs(z.mean()))


def spectrum(ks: list[int], M: int, max_w: int = 64) -> np.ndarray:
    """Bias magnitude at integer frequencies w=1..max_w (the FFT-style scan).

    A modular-reduction fold against modulus m shows a peak at a w tied to m,
    distinguishing it from a clean power-of-two truncation. Feeds the Fingerprint
    classifier and the UI spectrum plot.
    """
    vals = _nonzero(ks)
    if not vals:
        return np.zeros(max_w)
    phases = np.array([(v % M) / M for v in vals], dtype=np.float64)
    out = np.empty(max_w)
    for w in range(1, max_w + 1):
        z = np.exp(2j * np.pi * (w * phases))
        out[w - 1] = np.abs(z.mean())
    return out


def exact_period(seq: list[int], max_lag: int | None = None) -> int | None:
    """Smallest lag P>0 with seq[i] == seq[i+P] for every overlapping i.

    Detects the pool-based short-period PRNG (k_i = pool[i mod P]) exactly, with
    no floating point. Returns None if no full period is found within max_lag.
    """
    n = len(seq)
    if n < 4:
        return None
    limit = max_lag if max_lag is not None else n // 2
    for p in range(1, limit + 1):
        if all(seq[i] == seq[i + p] for i in range(n - p)):
            return p
    return None


def distinct_ratio(ks: list[int]) -> float:
    """Fraction of distinct values; low for short-period / weak-seed sources."""
    if not ks:
        return 0.0
    return len(set(int(k) for k in ks)) / len(ks)


def collision_pairs(values: list[int]) -> int:
    """Number of colliding pairs (sum over duplicated values of C(count, 2))."""
    from collections import Counter

    counts = Counter(int(v) for v in values)
    return sum(c * (c - 1) // 2 for c in counts.values() if c > 1)


def lag1_autocorrelation(ks: list[int], M: int) -> float:
    """Pearson autocorrelation at lag 1 of the nonce sequence (as phases k/M).

    Catches an LCG-style short period (x_{i+1} = a*x_i + c), where consecutive
    nonces are linearly related. Note it is ~0 for a *pool*-style short period
    (k_i = pool[i mod P]) whose signal is repeated values, not serial correlation
    -- for that, see distinct_ratio / collision_pairs.
    """
    if len(ks) < 3:
        return 0.0
    x = np.array([(int(k) % M) / M for k in ks], dtype=np.float64)
    a, b = x[:-1], x[1:]
    if a.std() == 0 or b.std() == 0:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


# --------------------------------------------------------------------------- #
# Statistical bias-detection tests (first-class MSB-bias classifiers)
# --------------------------------------------------------------------------- #


def chi2_msb_stat(ks: list[int], L: int, b: int = 16) -> float:
    """Per-bit chi-square of the top ``b`` MSBs vs uniform (sum of z^2, ~chi2_b).

    Each top bit is Binomial(N, 1/2) under a uniform nonce; the summed squared
    z-scores are ~0 for uniform and blow up when top bits are dead (truncation).
    More sensitive to weak bias than a hard leading-zero-bit count, but inflated
    by a tiny distinct-value pool (few-value short-period sources).
    """
    n = len(ks)
    if n == 0:
        return 0.0
    stat = 0.0
    for j in range(b):
        ones = sum((int(v) >> (L - 1 - j)) & 1 for v in ks)
        stat += (ones - n / 2) ** 2 / (n / 4)
    return stat


def ks_uniform_stat(ks: list[int], L: int, bound: int | None = None) -> float:
    """Kolmogorov-Smirnov statistic of the phases k/bound against Uniform[0,1).

    ~1/sqrt(N) under uniformity; approaches 1 as the nonces concentrate (any MSB
    bias, however shallow). The most sample-efficient of the bias tests here.

    ``bound`` is the width of the range the nonces are *expected* to fill, and
    defaults to the raw nonce width 2^L. It has to move when the nonces do:
    canonicalised nonces (``k -> min(k, n-k)``, see ``fingerprint``) live in
    [0, n/2), so tested against the full width every key would look maximally
    biased -- no phase could ever exceed 0.5 -- and the reference must be the
    half-range instead.
    """
    if len(ks) < 2:
        return 0.0
    from scipy.stats import kstest

    hi = bound if bound is not None else (1 << L)
    phases = [(int(v) % hi) / hi for v in ks]
    return float(kstest(phases, "uniform").statistic)


def fft_peak_to_floor(ks: list[int], L: int, max_w: int = 32) -> float:
    """Bleichenbacher spectrum peak over the uniform noise floor: peak * sqrt(N).

    The raw peak-to-floor ratio of the DFT bias scan -- a few for uniform nonces,
    large under MSB bias. Weaker than KS at the shallowest (1-bit) bias.
    """
    import math

    if not ks:
        return 0.0
    return float(spectrum(ks, 1 << L, max_w).max()) * math.sqrt(len(ks))
