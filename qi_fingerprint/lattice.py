"""Stage 2: HNP lattice recovery of the ECDSA private key -- the centerpiece.

Given several signatures whose nonces share a known MSB bias (top ``bias_bits``
are zero), recover the private key. We use the *elimination form* of the HNP:
eliminate ``d`` using the first signature so the unknowns are the small nonces
``k_i`` themselves. That yields a fully-integer lattice basis with no fractional
bound-scaling -- the classic home of silent, mis-scaled-basis bugs.

    From  k_i == a_i + t_i*d (mod n)  and  d == t_0^-1 (k_0 - a_0) (mod n):
        k_i - tau_i*k_0 == alpha_i (mod n),   tau_i = t_i*t_0^-1,  alpha_i = a_i - tau_i*a_0

    Lattice L = { y in Z^m : y_i == tau_i*y_0 (mod n) } contains (k - offset); a
    Kannan embedding turns the closest-vector search into an SVP whose short
    vector reveals the nonces. From any nonce, d follows algebraically.

NOTHING is returned unless ``d*G == Q``. A mis-scaled basis returns garbage
without raising, so the gate is the oracle -- not an afterthought. Extraction
scans every reduced row and both signs and lets the gate arbitrate, so sign/scale
ambiguity in the short vector cannot produce a wrong key (only, at worst, a miss).
"""

from __future__ import annotations

from typing import Optional

from fpylll import BKZ, LLL, IntegerMatrix

from .corpus import Signature
from .curves import Curve
from .hnp import build_hnp
from .verify import recovers_key


def _build_basis(n: int, t: list[int], a: list[int], bound: int) -> list[list[int]]:
    """(m+1) x (m+1) integer Kannan-embedding basis for the elimination HNP."""
    m = len(t)
    t0_inv = pow(t[0], -1, n)
    tau = [(t[i] * t0_inv) % n for i in range(m)]  # tau[0] == 1
    alpha = [(a[i] - tau[i] * a[0]) % n for i in range(m)]  # alpha[0] == 0

    dim = m + 1
    rows = [[0] * dim for _ in range(dim)]
    # Row 0: y_0 = 1 generates y_i = tau_i.
    rows[0][0] = 1
    for j in range(1, m):
        rows[0][j] = tau[j]
    # Rows 1..m-1: the modular freedom n*e_j.
    for i in range(1, m):
        rows[i][i] = n
    # Row m: the embedded target (0, alpha_1, ..., alpha_{m-1}, bound).
    for j in range(1, m):
        rows[m][j] = alpha[j]
    rows[m][m] = bound
    return rows


def _reduce(rows: list[list[int]], method: str, block_size: int) -> list[list[int]]:
    dim = len(rows)
    A = IntegerMatrix(dim, dim)
    for i in range(dim):
        for j in range(dim):
            A[i, j] = int(rows[i][j])
    if method == "bkz":
        BKZ.reduction(A, BKZ.Param(block_size=block_size))
    else:
        LLL.reduction(A)
    return [[A[i, j] for j in range(dim)] for i in range(dim)]


def _extract_d(
    curve: Curve,
    sigs: list[Signature],
    reduced: list[list[int]],
    bound: int,
    Q,
) -> Optional[int]:
    """Read a plausible nonce off a reduced row, derive d, and let the gate decide."""
    n = curve.n
    m = len(sigs)
    for row in reduced:
        for sign in (1, -1):
            for i in range(m):
                ki = sign * row[i]
                if 0 <= ki < bound:  # plausible small nonce
                    sig = sigs[i]
                    d = ((sig.s * ki - sig.h) * curve.inv(sig.r)) % n
                    if recovers_key(d, Q, curve):
                        return d
    return None


def recover_d(
    curve: Curve,
    sigs: list[Signature],
    bias_bits: int,
    Q,
    method: str = "auto",
    block_size: int = 20,
    max_dim: int = 80,
) -> Optional[int]:
    """Recover the private key from MSB-biased signatures, or None.

    ``method``: "lll", "bkz", or "auto" (LLL first, then escalate to BKZ). The
    return value is guaranteed to satisfy d*G == Q or be None -- never a wrong key.
    """
    use = sigs[:max_dim]
    if len(use) < 3:
        return None

    hnp = build_hnp(curve, use, bias_bits)
    rows = _build_basis(hnp.n, hnp.t, hnp.a, hnp.bound)

    if method == "lll":
        plan = [("lll", 0)]
    elif method == "bkz":
        plan = [("bkz", block_size)]
    else:  # auto: cheapest first, escalate block size only if needed
        plan = [("lll", 0), ("bkz", 20), ("bkz", 30)]

    for meth, bs in plan:
        reduced = _reduce(rows, meth, bs)
        d = _extract_d(curve, use, reduced, hnp.bound, Q)
        if d is not None:
            return d
    return None
