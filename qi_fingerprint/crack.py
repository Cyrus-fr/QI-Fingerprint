"""Crack dispatch: run the recovery matched to a Screen crack target.

Every path returns a key only after d*G == Q. For the lattice we do not know the
true MSB-bias depth, so we try a ladder of hypotheses; the gate makes wrong
guesses harmless -- they simply fail to recover, never return a wrong key.
"""

from __future__ import annotations

from typing import Optional

from .curves import Curve
from .lattice import recover_d
from .reuse import recover_by_reuse, recover_by_seed_bruteforce

# A conservative (small) bias guess uses a larger bound, which still contains a
# more-strongly-biased nonce, so 8 tends to crack 8-or-more-bit cohorts in one go.
LATTICE_BIAS_LADDER = (8, 12, 16, 4, 24, 32)
SEED_BITS_LADDER = (12, 14, 16)


def crack_key(
    curve: Curve, sigs, Q, method: str
) -> tuple[Optional[int], Optional[str]]:
    """Return (d, method_used) or (None, None)."""
    if method == "reuse":
        d = recover_by_reuse(curve, sigs, Q)
        return (d, "reuse") if d is not None else (None, None)

    if method == "seed":
        for seed_bits in SEED_BITS_LADDER:
            d = recover_by_seed_bruteforce(curve, sigs, Q, seed_bits)
            if d is not None:
                return d, "seed"
        return None, None

    if method == "lattice":
        for bias_bits in LATTICE_BIAS_LADDER:
            d = recover_d(curve, sigs, bias_bits, Q)
            if d is not None:
                return d, "lattice"
        return None, None

    return None, None
