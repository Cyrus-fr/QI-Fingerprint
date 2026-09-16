"""Stage 2b: non-lattice private-key recovery.

Three cheap, deterministic cracks that Screen routes work to:
  * nonce reuse -- two signatures under one key sharing r (=> sharing k); the
    catastrophic case, and how short-period-PRNG keys fall (a small period forces
    repeats);
  * weak seed  -- nonces drawn from a tiny seed space, brute-forced against a
    known PRNG model (as real attacks do for known-weak implementations);
  * shared nonce across keys -- ``nonce_from_signature`` /
    ``recover_from_shared_nonce``, the pair `chain.py` walks a cohort with. Two
    *different* keys sharing a nonce is two equations in three unknowns and has
    no solution on its own; the moment either key is known it collapses to one
    equation in one unknown.

All of them verify d*G == Q before returning; a candidate that fails the gate is
discarded.
"""

from __future__ import annotations

from typing import Optional

from .corpus import Signature
from .curves import Curve
from .generator import weak_seed_nonce
from .verify import recovers_key


def recover_from_reuse(
    curve: Curve, sig1: Signature, sig2: Signature, Q
) -> Optional[int]:
    """Recover d from two signatures that reused a nonce (same r, different h).

    Two cases, and both must be tried. BIP146 low-s normalisation rewrites
    ``s -> n - s``, which is exactly ``k -> -k``; since ``x(kG) == x(-kG)`` the
    r-collision fires either way. So a shared ``r`` does NOT imply the two
    signatures share the same *signed* nonce:

        same sign   s1 - s2 = k^-1 (h1 - h2)  ->  k = (h1-h2) / (s1-s2)
        mixed sign  s1 + s2 = k^-1 (h1 - h2)  ->  k = (h1-h2) / (s1+s2)

    On a normalised corpus roughly half of all genuine reuse pairs are mixed.
    Trying only the same-sign form makes Screen find a real compromise that
    Crack then silently declines to recover -- which on real data is
    indistinguishable from "nothing found". ``k`` here is always sig1's own
    nonce, so one ``d`` formula serves both branches, and ``d*G == Q`` decides
    between them: a wrong branch simply fails the gate.
    """
    n = curve.n
    if sig1.r != sig2.r:
        return None
    dh = (sig1.h - sig2.h) % n
    if dh == 0:
        return None  # same message -> no information in either case
    rinv = curve.inv(sig1.r)
    for denominator in ((sig1.s - sig2.s) % n, (sig1.s + sig2.s) % n):
        if denominator == 0:
            continue  # degenerate for THIS branch only; the other may still work
        k = (dh * curve.inv(denominator)) % n
        if k == 0:
            continue
        d = ((sig1.s * k - sig1.h) * rinv) % n
        if recovers_key(d, Q, curve):
            return d
    return None


def recover_by_reuse(curve: Curve, sigs: list[Signature], Q) -> Optional[int]:
    """Scan a key's signatures for any nonce-reuse (r-collision) pair."""
    seen: dict[int, Signature] = {}
    for sig in sigs:
        prior = seen.get(sig.r)
        if prior is not None:
            d = recover_from_reuse(curve, prior, sig, Q)
            if d is not None:
                return d
        else:
            seen[sig.r] = sig
    return None


# --------------------------------------------------------------------------- #
# Shared nonce across two DIFFERENT keys -- the cohort edge `chain.py` walks
# --------------------------------------------------------------------------- #


def nonce_from_signature(curve: Curve, sig: Signature, d: int) -> int:
    """The nonce a signature was actually made with, given its private key.

    Inverting ``s = k^-1 (h + r d)`` gives ``k = s^-1 (h + r d)``.

    This is **exact, not up-to-sign**: it is derived from this signature's own
    equation, so it is the nonce that was signed with -- not merely one of the
    two nonces consistent with ``r``. That matters, because the sign ambiguity
    then lives entirely on the *other* side of the edge, where
    ``recover_from_shared_nonce`` resolves it with the gate.
    """
    n = curve.n
    if sig.s % n == 0:
        raise ValueError("degenerate signature: s == 0 mod n")
    return (curve.inv(sig.s) * (sig.h + sig.r * d)) % n


def recover_from_shared_nonce(
    curve: Curve, k: int, sig: Signature, Q
) -> Optional[int]:
    """Recover d from a signature known to share nonce ``k`` -- up to sign.

    Both signs must be tried, for exactly the reason `recover_from_reuse`
    documents: ``x(kG) == x(-kG)``, so a shared ``r`` says the two signatures
    share a nonce *up to sign*, and BIP146 may have normalised one of them and
    not the other. Here the asymmetry is worse than in the same-key case,
    because the two signatures belong to different keys and were plausibly
    produced by different software at different times::

        d = (s k' - h) r^-1        for k' in {k, n - k}

    ``d*G == Q`` decides; a wrong sign simply fails the gate. Trying only ``k``
    would silently miss half of all genuine cross-key edges -- the failure that
    reads as "nothing found" rather than as an error.
    """
    n = curve.n
    k %= n
    if k == 0 or sig.r % n == 0:
        return None
    rinv = curve.inv(sig.r)
    for signed_k in (k, n - k):
        d = ((sig.s * signed_k - sig.h) * rinv) % n
        if recovers_key(d, Q, curve):
            return d
    return None


def recover_by_seed_bruteforce(
    curve: Curve,
    sigs: list[Signature],
    Q,
    seed_bits: int,
    max_positions: int = 4,
) -> Optional[int]:
    """Brute-force a tiny nonce seed space against the known weak-seed PRNG model.

    Each candidate is screened by ``x(kG) == r`` before any key arithmetic. That
    is one scalar multiplication -- the same cost as the old ``d*G == Q`` probe --
    but it is *sign-blind*, so it accepts a candidate whose signature was later
    low-s normalised (``s -> n-s``, i.e. ``k -> -k``) at no extra cost. Only on a
    match do we spend two more multiplications resolving the sign.
    """
    n = curve.n
    if not sigs:
        return None
    sig = sigs[0]
    rinv = curve.inv(sig.r)
    for seed in range(1 << seed_bits):
        for i in range(max_positions):
            k = weak_seed_nonce(seed, i, n)
            x = getattr(curve.mul(k), "x", None)
            if x is None or x % n != sig.r:
                continue
            for candidate in (k, n - k):
                d = ((sig.s * candidate - sig.h) * rinv) % n
                if recovers_key(d, Q, curve):
                    return d
    return None
