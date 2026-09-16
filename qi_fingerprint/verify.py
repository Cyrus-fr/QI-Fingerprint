"""ECDSA verification and the ``d*G == Q`` recovery gate.

``recovers_key`` is the single source of truth every recovery path asserts against.
A mis-scaled lattice basis returns a wrong ``d`` *without raising*; this gate is
what converts that silent-wrong-answer into a caught failure. It is deliberately
cheap (one scalar mult + a point comparison) so it can be an assertion, not an
afterthought.
"""

from __future__ import annotations

from fastecdsa.point import Point

from .curves import Curve


def recovers_key(d: int | None, Q: Point, curve: Curve) -> bool:
    """True iff candidate scalar ``d`` reproduces public key ``Q`` (Q == d*G)."""
    if d is None:
        return False
    d %= curve.n
    if d == 0:
        return False
    return curve.mul(d) == Q


def ecdsa_verify(h: int, r: int, s: int, Q: Point, curve: Curve) -> bool:
    """Standard ECDSA signature verification of ``(r, s)`` on hash ``h``."""
    n = curve.n
    if not (0 < r < n and 0 < s < n):
        return False
    w = curve.inv(s)
    u1 = (h * w) % n
    u2 = (r * w) % n
    x = u1 * curve.G + u2 * Q
    x_coord = getattr(x, "x", None)
    if x_coord is None:  # point at infinity -> invalid
        return False
    return (x_coord % n) == r
