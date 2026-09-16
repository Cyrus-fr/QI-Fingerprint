"""Elliptic-curve parameters and low-level primitives.

A thin wrapper over fastecdsa so the rest of the pipeline speaks a single small
vocabulary: order ``n``, bit length ``L``, generator ``G``, scalar multiplication,
modular inverse, and controlled-nonce signing (used to inject bias in the
generator, never in production).
"""

from __future__ import annotations

from dataclasses import dataclass

from fastecdsa.curve import P256, Curve as _FECurve, secp256k1
from fastecdsa.point import Point

# Accept a few spellings; the canonical name is stored on the Curve.
_SUPPORTED: dict[str, tuple[str, _FECurve]] = {
    "secp256k1": ("secp256k1", secp256k1),
    "p-256": ("P-256", P256),
    "p256": ("P-256", P256),
    "prime256v1": ("P-256", P256),
}


@dataclass(frozen=True)
class Curve:
    """A named curve exposing only the operations the pipeline needs."""

    name: str
    fe: _FECurve

    @property
    def n(self) -> int:
        """Group (subgroup) order."""
        return self.fe.q

    @property
    def L(self) -> int:
        """Bit length of the order ``n`` (256 for secp256k1 / P-256)."""
        return self.n.bit_length()

    @property
    def G(self) -> Point:
        """Base point / generator."""
        return self.fe.G

    def mul(self, k: int) -> Point:
        """Scalar multiplication ``k*G`` (k reduced mod n)."""
        return (k % self.n) * self.fe.G

    def pubkey(self, d: int) -> Point:
        """Public key ``Q = d*G``."""
        return self.mul(d)

    def inv(self, x: int) -> int:
        """Modular inverse of ``x`` modulo ``n``."""
        return pow(x % self.n, -1, self.n)

    def point(self, x: int, y: int) -> Point:
        """Reconstruct an on-curve point (e.g., a public key) from coordinates."""
        return Point(x, y, self.fe)


def get_curve(name: str = "secp256k1") -> Curve:
    """Look up a supported curve by (case-insensitive) name."""
    key = name.strip().lower()
    if key not in _SUPPORTED:
        canonical = sorted({v[0] for v in _SUPPORTED.values()})
        raise ValueError(f"Unsupported curve {name!r}; choose from {canonical}")
    canonical_name, fe = _SUPPORTED[key]
    return Curve(name=canonical_name, fe=fe)


def sign_with_nonce(curve: Curve, h: int, d: int, k: int) -> tuple[int, int]:
    """Produce an ECDSA ``(r, s)`` using an explicit nonce ``k``.

    This is the bias-injection primitive: the generator calls it with nonces
    drawn from deliberately weak distributions. Raises on the (astronomically
    rare) degenerate cases so bad synthetic data never slips through silently.
    """
    n = curve.n
    k %= n
    if k == 0:
        raise ValueError("nonce k must be nonzero mod n")
    r = curve.mul(k).x % n
    if r == 0:
        raise ValueError("degenerate signature: r == 0")
    s = (curve.inv(k) * (h + r * d)) % n
    if s == 0:
        raise ValueError("degenerate signature: s == 0")
    return r, s
