"""Stage 2: reduce ECDSA signatures to a Hidden Number Problem instance.

For each signature, ``k = s^-1*h + s^-1*r*d (mod n)``. Writing ``a = s^-1*h`` and
``t = s^-1*r`` gives ``k_i == a_i + t_i*d (mod n)`` with the nonce ``k_i`` small
whenever it carries an MSB bias. That is exactly the Hidden Number Problem the
lattice stage solves.
"""

from __future__ import annotations

from dataclasses import dataclass

from .corpus import Signature
from .curves import Curve


@dataclass
class HNPInstance:
    n: int
    L: int
    bias_bits: int  # number of known-zero MSBs => bound k < 2^(L-bias_bits)
    t: list[int]
    a: list[int]

    @property
    def bound(self) -> int:
        return 1 << (self.L - self.bias_bits)


def build_hnp(curve: Curve, sigs: list[Signature], bias_bits: int) -> HNPInstance:
    n = curve.n
    t: list[int] = []
    a: list[int] = []
    for sig in sigs:
        sinv = curve.inv(sig.s)
        t.append((sinv * sig.r) % n)
        a.append((sinv * sig.h) % n)
    return HNPInstance(n=n, L=curve.L, bias_bits=bias_bits, t=t, a=a)
