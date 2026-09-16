"""M0 gate: backends import, curve helpers work, and the d*G == Q gate is real."""

import pytest

from qi_fingerprint.curves import get_curve, sign_with_nonce
from qi_fingerprint.verify import ecdsa_verify, recovers_key


def test_lattice_backend_imports():
    # If fpylll can't be imported, the whole Crack stage is dead on arrival.
    import fpylll  # noqa: F401


@pytest.mark.parametrize("name", ["secp256k1", "P-256"])
def test_sign_verify_roundtrip(name):
    curve = get_curve(name)
    d = 0x1234_5678_90AB_CDEF % curve.n
    Q = curve.pubkey(d)
    h = 0xDEAD_BEEF_CAFE % curve.n
    k = 0x9999_AAAA_BBBB % curve.n

    r, s = sign_with_nonce(curve, h, d, k)

    assert ecdsa_verify(h, r, s, Q, curve)
    # Tampered signature must fail.
    assert not ecdsa_verify(h, (r + 1) % curve.n, s, Q, curve)


@pytest.mark.parametrize("name", ["secp256k1", "P-256"])
def test_recovers_key_gate(name):
    curve = get_curve(name)
    d = 0xC0FFEE_1234_5678 % curve.n
    Q = curve.pubkey(d)

    assert recovers_key(d, Q, curve)
    assert not recovers_key(d + 1, Q, curve)
    assert not recovers_key(0, Q, curve)
    assert not recovers_key(None, Q, curve)


def test_order_bit_length():
    assert get_curve("secp256k1").L == 256
    assert get_curve("P-256").L == 256
