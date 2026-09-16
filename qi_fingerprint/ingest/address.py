"""Public key -> P2PKH address.

Needed for one reason only: §9 of the safety rules says a recovered key is
reported as a count, a `(txid, vin)` provenance, and the **derived address** --
never as the scalar itself. The address is what lets a reader confirm the finding
against a block explorer without us handing anyone a spending key.

Pure functions over bytes; nothing here touches the network or a wallet.
"""

from __future__ import annotations

import hashlib

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
P2PKH_VERSION = 0x00  # mainnet


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)), Bitcoin's key/script digest.

    RIPEMD-160 ships as an OpenSSL *legacy* provider algorithm, so it can be
    absent depending on how the interpreter was built. Fail loudly rather than
    let a report quietly lose the address field.
    """
    try:
        ripemd = hashlib.new("ripemd160")
    except ValueError as exc:  # pragma: no cover - build-dependent
        raise RuntimeError(
            "RIPEMD-160 unavailable in this build; addresses cannot be derived"
        ) from exc
    ripemd.update(hashlib.sha256(data).digest())
    return ripemd.digest()


def b58encode(data: bytes) -> str:
    """Base58 with the leading-zero-byte convention (each becomes a '1')."""
    value = int.from_bytes(data, "big")
    out = ""
    while value > 0:
        value, remainder = divmod(value, 58)
        out = B58_ALPHABET[remainder] + out
    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + out


def base58check(version: int, payload: bytes) -> str:
    body = bytes([version]) + payload
    return b58encode(body + sha256d(body)[:4])


def serialize_pubkey(qx: int, qy: int, compressed: bool) -> bytes:
    """The exact bytes that appeared on chain.

    Which encoding was used is not cosmetic: the two forms of one key hash to
    two different addresses, so the corpus groups by the *point* while the
    address must be derived from the *bytes*.
    """
    x = qx.to_bytes(32, "big")
    if compressed:
        return bytes([0x02 | (qy & 1)]) + x
    return b"\x04" + x + qy.to_bytes(32, "big")


def p2pkh_address(qx: int, qy: int, compressed: bool) -> str:
    return base58check(P2PKH_VERSION, hash160(serialize_pubkey(qx, qy, compressed)))


def address_from_pubkey_len(qx: int, qy: int, pubkey_len: int) -> str:
    """Convenience for `ExtractedSig`, which records the on-chain encoding length."""
    if pubkey_len not in (33, 65):
        raise ValueError(f"unexpected pubkey length {pubkey_len}")
    return p2pkh_address(qx, qy, compressed=pubkey_len == 33)
