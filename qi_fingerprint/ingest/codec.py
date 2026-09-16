"""Byte-level decoding: varints, script pushes, DER signatures, public keys.

Pure functions over ``bytes``. No IO, no network, no transaction semantics -- this
module knows how Bitcoin encodes things, not what they mean.

Leniency policy, which matters for historical blocks: be **lenient about
structure, strict about values**. Pre-BIP66 signatures carry non-canonical DER
(long-form lengths, extra padding), and those are real signatures that really
verify, so refusing to parse them would silently discard exactly the old data we
came for. But a decoded ``r``/``s`` outside ``[1, n)`` is not a signature we can
use, and an off-curve public key is not a public key -- those raise.
"""

from __future__ import annotations

from ..curves import get_curve

# secp256k1 field prime and group order, read from the curve the pipeline already
# uses rather than restated here (a second copy is a second thing to get wrong).
_CURVE = get_curve("secp256k1")
FIELD_P: int = _CURVE.fe.p
ORDER_N: int = _CURVE.n

OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_CODESEPARATOR = 0xAB


class ParseError(ValueError):
    """Malformed input bytes."""


class DerError(ParseError):
    """A script element that is not a usable DER signature."""


class PubkeyError(ParseError):
    """A script element that is not a usable secp256k1 public key."""


class ByteReader:
    """Sequential little-endian reader that refuses to run off the end."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    @property
    def eof(self) -> bool:
        return self.pos >= len(self.data)

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ParseError(
                f"read {n} at offset {self.pos} overruns {len(self.data)} bytes"
            )
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.read(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def i32(self) -> int:
        return int.from_bytes(self.read(4), "little", signed=True)

    def varint(self) -> int:
        """Bitcoin's CompactSize. Non-minimal encodings are accepted (they occur)."""
        first = self.u8()
        if first < 0xFD:
            return first
        if first == 0xFD:
            return self.u16()
        if first == 0xFE:
            return self.u32()
        return self.u64()

    def var_bytes(self) -> bytes:
        return self.read(self.varint())


def write_varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint cannot be negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFF_FFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def push_data(data: bytes) -> bytes:
    """Minimal push encoding for a data element (used to assemble scriptCode)."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + n.to_bytes(2, "little") + data
    return bytes([OP_PUSHDATA4]) + n.to_bytes(4, "little") + data


def script_pushes(script: bytes) -> list[bytes] | None:
    """Data elements of a push-only script, or None if it contains any opcode.

    A P2PKH scriptSig is push-only by consensus (BIP62-era rule, and universally
    true in practice), so "not push-only" is a clean signal that this input is not
    a type we handle.
    """
    out: list[bytes] = []
    reader = ByteReader(script)
    try:
        while not reader.eof:
            op = reader.u8()
            if op == 0x00:  # OP_0 pushes an empty element
                out.append(b"")
            elif op < OP_PUSHDATA1:
                out.append(reader.read(op))
            elif op == OP_PUSHDATA1:
                out.append(reader.read(reader.u8()))
            elif op == OP_PUSHDATA2:
                out.append(reader.read(reader.u16()))
            elif op == OP_PUSHDATA4:
                out.append(reader.read(reader.u32()))
            else:
                return None  # a real opcode -- not push-only
    except ParseError:
        return None
    return out


def script_has_op(script: bytes, opcode: int) -> bool:
    """True if `opcode` appears as an executed opcode (not inside pushed data).

    Used to refuse inputs whose scriptCode contains OP_CODESEPARATOR, where the
    legacy sighash rules get materially more complicated. Refusing loudly beats
    implementing them halfway.
    """
    reader = ByteReader(script)
    try:
        while not reader.eof:
            op = reader.u8()
            if op == opcode:
                return True
            if 0x00 < op < OP_PUSHDATA1:
                reader.read(op)
            elif op == OP_PUSHDATA1:
                reader.read(reader.u8())
            elif op == OP_PUSHDATA2:
                reader.read(reader.u16())
            elif op == OP_PUSHDATA4:
                reader.read(reader.u32())
    except ParseError:
        return False
    return False


def _der_int(reader: ByteReader) -> int:
    if reader.u8() != 0x02:
        raise DerError("expected DER INTEGER tag 0x02")
    length = reader.u8()
    if length == 0:
        raise DerError("zero-length DER INTEGER")
    if length & 0x80:  # long-form length; rare but legal pre-BIP66
        n_len = length & 0x7F
        length = int.from_bytes(reader.read(n_len), "big")
    raw = reader.read(length)
    return int.from_bytes(raw, "big")


def parse_der_sig(element: bytes) -> tuple[int, int, int]:
    """Split a scriptSig signature element into ``(r, s, hashtype)``.

    The element is ``DER || hashtype`` -- Bitcoin Core's rule is exactly that the
    final byte is the sighash type and everything before it is the DER structure,
    so that is what we do rather than trying to be clever about lengths.
    """
    if len(element) < 9:
        raise DerError(f"signature element too short ({len(element)} bytes)")

    hashtype = element[-1]
    der = element[:-1]

    reader = ByteReader(der)
    if reader.u8() != 0x30:
        raise DerError("expected DER SEQUENCE tag 0x30")
    seq_len = reader.u8()
    if seq_len & 0x80:
        reader.read(seq_len & 0x7F)  # long-form; body length re-derived below

    r = _der_int(reader)
    s = _der_int(reader)

    # Strict on values: anything outside [1, n) cannot be a usable signature, and
    # letting it through would only fail later inside the verify gate.
    if not (0 < r < ORDER_N):
        raise DerError("r out of range [1, n)")
    if not (0 < s < ORDER_N):
        raise DerError("s out of range [1, n)")
    return r, s, hashtype


def parse_pubkey(data: bytes) -> tuple[int, int]:
    """Decode a secp256k1 public key element to ``(Qx, Qy)``.

    Handles compressed (33 bytes, 0x02/0x03), uncompressed (65 bytes, 0x04) and
    the historical hybrid encodings (0x06/0x07). Always confirms the point is on
    the curve -- an off-curve "key" would make every downstream verify fail for a
    reason that has nothing to do with the sighash.
    """
    if len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:], "big")
        if x >= FIELD_P:
            raise PubkeyError("compressed x >= field prime")
        alpha = (pow(x, 3, FIELD_P) + 7) % FIELD_P
        # p % 4 == 3 for secp256k1, so the square root is a single exponentiation.
        y = pow(alpha, (FIELD_P + 1) // 4, FIELD_P)
        if (y * y) % FIELD_P != alpha:
            raise PubkeyError("compressed x is not on the curve")
        if (y & 1) != (data[0] & 1):
            y = FIELD_P - y
    elif len(data) == 65 and data[0] in (0x04, 0x06, 0x07):
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        if x >= FIELD_P or y >= FIELD_P:
            raise PubkeyError("uncompressed coordinate >= field prime")
    else:
        what = f"{len(data)} bytes, prefix {data[0]:#04x}" if data else "empty element"
        raise PubkeyError(f"not a public key: {what}")

    if (y * y - (pow(x, 3, FIELD_P) + 7)) % FIELD_P != 0:
        raise PubkeyError("point is not on secp256k1")
    return x, y
