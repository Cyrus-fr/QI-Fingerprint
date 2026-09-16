"""Transaction and block structure: parse, re-serialise, and self-check.

Pure functions over ``bytes``. The load-bearing property of this module is the
round trip: ``parse_tx(raw).serialize() == raw``. If that holds, and the
recomputed txid matches the one a data source claims, then the source did not
alter the transaction -- which is most of what we need from an untrusted API.

Byte-order convention, stated once because it is the classic source of bugs:
txids are handled in **internal** (little-endian) order everywhere in this
module. The reversed, display-order hex string is available as ``txid_hex`` and
is used only when talking to humans or to an API.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .codec import ByteReader, ParseError, write_varint


def sha256d(data: bytes) -> bytes:
    """Bitcoin's double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


@dataclass(frozen=True)
class OutPoint:
    """A reference to a previous output. ``txid`` is in internal byte order."""

    txid: bytes
    vout: int

    def serialize(self) -> bytes:
        return self.txid + self.vout.to_bytes(4, "little")

    @property
    def txid_hex(self) -> str:
        return self.txid[::-1].hex()


@dataclass(frozen=True)
class TxIn:
    prevout: OutPoint
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...] = ()

    def serialize(self) -> bytes:
        return (
            self.prevout.serialize()
            + write_varint(len(self.script_sig))
            + self.script_sig
            + self.sequence.to_bytes(4, "little")
        )


@dataclass(frozen=True)
class TxOut:
    value: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        # Signed, because the legacy SIGHASH_SINGLE rules blank an output's value
        # to -1 and that -1 must serialise as 0xffffffffffffffff.
        return (
            self.value.to_bytes(8, "little", signed=self.value < 0)
            + write_varint(len(self.script_pubkey))
            + self.script_pubkey
        )


@dataclass(frozen=True)
class Tx:
    version: int
    vin: tuple[TxIn, ...]
    vout: tuple[TxOut, ...]
    locktime: int
    has_witness: bool = False

    def serialize(self, witness: bool = True) -> bytes:
        include_witness = witness and self.has_witness
        parts = [self.version.to_bytes(4, "little", signed=True)]
        if include_witness:
            parts.append(b"\x00\x01")  # segwit marker + flag
        parts.append(write_varint(len(self.vin)))
        parts.extend(i.serialize() for i in self.vin)
        parts.append(write_varint(len(self.vout)))
        parts.extend(o.serialize() for o in self.vout)
        if include_witness:
            for txin in self.vin:
                parts.append(write_varint(len(txin.witness)))
                for item in txin.witness:
                    parts.append(write_varint(len(item)) + item)
        parts.append(self.locktime.to_bytes(4, "little"))
        return b"".join(parts)

    @property
    def txid(self) -> bytes:
        """Internal-order txid: the hash of the NON-witness serialisation."""
        return sha256d(self.serialize(witness=False))

    @property
    def txid_hex(self) -> str:
        return self.txid[::-1].hex()

    @property
    def wtxid(self) -> bytes:
        return sha256d(self.serialize(witness=True))

    @property
    def is_coinbase(self) -> bool:
        return (
            len(self.vin) == 1
            and self.vin[0].prevout.txid == b"\x00" * 32
            and self.vin[0].prevout.vout == 0xFFFF_FFFF
        )


def _parse_tx_from(reader: ByteReader) -> Tx:
    version = reader.i32()

    # SegWit marker/flag: a 0x00 input count is impossible in a legacy tx, so it
    # unambiguously signals the extended serialisation.
    has_witness = False
    save = reader.pos
    if reader.remaining >= 2 and reader.data[reader.pos] == 0x00:
        marker = reader.u8()
        flag = reader.u8()
        if marker == 0x00 and flag != 0x00:
            has_witness = True
        else:
            reader.pos = save

    n_in = reader.varint()
    if n_in == 0 and not has_witness:
        raise ParseError("transaction with zero inputs")
    vin: list[TxIn] = []
    for _ in range(n_in):
        txid = reader.read(32)
        vout_index = reader.u32()
        script_sig = reader.var_bytes()
        sequence = reader.u32()
        vin.append(TxIn(OutPoint(txid, vout_index), script_sig, sequence))

    n_out = reader.varint()
    vout: list[TxOut] = []
    for _ in range(n_out):
        value = reader.u64()
        vout.append(TxOut(value, reader.var_bytes()))

    if has_witness:
        for i in range(n_in):
            stack = tuple(reader.var_bytes() for _ in range(reader.varint()))
            vin[i] = TxIn(vin[i].prevout, vin[i].script_sig, vin[i].sequence, stack)

    locktime = reader.u32()
    return Tx(version, tuple(vin), tuple(vout), locktime, has_witness)


def parse_tx(raw: bytes) -> Tx:
    """Parse one transaction, requiring that it consumes exactly `raw`."""
    reader = ByteReader(raw)
    tx = _parse_tx_from(reader)
    if not reader.eof:
        raise ParseError(f"{reader.remaining} trailing bytes after transaction")
    return tx


def parse_block(raw: bytes) -> tuple[bytes, list[Tx]]:
    """Split a serialised block into its 80-byte header and its transactions."""
    reader = ByteReader(raw)
    header = reader.read(80)
    return header, [_parse_tx_from(reader) for _ in range(reader.varint())]


def merkle_root(txids: list[bytes]) -> bytes:
    """Merkle root over internal-order txids, with Bitcoin's duplicate-last rule."""
    if not txids:
        raise ValueError("merkle root of an empty transaction list")
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])  # the CVE-2012-2459 quirk, kept for fidelity
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def header_fields(header: bytes) -> dict:
    """Decode an 80-byte block header."""
    if len(header) != 80:
        raise ParseError(f"block header must be 80 bytes, got {len(header)}")
    reader = ByteReader(header)
    return {
        "version": reader.i32(),
        "prev_hash": reader.read(32),
        "merkle_root": reader.read(32),
        "time": reader.u32(),
        "bits": reader.u32(),
        "nonce": reader.u32(),
    }


def block_hash(header: bytes) -> bytes:
    """Internal-order block hash."""
    return sha256d(header)


def target_from_bits(bits: int) -> int:
    """Expand the compact nBits difficulty encoding to a full 256-bit target."""
    exponent = bits >> 24
    mantissa = bits & 0x00FF_FFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def check_pow(header: bytes) -> bool:
    """True if the header hashes below its own stated target.

    This is what makes a public API's block data self-authenticating: forging a
    header that passes requires redoing the proof of work.
    """
    fields = header_fields(header)
    digest = int.from_bytes(block_hash(header), "little")
    return digest <= target_from_bits(fields["bits"])
