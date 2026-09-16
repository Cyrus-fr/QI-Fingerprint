"""Legacy (pre-SegWit) signature hashing: the digest ``z`` that was actually signed.

``z`` is not the txid and not a hash of the raw transaction. It is a hash of a
*modified* serialisation of the transaction, and the modifications depend on the
sighash type byte carried in the signature itself.

Getting this exactly right is the whole ballgame: every stage downstream is
arithmetic on ``h``, and a wrong ``z`` produces plausible-looking nonsense rather
than an error. We are not relying on care alone, though -- ``ecdsa_verify`` is a
total oracle for this module. If ``z`` is wrong, verification fails, and the
ingest gate refuses to write the record.

Deliberately implemented as Bitcoin Core's *branch structure* rather than a
whitelist of known sighash types, because every one of the 256 byte values is
valid on-chain and ``0x00`` (which falls through to ALL-like behaviour) does
occur historically.
"""

from __future__ import annotations

from .codec import OP_CODESEPARATOR, script_has_op, write_varint
from .tx import Tx, TxIn, TxOut, sha256d

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

# The legacy SIGHASH_SINGLE index bug. When the signed input has no corresponding
# output, Core does not compute a hash at all -- it returns the uint256 value 1.
# Core stores uint256 little-endian internally while libsecp256k1 reads msg32 as
# big-endian, so the scalar actually signed is 0x0100...00 == 2**248, NOT 1.
ONE_HASH = b"\x01" + b"\x00" * 31


class SighashUnsupported(ValueError):
    """A construct whose sighash we decline to compute rather than guess at."""


def legacy_sighash(tx: Tx, index: int, script_code: bytes, hashtype: int) -> bytes:
    """The 32-byte legacy sighash digest for input `index`.

    `script_code` is what replaces the signed input's scriptSig in the preimage.
    For P2PKH that is simply the previous output's scriptPubKey.
    """
    if not (0 <= index < len(tx.vin)):
        raise IndexError(f"input index {index} out of range for {len(tx.vin)} inputs")

    base = hashtype & 0x1F
    anyone = bool(hashtype & SIGHASH_ANYONECANPAY)

    # The index bug: short-circuit before any serialisation happens.
    if base == SIGHASH_SINGLE and index >= len(tx.vout):
        return ONE_HASH

    # Two constructs change what the preimage means. Neither occurs in the input
    # types we support, and half-implementing them would corrupt z silently, so
    # they are refused and counted instead.
    if script_has_op(script_code, OP_CODESEPARATOR):
        raise SighashUnsupported("scriptCode contains OP_CODESEPARATOR")

    # --- inputs -------------------------------------------------------------
    if anyone:
        signed = tx.vin[index]
        vin = [TxIn(signed.prevout, script_code, signed.sequence)]
    else:
        vin = []
        for i, txin in enumerate(tx.vin):
            if i == index:
                vin.append(TxIn(txin.prevout, script_code, txin.sequence))
            else:
                # NONE and SINGLE free the other inputs' sequences so they can be
                # changed without invalidating this signature.
                sequence = 0 if base in (SIGHASH_NONE, SIGHASH_SINGLE) else txin.sequence
                vin.append(TxIn(txin.prevout, b"", sequence))

    # --- outputs ------------------------------------------------------------
    if base == SIGHASH_NONE:
        vout: list[TxOut] = []
    elif base == SIGHASH_SINGLE:
        # Commit to only the output at the same index; blank the ones before it
        # to (value=-1, script=empty), which serialises the value as all-ones.
        vout = [TxOut(-1, b"") for _ in range(index)]
        vout.append(tx.vout[index])
    else:
        vout = list(tx.vout)

    stripped = Tx(
        version=tx.version,
        vin=tuple(vin),
        vout=tuple(vout),
        locktime=tx.locktime,
        has_witness=False,  # witnesses are never part of a legacy preimage
    )
    preimage = stripped.serialize(witness=False) + hashtype.to_bytes(4, "little")
    return sha256d(preimage)


# --------------------------------------------------------------------------- #
# SegWit v0 (BIP143)
# --------------------------------------------------------------------------- #

_ZERO32 = b"\x00" * 32


def p2wpkh_script_code(keyhash: bytes) -> bytes:
    """The scriptCode BIP143 specifies for a P2WPKH input.

    Deliberately the *bare* script, without the leading length byte: the spec
    writes it as ``0x1976a914{20}88ac``, but that ``0x19`` is the length prefix
    the preimage adds, and carrying it inside the value is the classic way to
    hash 26 bytes where 25 were meant.
    """
    if len(keyhash) != 20:
        raise ValueError(f"key hash must be 20 bytes, got {len(keyhash)}")
    return b"\x76\xa9\x14" + keyhash + b"\x88\xac"


def bip143_sighash(
    tx: Tx, index: int, script_code: bytes, amount: int, hashtype: int
) -> bytes:
    """The 32-byte SegWit v0 sighash digest for input `index`.

    The material difference from legacy is the **amount**: BIP143 commits to the
    value of the output being spent, which is why a source that cannot supply
    prevout values cannot compute this digest at all.

    Two other differences worth stating, because both are places to go wrong:

    * There is **no SIGHASH_SINGLE index bug** here. Where legacy returns the
      constant ``1`` when the input has no matching output, BIP143 simply leaves
      ``hashOutputs`` zeroed -- so no `ONE_HASH` short-circuit belongs in this
      function.
    * The three midstate hashes are ``sha256d``, but a *zeroed* midstate is 32
      zero bytes, not the hash of nothing.
    """
    if not (0 <= index < len(tx.vin)):
        raise IndexError(f"input index {index} out of range for {len(tx.vin)} inputs")
    if amount < 0:
        raise ValueError(f"input amount must be non-negative, got {amount}")

    base = hashtype & 0x1F
    anyone = bool(hashtype & SIGHASH_ANYONECANPAY)

    if script_has_op(script_code, OP_CODESEPARATOR):
        raise SighashUnsupported("scriptCode contains OP_CODESEPARATOR")

    if anyone:
        hash_prevouts = _ZERO32
        hash_sequence = _ZERO32
    else:
        hash_prevouts = sha256d(b"".join(i.prevout.serialize() for i in tx.vin))
        hash_sequence = (
            _ZERO32
            if base in (SIGHASH_NONE, SIGHASH_SINGLE)
            else sha256d(b"".join(i.sequence.to_bytes(4, "little") for i in tx.vin))
        )

    if base not in (SIGHASH_NONE, SIGHASH_SINGLE):
        hash_outputs = sha256d(b"".join(o.serialize() for o in tx.vout))
    elif base == SIGHASH_SINGLE and index < len(tx.vout):
        hash_outputs = sha256d(tx.vout[index].serialize())
    else:
        hash_outputs = _ZERO32

    signed = tx.vin[index]
    preimage = b"".join(
        [
            tx.version.to_bytes(4, "little", signed=True),
            hash_prevouts,
            hash_sequence,
            signed.prevout.serialize(),
            write_varint(len(script_code)),
            script_code,
            amount.to_bytes(8, "little"),
            signed.sequence.to_bytes(4, "little"),
            hash_outputs,
            tx.locktime.to_bytes(4, "little"),
            hashtype.to_bytes(4, "little"),
        ]
    )
    return sha256d(preimage)


def sighash_to_z(digest: bytes) -> int:
    """Interpret a 32-byte sighash as the scalar that was signed.

    The single place endianness is decided for the whole ingest path. Big-endian,
    matching libsecp256k1's msg32 convention -- which is also what makes the
    SIGHASH_SINGLE bug constant come out as 2**248 rather than 1.
    """
    if len(digest) != 32:
        raise ValueError(f"sighash must be 32 bytes, got {len(digest)}")
    return int.from_bytes(digest, "big")
