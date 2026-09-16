"""One transaction input -> a usable ``(r, s, z, Q)`` tuple, or a counted skip.

The unit of work is a single input. Every input either yields signatures or is
recorded as a `SkippedInput` with a reason -- nothing is ever dropped silently,
because "we ignored 40% of the block" and "the block had no signatures" must not
look the same in the report.

Supported: legacy **P2PKH** and **P2PK**, and SegWit v0 **P2WPKH**, both native
and P2SH-wrapped. Everything else is classified and counted so the coverage
number is honest. `extract_input` returns a *list* (almost always of length one)
so multisig can be added later without changing the signature.

The three input shapes differ in exactly two places -- where the public key comes
from, and what the scriptCode is:

    p2pkh        pubkey from the scriptSig       scriptCode = prevout script
    p2pk         pubkey from the PREVOUT script  scriptCode = prevout script
    v0_p2wpkh    pubkey from the witness         scriptCode = 76a914{h160}88ac
    p2sh_p2wpkh  pubkey from the witness         scriptCode = 76a914{h160}88ac,
                 with the key hash taken from the redeemScript rather than the
                 witness program, and the redeemScript checked against the P2SH
                 address it claims to open

Getting a scriptCode wrong changes ``z``, and a wrong ``z`` fails
`ecdsa_verify`. `Stratum` buckets by ``(script_type, sigversion, ...)``, so a bug
confined to one of these shapes shows up as one failing row rather than as a
slightly lower global rate.
"""

from __future__ import annotations

from dataclasses import dataclass

from .address import hash160
from .codec import ParseError, parse_der_sig, parse_pubkey, script_pushes
from .sighash import (
    SighashUnsupported,
    bip143_sighash,
    legacy_sighash,
    p2wpkh_script_code,
    sighash_to_z,
)
from .tx import Tx

# secp256k1 order, for the low-s flag. Imported here rather than recomputed.
from .codec import ORDER_N

_HALF_N = ORDER_N // 2


@dataclass(frozen=True)
class PrevOut:
    """The output being spent.

    ``value`` is unused by the legacy sighash but required by BIP143, which
    commits to the amount -- which is in turn why a data source that cannot give
    you prevout values cannot support SegWit at all.
    """

    value: int
    script_pubkey: bytes


@dataclass(frozen=True)
class ExtractedSig:
    height: int
    txid: str
    vin: int
    script_type: str
    sigversion: str
    hashtype: int
    r: int
    s: int
    z: int
    qx: int
    qy: int
    pubkey_len: int
    low_s: bool


@dataclass(frozen=True)
class SkippedInput:
    height: int
    txid: str
    vin: int
    reason: str


def is_p2pkh(spk: bytes) -> bool:
    """OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG."""
    return (
        len(spk) == 25
        and spk[0] == 0x76
        and spk[1] == 0xA9
        and spk[2] == 0x14
        and spk[23] == 0x88
        and spk[24] == 0xAC
    )


def is_p2pk(spk: bytes) -> bool:
    """<pubkey> OP_CHECKSIG -- the earliest output form, still spent today."""
    if not spk or spk[-1] != 0xAC:
        return False
    return (len(spk) == 35 and spk[0] == 0x21) or (len(spk) == 67 and spk[0] == 0x41)


def is_p2sh(spk: bytes) -> bool:
    """OP_HASH160 <20> OP_EQUAL."""
    return len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[22] == 0x87


def is_p2wpkh_program(spk: bytes) -> bool:
    """OP_0 <20> -- the native witness-v0 key-hash program."""
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14


def classify_input(spk: bytes, script_sig: bytes, witness: tuple[bytes, ...]) -> str:
    """Name the input's script type."""
    if witness:
        # A witness means SegWit; even over a P2PKH-looking prevout that would be
        # a different sighash algorithm, so never treat it as legacy.
        if is_p2wpkh_program(spk):
            return "v0_p2wpkh"
        if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
            return "v0_p2wsh"
        if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
            return "v1_p2tr"
        if is_p2sh(spk):
            # P2SH-wrapped SegWit: the scriptSig is a single push of the witness
            # program, which the redeemScript check below has to confirm.
            pushes = script_pushes(script_sig)
            if pushes and len(pushes) == 1 and is_p2wpkh_program(pushes[0]):
                return "p2sh_p2wpkh"
            return "p2sh_witness_other"
        return "witness_other"
    if is_p2pkh(spk):
        return "p2pkh"
    if is_p2pk(spk):
        return "p2pk"
    if is_p2sh(spk):
        return "p2sh"
    if spk and spk[-1] == 0xAE:
        return "bare_multisig"
    return "nonstandard"


def _witness_key_hash(script_type: str, spk: bytes, script_sig: bytes) -> bytes | None:
    """The 20-byte key hash a P2WPKH scriptCode is built from.

    For a native input it is the witness program itself. For a wrapped one it
    comes from the redeemScript, which must hash to the P2SH address being spent
    -- otherwise the scriptSig is claiming to open a script it cannot.
    """
    if script_type == "v0_p2wpkh":
        return spk[2:22]
    pushes = script_pushes(script_sig)
    if not pushes or len(pushes) != 1:
        return None
    redeem = pushes[0]
    if not is_p2wpkh_program(redeem):
        return None
    if hash160(redeem) != spk[2:22]:
        return None  # the redeemScript does not open this P2SH output
    return redeem[2:22]


def extract_input(
    tx: Tx, index: int, prevout: PrevOut, height: int
) -> list[ExtractedSig] | SkippedInput:
    """Extract every signature from one input, or say why we could not."""
    txid = tx.txid_hex
    txin = tx.vin[index]

    def skip(reason: str) -> SkippedInput:
        return SkippedInput(height, txid, index, reason)

    if tx.is_coinbase:
        return skip("coinbase")

    spk = prevout.script_pubkey
    script_type = classify_input(spk, txin.script_sig, txin.witness)

    if script_type in ("v0_p2wpkh", "p2sh_p2wpkh"):
        sigversion = "witness_v0"
        if len(txin.witness) != 2:
            return skip(f"witness_elements:{len(txin.witness)}")
        sig_element, key_element = txin.witness
        key_hash = _witness_key_hash(script_type, spk, txin.script_sig)
        if key_hash is None:
            return skip("redeemscript_mismatch")
    elif script_type in ("p2pkh", "p2pk"):
        sigversion = "legacy"
        pushes = script_pushes(txin.script_sig)
        if pushes is None:
            return skip("scriptsig_not_push_only")
        expected = 2 if script_type == "p2pkh" else 1
        if len(pushes) != expected:
            return skip(f"scriptsig_elements:{len(pushes)}")
        sig_element = pushes[0]
        # P2PK carries no pubkey in the scriptSig; it is in the output it spends.
        key_element = pushes[1] if script_type == "p2pkh" else spk[1:-1]
        key_hash = None
    else:
        return skip(f"unsupported_type:{script_type}")

    try:
        r, s, hashtype = parse_der_sig(sig_element)
        qx, qy = parse_pubkey(key_element)
    except ParseError as exc:
        return skip(f"decode:{type(exc).__name__}")

    try:
        if sigversion == "witness_v0":
            # BIP143 commits to the amount, so a prevout with no value would
            # silently produce a wrong z rather than an error.
            digest = bip143_sighash(
                tx, index, p2wpkh_script_code(key_hash), prevout.value, hashtype
            )
        else:
            # For P2PKH and P2PK alike the scriptCode IS the prevout's script.
            digest = legacy_sighash(tx, index, spk, hashtype)
    except SighashUnsupported as exc:
        return skip(f"sighash_unsupported:{exc}")

    return [
        ExtractedSig(
            height=height,
            txid=txid,
            vin=index,
            script_type=script_type,
            sigversion=sigversion,
            hashtype=hashtype,
            r=r,
            s=s,
            z=sighash_to_z(digest),
            qx=qx,
            qy=qy,
            pubkey_len=len(key_element),
            low_s=s <= _HALF_N,
        )
    ]


def extract_tx(
    tx: Tx, prevouts: list[PrevOut], height: int
) -> tuple[list[ExtractedSig], list[SkippedInput]]:
    """Extract every input of one transaction."""
    if len(prevouts) != len(tx.vin):
        raise ValueError(
            f"{tx.txid_hex}: {len(prevouts)} prevouts for {len(tx.vin)} inputs"
        )
    sigs: list[ExtractedSig] = []
    skips: list[SkippedInput] = []
    for i, prevout in enumerate(prevouts):
        result = extract_input(tx, i, prevout, height)
        if isinstance(result, SkippedInput):
            skips.append(result)
        else:
            sigs.extend(result)
    return sigs, skips
