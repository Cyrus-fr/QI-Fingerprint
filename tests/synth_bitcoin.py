"""Build real, self-consistent P2PKH transactions for offline tests.

The pinned mainnet fixtures are ordinary spends: correct, but they contain no
nonce reuse, so they cannot exercise the hunt or the Phase B control. These
helpers construct transactions that *do* -- signed with chosen nonces, so a
mixed-sign reuse pair can be built deliberately rather than waited for.

Nothing here is a mock. The transactions serialise, hash to their own txids, and
their signatures verify against a `z` the extractor recomputes from the prevout
script -- the same gate real data goes through. What is synthetic is only which
nonce was used.
"""

from __future__ import annotations

from qi_fingerprint.curves import get_curve, sign_with_nonce
from qi_fingerprint.ingest.address import hash160, serialize_pubkey
from qi_fingerprint.ingest.codec import push_data
from qi_fingerprint.ingest.extract import PrevOut
from qi_fingerprint.ingest.sighash import (
    bip143_sighash,
    legacy_sighash,
    p2wpkh_script_code,
    sighash_to_z,
)
from qi_fingerprint.ingest.tx import OutPoint, Tx, TxIn, TxOut

CURVE = get_curve("secp256k1")
SEQUENCE = 0xFFFFFFFF


def der_integer(value: int) -> bytes:
    """Minimal DER INTEGER: big-endian, no leading zeros, sign bit padded."""
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def der_signature(r: int, s: int, hashtype: int = 0x01) -> bytes:
    body = der_integer(r) + der_integer(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([hashtype])


def p2pkh_script(qx: int, qy: int, compressed: bool = True) -> bytes:
    """OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG."""
    digest = hash160(serialize_pubkey(qx, qy, compressed))
    return b"\x76\xa9\x14" + digest + b"\x88\xac"


def build_signed_tx(
    d: int,
    nonces: list[int],
    *,
    funding: list[tuple[bytes, int]] | None = None,
    compressed: bool = True,
    hashtype: int = 0x01,
    out_value: int = 50_000,
    locktime: int = 0,
    low_s: list[bool] | None = None,
) -> tuple[Tx, list[PrevOut]]:
    """One transaction spending `len(nonces)` P2PKH outputs of a single key.

    Each input is signed with the nonce at its index. `low_s` optionally forces
    BIP146 normalisation per input, which is how a mixed-sign reuse pair -- the
    case the plan's §8 fixes exist for -- is constructed on purpose.

    Signing is a two-pass process because the digest covers the transaction: the
    sighash is computed over inputs whose scriptSigs are blanked, so filling them
    in afterwards cannot change any `z`.
    """
    n = CURVE.n
    Q = CURVE.pubkey(d)
    script = p2pkh_script(Q.x, Q.y, compressed)
    pubkey = serialize_pubkey(Q.x, Q.y, compressed)

    if funding is None:
        funding = [(bytes([i + 1]) * 32, i) for i in range(len(nonces))]
    prevouts = [PrevOut(out_value * 2, script) for _ in nonces]

    blank = Tx(
        version=1,
        vin=tuple(
            TxIn(OutPoint(txid, vout), b"", SEQUENCE) for txid, vout in funding
        ),
        vout=(TxOut(out_value, script),),
        locktime=locktime,
    )

    scripts: list[bytes] = []
    for index, k in enumerate(nonces):
        z = sighash_to_z(legacy_sighash(blank, index, script, hashtype))
        r, s = sign_with_nonce(CURVE, z, d, k)
        if low_s is not None and low_s[index] and s > n // 2:
            s = n - s
        elif low_s is not None and not low_s[index] and s <= n // 2:
            s = n - s
        scripts.append(push_data(der_signature(r, s, hashtype)) + push_data(pubkey))

    signed = Tx(
        version=blank.version,
        vin=tuple(
            TxIn(txin.prevout, scripts[i], txin.sequence)
            for i, txin in enumerate(blank.vin)
        ),
        vout=blank.vout,
        locktime=blank.locktime,
    )
    return signed, prevouts


# --------------------------------------------------------------------------- #
# The other extraction paths: P2PK and SegWit v0
# --------------------------------------------------------------------------- #


def p2pk_script(qx: int, qy: int, compressed: bool = False) -> bytes:
    """<pubkey> OP_CHECKSIG. Uncompressed by default -- the historical form."""
    pubkey = serialize_pubkey(qx, qy, compressed)
    return push_data(pubkey) + b"\xac"


def p2wpkh_program(qx: int, qy: int) -> bytes:
    """OP_0 <20-byte key hash>. SegWit v0 keys are always compressed."""
    return b"\x00\x14" + hash160(serialize_pubkey(qx, qy, True))


def p2sh_script(redeem: bytes) -> bytes:
    """OP_HASH160 <20> OP_EQUAL."""
    return b"\xa9\x14" + hash160(redeem) + b"\x87"


def build_typed_tx(
    d: int,
    nonces: list[int],
    script_type: str,
    *,
    funding: list[tuple[bytes, int]] | None = None,
    hashtype: int = 0x01,
    out_value: int = 50_000,
    amount: int = 250_000,
    locktime: int = 0,
) -> tuple[Tx, list[PrevOut]]:
    """One transaction spending `len(nonces)` outputs of one key, of any type.

    Covers every shape `extract_input` supports, so a test can drive each
    extraction path with a key it chose -- which is what makes a leak check over
    those paths meaningful. `build_signed_tx` remains the P2PKH-only workhorse;
    this is the general form.

    The witness types sign the BIP143 digest, which commits to ``amount``; pass
    the same value here and in the `PrevOut` or the signature will not verify,
    exactly as on chain.
    """
    Q = CURVE.pubkey(d)
    compressed = script_type != "p2pk"
    pubkey = serialize_pubkey(Q.x, Q.y, compressed)
    witness_types = ("v0_p2wpkh", "p2sh_p2wpkh")

    if script_type == "p2pkh":
        spk, redeem = p2pkh_script(Q.x, Q.y), b""
    elif script_type == "p2pk":
        spk, redeem = p2pk_script(Q.x, Q.y), b""
    elif script_type == "v0_p2wpkh":
        spk, redeem = p2wpkh_program(Q.x, Q.y), b""
    elif script_type == "p2sh_p2wpkh":
        redeem = p2wpkh_program(Q.x, Q.y)
        spk = p2sh_script(redeem)
    else:
        raise ValueError(f"unsupported script type {script_type!r}")

    if funding is None:
        funding = [(bytes([i + 1]) * 32, i) for i in range(len(nonces))]
    prevouts = [PrevOut(amount, spk) for _ in nonces]

    # A P2SH-wrapped input carries its redeemScript in the scriptSig, and that
    # scriptSig IS committed to by nothing -- but it must be present before the
    # txid is final, so it goes in from the start.
    script_sig = push_data(redeem) if script_type == "p2sh_p2wpkh" else b""

    blank = Tx(
        version=1,
        vin=tuple(
            TxIn(OutPoint(txid, vout), script_sig, SEQUENCE) for txid, vout in funding
        ),
        vout=(TxOut(out_value, p2pkh_script(Q.x, Q.y)),),
        locktime=locktime,
        has_witness=script_type in witness_types,
    )

    sigs: list[bytes] = []
    for index, k in enumerate(nonces):
        if script_type in witness_types:
            script_code = p2wpkh_script_code(hash160(pubkey))
            digest = bip143_sighash(blank, index, script_code, amount, hashtype)
        else:
            # P2PKH and P2PK alike: the scriptCode is the prevout script.
            digest = legacy_sighash(blank, index, spk, hashtype)
        r, s = sign_with_nonce(CURVE, sighash_to_z(digest), d, k)
        sigs.append(der_signature(r, s, hashtype))

    if script_type in witness_types:
        vin = tuple(
            TxIn(txin.prevout, txin.script_sig, txin.sequence, (sigs[i], pubkey))
            for i, txin in enumerate(blank.vin)
        )
    else:
        scripts = [
            push_data(sig) + (push_data(pubkey) if script_type == "p2pkh" else b"")
            for sig in sigs
        ]
        vin = tuple(
            TxIn(txin.prevout, scripts[i], txin.sequence)
            for i, txin in enumerate(blank.vin)
        )

    signed = Tx(
        version=blank.version,
        vin=vin,
        vout=blank.vout,
        locktime=blank.locktime,
        has_witness=blank.has_witness,
    )
    return signed, prevouts
