"""The ingest gate: every extracted signature must verify, or nothing is written.

This is the only correctness oracle available without ground truth. A real corpus
has no `bias_type` to score against, but it does have a fact we can check: the
signer possessed a private key for `Q` and signed *some* digest. If our computed
`z` is that digest, `ecdsa_verify` passes; if we got the serialisation, scriptCode,
sighash type or endianness wrong, `z` changes and it fails.

So verification failure is never noise -- for a supported input type the sighash
is deterministic. It is a bug in this package, and the correct response is to
refuse to produce a corpus rather than to emit one built on arithmetic we cannot
justify. Hence `min_rate` defaults to **1.0**, not 0.99.

Two design details that are easy to get wrong and matter a lot:

* **The denominator is `attempted`, never total inputs.** Skips (Taproot, multisig,
  coinbase) are not failures; folding them in would let a genuinely broken stratum
  hide behind a large skip count.
* **Per-stratum gating.** "99.9% global" cheerfully conceals "all 40 SIGHASH_NONE
  inputs failed." The bucket is where a systematic bug actually shows up.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..curves import Curve, get_curve, sign_with_nonce
from ..verify import ecdsa_verify
from .extract import ExtractedSig


class IngestGateError(RuntimeError):
    """The verify gate failed; no corpus was written."""


@dataclass(frozen=True)
class Stratum:
    """A bucket a systematic sighash bug would show up in."""

    script_type: str
    sigversion: str
    base_type: int  # hashtype & 0x1f
    anyonecanpay: bool

    def __str__(self) -> str:
        acp = "|ACP" if self.anyonecanpay else ""
        return f"{self.script_type}/{self.sigversion}/ht={self.base_type:#04x}{acp}"


@dataclass
class StratumStats:
    attempted: int = 0
    passed: int = 0

    @property
    def rate(self) -> float:
        return self.passed / self.attempted if self.attempted else 0.0


@dataclass
class ValidationReport:
    attempted: int = 0
    passed: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    per_stratum: dict[Stratum, StratumStats] = field(default_factory=dict)
    failures: list[tuple[ExtractedSig, str]] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return self.passed / self.attempted if self.attempted else 0.0

    def worst_stratum(self) -> tuple[Stratum, float] | None:
        if not self.per_stratum:
            return None
        worst = min(self.per_stratum.items(), key=lambda kv: kv[1].rate)
        return worst[0], worst[1].rate

    def format_table(self) -> str:
        lines = [
            f"  verified {self.passed}/{self.attempted} "
            f"({self.pass_rate * 100:.4f}%)",
            "  per stratum:",
        ]
        for stratum, stats in sorted(self.per_stratum.items(), key=lambda kv: str(kv[0])):
            flag = "" if stats.rate == 1.0 else "   <-- FAILING"
            lines.append(
                f"    {str(stratum):<34} {stats.passed:>6}/{stats.attempted:<6} "
                f"{stats.rate * 100:7.3f}%{flag}"
            )
        if self.skipped:
            lines.append("  skipped:")
            for reason, count in sorted(self.skipped.items(), key=lambda kv: -kv[1]):
                lines.append(f"    {reason:<40} {count:>6}")
        return "\n".join(lines)


def stratum_of(sig: ExtractedSig) -> Stratum:
    return Stratum(
        script_type=sig.script_type,
        sigversion=sig.sigversion,
        base_type=sig.hashtype & 0x1F,
        anyonecanpay=bool(sig.hashtype & 0x80),
    )


def gate_self_test(curve: Curve | None = None) -> None:
    """Prove the gate can fail before trusting it to pass.

    A verifier that returned True unconditionally would make every ingest look
    perfect. This signs a known message, asserts it verifies, then perturbs the
    digest by one bit and asserts it does NOT -- so a green gate means something.
    """
    curve = curve or get_curve("secp256k1")
    d = 0x0F1E_2D3C_4B5A_6978 % curve.n
    Q = curve.pubkey(d)
    h = 0xC0FF_EE00_1234_5678 % curve.n
    r, s = sign_with_nonce(curve, h, d, 0xA5A5_5A5A_1234 % curve.n)

    if not ecdsa_verify(h, r, s, Q, curve):
        raise IngestGateError("gate self-test: a valid signature failed to verify")
    if ecdsa_verify(h ^ 1, r, s, Q, curve):
        raise IngestGateError("gate self-test: a tampered digest verified -- gate is vacuous")


def validate(
    sigs: list[ExtractedSig],
    curve: Curve | None = None,
    *,
    max_failures: int = 50,
) -> tuple[list[ExtractedSig], ValidationReport]:
    """Verify every extracted signature. Returns only those that passed."""
    curve = curve or get_curve("secp256k1")
    gate_self_test(curve)

    report = ValidationReport()
    per_stratum: dict[Stratum, StratumStats] = defaultdict(StratumStats)
    kept: list[ExtractedSig] = []
    # Reconstructing a Point per signature dominates the cost; keys repeat.
    points: dict[tuple[int, int], object] = {}

    for sig in sigs:
        key = (sig.qx, sig.qy)
        Q = points.get(key)
        if Q is None:
            Q = curve.point(sig.qx, sig.qy)
            points[key] = Q

        stats = per_stratum[stratum_of(sig)]
        stats.attempted += 1
        report.attempted += 1

        if ecdsa_verify(sig.z, sig.r, sig.s, Q, curve):
            stats.passed += 1
            report.passed += 1
            kept.append(sig)
        elif len(report.failures) < max_failures:
            report.failures.append((sig, "ecdsa_verify returned False"))

    report.per_stratum = dict(per_stratum)
    return kept, report


def assert_gate(
    report: ValidationReport,
    *,
    min_rate: float = 1.0,
    min_stratum_n: int = 20,
    min_stratum_rate: float = 1.0,
) -> None:
    """Raise unless the run is clean globally *and* in every populated stratum."""
    if report.attempted == 0:
        raise IngestGateError("no inputs were attempted -- nothing to validate")

    if report.pass_rate < min_rate:
        raise IngestGateError(
            f"verify pass rate {report.pass_rate * 100:.4f}% "
            f"< required {min_rate * 100:.4f}%\n{report.format_table()}"
        )

    for stratum, stats in report.per_stratum.items():
        if stats.attempted >= min_stratum_n and stats.rate < min_stratum_rate:
            raise IngestGateError(
                f"stratum {stratum} passed {stats.passed}/{stats.attempted} "
                f"({stats.rate * 100:.3f}%) < required "
                f"{min_stratum_rate * 100:.3f}%\n{report.format_table()}"
            )
