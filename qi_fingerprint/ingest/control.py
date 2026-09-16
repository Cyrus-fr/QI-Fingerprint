"""Phase B: promote an r-collision candidate to a verified recovery.

A clean run on a range where the pipeline has never been shown to *fire* is
indistinguishable from a broken run. This module closes that gap: it takes a
candidate from the scan, refetches the implicated blocks in full, recomputes
``z`` from the real prevouts, puts both signatures through the same verify gate
the corpus builder uses, and requires ``d*G == Q``.

**Safety (plan §9).** Recovered keys in the 2013 range may control real funds.

  * ``d`` is a local, and dies with the function. `Confirmation` has nowhere to
    put it -- ``recovered`` is a bool. Nothing here returns, prints, logs or
    persists a private scalar, and there is no code path that can spend: this
    package cannot construct a transaction, sign one, or open a wallet.
  * Verification is ``d*G == Q`` against the on-chain public key, which is
    arithmetic on data we already hold. No balance is ever queried.
  * What is reported is the count, the ``(txid, vin)`` provenance, and the
    derived address -- enough for anyone to check the finding on an explorer,
    and not enough to move a coin.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from ..corpus import Signature
from ..curves import Curve, get_curve
from ..reuse import nonce_from_signature, recover_from_reuse, recover_from_shared_nonce
from ..verify import recovers_key
from .address import address_from_pubkey_len
from .extract import ExtractedSig, extract_tx
from .hunt import CrossKeyCandidate, ReuseCandidate, SigSite
from .sources import BlockSource
from .validate import assert_gate, validate

SAFETY_BANNER = """
  !! A real private key was recovered from public chain data.
     This key may control funds. It is NOT printed, logged or written to disk,
     and this tool cannot construct, sign or broadcast a transaction.
     Reported below: provenance and the derived address only.
     Recover, verify, count -- never access or move a balance.
"""


class ControlError(RuntimeError):
    """The candidate could not be turned into a checkable claim."""


@dataclass(frozen=True)
class Confirmation:
    """The result of trying to recover one candidate.

    Note what is absent: there is no field for the private key. That is the §9
    rule expressed as a type, rather than as a promise to remember.
    """

    candidate: ReuseCandidate
    recovered: bool
    addresses: tuple[str, ...]
    verified_sigs: tuple[ExtractedSig, ...]
    detail: str

    @property
    def provenance(self) -> tuple[tuple[str, int], ...]:
        return tuple((s.txid, s.vin) for s in self.verified_sigs)

    def format(self) -> str:
        shown = ", ".join(self.addresses) if self.addresses else "(address unavailable)"
        lines = [
            f"  key    {shown}",
            f"  r      {self.candidate.r:064x}",
        ]
        for sig in self.verified_sigs:
            lines.append(
                f"  input  {sig.txid}:{sig.vin}  height {sig.height}"
                f"  low_s={str(sig.low_s).lower()}"
            )
        lines.append(
            f"  result {'RECOVERED (d*G == Q)' if self.recovered else 'not recovered'}"
            f" -- {self.detail}"
        )
        return "\n".join(lines)


def _locate(source: BlockSource, sites: Iterable[SigSite]) -> list[ExtractedSig]:
    """Refetch the implicated blocks and re-extract the named inputs properly.

    The scan saw only scriptSigs. Everything that makes a signature *usable* --
    the spent output's script, and therefore ``z`` -- is recomputed here from a
    fully self-authenticating block, not carried over from the scan.

    Takes sites rather than a candidate so one path serves both a same-key
    `ReuseCandidate` and a `CrossKeyCandidate`: the two differ in what can be
    *done* with the signatures, not in how they are fetched.
    """
    sites = tuple(sites)
    wanted = {(s.txid, s.vin) for s in sites}
    by_height: dict[int, set[str]] = {}
    for site in sites:
        by_height.setdefault(site.height, set()).add(site.txid)

    found: list[ExtractedSig] = []
    for height, txids in sorted(by_height.items()):
        record = source.block(height)
        for tx, prevouts in record.txs:
            if tx.txid_hex not in txids:
                continue
            sigs, _skips = extract_tx(tx, prevouts, height)
            found.extend(s for s in sigs if (s.txid, s.vin) in wanted)

    if len(found) < 2:
        raise ControlError(
            f"re-extraction found {len(found)} of {len(wanted)} candidate inputs; "
            f"the scan's shape filter accepted something the extractor rejects"
        )
    return found


def _addresses_for(qx: int, qy: int, sigs: Iterable[ExtractedSig]) -> tuple[str, ...]:
    """Every address one key spent from, in first-seen order.

    One private key has two on-chain encodings, and they hash to two different
    addresses. The corpus groups by the *point*, so a key that appears
    compressed in one input and uncompressed in another is correctly one key --
    but the report has to name both addresses, or a reader checking the finding
    on an explorer will look at the wrong one.

    Takes the point rather than a candidate, because a chained peer key has no
    candidate of its own -- only the edge that led to it.
    """
    encodings: list[int] = []
    for sig in sigs:
        if sig.pubkey_len not in encodings:
            encodings.append(sig.pubkey_len)
    return tuple(address_from_pubkey_len(qx, qy, length) for length in encodings)


def _same_sign_suffices(curve: Curve, a: ExtractedSig, b: ExtractedSig, Q) -> bool:
    """Would the pre-§8 formula alone have recovered this pair?

    A diagnostic, not a second recovery path: it re-derives only the same-sign
    candidate, to report whether the low-s branch was load-bearing on real chain
    data. The scalar is local and discarded either way.
    """
    n = curve.n
    denominator = (a.s - b.s) % n
    if denominator == 0:
        return False
    k = ((a.z - b.z) * curve.inv(denominator)) % n
    if k == 0:
        return False
    candidate_d = ((a.s * k - a.z) * curve.inv(a.r)) % n
    return recovers_key(candidate_d, Q, curve)


def confirm_candidate(
    candidate: ReuseCandidate, source: BlockSource, curve: Curve | None = None
) -> Confirmation:
    """Try to recover the key behind one candidate. Never returns the key."""
    confirmation, d = _recover_candidate(candidate, source, curve)
    del d  # the public entry point drops the scalar; see `_recover_candidate`
    return confirmation


def _recover_candidate(
    candidate: ReuseCandidate, source: BlockSource, curve: Curve | None = None
) -> tuple[Confirmation, Optional[int]]:
    """Internal: the recovery, plus the scalar, for callers that must cascade.

    §9 is not weakened by this. The scalar is returned only *within* this module,
    to `confirm_with_cascade`, which needs it to derive the shared nonce and
    which drops it again before returning. Nothing outside this module can reach
    it: `confirm_candidate` is the public door and it deletes the value.
    """
    curve = curve or get_curve("secp256k1")
    sigs = _locate(source, candidate.sites)

    # Same gate as the corpus path: a signature that does not verify is not
    # evidence of anything, and a failure here means our z is wrong, not that
    # the key is safe. min_rate is 1.0, so the global check already requires
    # every record to pass; the default min_stratum_n correctly leaves a
    # two-record bucket ungated rather than double-counting it.
    verified, report = validate(sigs, curve)
    assert_gate(report)

    Q = curve.point(candidate.qx, candidate.qy)
    addresses = _addresses_for(candidate.qx, candidate.qy, verified)

    found: Optional[int] = None
    detail = "no pair yielded a key that satisfies d*G == Q"
    for i in range(len(verified)):
        for j in range(i + 1, len(verified)):
            a, b = verified[i], verified[j]
            if a.z == b.z:
                continue  # identical message: no information
            d = recover_from_reuse(
                curve,
                Signature(0, a.z, a.r, a.s),
                Signature(0, b.z, b.r, b.s),
                Q,
            )
            if d is None:
                continue
            # `recover_from_reuse` already checked d*G == Q, so this is verified.
            # It stays a local of this private function; `confirm_candidate`
            # deletes it, and `confirm_with_cascade` uses it only to derive k.
            found = d
            detail = (
                "same-sign pair"
                if _same_sign_suffices(curve, a, b, Q)
                else "mixed-sign pair -- required the s1+s2 branch"
            )
            break
        if found is not None:
            break

    confirmation = Confirmation(
        candidate=candidate,
        recovered=found is not None,
        addresses=addresses,
        verified_sigs=tuple(verified),
        detail=detail,
    )
    return confirmation, found


# --------------------------------------------------------------------------- #
# Cascading across cross-key edges
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ChainConfirmation:
    """A key recovered by walking a shared-nonce edge from an already-known key.

    Like `Confirmation`, it has no field for the private scalar -- and for the
    same reason. What it adds is the edge: which key opened this one, and over
    which ``r``, so a chain of findings is auditable hop by hop.
    """

    r: int
    recovered: bool
    addresses: tuple[str, ...]
    via_addresses: tuple[str, ...]
    verified_sigs: tuple[ExtractedSig, ...]
    depth: int
    detail: str

    @property
    def provenance(self) -> tuple[tuple[str, int], ...]:
        return tuple((s.txid, s.vin) for s in self.verified_sigs)

    def format(self) -> str:
        shown = ", ".join(self.addresses) if self.addresses else "(address unavailable)"
        via = ", ".join(self.via_addresses) if self.via_addresses else "(unknown)"
        lines = [
            f"  key    {shown}",
            f"  via    {via}  (depth {self.depth})",
            f"  r      {self.r:064x}",
        ]
        for sig in self.verified_sigs:
            lines.append(
                f"  input  {sig.txid}:{sig.vin}  height {sig.height}"
                f"  low_s={str(sig.low_s).lower()}"
            )
        lines.append(
            f"  result {'RECOVERED (d*G == Q)' if self.recovered else 'not recovered'}"
            f" -- {self.detail}"
        )
        return "\n".join(lines)


def _edges_by_key(
    cross_hits: Iterable[CrossKeyCandidate],
) -> dict[tuple[int, int], list[CrossKeyCandidate]]:
    """Index the retained cross-key pairs by each endpoint's public key."""
    edges: dict[tuple[int, int], list[CrossKeyCandidate]] = {}
    for hit in cross_hits:
        for site in hit.sites:
            edges.setdefault((site.qx, site.qy), []).append(hit)
    return edges


def confirm_with_cascade(
    candidate: ReuseCandidate,
    cross_hits: Sequence[CrossKeyCandidate],
    source: BlockSource,
    curve: Curve | None = None,
) -> tuple[Confirmation, list[ChainConfirmation]]:
    """Confirm a same-key candidate, then cascade across its cross-key edges.

    Confirmation and cascade live in one function on purpose: the cascade needs
    the recovered scalar to derive the shared nonce, and keeping both here means
    the scalar never crosses a module boundary. Callers get provenance only.

    Every hop refetches its blocks, re-derives ``z`` from real prevouts, passes
    the same verify gate, and is accepted only on ``d*G == Q`` -- a cascade is
    held to exactly the standard a single recovery is.
    """
    curve = curve or get_curve("secp256k1")
    confirmation, seed_d = _recover_candidate(candidate, source, curve)
    if seed_d is None:
        return confirmation, []

    edges = _edges_by_key(cross_hits)
    solved: dict[tuple[int, int], int] = {(candidate.qx, candidate.qy): seed_d}
    depth: dict[tuple[int, int], int] = {(candidate.qx, candidate.qy): 0}
    walked: set[int] = set()
    results: list[ChainConfirmation] = []

    queue: deque[tuple[int, int]] = deque([(candidate.qx, candidate.qy)])
    while queue:
        here = queue.popleft()
        for hit in edges.get(here, []):
            if hit.r in walked:
                continue
            walked.add(hit.r)

            ours = next((s for s in hit.sites if (s.qx, s.qy) == here), None)
            theirs = next((s for s in hit.sites if (s.qx, s.qy) != here), None)
            if ours is None or theirs is None:
                continue
            peer = (theirs.qx, theirs.qy)
            if peer in solved:
                continue

            try:
                extracted = _locate(source, (ours, theirs))
            except ControlError:
                continue
            verified, report = validate(extracted, curve)
            assert_gate(report)

            our_sig = next(
                (s for s in verified if (s.qx, s.qy) == here and s.r == hit.r), None
            )
            their_sig = next(
                (s for s in verified if (s.qx, s.qy) == peer and s.r == hit.r), None
            )
            if our_sig is None or their_sig is None:
                continue

            k = nonce_from_signature(
                curve, Signature(0, our_sig.z, our_sig.r, our_sig.s), solved[here]
            )
            peer_Q = curve.point(*peer)
            peer_d = recover_from_shared_nonce(
                curve, k, Signature(0, their_sig.z, their_sig.r, their_sig.s), peer_Q
            )

            hop_depth = depth[here] + 1
            results.append(
                ChainConfirmation(
                    r=hit.r,
                    recovered=peer_d is not None,
                    addresses=_addresses_for(*peer, [their_sig]),
                    via_addresses=_addresses_for(*here, [our_sig]),
                    verified_sigs=(our_sig, their_sig),
                    depth=hop_depth,
                    detail=(
                        "recovered from the shared nonce"
                        if peer_d is not None
                        else "shared r did not yield a key satisfying d*G == Q"
                    ),
                )
            )
            if peer_d is None:
                continue
            solved[peer] = peer_d
            depth[peer] = hop_depth
            queue.append(peer)

    return confirmation, results
