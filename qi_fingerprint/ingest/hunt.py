"""Cheap first pass: find r-collision candidates without computing any sighash.

Recovering a key needs ``z``, and ``z`` needs the spent output's script -- which
on Esplora costs an extra paginated request per 25 transactions. But *finding* a
reuse candidate needs only ``r`` and the public key, and both sit in the
scriptSig. So the hunt runs on raw blocks alone -- two requests per block instead
of two plus one per 25 transactions, about 4x cheaper on a 2013-era block -- and
the fully-gated extraction runs only on the two or three blocks a candidate
actually implicates.

**Nothing here is evidence.** A candidate is a claim about two scriptSigs. It
becomes a finding only after `extract`/`validate` recompute ``z`` from the real
prevouts and ``d*G == Q`` closes. This module deliberately cannot recover a key;
it does not even know what was signed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .codec import ParseError, parse_der_sig, parse_pubkey, script_pushes
from .tx import Tx


@dataclass(frozen=True)
class SigSite:
    """One (r, s) found in one transaction input, with the key that signed it."""

    height: int
    txid: str
    vin: int
    r: int
    s: int
    qx: int
    qy: int

    @property
    def location(self) -> tuple[str, int]:
        return (self.txid, self.vin)


@dataclass(frozen=True)
class ReuseCandidate:
    """Two or more inputs under ONE key sharing an ``r``.

    Same key, same ``r`` => same nonce up to sign, because ``x(kG) == x(-kG)``.
    Which sign is a question for `reuse.recover_from_reuse`, not for the scan.
    """

    qx: int
    qy: int
    r: int
    sites: tuple[SigSite, ...]

    @property
    def heights(self) -> tuple[int, ...]:
        return tuple(sorted({s.height for s in self.sites}))


@dataclass(frozen=True)
class CrossKeyCandidate:
    """Two inputs under DIFFERENT keys sharing an ``r`` -- one nonce, two keys.

    Not recoverable on its own: two equations in three unknowns. But it stops
    being unsolvable the moment either key is known by some other route, and
    `chain.propagate_keys` is what walks it then. So the pair is *retained*
    rather than merely counted -- a collision you cannot name is a collision you
    cannot come back to.
    """

    r: int
    sites: tuple[SigSite, SigSite]

    @property
    def heights(self) -> tuple[int, ...]:
        return tuple(sorted({s.height for s in self.sites}))

    @property
    def keys(self) -> tuple[tuple[int, int], ...]:
        return tuple((s.qx, s.qy) for s in self.sites)

    @property
    def provenance(self) -> tuple[tuple[str, int], ...]:
        """``(txid, vin)`` per site -- the same shape `Confirmation` reports."""
        return tuple((s.txid, s.vin) for s in self.sites)


def scan_tx(tx: Tx, height: int) -> list[SigSite]:
    """Every input that presents a ``<DER sig> <pubkey>`` pair.

    Shape-based and prevout-free, so it accepts anything P2PKH- or P2WPKH-
    *looking*. False candidates cost one wasted confirmation and nothing else; a
    missed one is what would actually hurt, so the filter stays loose.

    **SegWit costs nothing here.** The hunt computes no sighash -- it needs only
    ``r`` and the public key -- so the fact that a witness input would need
    BIP143 to *confirm* is irrelevant to *finding* it. A P2WPKH witness stack is
    literally ``[<DER sig>, <pubkey>]``, the same two elements a P2PKH scriptSig
    pushes, which is why both go through one branch. That covers native and
    P2SH-wrapped P2WPKH; P2WSH and multisig present a different shape and are
    skipped.

    **P2PK cannot be hunted**, and that is a property of the input rather than an
    omission: its public key lives in the *prevout* script, which this pass
    deliberately never fetches. It is handled by `extract`, which has prevouts.
    """
    if tx.is_coinbase:
        return []
    found: list[SigSite] = []
    txid = tx.txid_hex
    for index, txin in enumerate(tx.vin):
        if txin.witness:
            elements: list[bytes] | None = list(txin.witness)
        else:
            elements = script_pushes(txin.script_sig)
        if elements is None or len(elements) != 2:
            continue
        try:
            r, s, _hashtype = parse_der_sig(elements[0])
            qx, qy = parse_pubkey(elements[1])
        except ParseError:
            continue
        found.append(SigSite(height, txid, index, r, s, qx, qy))
    return found


def scan_block(txs, height: int) -> list[SigSite]:
    return [site for tx in txs for site in scan_tx(tx, height)]


def find_candidates(sites) -> list[ReuseCandidate]:
    """Group by ``(key, r)`` and keep the groups holding two or more inputs.

    Deduplicated by ``(txid, vin)``: a block refetched or a page served twice
    must not manufacture a collision out of one signature.
    """
    grouped: dict[tuple[int, int, int], dict[tuple[str, int], SigSite]] = defaultdict(dict)
    for site in sites:
        grouped[(site.qx, site.qy, site.r)][site.location] = site

    candidates = [
        ReuseCandidate(qx, qy, r, tuple(sorted(by_loc.values(), key=lambda s: (s.height, s.txid, s.vin))))
        for (qx, qy, r), by_loc in grouped.items()
        if len(by_loc) > 1
    ]
    return sorted(candidates, key=lambda c: (c.sites[0].height, c.sites[0].txid, c.sites[0].vin))


class ReuseIndex:
    """Streaming detector for a range too wide to hold blocks in memory.

    Blocks are scanned and discarded; what survives is one `SigSite` per distinct
    ``(Qx, Qy, r)``. The dict key is the plain int tuple, which references the
    very ints the `SigSite` already holds -- so it costs a tuple header and no
    duplicated 256-bit values, and unlike a truncated digest it is exact. An
    r-collision in a forensic tool should not come with a probability attached.
    """

    def __init__(self) -> None:
        self._by_key_r: dict[tuple[int, int, int], SigSite] = {}
        # The first site seen for each r. Storing the `SigSite` already held in
        # `_by_key_r` is a pointer to an existing object, so it costs *less* than
        # the freshly allocated (qx, qy) tuple it replaces -- retaining the
        # evidence is cheaper than counting it was.
        self._first_with_r: dict[int, SigSite] = {}
        self.n_sites = 0
        self.cross_key_hits: list[CrossKeyCandidate] = []

    @property
    def cross_key_r(self) -> int:
        """Occurrences of an ``r`` already owned by a different key."""
        return len(self.cross_key_hits)

    def add(self, site: SigSite) -> ReuseCandidate | None:
        """Record one signature; return a candidate if it collides with an earlier one.

        Only the same-key case is *returned*, because only it is immediately
        actionable. A cross-key hit is appended to `cross_key_hits` instead: it
        is a lead, not a trigger, and stays inert until some key in its component
        is recovered by another route.
        """
        self.n_sites += 1

        first_r = self._first_with_r.get(site.r)
        if first_r is None:
            self._first_with_r[site.r] = site
        elif (first_r.qx, first_r.qy) != (site.qx, site.qy):
            # One nonce, two keys. Unsolvable alone; solvable the moment either
            # endpoint is known, so keep the pair rather than a tally.
            pair = tuple(
                sorted((first_r, site), key=lambda s: (s.height, s.txid, s.vin))
            )
            self.cross_key_hits.append(CrossKeyCandidate(site.r, pair))

        key = (site.qx, site.qy, site.r)
        first = self._by_key_r.get(key)
        if first is None:
            self._by_key_r[key] = site
            return None
        if first.location == site.location:
            return None  # the same input seen twice is not a collision
        # Canonical order, so a candidate does not depend on whether the range
        # was walked up or down -- `iter_raw_blocks` descends.
        pair = tuple(sorted((first, site), key=lambda s: (s.height, s.txid, s.vin)))
        return ReuseCandidate(site.qx, site.qy, site.r, pair)


def count_cross_key_r(sites) -> int:
    """Distinct ``r`` values shared by two or more *different* public keys.

    Two keys sharing a nonce give two equations in three unknowns, so there is no
    recovery from the pair alone -- unlike the same-key case. It is not a dead
    end though: `chain.propagate_keys` solves it as soon as either key falls, so
    a nonzero count here is both a finding and a list of leads.

    This is the batch counterpart of `ReuseIndex.cross_key_r`; use `ReuseIndex`
    when you also want the pairs themselves.
    """
    keys_by_r: dict[int, set[tuple[int, int]]] = defaultdict(set)
    for site in sites:
        keys_by_r[site.r].add((site.qx, site.qy))
    return sum(1 for owners in keys_by_r.values() if len(owners) > 1)
