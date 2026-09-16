"""Stage 2c: chained recovery -- one known key unlocks its shared-nonce neighbours.

Screen links keys into cohorts through shared ``r`` values, and Stage 4 has always
carried a *diagnosis* along those edges. This module carries the *key*.

Two different keys sharing a nonce is two equations in three unknowns::

    s_A = k^-1 (h_A + r d_A)
    s_B = k^-1 (h_B + r d_B)

-- genuinely unsolvable in isolation, which is what `hunt.ReuseIndex` means when
it counts cross-key collisions without chasing them. But the moment *either*
endpoint is known the system collapses::

    k   = s_A^-1 (h_A + r d_A)      exact: derived from A's own equation
    d_B = (s_B k' - h_B) r^-1       k' in {k, n-k}, decided by d_B*G == Q_B

and ``d_B`` then unlocks *its* edges in turn. So a single recovered key can
cascade through a whole connected component. This is the payoff the Propagate
stage was named for, applied to keys rather than labels.

Two properties worth stating plainly, because both are easy to get wrong:

* **Every hop is gated.** A wrong sign, a coincidental ``r``, or a corrupt
  signature fails ``d*G == Q`` and is discarded. There is no path here that
  returns an unverified key, so a cascade cannot drift.
* **Nothing is recovered from an unknown component.** Seed the walk with an
  empty ``known`` and it returns nothing, no matter how densely the cohort is
  linked. The upgrade is not a claim that cross-key collisions alone are
  solvable -- they are not.

SAFETY (plan §9): the scalars here are live keys on a real corpus. This module
returns them to its caller and does nothing else with them -- no printing, no
persistence, no transaction path. See `qi_fingerprint/ingest/control.py` for the
same rule expressed as a type.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .corpus import Corpus, Signature
from .curves import Curve
from .reuse import nonce_from_signature, recover_from_shared_nonce


@dataclass(frozen=True)
class ChainedKey:
    """One key recovered by walking an edge from an already-known key.

    The provenance fields are the point: "we recovered 40 keys" is a claim, while
    "key 57 fell at depth 3 from key 12 over r=0x2389.." is a checkable one.
    """

    key_id: int
    d: int
    via_key_id: int  # the known key whose nonce opened this one
    via_r: int  # the shared-r edge that was walked
    depth: int  # hops from the originally cracked key (a direct hop is 1)


def shared_r_index(corpus: Corpus) -> dict[int, list[tuple[int, Signature]]]:
    """``r -> [(key_id, signature)]`` for every ``r`` signed by two or more keys.

    Built here rather than taken from `ScreenReport`, whose ``cross_key_groups``
    keeps the key sets but discards the ``r`` -- and ``r`` is precisely what the
    chain needs to know which signature sits on the edge.

    Two passes so the returned index holds only the edges: on a real corpus the
    overwhelming majority of ``r`` values are signed once and would otherwise
    dominate the memory for nothing.
    """
    keys_per_r: dict[int, set[int]] = {}
    for sig in corpus.signatures:
        keys_per_r.setdefault(sig.r, set()).add(sig.key_id)

    multi = {r for r, kids in keys_per_r.items() if len(kids) > 1}
    index: dict[int, list[tuple[int, Signature]]] = {r: [] for r in multi}
    for sig in corpus.signatures:
        if sig.r in multi:
            index[sig.r].append((sig.key_id, sig))
    return index


def propagate_keys(
    curve: Curve, corpus: Corpus, known: dict[int, int]
) -> dict[int, ChainedKey]:
    """Walk shared-nonce edges outward from every already-recovered key.

    ``known`` maps key_id -> d for keys recovered by some other means (reuse,
    seed, lattice). Returns only the *newly* recovered keys; the seeds are not
    echoed back.

    Breadth-first, so ``depth`` is the true shortest hop count rather than an
    artefact of traversal order, and each key is solved at most once -- which is
    also what makes termination obvious.
    """
    index = shared_r_index(corpus)
    if not index:
        return {}

    keys = corpus.key_index()
    sigs_by_key = corpus.sigs_by_key()

    solved: dict[int, int] = dict(known)
    depth: dict[int, int] = {kid: 0 for kid in known}
    chained: dict[int, ChainedKey] = {}

    queue: deque[int] = deque(known)
    while queue:
        src = queue.popleft()
        d_src = solved[src]

        for sig in sigs_by_key.get(src, []):
            peers = index.get(sig.r)
            if not peers:
                continue  # this r is this key's alone -- not an edge

            # Only worth inverting once we know the edge leads somewhere new.
            unsolved = [(kid, s) for kid, s in peers if kid != src and kid not in solved]
            if not unsolved:
                continue

            k = nonce_from_signature(curve, sig, d_src)

            for kid, peer_sig in unsolved:
                if kid in solved:
                    continue  # solved by an earlier peer in this same loop
                record = keys.get(kid)
                if record is None:
                    continue
                Q = curve.point(record.Qx, record.Qy)
                d = recover_from_shared_nonce(curve, k, peer_sig, Q)
                if d is None:
                    continue  # gate refused: not actually a shared nonce
                solved[kid] = d
                depth[kid] = depth[src] + 1
                chained[kid] = ChainedKey(
                    key_id=kid,
                    d=d,
                    via_key_id=src,
                    via_r=sig.r,
                    depth=depth[kid],
                )
                queue.append(kid)

    return chained


def unwalked_edges(corpus: Corpus, known: dict[int, int] | None = None) -> int:
    """How many shared-r edges touch a known key but were never walked.

    Reported by the CLI when ``--chain`` is absent, so declining to chase the
    edges is visible rather than silent -- the same reasoning that made the
    cross-key count worth printing in the first place.
    """
    index = shared_r_index(corpus)
    if not index:
        return 0
    if known is None:
        return len(index)

    sigs_by_key = corpus.sigs_by_key()
    reachable: set[int] = set()
    for kid in known:
        for sig in sigs_by_key.get(kid, []):
            peers = index.get(sig.r)
            if peers and any(other != kid for other, _ in peers):
                reachable.add(sig.r)
    return len(reachable)
