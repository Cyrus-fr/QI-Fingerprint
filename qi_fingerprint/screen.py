"""Stage 1: Screen -- population statistics over the UNLABELED corpus.

No private key is needed. Screening finds the cheap, certain signals and decides
where to spend the expensive Crack:

  * intra-key r-collision  -> a reused nonce -> instantly key-recoverable;
  * cross-key r-collision  -> a shared / weak generator -> links keys into a cohort;
  * high signature count   -> a speculative lattice candidate (MSB bias is invisible
                             in r, so we simply try the lattice on well-sampled keys
                             and let d*G == Q arbitrate).

Honest limit: a pure MSB-truncation cohort with few signatures per key and no
reuse is INVISIBLE here (r is scrambled by the curve). It surfaces only once a
well-sampled cohort member is cracked and the diagnosis is propagated.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .corpus import Corpus
from .curves import get_curve

_METHOD_PRIORITY = {"reuse": 0, "seed": 1, "lattice": 2}


@dataclass
class CrackTarget:
    key_id: int
    method: str  # "reuse" | "seed" | "lattice"
    priority: int
    reason: str


@dataclass
class ScreenReport:
    n_keys: int
    n_signatures: int
    intra_key_reuse: list[int]  # keys with a nonce-reuse (r-collision) pair
    cross_key_groups: list[list[int]]  # keys linked by a single shared r
    cohorts: list[list[int]]  # connected components over shared-r edges
    lattice_candidates: list[int]  # keys with enough signatures to attempt LLL/BKZ
    n_r_collisions: int  # colliding signature occurrences (anomaly magnitude)
    expected_random_collisions: float  # birthday-bound expectation under good RNG

    def crack_queue(self) -> list[CrackTarget]:
        """Cheapest, most certain crack per key, cheap-first."""
        best: dict[int, CrackTarget] = {}

        def offer(kid: int, method: str, reason: str) -> None:
            target = CrackTarget(kid, method, _METHOD_PRIORITY[method], reason)
            current = best.get(kid)
            if current is None or target.priority < current.priority:
                best[kid] = target

        for kid in self.intra_key_reuse:
            offer(kid, "reuse", "intra-key nonce reuse (r-collision)")
        for group in self.cross_key_groups:
            for kid in group:
                offer(kid, "seed", "cross-key r-collision (shared weak seed)")
        for kid in self.lattice_candidates:
            offer(kid, "lattice", "high signature count (speculative MSB-bias lattice)")

        return sorted(best.values(), key=lambda t: (t.priority, t.key_id))


def _connected_components(nodes: list[int], edges: list[tuple[int, int]]) -> list[list[int]]:
    parent = {x: x for x in nodes}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    comps: dict[int, list[int]] = {}
    for x in nodes:
        comps.setdefault(find(x), []).append(x)
    return [sorted(v) for v in comps.values()]


def screen(corpus: Corpus, lattice_min_sigs: int = 25) -> ScreenReport:
    order = get_curve(corpus.curve).n
    sigs_by_key = corpus.sigs_by_key()

    r_to_keys: dict[int, set[int]] = {}
    intra: list[int] = []
    for kid, sigs in sigs_by_key.items():
        seen_r: set[int] = set()
        reused = False
        for sig in sigs:
            if sig.r in seen_r:
                reused = True
            seen_r.add(sig.r)
        for r in seen_r:
            r_to_keys.setdefault(r, set()).add(kid)
        if reused:
            intra.append(kid)

    cross_groups = [sorted(keys) for keys in r_to_keys.values() if len(keys) >= 2]

    edges: list[tuple[int, int]] = []
    for group in cross_groups:
        for other in group[1:]:
            edges.append((group[0], other))
    components = _connected_components(list(sigs_by_key.keys()), edges)
    cohorts = [c for c in components if len(c) >= 2]

    lattice_candidates = sorted(
        kid for kid, sigs in sigs_by_key.items() if len(sigs) >= lattice_min_sigs
    )

    r_count = Counter(sig.r for sig in corpus.signatures)
    n_r_collisions = sum(c - 1 for c in r_count.values() if c > 1)
    n_sigs = len(corpus.signatures)
    expected = (n_sigs * (n_sigs - 1) / 2) / order if order else 0.0

    return ScreenReport(
        n_keys=len(sigs_by_key),
        n_signatures=n_sigs,
        intra_key_reuse=sorted(intra),
        cross_key_groups=cross_groups,
        cohorts=cohorts,
        lattice_candidates=lattice_candidates,
        n_r_collisions=n_r_collisions,
        expected_random_collisions=expected,
    )
