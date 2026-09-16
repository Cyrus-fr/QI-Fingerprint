"""Stage 0: synthetic ECDSA signature corpus with controlled nonce bias.

Produces a realistic *unlabeled-corpus* shape -- a large benign background plus a
few planted cohorts, each sharing one weak nonce generator. Every bias type is
designed to have BOTH a crack path (so ``d`` is recoverable downstream) and a
distinct statistical fingerprint (so the diagnosis is meaningful):

    clean             uniform k                      -> not crackable, no signal
    truncated_msb     k in [0, 2^(L-B))              -> lattice; hard-zero MSBs
    modular_reduction k = rand(L) mod m  (m != 2^x)  -> lattice; modular fold
    short_period_prng k = pool[i mod P]              -> nonce reuse; autocorr period
    weak_seed         k = PRNG(seed), seed in [0,2^S)-> seed brute force; low entropy

The generator records ground truth (per-key ``d``/``bias_type``, per-signature
``true_k``/``gen_index``) into the corpus; the pipeline stages never read it.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Optional

from .corpus import Corpus, KeyRecord, Signature
from .curves import Curve, get_curve, sign_with_nonce

BIAS_TYPES = (
    "clean",
    "truncated_msb",
    "modular_reduction",
    "short_period_prng",
    "weak_seed",
    "related_nonce",
)


# --------------------------------------------------------------------------- #
# Per-key nonce sources
# --------------------------------------------------------------------------- #


@dataclass
class NonceSource:
    """A stateful per-key nonce stream. Calling it yields ``(gen_index, k)``."""

    bias_type: str
    params: dict
    _draw: Callable[[int], int]
    i: int = 0

    def __call__(self) -> tuple[int, int]:
        gi = self.i
        k = self._draw(gi)
        self.i += 1
        return gi, k


def clean_source(curve: Curve, rng: random.Random) -> NonceSource:
    n = curve.n
    return NonceSource("clean", {}, lambda i: rng.randrange(1, n))


def truncated_msb_source(curve: Curve, B: int, rng: random.Random) -> NonceSource:
    """Top ``B`` bits of k are hard zero -> k in [1, 2^(L-B)). Power-of-two range."""
    hi = 1 << (curve.L - B)
    return NonceSource("truncated_msb", {"B": B}, lambda i: rng.randrange(1, hi))


def _fold_modulus(L: int, headroom_bits: int, rng: random.Random) -> int:
    """A non-power-of-two modulus near 3/4 of 2^(L-headroom_bits).

    Reducing a full-width draw modulo this leaves ~headroom_bits of MSB bias
    (crackable) while placing the range boundary well below the next power of two,
    so the reconstructed-nonce range distinguishes a modular fold from a clean
    power-of-two truncation.
    """
    top = 1 << (L - headroom_bits)
    base = (top >> 1) + (top >> 2)  # 0.75 * top
    perturb = rng.randrange(1, top >> 4) | 1  # odd -> m is odd -> not a power of two
    return base - perturb


def modular_reduction_source(curve: Curve, m: int, rng: random.Random) -> NonceSource:
    L = curve.L

    def draw(i: int) -> int:
        while True:
            k = rng.getrandbits(L) % m
            if k:
                return k

    return NonceSource(
        "modular_reduction",
        {"m": m, "headroom_bits": L - m.bit_length()},
        draw,
    )


def short_period_source(pool: list[int]) -> NonceSource:
    """k_i = pool[i mod P]: full-range but exactly periodic -> guaranteed reuse."""
    P = len(pool)
    return NonceSource("short_period_prng", {"P": P}, lambda i: pool[i % P])


def weak_seed_nonce(seed: int, i: int, n: int) -> int:
    """The weak-seed PRNG model: nonce is a pure function of (seed, index).

    random.Random accepts int/str/bytes -- not a tuple -- so (seed, i) is folded
    into a collision-free int (i is small and never overlaps the shifted seed).
    reuse.py's brute-forcer imports this so attacker and generator stay in sync.
    """
    return random.Random((seed << 64) + i).randrange(1, n)


def weak_seed_source(curve: Curve, seed: int, seed_bits: int) -> NonceSource:
    """Nonces deterministic in a tiny seed space: k_i = PRNG(seed, i).

    A shared seed across keys yields identical streams (cross-key r-collisions);
    the small seed space makes the stream brute-forceable.
    """
    n = curve.n
    return NonceSource(
        "weak_seed",
        {"seed": seed, "seed_bits": seed_bits},
        lambda i: weak_seed_nonce(seed, i, n),
    )


def related_nonce_source(
    curve: Curve,
    a: int | None = None,
    c: int | None = None,
    k0: int | None = None,
    rng: random.Random | None = None,
) -> NonceSource:
    """Nonces linked by the linear recurrence k_{i+1} = a*k_i + c (mod n).

    Models ePrint 2023/305 (related-nonce attack): a secret affine recurrence over
    the FULL group order. Nonces are full-range and distinct -- no MSB bias, no
    repeats -- so the recurrence is invisible to every current Stage-3 signal
    except serial correlation, and even that only for a small multiplier a (an
    LCG's lag-1 correlation ~ 1/a vanishes for a large secret a). Recovery is
    algebraic (resultants / Groebner), which the pipeline does not implement.
    """
    rng = rng or random.Random()
    n = curve.n
    a = a if a is not None else rng.randrange(2, n)
    c = c if c is not None else rng.randrange(1, n)
    k0 = k0 if k0 is not None else rng.randrange(1, n)
    inv = pow((a - 1) % n, -1, n)  # n is prime and a != 1 almost surely

    def draw(i: int) -> int:
        ai = pow(a, i, n)
        k = (ai * k0 + c * (ai - 1) * inv) % n  # closed form of the LCG
        return k or 1

    return NonceSource("related_nonce", {"a": a, "c": c}, draw)


def sample_nonces(source: NonceSource, count: int) -> tuple[list[int], list[int]]:
    """Draw ``count`` nonces; returns (gen_indices, nonces). Used by the M1 gate."""
    idxs: list[int] = []
    ks: list[int] = []
    for _ in range(count):
        gi, k = source()
        idxs.append(gi)
        ks.append(k)
    return idxs, ks


# --------------------------------------------------------------------------- #
# Signature synthesis
# --------------------------------------------------------------------------- #


def generate_signatures(
    curve: Curve,
    key_id: int,
    d: int,
    source: NonceSource,
    m: int,
    rng_h: random.Random,
) -> list[Signature]:
    """Produce ``m`` signatures for one key, recording true_k / gen_index."""
    n = curve.n
    sigs: list[Signature] = []
    while len(sigs) < m:
        gi, k = source()
        h = rng_h.randrange(1, n)
        try:
            r, s = sign_with_nonce(curve, h, d, k)
        except ValueError:
            continue  # astronomically rare degenerate r/s; skip
        sigs.append(Signature(key_id=key_id, h=h, r=r, s=s, true_k=k, gen_index=gi))
    return sigs


# --------------------------------------------------------------------------- #
# Corpus assembly
# --------------------------------------------------------------------------- #


@dataclass
class CohortSpec:
    bias_type: str
    n_keys: int
    sigs_lo: int
    sigs_hi: int
    n_crackable: int  # keys given enough signatures / reuse to be directly cracked
    crackable_sigs: int
    params: dict = field(default_factory=dict)


def default_cohorts() -> list[CohortSpec]:
    return [
        CohortSpec("truncated_msb", 6, 2, 5, 1, 70, {"B": 12}),
        CohortSpec("modular_reduction", 6, 2, 5, 1, 90, {"headroom_bits": 8}),
        CohortSpec("short_period_prng", 6, 3, 6, 2, 12, {"P": 6}),
        CohortSpec("weak_seed", 6, 2, 4, 1, 8, {"seed_bits": 12, "seed_pool_size": 3}),
        # Few sigs, none crackable: the pipeline has no recovery path for this class,
        # so its keys correctly stay unattributed (like the MSB-bias siblings).
        CohortSpec("related_nonce", 6, 3, 6, 0, 0, {}),
    ]


def _cohort_state(curve: Curve, spec: CohortSpec, rng: random.Random) -> dict:
    bt = spec.bias_type
    if bt == "short_period_prng":
        P = spec.params.get("P", 6)
        return {"pool": [rng.randrange(1, curve.n) for _ in range(P)]}
    if bt == "modular_reduction":
        headroom = spec.params.get("headroom_bits", 8)
        return {"m": _fold_modulus(curve.L, headroom, rng)}
    if bt == "truncated_msb":
        return {"B": spec.params.get("B", 12)}
    if bt == "weak_seed":
        seed_bits = spec.params.get("seed_bits", 14)
        pool_size = spec.params.get("seed_pool_size", 3)
        # A tiny pool of seeds shared across the cohort's keys guarantees cross-key
        # r-collisions (the Screen signal); the attacker still searches 2^seed_bits.
        # pool_index cycles the pool so every seed is reused by >=2 keys.
        seed_pool = [rng.randrange(0, 1 << seed_bits) for _ in range(pool_size)]
        return {"seed_bits": seed_bits, "seed_pool": seed_pool, "pool_index": 0}
    if bt == "related_nonce":
        # Secret recurrence params shared across the cohort (a fixed library bug);
        # each key gets its own k0, so the sequences differ and never r-collide.
        return {"a": rng.randrange(2, curve.n), "c": rng.randrange(1, curve.n)}
    return {}


def _make_source(
    curve: Curve, spec: CohortSpec, shared: dict, rng: random.Random
) -> NonceSource:
    bt = spec.bias_type
    if bt == "clean":
        return clean_source(curve, rng)
    if bt == "truncated_msb":
        return truncated_msb_source(curve, shared["B"], rng)
    if bt == "modular_reduction":
        return modular_reduction_source(curve, shared["m"], rng)
    if bt == "short_period_prng":
        return short_period_source(shared["pool"])
    if bt == "weak_seed":
        pool = shared["seed_pool"]
        idx = shared["pool_index"] % len(pool)
        seed = pool[idx]
        shared["pool_index"] += 1
        return weak_seed_source(curve, seed, shared["seed_bits"])
    if bt == "related_nonce":
        return related_nonce_source(curve, a=shared["a"], c=shared["c"], rng=rng)
    raise ValueError(f"unknown bias type {bt!r}")


def build_corpus(
    curve_name: str = "secp256k1",
    seed: int = 0,
    n_background: int = 40,
    bg_sigs: tuple[int, int] = (2, 5),
    cohorts: Optional[list[CohortSpec]] = None,
) -> Corpus:
    """Assemble a full labeled corpus: benign background + planted cohorts."""
    curve = get_curve(curve_name)
    n = curve.n
    master = random.Random(seed)

    def sub() -> random.Random:
        return random.Random(master.getrandbits(64))

    corpus = Corpus(curve=curve.name)
    kid = 0
    gen_id = 0

    # Benign background.
    for _ in range(n_background):
        d = master.getrandbits(curve.L) % n or 1
        Q = curve.pubkey(d)
        msig = master.randint(bg_sigs[0], bg_sigs[1])
        sigs = generate_signatures(curve, kid, d, clean_source(curve, sub()), msig, sub())
        corpus.keys.append(
            KeyRecord(kid, curve.name, Q.x, Q.y, bias_type="clean", generator_id=gen_id, d=d)
        )
        corpus.signatures.extend(sigs)
        kid += 1
    gen_id += 1

    for spec in cohorts if cohorts is not None else default_cohorts():
        shared = _cohort_state(curve, spec, sub())
        for j in range(spec.n_keys):
            d = master.getrandbits(curve.L) % n or 1
            Q = curve.pubkey(d)
            crackable = j < spec.n_crackable
            msig = spec.crackable_sigs if crackable else master.randint(spec.sigs_lo, spec.sigs_hi)
            source = _make_source(curve, spec, shared, sub())
            sigs = generate_signatures(curve, kid, d, source, msig, sub())
            corpus.keys.append(
                KeyRecord(
                    kid, curve.name, Q.x, Q.y,
                    bias_type=spec.bias_type, generator_id=gen_id, d=d,
                )
            )
            corpus.signatures.extend(sigs)
            kid += 1
        gen_id += 1

    return corpus
