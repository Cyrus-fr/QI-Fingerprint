"""Stage 1 operating-window sweep + figure (repro).

The r-collision screen fires iff two pooled signatures share a nonce: r=(k*G).x,
and r(k1)==r(k2) <=> k1==k2 or k2==n-k1. For a nonce drawn from a 2^e space with
e << 256, n-k1 is never in range, so r-collision <=> nonce-collision EXACTLY.
Detection therefore reduces to a birthday collision among N draws from 2^e.

This script:
  1. VALIDATES that reduction against the live screen() on real ECDSA signatures
     at small N (real EC math, real screen()).
  2. SWEEPS e in {32,40,48,56,64} x N=2^10..2^24 (log-spaced) with the equivalent
     birthday simulation -- the only way to reach 2^24 pooled signatures.
  3. MEASURES the single-signature brute-force rate to place the brute-force line.
  4. PLOTS the detection-rate heatmap + birthday (~2^(e/2)) and brute-force
     boundaries, saving tools/stage1_operating_window.png.

Nothing is tuned to a prediction; the empirical window is reported as measured.
"""

from __future__ import annotations

import os
import random
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

from qi_fingerprint.corpus import Corpus, KeyRecord  # noqa: E402
from qi_fingerprint.curves import get_curve  # noqa: E402
from qi_fingerprint.generator import generate_signatures, truncated_msb_source  # noqa: E402
from qi_fingerprint.screen import screen  # noqa: E402

CURVE = get_curve("secp256k1")
L = CURVE.L
HERE = os.path.dirname(os.path.abspath(__file__))

ENTROPIES = [32, 40, 48, 56, 64]
LOG2_N = list(range(10, 25))  # 2^10 .. 2^24, log-spaced


# 1. Validate: real screen() fires iff a nonce repeats (r-collision <=> k-collision)
def validate_reduction() -> bool:
    print("VALIDATION -- live screen() vs nonce duplication on REAL signatures:")
    ok = True
    for e, n_sigs, seed in [(10, 200, 1), (20, 1024, 2), (24, 4096, 3), (48, 200, 4)]:
        d = random.Random(seed).randrange(1, CURVE.n)
        Q = CURVE.pubkey(d)
        src = truncated_msb_source(CURVE, L - e, random.Random(seed + 10))  # nonce in [0, 2^e)
        sigs = generate_signatures(CURVE, 0, d, src, n_sigs, random.Random(seed + 20))
        corpus = Corpus(
            curve=CURVE.name, signatures=sigs,
            keys=[KeyRecord(0, CURVE.name, Q.x, Q.y)],
        )
        fired = screen(corpus).n_r_collisions > 0
        has_dup = len({s.true_k for s in sigs}) < len(sigs)
        match = fired == has_dup
        ok &= match
        print(f"  e={e:2d} N=2^{np.log2(n_sigs):4.1f}  screen_fired={str(fired):5}  "
              f"nonce_dup={str(has_dup):5}  {'OK' if match else 'MISMATCH'}")
    print(f"  r-collision <=> nonce-collision holds: {ok}\n")
    return ok


# 2. Birthday simulation of the screen firing (equivalent to the above, at scale)
def sim_detection_rate(e: int, n: int, trials: int, rng) -> float:
    mask = np.uint64((1 << e) - 1) if e < 64 else None
    shift = np.uint64(32)
    fired = 0
    for _ in range(trials):
        lo = rng.integers(0, 1 << 32, size=n, dtype=np.uint64)
        hi = rng.integers(0, 1 << 32, size=n, dtype=np.uint64)
        vals = (hi << shift) | lo
        del lo, hi
        if mask is not None:
            vals &= mask
        vals.sort()
        if bool(np.any(vals[1:] == vals[:-1])):
            fired += 1
        del vals
    return fired / trials


def sweep() -> np.ndarray:
    print("SWEEP -- detection rate (Monte Carlo birthday sim):")
    rng = np.random.default_rng(1234)
    Z = np.zeros((len(LOG2_N), len(ENTROPIES)))
    for i, k in enumerate(LOG2_N):
        n = 1 << k
        trials = int(np.clip(2 ** 27 // n, 16, 128))
        for j, e in enumerate(ENTROPIES):
            Z[i, j] = sim_detection_rate(e, n, trials, rng)
        print(f"  N=2^{k:2d} (t={trials:3d})  " +
              "  ".join(f"e{e}:{Z[i, j]:.2f}" for j, e in enumerate(ENTROPIES)))
    return Z


# 3. Brute-force line: one candidate ~ one scalar mult (test d*G==Q); measure the rate.
def bruteforce_line(budget_seconds: float) -> tuple[float, float]:
    m = 2000
    ks = [random.randrange(1, CURVE.n) for _ in range(m)]
    t0 = time.perf_counter()
    for k in ks:
        CURVE.mul(k)
    rate = m / (time.perf_counter() - t0)
    return rate, float(np.log2(rate * budget_seconds))


# 4. Figure
def make_figure(Z: np.ndarray, e_bf_day: float, e_bf_res: float = 48.0) -> str:
    blues = ["#f7fafe", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
    cmap = LinearSegmentedColormap.from_list("qi_blue", blues)
    e_edges = np.array([28, 36, 44, 52, 60, 68])
    k_edges = np.array([LOG2_N[0] - 0.5] + [k + 0.5 for k in LOG2_N])

    fig, ax = plt.subplots(figsize=(9, 6), dpi=130)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")
    pm = ax.pcolormesh(e_edges, k_edges, Z, cmap=cmap, vmin=0, vmax=1, shading="flat")
    cb = fig.colorbar(pm, ax=ax, pad=0.02)
    cb.set_label("r-collision detection rate", color="#0b0b0b")
    cb.ax.yaxis.set_tick_params(color="#52514e")
    plt.setp(plt.getp(cb.ax, "yticklabels"), color="#52514e")

    xlo = min(24.0, e_bf_day - 2)
    ex = np.linspace(xlo, 68, 200)
    ax.plot(ex, ex / 2, color="#eb6834", lw=2.6, label="birthday  N ~ 2^(e/2)")
    ax.axvline(e_bf_day, color="#0b0b0b", lw=2, ls="--",
               label=f"brute-force, 1 core-day (e<{e_bf_day:.0f})")
    ax.axvline(e_bf_res, color="#0b0b0b", lw=1.6, ls=":",
               label=f"brute-force, 2^48-op (e<{e_bf_res:.0f})")
    ax.axvspan(xlo, e_bf_day, color="#0b0b0b", alpha=0.06)

    ax.set_xlim(xlo, 68)
    ax.set_ylim(9.5, 24.5)
    ax.set_xticks([round(xlo)] + ENTROPIES)
    ax.set_yticks(LOG2_N[::2])
    ax.set_xlabel("effective nonce entropy  e  (bits)", color="#0b0b0b")
    ax.set_ylabel("log2  pooled signatures", color="#0b0b0b")
    ax.set_title("Stage 1  r-collision screen -- operating window", color="#0b0b0b")
    ax.annotate(
        "usable window\n(laptop attacker):\nfires + not brute-forceable",
        xy=(36, 21), ha="center", fontsize=8.5, color="#0b0b0b",
        bbox=dict(boxstyle="round", fc="white", ec="#898781", alpha=0.9),
    )
    ax.annotate("sweep starts at e=32", xy=(31.6, 10.2), fontsize=7.5, color="#898781")
    for s in ax.spines.values():
        s.set_color("#c3c2b7")
    ax.tick_params(colors="#52514e")
    ax.legend(loc="lower right", framealpha=0.94, edgecolor="#c3c2b7", fontsize=8.5)

    out = os.path.join(HERE, "stage1_operating_window.png")
    fig.tight_layout()
    fig.savefig(out, facecolor="#fcfcfb")
    print(f"\nsaved {out}")
    return out


def report_window(Z: np.ndarray, e_bf: float, rate: float) -> None:
    print("\nEMPIRICAL WINDOW (detection threshold 0.5 for the crossing, 0.9 for 'covered'):")
    print("   e | birthday 2^(e/2) | N@50%det (empirical) | det@2^24 | covered within 2^24?")
    for j, e in enumerate(ENTROPIES):
        col = Z[:, j]
        n50 = None
        for i in range(1, len(LOG2_N)):
            if col[i - 1] < 0.5 <= col[i]:
                frac = (0.5 - col[i - 1]) / (col[i] - col[i - 1] + 1e-12)
                n50 = LOG2_N[i - 1] + frac * (LOG2_N[i] - LOG2_N[i - 1])
                break
        n50s = f"2^{n50:4.1f}" if n50 is not None else ">2^24  "
        covered = "yes" if col[-1] >= 0.9 else "no"
        print(f"  {e:2d} |   2^{e / 2:4.1f}        |   {n50s}            |   {col[-1]:.2f}   |   {covered}")

    covered_es = [e for j, e in enumerate(ENTROPIES) if Z[-1, j] >= 0.9 and e > e_bf]
    print(f"\n  brute-force rate: {rate:,.0f} scalar-mults/sec/core  ->  e_bf(1 day) = {e_bf:.1f} bits")
    if covered_es:
        print(f"  usable entropy window within a 2^24 signature budget: "
              f"e in ({e_bf:.0f}, {max(covered_es)}]  (fully covered: {covered_es})")
    print("  prediction was e ~ 40-60.")


def main() -> None:
    validate_reduction()
    Z = sweep()
    rate, e_bf_day = bruteforce_line(86_400)
    _, e_bf_hour = bruteforce_line(3_600)
    make_figure(Z, e_bf_day)
    report_window(Z, e_bf_day, rate)
    print(f"  (brute-force line sensitivity: e_bf = {e_bf_hour:.0f} @1h, {e_bf_day:.0f} @1day, "
          f"48 @2^48-ops resourced)")


if __name__ == "__main__":
    main()
