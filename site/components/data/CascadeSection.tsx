"use client";

import { useEffect, useRef, useState } from "react";
import { Interval } from "../log/Sheet";
import { CascadeDiagram } from "./CascadeDiagram";
import { useCountUp, useInView } from "@/lib/hooks";
import { prefersReducedMotion } from "@/lib/motion";
import { DIAGNOSIS_COLOR, type RunData } from "@/lib/types";

/**
 * N°005 -- what one recovered key is worth.
 *
 * The section is built around a single claim with a number on each side of it:
 * the crack loop alone recovers six keys, and walking the shared-nonce edges out
 * of those six recovers fourteen. Everything else here exists to make that
 * checkable -- the derivation that licenses the hop, the ledger of which key
 * opened which, and the honest gap between "recovered" and "diagnosable".
 *
 * The diagram and the ledger share one hover state, so they read as one control
 * rather than two views that happen to sit together.
 */

/** The three lines that turn an unsolvable pair into a recovery. */
const DERIVATION = [
  {
    step: "given",
    tex: "sₐ = k⁻¹ (hₐ + r·dₐ)",
    note: "key A is already recovered, and its signature shares r with key B",
  },
  {
    step: "solve for the nonce",
    tex: "k = sₐ⁻¹ (hₐ + r·dₐ)",
    note: "exact, not up to sign — it comes out of A's own equation",
  },
  {
    step: "solve for the neighbour",
    tex: "dᵦ = (sᵦ·k′ − hᵦ)·r⁻¹",
    note: "k′ ∈ {k, n−k}, decided by dᵦ·G == Qᵦ",
  },
];

function Figure({
  value,
  label,
  tone = "accent",
  from,
}: {
  value: number;
  label: string;
  tone?: "accent" | "ink" | "warn";
  from?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const shown = useCountUp(value, ref, { from: from ?? 0, duration: 1100 });
  const colour =
    tone === "accent" ? "text-field" : tone === "warn" ? "text-weak_seed" : "text-ink";
  return (
    <div ref={ref}>
      <div className={`reading text-[2.6rem] leading-none font-bold ${colour}`}>{shown}</div>
      <div className="mt-2 text-xs leading-snug text-ink-2">{label}</div>
    </div>
  );
}

export function CascadeSection({ run }: { run: RunData }) {
  const [active, setActive] = useState<number | null>(null);
  const derivRef = useRef<HTMLOListElement>(null);
  const derivIn = useInView(derivRef);
  // Same contract as the diagram: the derivation is resolved in the markup and
  // only hides itself once JS has confirmed motion is wanted. A reader with
  // scripting off, or reduced motion on, gets all three lines immediately --
  // reduced motion means arriving at the end state at once, never arriving at a
  // blank panel.
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (prefersReducedMotion()) return;
    const el = derivRef.current;
    if (!el) return;
    // Arming something already on screen would blink it out and back in.
    const box = el.getBoundingClientRect();
    if (box.top < window.innerHeight && box.bottom > 0) return;
    setArmed(true);
  }, []);
  const shown = !armed || derivIn;
  const chain = run.chain;

  return (
    <Interval
      id="cascade"
      depth="cascade"
      title="What one recovered key is worth"
      standfirst="Two different keys sharing a nonce is two equations in three unknowns. Unsolvable on its own — and solvable the instant either end is known. Walking those edges takes the same corpus from six recovered keys to fourteen, with every hop gated on d·G == Q."
    >
      {/* -------------------------------------------------- the derivation */}
      <ol
        ref={derivRef}
        className="grid gap-px border border-rule bg-rule md:grid-cols-3"
      >
        {DERIVATION.map((line, i) => (
          <li
            key={line.step}
            className="deriv-step min-w-0 bg-ground p-6"
            style={{
              opacity: shown ? 1 : 0,
              transform: shown ? "none" : "translateY(10px)",
              transitionDelay: armed ? `${i * 190}ms` : "0ms",
            }}
          >
            <div className="reading mb-4 flex items-baseline gap-3 text-[0.6rem] tracking-[0.2em] text-ink-3">
              <span className="text-field">{i + 1}</span>
              {line.step}
            </div>
            <p className="reading text-lg leading-snug font-bold text-ink">{line.tex}</p>
            <p className="mt-3 text-xs leading-relaxed text-ink-2">{line.note}</p>
          </li>
        ))}
      </ol>

      <p className="reading mt-5 border-t border-weak_seed pt-4 text-sm leading-relaxed text-ink-2">
        Both signs of k&prime; must be tried. BIP146 may have normalised one signature and not
        the other, and across two keys that is a coin flip &mdash; trying only +k recovers
        nothing and looks exactly like an empty range.
      </p>

      {/* ------------------------------------------------------ the result */}
      <div className="mt-12 grid gap-10 md:grid-cols-12">
        <div className="md:col-span-3">
          <div className="grid grid-cols-2 gap-x-6 gap-y-8">
            <Figure value={run.stats.nCracked} label="cracked by the queue alone" tone="ink" />
            <Figure
              value={chain.nCracked}
              from={run.stats.nCracked}
              label="recovered once the edges are walked"
            />
            <Figure
              value={chain.nUndiagnosable}
              label="recovered but carrying too few nonces to diagnose — labelled from their cohort, not guessed"
              tone="warn"
            />
            <Figure
              value={chain.unwalkedEdges}
              label="shared-r edges the default run declines to walk"
              tone="ink"
            />
          </div>
          <p className="reading mt-8 border-t border-rule pt-5 text-xs leading-relaxed text-ink-3">
            attribution stays {Math.round(chain.attributionAccuracy * 100)}% correct across
            both runs. Recovery more than doubles; accuracy does not move.
          </p>
        </div>

        {/* ------------------------------------------------- the cascade */}
        {/* `min-w-0`: a grid item defaults to `min-width: auto` and will not
            shrink below its content. The diagram lays itself out for whatever
            width this box gives it (see CascadeDiagram), so the box never scrolls. */}
        <div className="min-w-0 md:col-span-9">
          <div className="border border-rule bg-ground-raised p-3 md:p-5">
            <CascadeDiagram run={run} active={active} onActive={setActive} />
          </div>

          <ul className="mt-px grid gap-px border border-t-0 border-rule bg-rule sm:grid-cols-2">
            {chain.hops.map((hop) => (
              <li
                key={hop.keyId}
                onPointerEnter={() => setActive(hop.keyId)}
                onPointerLeave={() => setActive(null)}
                className={`logged-row flex items-baseline gap-3 px-4 py-3 ${
                  active === hop.keyId ? "bg-ground-raised" : "bg-ground"
                }`}
              >
                <span
                  aria-hidden="true"
                  className="inline-block h-2 w-2 shrink-0 translate-y-[-1px]"
                  style={{
                    background: DIAGNOSIS_COLOR[hop.truth],
                    opacity: hop.selfDiagnosable ? 1 : 0.35,
                  }}
                />
                <span className="reading text-sm font-bold text-ink">{hop.viaKeyId}</span>
                <span className="reading text-xs text-field">&rarr;</span>
                <span className="reading text-sm font-bold text-ink">{hop.keyId}</span>
                <span className="reading ml-auto text-[0.65rem] text-ink-3">
                  depth {hop.depth}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Interval>
  );
}
