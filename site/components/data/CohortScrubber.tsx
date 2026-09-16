"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { CohortGraph, GraphLegend, edgeId, propagationOrder } from "./CohortGraph";
import { prefersReducedMotion } from "@/lib/motion";
import type { RunData } from "@/lib/types";

/**
 * The centrepiece: cohort propagation, scrubbed by scroll position.
 *
 * The whole thesis in one shot -- an unlabeled population, one member cracked and
 * proven, then its diagnosis carried outward edge by edge to keys that were never
 * cracked at all.
 *
 * Three things keep this honest rather than merely cinematic:
 *
 *  - Scrub, not autoplay. The reader owns the clock; the animation has no opinion
 *    about how long they want to look at any given frame.
 *  - Opacity only. Every element is at its final coordinates in the server-rendered
 *    SVG, and the timeline animates opacity alone -- so nothing in this section can
 *    move under a reader, and the graph cannot reflow.
 *  - The resolved state is the source of truth. Reduced motion and no-JS skip
 *    straight to it and lose nothing but the choreography.
 */

const PHASES = [
  {
    at: 0,
    kicker: "population",
    line: "An unlabeled population. No private keys, no vendor metadata, no ground truth — only public signatures.",
  },
  {
    at: 0.18,
    kicker: "crack",
    line: "The cheapest certain recovery fires first. Each cracked key passes d·G == Q before the pipeline will even look at it.",
  },
  {
    at: 0.32,
    kicker: "propagate",
    line: "Cohort membership comes purely from shared r values. The diagnosis carries along those links to keys that were never cracked.",
  },
  {
    at: 0.8,
    kicker: "attributed",
    line: "One diagnosis per cohort, spread across the population — and the keys with no observable link are left grey rather than guessed.",
  },
];

export function CohortScrubber({ run, children }: { run: RunData; children: ReactNode }) {
  const rootRef = useRef<HTMLDivElement>(null);
  const trackRef = useRef<HTMLDivElement>(null);
  const [phase, setPhase] = useState(0);
  const [scrubbing, setScrubbing] = useState(false);

  useEffect(() => {
    const root = rootRef.current;
    const track = trackRef.current;
    if (!root || !track) return;

    // Reduced motion: leave the server-rendered resolved state exactly as it is.
    if (prefersReducedMotion()) {
      setPhase(PHASES.length - 1);
      return;
    }

    gsap.registerPlugin(ScrollTrigger);
    setScrubbing(true);

    const ctx = gsap.context(() => {
      const order = propagationOrder(run);
      const crackedIds = run.cohortGraph.nodes
        .filter((n) => n.source === "cracked")
        .map((n) => n.id);

      const populationEls = gsap.utils.toArray<SVGElement>("[data-population]");
      const ringEls = gsap.utils.toArray<SVGElement>("[data-ring]");
      // Both compositions are in the DOM, one hidden by CSS at each breakpoint, so
      // every id matches twice. Drive all copies: the hidden one animates unseen and
      // is already in the right state the moment a resize reveals it.
      const all = (sel: string) => [...root.querySelectorAll<SVGElement>(sel)];
      const crackedNodeEls = crackedIds.flatMap((id) => all(`[data-node="${id}"]`));

      // Hide only what the timeline will bring back. Done here rather than in the
      // markup so the no-JS render stays fully resolved.
      gsap.set([...populationEls, ...ringEls], { opacity: 0 });
      gsap.set(
        gsap.utils.toArray<SVGElement>("[data-node]"),
        { opacity: 0 },
      );
      gsap.set(gsap.utils.toArray<SVGElement>("[data-edge]"), { opacity: 0 });

      const tl = gsap.timeline({
        defaults: { ease: "none" },
        scrollTrigger: {
          // The TRACK, not the section. The graph is sticky for exactly the
          // track's length, so triggering on the section made progress a
          // fraction of itself: on a phone the figure scrolled away at 13%
          // progress, before the diagnosis layer fired at all, and the reader
          // got an empty box. Tie the clock to the span the figure is visible
          // for and phase 4 lands while it is still on screen.
          trigger: track,
          start: "top top",
          end: "bottom bottom",
          scrub: 0.6,
          onUpdate: (self) => {
            let next = 0;
            for (let i = 0; i < PHASES.length; i += 1) {
              if (self.progress >= PHASES[i].at) next = i;
            }
            // Only a phase change crosses the React boundary -- never a frame.
            setPhase((cur) => (cur === next ? cur : next));
          },
        },
      });

      // Fix the timeline's length at exactly 1, so a position written below is the
      // scroll progress it fires at. Without this the duration is whatever the last
      // tween happens to end at (0.757), ScrollTrigger normalises progress across
      // that, and every authored beat is stretched by 1.32 -- which put the
      // "attributed" caption on screen while a third of the propagation had yet to
      // run, and left the final key landing in the last instant before the figure
      // released. The spacer animates nothing; it only reserves the length.
      tl.to({}, { duration: 1 }, 0);

      // 1 — the population arrives, unlabeled.
      tl.to(populationEls, { opacity: 1, duration: 0.14, stagger: { amount: 0.07 } }, 0);

      // 2 — the cracked members ignite: double ring, then their own diagnosis colour.
      tl.to(ringEls, { opacity: 1, duration: 0.08, stagger: { amount: 0.04 } }, 0.19);
      tl.to(crackedNodeEls, { opacity: 1, duration: 0.07, stagger: { amount: 0.04 } }, 0.22);

      // 3 — propagation, edge by edge, in the BFS order fixed by the export script.
      const SPAN_START = 0.33;
      const SPAN_END = 0.76;
      const slice = order.length > 0 ? (SPAN_END - SPAN_START) / order.length : 0;
      order.forEach((step, i) => {
        const at = SPAN_START + i * slice;
        const edge = all(`[data-edge="${edgeId(step.from, step.to)}"]`);
        const node = all(`[data-node="${step.to}"]`);
        if (edge.length) tl.to(edge, { opacity: 1, duration: slice * 0.55 }, at);
        if (node.length) tl.to(node, { opacity: 1, duration: slice * 0.5 }, at + slice * 0.45);
      });

      // The attribution table is NOT animated, and now sits past the end of this
      // trigger's range entirely. When it was inside the range, a scrub finished
      // revealing its rows only after the reader had scrolled past them -- 1,052px
      // of ghosted table on a phone. Data is legible the instant it is on screen.

      // Re-measure on any document reflow.
      //
      // ScrollTrigger caches start/end as ABSOLUTE scroll positions, taken once.
      // Everything above this section settles after first paint -- web fonts land,
      // the descent arms its readings, the rail measures itself -- and every pixel
      // of that drift moves the track without moving the cached range. On the
      // 36,000px mobile document the range ended up entirely above the track, so
      // the timeline read as already finished the moment the figure arrived: a
      // phone reader got the resolved graph and never saw a diagnosis propagate.
      // Desktop is a shorter document and drifted less, which is why it looked fine.
      let pending = 0;
      const remeasure = () => {
        window.clearTimeout(pending);
        pending = window.setTimeout(() => ScrollTrigger.refresh(), 120);
      };
      const ro = new ResizeObserver(remeasure);
      ro.observe(document.body);
      void document.fonts?.ready.then(remeasure);

      // Returned to the context, so revert() tears it down with the timeline.
      return () => {
        window.clearTimeout(pending);
        ro.disconnect();
      };
    }, root);

    return () => ctx.revert();
  }, [run]);

  const active = PHASES[phase];

  return (
    <div ref={rootRef} className="relative">
      {/* Tall track: the sticky graph reads the scroll position across it, and the
          timeline is triggered on this element so progress 0..1 maps to the span
          the figure is actually on screen. Sticky rather than a GSAP pin -- no
          pin-spacer, no layout shift on resize. The mobile track carries the same
          four phases through a shorter viewport, so it needs its own length. */}
      <div ref={trackRef} className={scrubbing ? "h-[260vh] md:h-[320vh]" : ""}>
        <div className={scrubbing ? "sticky top-0 flex min-h-screen flex-col justify-center py-8" : ""}>
          {/* No overflow-x: both compositions are drawn to fit their panel, so a
              scrollbar here could only ever be chrome with nothing behind it. */}
          <div className="border border-rule bg-ground-raised p-3 md:p-5">
            {/* Two authored compositions, the breakpoint chooses. The narrow one is
                not the wide one scaled down -- see CohortGraph. */}
            <CohortGraph run={run} layout="compact" className="mx-auto block h-auto w-full md:hidden" />
            <CohortGraph
              run={run}
              layout="wide"
              className="mx-auto hidden h-auto w-full md:block md:h-[clamp(260px,52vh,500px)] md:w-auto md:max-w-full"
            />
          </div>
          <GraphLegend />

          <div className="mt-6 grid gap-4 border-t border-rule pt-5 md:grid-cols-12">
            <div className="reading text-xs tracking-[0.2em] text-field md:col-span-2">
              {active.kicker}
            </div>
            <p className="text-sm leading-relaxed text-ink-2 md:col-span-8">{active.line}</p>
            <div
              className="reading text-xs text-ink-3 md:col-span-2 md:text-right"
              aria-hidden="true"
            >
              {phase + 1} / {PHASES.length}
            </div>
          </div>
        </div>
      </div>

      {children}
    </div>
  );
}
