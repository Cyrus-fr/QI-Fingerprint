"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useInView } from "@/lib/hooks";
import { prefersReducedMotion } from "@/lib/motion";
import { DIAGNOSIS_COLOR, type ChainHop, type RunData } from "@/lib/types";

/**
 * The cascade, drawn as what it is: a fan out of each key that was cracked on its
 * own merits into the keys that only fell because it did.
 *
 * Not a second cohort graph. The cohort graph answers "who is linked to whom";
 * this answers what knowing one key actually bought, so it is anchored on the
 * seed keys and ordered by hop depth, and the connector is labelled with the
 * shared r rather than left as a generic edge.
 *
 * Interaction carries information rather than decorating it: hovering a hop
 * raises its connector and dims the rest, so one derivation can be isolated from
 * a picture of eight. The ledger beside it drives the same state, so the two
 * halves of the section behave as one control.
 *
 * It is drawn at 1:1 for the width it is given -- never scaled, never scrolled.
 * A fixed 1000-unit viewBox with a 46rem floor meant a scrollbar below ~1280px
 * and, wherever it did fit, labels rendered under 7px. The figure measures its
 * box instead, and a narrower box drops whole text columns, starting with the
 * ones a legend or the ledger below already carries.
 */

/**
 * Rows sit on a fixed pitch, so the height depends on the data and never on the
 * width: nothing moves vertically when the layout re-tiers. At 36px a resting
 * node (r=12) keeps 10.8px clear of its neighbour and a hovered one (r=15) 7.8px.
 * Squeezing eleven rows into a fixed 300 gave a 23.2 pitch and the circles overlapped.
 */
// Row pitch. Against a node radius of 12 this leaves 20 units between one child
// and the next; at 36 the five children of a single seed read as a column of
// touching discs rather than five separate keys.
const STEP = 44;
const PAD_TOP = 30;
/** Room for the column captions under the last seed ring (r=19), with ~11px clear. */
const PAD_BOTTOM = 50;
const NODE_R = 12;
const NODE_R_ACTIVE = 15;
const SEED_RING_R = 19;

/** Spline Sans Mono's advance, in em. Every text column is placed from it. */
const MONO_EM = 0.6;
const R_FONT = 11;
const META_FONT = 10;

/** The server has no box to measure, so it renders the desktop composition. */
const SSR_WIDTH = 760;

type Tier = "wide" | "medium" | "narrow";

interface CascadeLayout {
  tier: Tier;
  seedX: number;
  childX: number;
  rX: number;
  rChars: number;
  /** null when the box is too narrow; the ledger below carries depth. */
  depthX: number | null;
  /** null when the box is too narrow; the legend carries it. */
  diagX: number | null;
}

/**
 * Column positions for a width. Each threshold is where the longest string of the
 * next column still fits: at 720 "diagnosed from its own nonces" ends at 688, at
 * 440 "depth N" ends at 416, and the narrow composition ends at 242 (its caption)
 * so it holds on a 320px phone.
 */
function cascadeLayout(width: number): CascadeLayout {
  const tier: Tier = width >= 720 ? "wide" : width >= 440 ? "medium" : "narrow";
  const seedX = { wide: 56, medium: 48, narrow: 26 }[tier];
  const childX = { wide: 320, medium: 240, narrow: 128 }[tier];
  const rChars = tier === "narrow" ? 8 : 12;
  const rX = childX + 24;
  const rEnd = rX + (2 + rChars) * R_FONT * MONO_EM;
  const depthX = tier === "narrow" ? null : Math.round(rEnd + 18);
  const diagX = tier === "wide" && depthX !== null ? depthX + 60 : null;
  return { tier, seedX, childX, rX, rChars, depthX, diagX };
}

export interface CascadeGeometry {
  layout: CascadeLayout;
  height: number;
  seeds: { id: number; x: number; y: number; label: string }[];
  hops: { hop: ChainHop; x: number; y: number; sy: number; path: string }[];
}

/** Lay the fans out top to bottom, biggest first, so the eye starts at the payoff. */
export function cascadeGeometry(run: RunData, width: number): CascadeGeometry {
  const layout = cascadeLayout(width);
  const { seedX, childX } = layout;

  const byVia = new Map<number, ChainHop[]>();
  for (const hop of run.chain.hops) {
    const list = byVia.get(hop.viaKeyId) ?? [];
    list.push(hop);
    byVia.set(hop.viaKeyId, list);
  }

  const groups = [...byVia.entries()].sort(
    (a, b) => b[1].length - a[1].length || a[0] - b[0],
  );
  const truthOf = new Map(run.chain.hops.map((h) => [h.viaKeyId, h.truth]));

  // A blank row between fans. Without it, adjacent single-child groups put their
  // seed rings (r=19) one pitch apart and three separate recoveries read as one
  // smear.
  const GAP = 1;
  const rows =
    groups.reduce((n, [, hops]) => n + hops.length, 0) + GAP * Math.max(0, groups.length - 1);
  const height = PAD_TOP + Math.max(0, rows - 1) * STEP + PAD_BOTTOM;

  const seeds: CascadeGeometry["seeds"] = [];
  const out: CascadeGeometry["hops"] = [];
  let row = 0;

  for (const [viaId, hops] of groups) {
    const first = row;
    const last = row + hops.length - 1;
    const sy = PAD_TOP + ((first + last) / 2) * STEP;
    seeds.push({
      id: viaId,
      x: seedX,
      y: sy,
      label: truthOf.get(viaId) ?? "clean",
    });

    hops.forEach((hop, i) => {
      const y = PAD_TOP + (row + i) * STEP;
      // A flat S-curve: the horizontal run at each end keeps the label baseline
      // clear of the stroke, which a straight line would cut through.
      const mid = (seedX + childX) / 2;
      out.push({
        hop,
        x: childX,
        y,
        sy,
        path: `M ${seedX + 26} ${sy} C ${mid} ${sy}, ${mid} ${y}, ${childX - 26} ${y}`,
      });
    });
    row += hops.length + GAP;
  }

  return { layout, height, seeds, hops: out };
}

export function CascadeDiagram({
  run,
  active,
  onActive,
}: {
  run: RunData;
  active: number | null;
  onActive: (keyId: number | null) => void;
}) {
  const ref = useRef<SVGSVGElement>(null);

  // The box decides the composition. The SVG's CSS width is 100% of its box and
  // independent of the viewBox, so measuring it cannot feed back into itself.
  const [width, setWidth] = useState(SSR_WIDTH);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.round(entry.contentRect.width);
      if (w > 0) setWidth(w);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const geo = useMemo(() => cascadeGeometry(run, width), [run, width]);
  const { layout, height } = geo;

  /**
   * The diagram is RESOLVED until something actively decides to animate it.
   *
   * This is the same contract `Reveal` states: the server-rendered markup is the
   * finished picture, and the hidden start state is only applied once we know JS
   * is running *and* motion is allowed. Computing that during render instead --
   * as this component first did -- meant the server emitted `opacity: 0`, the
   * client's reduced-motion branch never got a re-render to correct it, and the
   * entire cascade stayed invisible for exactly the readers who had asked for
   * less motion. Reduced motion must mean arriving at the end state instantly,
   * never arriving at nothing.
   *
   *   "resolved" -> fully visible (server, no-JS, reduced motion, already in view)
   *   "armed"    -> hidden, waiting to enter the viewport
   *   "playing"  -> igniting, then settling into hover-speed transitions
   */
  const [phase, setPhase] = useState<"resolved" | "armed" | "playing">("resolved");
  const armed = phase === "armed";
  const inView = useInView(ref);

  useEffect(() => {
    if (phase !== "resolved" || prefersReducedMotion()) return;
    const el = ref.current;
    if (!el) return;
    // Arming something already on screen would blink it out and back in, so a
    // diagram the reader has already seen simply stays as it is.
    const box = el.getBoundingClientRect();
    if (box.top < window.innerHeight && box.bottom > 0) return;
    setPhase("armed");
  }, [phase]);

  useEffect(() => {
    if (phase === "armed" && inView) setPhase("playing");
  }, [phase, inView]);

  const lit = !armed;

  // The ignition staggers each hop by up to ~1.1s. Those delays must not survive
  // into the hover state, or pointing at a row leaves the other seven edges lit
  // for a second before they dim -- feedback slower than the reader's own
  // movement reads as no feedback at all. Once the sequence has played out, the
  // element drops its delay and switches to a hover-speed transition.
  const [settled, setSettled] = useState(true);
  useEffect(() => {
    if (phase !== "playing") return;
    setSettled(false);
    const ms = 460 + geo.hops.length * 105 + 640;
    const t = window.setTimeout(() => setSettled(true), ms);
    return () => window.clearTimeout(t);
  }, [phase, geo.hops.length]);

  const anim = (delay: number) => ({
    className: settled ? "cascade-anim settled" : "cascade-anim",
    delay: settled ? "0ms" : `${delay}ms`,
  });

  return (
    <>
      <svg
        ref={ref}
        viewBox={`0 0 ${width} ${height}`}
        height={height}
        preserveAspectRatio="xMinYMin meet"
        className="block w-full"
        role="img"
        aria-label={`Cascade: ${geo.seeds.length} keys cracked directly open ${geo.hops.length} more across shared-nonce edges`}
        onPointerLeave={() => onActive(null)}
      >
        <defs>
          {/* userSpaceOnUse, not the default objectBoundingBox: a fan with one
              child is a perfectly horizontal path, its bounding box has zero
              height, and SVG paints no gradient on a degenerate box -- which
              silently dropped three of the eight connectors. */}
          <linearGradient
            id="cascade-flow"
            gradientUnits="userSpaceOnUse"
            x1={layout.seedX}
            y1="0"
            x2={layout.childX}
            y2="0"
          >
            <stop offset="0%" stopColor="var(--color-field)" stopOpacity="0.12" />
            <stop offset="100%" stopColor="var(--color-field)" stopOpacity="0.9" />
          </linearGradient>
        </defs>

        {/* connectors, behind everything */}
        {geo.hops.map(({ hop, path }, i) => {
          const on = active === null || active === hop.keyId;
          return (
            <path
              key={`edge-${hop.keyId}`}
              d={path}
              fill="none"
              stroke="url(#cascade-flow)"
              strokeWidth={active === hop.keyId ? 2.4 : 1.3}
              className={anim(240 + i * 105).className}
              style={{
                opacity: lit ? (on ? 1 : 0.1) : 0,
                transitionDelay: anim(240 + i * 105).delay,
              }}
            />
          );
        })}

        {/* the keys that were cracked on their own merits */}
        {geo.seeds.map((seed) => (
          <g key={`seed-${seed.id}`}>
            <circle
              cx={seed.x}
              cy={seed.y}
              r={SEED_RING_R}
              fill="none"
              stroke="var(--color-field)"
              strokeWidth={1}
              className="cascade-anim"
              style={{ opacity: lit ? 0.55 : 0 }}
            />
            <circle
              cx={seed.x}
              cy={seed.y}
              r={13}
              fill={DIAGNOSIS_COLOR[seed.label as keyof typeof DIAGNOSIS_COLOR]}
              className="cascade-anim"
              style={{ opacity: lit ? 1 : 0 }}
            />
            <text
              x={seed.x}
              y={seed.y + 4}
              textAnchor="middle"
              className="reading"
              fontSize="11"
              fontWeight="700"
              fill="#07070b"
            >
              {seed.id}
            </text>
          </g>
        ))}

        {/* the keys the cascade reached */}
        {geo.hops.map(({ hop, x, y }, i) => {
          const on = active === null || active === hop.keyId;
          return (
            <g
              key={`node-${hop.keyId}`}
              className={anim(420 + i * 105).className}
              onPointerEnter={() => onActive(hop.keyId)}
              style={{
                opacity: lit ? (on ? 1 : 0.18) : 0,
                transitionDelay: anim(420 + i * 105).delay,
              }}
            >
              <circle
                cx={x}
                cy={y}
                r={active === hop.keyId ? NODE_R_ACTIVE : NODE_R}
                fill={DIAGNOSIS_COLOR[hop.truth]}
                fillOpacity={hop.selfDiagnosable ? 1 : 0.3}
                stroke={DIAGNOSIS_COLOR[hop.truth]}
                strokeWidth={hop.selfDiagnosable ? 0 : 1.2}
                className="cascade-anim"
              />
              <text
                x={x}
                y={y + 3.5}
                textAnchor="middle"
                className="reading"
                fontSize={META_FONT}
                fontWeight="700"
                fill={hop.selfDiagnosable ? "#07070b" : "var(--color-ink)"}
              >
                {hop.keyId}
              </text>
              {/* the shared nonce: the thing that made the hop possible */}
              <text
                x={layout.rX}
                y={y + 4}
                className="reading"
                fontSize={R_FONT}
                fill={active === hop.keyId ? "var(--color-field)" : "var(--color-ink-3)"}
              >
                r={hop.r.slice(0, layout.rChars)}
              </text>
              {layout.depthX !== null ? (
                <text
                  x={layout.depthX}
                  y={y + 3.5}
                  className="reading"
                  fontSize={META_FONT}
                  fill="var(--color-ink-3)"
                >
                  depth {hop.depth}
                </text>
              ) : null}
              {layout.diagX !== null ? (
                <text
                  x={layout.diagX}
                  y={y + 3.5}
                  className="reading"
                  fontSize={META_FONT}
                  fill={hop.selfDiagnosable ? "var(--color-field)" : "var(--color-weak_seed)"}
                >
                  {hop.selfDiagnosable ? "diagnosed from its own nonces" : "too few nonces to diagnose"}
                </text>
              ) : null}
            </g>
          );
        })}

        {/* Column captions, set from each column's left edge so they cannot
            collide however close the narrow composition pulls the columns. */}
        <text
          x={layout.seedX - SEED_RING_R}
          y={height - 12}
          className="reading"
          fontSize={META_FONT}
          fill="var(--color-ink-3)"
        >
          cracked directly
        </text>
        <text
          x={layout.childX - NODE_R}
          y={height - 12}
          className="reading"
          fontSize={META_FONT}
          fill="var(--color-ink-3)"
        >
          opened by the cascade
        </text>
      </svg>

      {/* Below the wide composition the per-row diagnosis column is gone; the
          fill already encodes it, and this says how to read the fill. */}
      {layout.tier !== "wide" ? (
        <p className="reading mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[0.65rem] text-ink-3">
          <span className="inline-flex items-center gap-1.5">
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <circle cx="5" cy="5" r="4.5" fill="var(--color-ink-2)" />
            </svg>
            diagnosed from its own nonces
          </span>
          <span className="inline-flex items-center gap-1.5">
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <circle
                cx="5"
                cy="5"
                r="4"
                fill="var(--color-ink-2)"
                fillOpacity="0.3"
                stroke="var(--color-ink-2)"
                strokeWidth="1.2"
              />
            </svg>
            too few nonces to diagnose
          </span>
        </p>
      ) : null}
    </>
  );
}
