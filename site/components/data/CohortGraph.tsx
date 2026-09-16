import { DIAGNOSIS_COLOR, type RunData } from "@/lib/types";

/**
 * Presentational cohort graph, in two authored compositions.
 *
 * Node positions for the WIDE composition are precomputed by the export script, so
 * this never runs a force simulation: the layout is identical on every load and
 * cannot re-settle under the reader.
 *
 * The COMPACT composition is not the wide one shrunk. Scaling a 1000-unit viewBox
 * into a 316px panel put the node numerals and the cohort captions at 5px --
 * present in the DOM, unreadable on the device -- and the numerals are the only
 * link between this figure and the attribution table below it. Widening the SVG
 * and letting the reader pan sideways fixed nothing, because a viewBox scales its
 * type along with its geometry, and it cost 196px of horizontal drag on a page
 * whose one navigation axis is vertical. So the narrow viewport gets its own
 * arrangement instead: one cohort per row, and a viewBox whose user unit is about
 * one device pixel at phone width, so 10 units of type renders as 10px of type.
 *
 * Every node is drawn twice -- a grey "population" circle, and a diagnosis-coloured
 * circle stacked on top of it. Same for edges. The scroll scrubber then animates
 * only the *opacity* of the upper layer, so it never re-renders React, never
 * touches layout, and the server-rendered markup is already the fully-resolved end
 * state. No-JS, no-WebGL and reduced-motion all land on that resolved state.
 *
 * Both compositions are rendered, one hidden by CSS at each breakpoint. That keeps
 * the choice in CSS rather than in a width measured after mount, which would mean
 * re-rendering React underneath the scrubber's own opacity writes. The scrubber
 * drives every matching copy, so the hidden one simply animates unseen.
 */

/** Node radius, in viewBox units, in both compositions. */
const R = 13;

/** Stable, orientation-independent key for an edge. */
export const edgeId = (a: number, b: number) => `${Math.min(a, b)}-${Math.max(a, b)}`;

/**
 * A flat, deterministic propagation order across every cohort: BFS depth first,
 * then cohort. The first wave lights all four cohorts at once and the deepest
 * cohort keeps going -- which reads as one diagnosis spreading through a
 * population rather than four separate demos played end to end.
 */
export function propagationOrder(run: RunData) {
  return run.propagation
    .flatMap((p) => p.steps.map((s) => ({ ...s, cohort: p.cohort, label: p.label })))
    .sort((a, b) => a.step - b.step || a.cohort - b.cohort);
}

type Anchor = "start" | "middle";

interface Caption {
  key: string;
  x: number;
  y: number;
  anchor: Anchor;
  /** Centred against a row of nodes, rather than sitting on a baseline above them. */
  centred?: boolean;
  text: string;
}

interface Plan {
  vw: number;
  vh: number;
  at: (id: number) => { x: number; y: number };
  captions: Caption[];
  /** Cohorts above, keys the screen could not link below. */
  divider: { y: number; x1: number; x2: number };
  fontSize: number;
  tracking: string;
}

const cohortCaption = (size: number, label: string | null | undefined) =>
  `${size} KEYS · ${(label ?? "").toUpperCase()}`;

const SINGLETON_CAPTION = "NO SHARED r — CRACKED ALONE, NOTHING TO PROPAGATE TO";

/** The wide composition: the export script's own coordinates, as logged. */
function widePlan(run: RunData): Plan {
  const VW = 1000;
  const VH = 470;
  const PAD = { x: 56, y: 48 };
  const ux = (v: number) => PAD.x + v * (VW - PAD.x * 2);
  const uy = (v: number) => PAD.y + v * (VH - PAD.y * 2);

  const { nodes, clusters, singletons, bandDividerY } = run.cohortGraph;
  const pos = new Map(nodes.map((n) => [n.id, { x: ux(n.x), y: uy(n.y) }]));

  // One caption per cohort, on a shared baseline so they align.
  const captions: Caption[] = clusters.map((c) => ({
    key: `c${c.cohort}`,
    x: ux(c.x),
    y: uy(bandDividerY) - 16,
    anchor: "middle",
    text: cohortCaption(c.size, c.label),
  }));

  if (singletons.length > 0) {
    captions.push({
      key: "singletons",
      x: ux(0.5),
      y: uy(0.86) + 34,
      anchor: "middle",
      text: SINGLETON_CAPTION,
    });
  }

  return {
    vw: VW,
    vh: VH,
    at: (id) => pos.get(id) ?? { x: 0, y: 0 },
    captions,
    divider: { y: uy(bandDividerY), x1: PAD.x * 0.5, x2: VW - PAD.x * 0.5 },
    fontSize: 10,
    tracking: "0.14em",
  };
}

/**
 * The compact composition: one cohort per row, largest first, each with its caption
 * set beside it at reading size. Cohorts of four or more are placed on a ring so
 * the shared-r chain closes into a figure instead of doubling edges back along a
 * row; pairs sit side by side, which is all a pair needs.
 *
 * The height is computed from what the run actually contains rather than fixed, so
 * a run with a different cohort census gets a taller or shorter sheet instead of a
 * crop.
 */
function compactPlan(run: RunData): Plan {
  const VW = 320;
  const LEFT = 16;
  const RIGHT = 12;
  const NODE_GAP = 14;
  const LABEL_GAP = 10;
  // A cracked key carries a double ring six units outside its own edge, so every
  // row and every caption is spaced against RING, not R. Spacing against the node
  // alone left four units between a ring and the row beneath it, and put the
  // singleton caption on top of the ring it was describing.
  const RING = R + 6;
  // Horizontal pitch along a row, for the same reason. Two cracked keys side by
  // side are two RINGs, not two nodes: spacing them on the node diameter left
  // their rings two units apart, which reads as one overlapping blob.
  const ROW_PITCH = RING * 2 + NODE_GAP;

  const { clusters, singletons } = run.cohortGraph;
  const pos = new Map<number, { x: number; y: number }>();
  const captions: Caption[] = [];
  let y = 12;

  const ordered = [...clusters].sort((a, b) => b.size - a.size || a.cohort - b.cohort);
  for (const c of ordered) {
    if (c.members.length >= 4) {
      // Sized from the CHORD between adjacent members, not the arc: on a six-point
      // ring the chord equals the radius, so spacing by arc length leaves a third
      // less room than it looks like it does. Solve it the other way round -- pick
      // the clearance a cracked member's double ring needs from the node beside it
      // (RING + R, plus eight units of air) and derive the radius that gives it.
      const ringR = Math.max(
        28,
        (RING + R + 8) / (2 * Math.sin(Math.PI / c.members.length)),
      );
      const cx = LEFT + ringR + RING;
      const cy = y + ringR + RING;
      c.members.forEach((id, i) => {
        const a = -Math.PI / 2 + (i * 2 * Math.PI) / c.members.length;
        pos.set(id, { x: cx + ringR * Math.cos(a), y: cy + ringR * Math.sin(a) });
      });
      captions.push({
        key: `c${c.cohort}`,
        x: cx + ringR + RING + LABEL_GAP,
        y: cy,
        anchor: "start",
        centred: true,
        text: cohortCaption(c.size, c.label),
      });
      y = cy + ringR + RING + 18;
    } else {
      const cy = y + RING;
      c.members.forEach((id, i) => pos.set(id, { x: LEFT + RING + i * ROW_PITCH, y: cy }));
      const right = LEFT + RING + (c.members.length - 1) * ROW_PITCH + RING;
      captions.push({
        key: `c${c.cohort}`,
        x: right + LABEL_GAP,
        y: cy,
        anchor: "start",
        centred: true,
        text: cohortCaption(c.size, c.label),
      });
      y = cy + RING + 14;
    }
  }

  const dividerY = y + 10;
  y = dividerY + 18;

  if (singletons.length > 0) {
    const cy = y + RING;
    singletons.forEach((id, i) => pos.set(id, { x: LEFT + RING + i * ROW_PITCH, y: cy }));
    y = cy + RING + 18;
    // Set on two lines: there is no room for the sentence across 320 units, and
    // shrinking it to fit would put it back at the size this composition exists
    // to escape.
    captions.push({ key: "s1", x: LEFT, y, anchor: "start", text: "NO SHARED r — CRACKED ALONE," });
    captions.push({ key: "s2", x: LEFT, y: y + 14, anchor: "start", text: "NOTHING TO PROPAGATE TO" });
    y += 14 + 10;
  }

  return {
    vw: VW,
    vh: Math.round(y),
    at: (id) => pos.get(id) ?? { x: 0, y: 0 },
    captions,
    divider: { y: dividerY, x1: LEFT - 6, x2: VW - RIGHT + 6 },
    fontSize: 10,
    tracking: "0.03em",
  };
}

export function CohortGraph({
  run,
  animated = false,
  layout = "wide",
  className = "",
}: {
  run: RunData;
  /** When true the reveal layers start hidden and the scrubber drives them. */
  animated?: boolean;
  /** Which authored composition to draw. */
  layout?: "wide" | "compact";
  className?: string;
}) {
  const { nodes, edges } = run.cohortGraph;
  const plan = layout === "compact" ? compactPlan(run) : widePlan(run);
  const carried = new Set(propagationOrder(run).map((s) => edgeId(s.from, s.to)));
  const start = animated ? 0 : 1;

  return (
    <svg
      viewBox={`0 0 ${plan.vw} ${plan.vh}`}
      className={className}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label={`Cohort graph: ${nodes.length} keys linked by shared r-values into ${run.propagation.length} cohorts. ${run.stats.nCracked} cracked keys propagate a diagnosis to ${run.stats.nAttributed - run.stats.nCracked} keys that were never cracked.`}
    >
      {/* --- chrome: the two bands and what they mean ---------------------- */}
      <g data-population="" opacity={start}>
        <line
          x1={plan.divider.x1}
          x2={plan.divider.x2}
          y1={plan.divider.y}
          y2={plan.divider.y}
          stroke="var(--color-rule-strong)"
          strokeWidth={1}
          strokeDasharray="2 6"
        />

        {plan.captions.map((c) => (
          <text
            key={c.key}
            x={c.x}
            y={c.y}
            textAnchor={c.anchor}
            dominantBaseline={c.centred ? "central" : undefined}
            className="reading"
            fontSize={plan.fontSize}
            letterSpacing={plan.tracking}
            fill="var(--color-ink-3)"
          >
            {c.text}
          </text>
        ))}
      </g>

      {/* --- edges: population link, then the carried-diagnosis overlay --- */}
      <g>
        {edges.map((e) => {
          const a = plan.at(e.source);
          const b = plan.at(e.target);
          const id = edgeId(e.source, e.target);
          return (
            <g key={id}>
              <line
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke="var(--color-rule-strong)"
                strokeWidth={1.25}
                data-population=""
                opacity={start}
              />
              {carried.has(id) ? (
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke="var(--color-field)"
                  strokeWidth={2}
                  data-edge={id}
                  opacity={start}
                />
              ) : null}
            </g>
          );
        })}
      </g>

      {/* --- nodes --- */}
      <g>
        {nodes.map((n) => {
          const p = plan.at(n.id);
          return (
            <g key={n.id}>
              {/* population layer: an unlabeled key, no diagnosis yet */}
              <circle
                cx={p.x}
                cy={p.y}
                r={R}
                fill="var(--color-clean)"
                stroke="var(--color-ground-raised)"
                strokeWidth={2}
                data-population=""
                opacity={start}
              />
              {/* diagnosis layer */}
              <circle
                cx={p.x}
                cy={p.y}
                r={R}
                fill={DIAGNOSIS_COLOR[n.label]}
                stroke="var(--color-ground-raised)"
                strokeWidth={2}
                data-node={n.id}
                opacity={start}
              />
              {/* Every key the pipeline actually cracked carries the double ring --
                  including the lattice singletons, which are cracked but belong to
                  no collision cohort. */}
              {n.source === "cracked" ? (
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={R + 6}
                  fill="none"
                  stroke="var(--color-field)"
                  strokeWidth={1.75}
                  data-ring={n.id}
                  opacity={start}
                />
              ) : null}
              <text
                x={p.x}
                y={p.y}
                textAnchor="middle"
                dominantBaseline="central"
                className="reading"
                fontSize={10}
                fontWeight={700}
                fill="#07070b"
                data-population=""
                opacity={start}
              >
                {n.id}
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}

export function GraphLegend() {
  const classes = ["truncated_msb", "modular_reduction", "short_period_prng", "weak_seed"] as const;
  return (
    <div className="reading mt-6 flex flex-wrap items-center gap-x-6 gap-y-3 text-xs">
      {classes.map((c) => (
        <span key={c} className="inline-flex items-center gap-2">
          <span
            aria-hidden="true"
            className="inline-block h-2.5 w-2.5"
            style={{ background: DIAGNOSIS_COLOR[c] }}
          />
          <span className="text-ink-2">{c}</span>
        </span>
      ))}
      <span className="inline-flex items-center gap-2">
        <span
          aria-hidden="true"
          className="inline-block h-3 w-3 rounded-full border-2 border-field"
        />
        <span className="text-ink-2">cracked (double ring)</span>
      </span>
    </div>
  );
}
