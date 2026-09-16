import { scaleBand, scaleLinear } from "d3-scale";
import { area, line, curveMonotoneX } from "d3-shape";
import type { KeyDetail } from "@/lib/types";

/**
 * Charts are rendered as static SVG on the server.
 *
 * D3 supplies the scale and path math at build time; no chart JavaScript ships to
 * the browser. That is deliberate on two counts: the data sections paint with the
 * first byte of HTML, and a histogram that is plain markup physically cannot
 * reflow or animate under a reader trying to count dead bits.
 */

const W = 640;
const H = 220;
const M = { top: 16, right: 12, bottom: 30, left: 40 };
const IW = W - M.left - M.right;
const IH = H - M.top - M.bottom;

function Axis({
  ticks,
  label,
}: {
  ticks: { y: number; text: string }[];
  label: string;
}) {
  return (
    <>
      {ticks.map((t) => (
        <g key={t.text}>
          <line
            x1={0}
            x2={IW}
            y1={t.y}
            y2={t.y}
            stroke="var(--color-rule)"
            strokeWidth={1}
            shapeRendering="crispEdges"
          />
          <text
            x={-8}
            y={t.y}
            textAnchor="end"
            dominantBaseline="middle"
            className="reading"
            fontSize={9}
            fill="var(--color-ink-3)"
          >
            {t.text}
          </text>
        </g>
      ))}
      <text
        transform={`translate(${-M.left + 10},${IH / 2}) rotate(-90)`}
        textAnchor="middle"
        className="reading"
        fontSize={9}
        fill="var(--color-ink-3)"
      >
        {label}
      </text>
    </>
  );
}

/**
 * MSB bit histogram: P(bit = 1) for the top 32 bits.
 *
 * Dead leading bits are the visible truncation signature, so they are drawn in the
 * accent rather than left to the reader to spot: a bar at exactly zero is the bug.
 */
export function MsbHistogram({ detail }: { detail: KeyDetail }) {
  const data = detail.msbBitMeans;
  const x = scaleBand<number>()
    .domain(data.map((_, i) => i))
    .range([0, IW])
    .padding(0.28);
  const y = scaleLinear().domain([0, 1]).range([IH, 0]);
  const bw = x.bandwidth();

  return (
    <figure className="min-w-0">
      <figcaption className="reading mb-3 text-[0.7rem] leading-relaxed text-ink-2">
        MSB bit histogram — P(bit = 1) across the top 32 bits.{" "}
        {detail.deadMsbBits > 0 ? (
          <span className="text-field">
            {detail.deadMsbBits} dead top bits: every reconstructed nonce is zero there.
          </span>
        ) : (
          <span className="text-ink-2">
            No dead top bits — this key&apos;s nonces are full-range.
          </span>
        )}
      </figcaption>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full"
        role="img"
        aria-label={`MSB bit histogram for key ${detail.keyId}. ${detail.deadMsbBits} of the top 32 bits are always zero.`}
      >
        <g transform={`translate(${M.left},${M.top})`}>
          <Axis
            label="P(bit = 1)"
            ticks={[0, 0.5, 1].map((v) => ({ y: y(v), text: v.toFixed(1) }))}
          />
          {/* Uniform reference: an unbiased generator sits on 0.5. */}
          <line
            x1={0}
            x2={IW}
            y1={y(0.5)}
            y2={y(0.5)}
            stroke="var(--color-clean)"
            strokeWidth={1}
            strokeDasharray="4 4"
          />
          {data.map((p, i) => {
            const dead = i < detail.deadMsbBits;
            const h = Math.max(IH - y(p), p === 0 ? 2 : 1);
            return (
              <rect
                key={i}
                x={x(i)}
                y={p === 0 ? IH - 2 : y(p)}
                width={bw}
                height={h}
                fill={dead ? "var(--color-field)" : "var(--color-clean)"}
                opacity={dead ? 1 : 0.75}
              />
            );
          })}
          {[0, 8, 16, 24, 31].map((i) => (
            <text
              key={i}
              x={(x(i) ?? 0) + bw / 2}
              y={IH + 18}
              textAnchor="middle"
              className="reading"
              fontSize={9}
              fill="var(--color-ink-3)"
            >
              {i}
            </text>
          ))}
          <text
            x={IW / 2}
            y={IH + 30}
            textAnchor="middle"
            className="reading"
            fontSize={9}
            fill="var(--color-ink-3)"
          >
            MSB position (0 = top bit)
          </text>
        </g>
      </svg>
    </figure>
  );
}

/** Bleichenbacher spectrum: bias magnitude at integer frequencies w = 1..64. */
export function SpectrumChart({ detail }: { detail: KeyDetail }) {
  const data = detail.spectrum;
  const peak = Math.max(...data);
  const x = scaleLinear()
    .domain([1, data.length])
    .range([0, IW]);
  const y = scaleLinear().domain([0, 1]).range([IH, 0]);

  const points: [number, number][] = data.map((v, i) => [i + 1, v]);
  const areaPath =
    area<[number, number]>()
      .x((d) => x(d[0]))
      .y0(IH)
      .y1((d) => y(d[1]))
      .curve(curveMonotoneX)(points) ?? "";
  const linePath =
    line<[number, number]>()
      .x((d) => x(d[0]))
      .y((d) => y(d[1]))
      .curve(curveMonotoneX)(points) ?? "";

  return (
    <figure className="min-w-0">
      <figcaption className="reading mb-3 text-[0.7rem] leading-relaxed text-ink-2">
        Bleichenbacher spectrum — bias magnitude at w = 1..64. Peak{" "}
        <span className="text-field">{peak.toFixed(3)}</span>
        {peak > 0.9
          ? " — a saturated peak is gross MSB bias."
          : " — a low, flat scan is a full-range generator."}
      </figcaption>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Bleichenbacher spectrum for key ${detail.keyId}, peak bias magnitude ${peak.toFixed(3)}.`}
      >
        <g transform={`translate(${M.left},${M.top})`}>
          <Axis
            label="bias magnitude"
            ticks={[0, 0.5, 1].map((v) => ({ y: y(v), text: v.toFixed(1) }))}
          />
          <path d={areaPath} fill="var(--color-field)" opacity={0.18} />
          <path d={linePath} fill="none" stroke="var(--color-field)" strokeWidth={1.75} />
          {[1, 16, 32, 48, 64].map((w) => (
            <text
              key={w}
              x={x(w)}
              y={IH + 18}
              textAnchor="middle"
              className="reading"
              fontSize={9}
              fill="var(--color-ink-3)"
            >
              {w}
            </text>
          ))}
          <text
            x={IW / 2}
            y={IH + 30}
            textAnchor="middle"
            className="reading"
            fontSize={9}
            fill="var(--color-ink-3)"
          >
            frequency w
          </text>
        </g>
      </svg>
    </figure>
  );
}
