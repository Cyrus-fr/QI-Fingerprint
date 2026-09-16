"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { HATCH_ID, HatchDefs } from "./Sheet";
import { prefersReducedMotion } from "@/lib/motion";
import { DIAGNOSIS_COLOR, type Lamina, type RunData } from "@/lib/types";
import { SeedNav } from "../SeedNav";

/**
 * The collar: where the hole starts, and the first thing anyone sees.
 *
 * There is no headline. The category ships a centred claim over a terminal
 * transcript; this ships the section itself, so the reader meets the evidence
 * before they meet a sentence about it.
 *
 * The corpus is laid out as cored rock: one lamina per key, in key order, its
 * width the signature count and its hatch the class the pipeline assigned. A
 * single run of seventy laminae is inherently tall and thin and renders as a
 * sliver, so the section is broken across runs the way a core tray actually
 * holds core -- which both fits the frame and is true to the object.
 *
 * Every mark is measured. The unmarked laminae are not filler: they are the keys
 * carrying too few signatures to say anything about, and drawing them as blank
 * host rock is the most honest thing on the page.
 *
 * The depth cursor is the only control. Wherever it rests, the readout gives that
 * lamina's key, count and class, the way a log viewer reads every track at one
 * depth at once.
 */

const RUNS = 2;
const LAM_H = 11;
const LAM_GAP = 3;
const RUN_W = 210;
const RUN_GAP = 34;
const MIN_W = 14;
const PAD_TOP = 20;

export function Collar({ run }: { run: RunData }) {
  const section = run.section;
  const [cursor, setCursor] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const geo = useMemo(() => {
    const perRun = Math.ceil(section.length / RUNS);
    const maxSigs = Math.max(...section.map((l) => l.nSignatures));
    const laid = section.map((lam, i) => {
      const runIndex = Math.floor(i / perRun);
      const row = i % perRun;
      return {
        lam,
        i,
        x: runIndex * (RUN_W + RUN_GAP),
        y: PAD_TOP + row * (LAM_H + LAM_GAP),
        w: MIN_W + (lam.nSignatures / maxSigs) * (RUN_W - MIN_W - 10),
      };
    });
    return {
      laid,
      perRun,
      maxSigs,
      W: RUNS * RUN_W + (RUNS - 1) * RUN_GAP,
      H: PAD_TOP + perRun * (LAM_H + LAM_GAP),
    };
  }, [section]);

  const active: Lamina | null = cursor === null ? null : section[cursor];

  // The tray cuts in bar by bar, on the per-bar delay the markup already carries.
  //
  // The markup ships at --in: 1, so no-JS and reduced motion get the finished tray
  // and never a blank collar waiting on something that may not run. This effect is
  // the only thing that ever sets it to 0, and only once JS has confirmed motion is
  // wanted: drop every lamina, force that state to land, then release them a frame
  // later so the transition has somewhere to travel from. Without it the .lamina
  // transition and its stagger were dead code describing a beat that never played.
  useEffect(() => {
    if (prefersReducedMotion()) return;
    const el = svgRef.current;
    if (!el) return;
    const bars = [...el.querySelectorAll<SVGElement>(".lamina")];
    if (bars.length === 0) return;
    // transition-property, not the shorthand: the shorthand would wipe the
    // per-bar transition-delay the markup carries, which is the stagger itself.
    // The reset has to be instant -- with the transition live, dropping to 0
    // merely started a DELAYED transition toward 0, so the bars sat at 1 through
    // their own delay and the release cancelled it before anything moved.
    for (const b of bars) {
      b.style.transitionProperty = "none";
      b.style.setProperty("--in", "0");
    }
    void el.getBoundingClientRect();
    const id = requestAnimationFrame(() => {
      for (const b of bars) {
        b.style.transitionProperty = "";
        b.style.setProperty("--in", "1");
      }
    });
    return () => cancelAnimationFrame(id);
  }, [section]);

  const onMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const el = svgRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * geo.W;
    const y = ((e.clientY - r.top) / r.height) * geo.H - PAD_TOP;
    const runIndex = x > RUN_W + RUN_GAP / 2 ? 1 : 0;
    const row = Math.floor(y / (LAM_H + LAM_GAP));
    const i = runIndex * geo.perRun + row;
    setCursor(
      i >= 0 && i < section.length && row >= 0 && row < geo.perRun ? i : null,
    );
  };

  return (
    <header className="relative flex min-h-[100svh] flex-col overflow-hidden lg:pl-32">
      <HatchDefs />

      <div className="relative z-2 flex items-baseline justify-between gap-6 border-b border-rule px-6 py-5 md:px-12">
        <span className="reading text-[0.78rem] text-ink">QI-Fingerprint</span>
        <SeedNav current={run.seed} />
      </div>

      <div className="relative z-2 flex flex-1 items-center px-6 py-10 md:px-12">
        <div className="grid w-full max-w-[1500px] items-center gap-x-16 gap-y-12 md:grid-cols-12">
          {/* ------------------------------------------------- the core tray */}
          <figure className="m-0 md:col-span-5">
            <svg
              ref={svgRef}
              viewBox={`0 0 ${geo.W} ${geo.H}`}
              // touch-action is suppressed only where a pointer can hover. At phone
              // width this figure is 400px of the first screen, and taking the touch
              // action there meant a drag across it scrolled nothing at all.
              className="h-auto w-full max-w-[34rem] touch-auto md:touch-none"
              role="img"
              aria-label={`Cored section: ${section.length} keys carrying ${run.stats.nSignatures} signatures. Bar width is signature count; hatch is the assigned class. ${run.stats.nCracked} recovered, ${run.stats.nAttributed} classified.`}
              onPointerMove={onMove}
              // A tap fires down and up with no move between them, so without this
              // the readout was unreachable by touch while the caption went on
              // instructing the reader to reach it.
              onPointerDown={onMove}
              // Only a hovering pointer clears on leave. Touch fires pointerleave the
              // instant the finger lifts, which set the reading and wiped it in the
              // same gesture; a tapped reading now stays up until the next tap.
              onPointerLeave={(e) => {
                if (e.pointerType !== "touch") setCursor(null);
              }}
            >
              {/* Each run is an index range. Without these the left run -- 35 keys that
          carry two to five signatures each -- reads as a broken graphic rather
          than as the honest shape of the corpus. */}
              {/* the scale the stubs are read against */}
              {Array.from({ length: RUNS }, (_, r) => {
                const x0 = r * (RUN_W + RUN_GAP);
                const wMin = MIN_W + (2 / geo.maxSigs) * (RUN_W - MIN_W - 10);
                return (
                  <g key={`scale-${r}`}>
                    <line
                      x1={x0 + wMin}
                      y1={PAD_TOP - 4}
                      x2={x0 + wMin}
                      y2={geo.H}
                      stroke="var(--color-rule-strong)"
                      strokeWidth="1"
                      strokeDasharray="2 4"
                    />
                    <text
                      x={x0 + wMin + 3}
                      y={PAD_TOP + 5}
                      className="reading"
                      fontSize="7"
                      fill="var(--color-ink-3)"
                    >
                      2
                    </text>
                    <text
                      x={x0 + RUN_W}
                      y={PAD_TOP - 7}
                      textAnchor="end"
                      className="reading"
                      fontSize="7.5"
                      fill="var(--color-ink-3)"
                    >
                      {geo.maxSigs} signatures
                    </text>
                  </g>
                );
              })}
              {Array.from({ length: RUNS }, (_, r) => (
                <text
                  key={`run-${r}`}
                  x={r * (RUN_W + RUN_GAP)}
                  y={10}
                  className="reading"
                  fontSize="9"
                  fill="var(--color-ink-3)"
                >
                  keys {r * geo.perRun}&ndash;
                  {Math.min(section.length - 1, (r + 1) * geo.perRun - 1)}
                </text>
              ))}
              {geo.laid.map(({ lam, i, x, y, w }) => {
                const on = cursor === i;
                return (
                  <g key={lam.keyId}>
                    <rect
                      className="lamina"
                      style={{
                        ["--in" as string]: "1",
                        transitionDelay: `${i * 9}ms`,
                      }}
                      x={x}
                      y={y}
                      width={w}
                      height={LAM_H}
                      fill={
                        lam.label
                          ? `url(#${HATCH_ID[lam.label]})`
                          : "var(--color-ground-raised)"
                      }
                      stroke={
                        lam.label
                          ? DIAGNOSIS_COLOR[lam.label]
                          : "var(--color-rule-strong)"
                      }
                      strokeWidth="1"
                    />
                    {/* recovered keys carry a field-ink tick, the way a logged
                        interval is flagged where a sample was actually taken */}
                    {lam.cracked ? (
                      <rect
                        // On the same clock as its own bar, a beat behind it: the
                        // flag goes in after the core is laid, not before. Without
                        // this the ticks hung in empty space while the tray drew.
                        className="lamina"
                        style={{
                          ["--in" as string]: "1",
                          transitionDelay: `${i * 9 + 200}ms`,
                        }}
                        x={x + w + 5}
                        y={y + 1}
                        width="4"
                        height={LAM_H - 2}
                        fill="var(--color-field)"
                      />
                    ) : null}
                    {on ? (
                      <rect
                        x={x - 5}
                        y={y - 1.5}
                        width={RUN_W + 10}
                        height={LAM_H + 3}
                        fill="none"
                        stroke="var(--color-field)"
                        strokeWidth="1"
                      />
                    ) : null}
                  </g>
                );
              })}
            </svg>

            <figcaption className="mt-5 flex flex-wrap items-baseline justify-between gap-x-8 gap-y-2 border-t border-rule pt-3">
              <span className="max-w-[38ch] text-[0.78rem] leading-snug text-ink-2">
                The left run is 35 keys carrying two to five signatures each
                &mdash; uncrackable alone, and the reason the unit of analysis
                is the population.
                <span className="reading mt-1 block text-[0.68rem] text-ink-3">
                  bar width = signatures, 2 to {geo.maxSigs}
                </span>
              </span>
              <span
                className="reading min-h-[1.2em] text-[0.72rem] text-ink-2"
                aria-live="polite"
              >
                {active ? (
                  <>
                    <span className="text-ink">key {active.keyId}</span>
                    <span className="text-ink-3"> · </span>
                    {active.nSignatures} signatures
                    <span className="text-ink-3"> · </span>
                    <span
                      style={{
                        color: active.label
                          ? DIAGNOSIS_COLOR[active.label]
                          : undefined,
                      }}
                    >
                      {active.label ?? "unattributed"}
                    </span>
                    {active.cracked ? (
                      <span className="text-field"> · recovered</span>
                    ) : null}
                  </>
                ) : (
                  <span className="text-ink-3">
                    <span className="md:hidden">tap a section to read a key</span>
                    <span className="hidden md:inline">
                      point at the section to read a key
                    </span>
                  </span>
                )}
              </span>
            </figcaption>
          </figure>

          {/* ------------------------------------------------ the title block */}
          <div className="md:col-span-6 md:col-start-7">
            <p className="max-w-[56ch] text-[1rem] leading-[1.72] text-ink-2">
              Four stages over an unlabeled corpus of ECDSA signatures,
              answering which nonce-generation bug is leaking private keys and
              which other keys share it. Every recovery is gated on{" "}
              <span className="reading text-ink">d&middot;G == Q</span>, so a
              listed crack is a proof rather than a guess.
            </p>

            {/* The survey title block. A drawing carries its identity in a ruled
                block of named fields, not in a row of big numbers over small
                labels -- that arrangement is the hero-metric template this
                world exists to refuse, and the tray already states the corpus
                totals in its own caption. */}
            <dl className="mt-10 max-w-xl border-t border-rule">
              {(
                [
                  ["finding", "one recovered key diagnoses the population"],
                  ["sheet", "QI-Fingerprint — cored section"],
                  [
                    "subject",
                    `unlabeled ECDSA corpus, seed ${run.seed}, ${run.curve}`,
                  ],
                  ["scanned", "1,026 blocks · 719,121 signatures"],
                  ["recovered", "1 reused-nonce key, block 252,474"],
                  ["gate", "d·G == Q on every recovery"],
                ] as const
              ).map(([field, value]) => (
                <div
                  key={field}
                  className="flex flex-wrap items-baseline gap-x-6 gap-y-1 border-b border-rule py-2.5"
                >
                  <dt className="reading w-24 shrink-0 text-[0.7rem] text-ink-3">
                    {field}
                  </dt>
                  <dd
                    className={
                      field === "finding"
                        ? "min-w-0 flex-1 text-[1.05rem] leading-snug font-700 text-ink"
                        : "reading min-w-0 flex-1 text-[0.8rem] text-ink"
                    }
                  >
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </div>

      <div className="relative z-2 flex flex-wrap items-baseline justify-between gap-x-10 gap-y-2 border-t border-rule px-6 py-5 md:px-12">
        <a
          href="#log"
          className="reading text-[0.72rem] text-ink-2 hover:text-ink"
        >
          descend the log
        </a>
        <span className="reading hidden text-[0.72rem] text-ink-3 lg:inline">
          classification measured on synthetic corpora &middot; recovery
          validated on mainnet
        </span>
        <span className="reading text-[0.72rem] text-ink-3">
          seed {run.seed} &middot; {run.curve}
        </span>
      </div>
    </header>
  );
}
