import type { ReactNode } from "react";
import { DIAGNOSIS_COLOR, type DiagnosisLabel } from "@/lib/types";

/**
 * The log's shared vocabulary: hatch, rule, interval, title block.
 *
 * A stratigraphic log encodes class in HATCH, not in colour, because the sheet
 * has to survive a photocopier and a reader who cannot separate green from
 * amber. Every lithology below therefore carries a pattern as well as a hue, and
 * the legend names both. Colour is the fast read; hatch is the true one.
 */

export const HATCH_ID: Record<DiagnosisLabel, string> = {
  truncated_msb: "h-truncated",
  modular_reduction: "h-modular",
  short_period_prng: "h-period",
  weak_seed: "h-seed",
  clean: "h-clean",
};

/** One <defs> block, rendered once per page, referenced by every figure. */
export function HatchDefs() {
  const stroke = 1;
  return (
    <svg aria-hidden="true" className="pointer-events-none absolute h-0 w-0">
      <defs>
        {/* truncated_msb: ruled hard right, like a truncated edge */}
        <pattern id="h-truncated" width="7" height="7" patternUnits="userSpaceOnUse">
          <path
            d="M0 7 L7 0"
            stroke={DIAGNOSIS_COLOR.truncated_msb}
            strokeWidth={stroke}
            fill="none"
          />
        </pattern>
        {/* modular_reduction: folded, so the hatch folds back on itself */}
        <pattern id="h-modular" width="7" height="7" patternUnits="userSpaceOnUse">
          <path
            d="M0 7 L7 0 M0 0 L7 7"
            stroke={DIAGNOSIS_COLOR.modular_reduction}
            strokeWidth={stroke}
            fill="none"
          />
        </pattern>
        {/* short_period_prng: a repeating pool, drawn as repeating dots */}
        <pattern id="h-period" width="6" height="6" patternUnits="userSpaceOnUse">
          <circle cx="1.6" cy="1.6" r="1.25" fill={DIAGNOSIS_COLOR.short_period_prng} />
        </pattern>
        {/* weak_seed: a short seam, dashed */}
        <pattern id="h-seed" width="8" height="6" patternUnits="userSpaceOnUse">
          <path
            d="M0 3 L4 3"
            stroke={DIAGNOSIS_COLOR.weak_seed}
            strokeWidth={1.4}
            fill="none"
          />
        </pattern>
        {/* clean: host rock, left unmarked */}
        <pattern id="h-clean" width="8" height="8" patternUnits="userSpaceOnUse">
          <rect width="8" height="8" fill="transparent" />
          <circle cx="4" cy="4" r="0.7" fill={DIAGNOSIS_COLOR.clean} />
        </pattern>
      </defs>
    </svg>
  );
}

/**
 * A lithology chip: hue and hatch together, at reading size. Used wherever a
 * class is named in running text or a table cell, so the hatch travels with the
 * label instead of living only in the legend.
 */
export function Lithology({
  label,
  size = 14,
}: {
  label: DiagnosisLabel;
  size?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 14 14"
      aria-hidden="true"
      className="inline-block shrink-0 align-[-0.15em]"
    >
      <rect
        width="14"
        height="14"
        fill={`url(#${HATCH_ID[label]})`}
        stroke={DIAGNOSIS_COLOR[label]}
        strokeWidth="1"
      />
    </svg>
  );
}

/**
 * An interval of the log.
 *
 * No kicker, no section number: the depth rail already says where you are, and a
 * label above a heading is a label the heading did not need. The heading is set
 * against the tray and the interval's content descends beneath it.
 */
export function Interval({
  id,
  title,
  standfirst,
  depth,
  children,
  className = "",
}: {
  id: string;
  title: string;
  /** The one sentence that says what this interval establishes. */
  standfirst?: string;
  /** What was logged here, shown on the rail. Real units where real units exist. */
  depth: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      id={id}
      aria-labelledby={`${id}-h`}
      data-interval={depth}
      className={`relative border-t border-rule px-6 py-20 md:px-12 md:py-28 lg:pl-40 ${className}`}
    >
      <div className="mx-auto max-w-[1500px]">
        <header className="mb-12 grid gap-x-12 gap-y-5 md:mb-16 md:grid-cols-12">
          <h2
            id={`${id}-h`}
            data-reading="0"
            className="reading-settle font-[family-name:var(--font-display)] text-[clamp(1.85rem,3.4vw,3rem)] leading-[1.02] font-700 tracking-[-0.035em] text-balance md:col-span-6"
          >
            {title}
          </h2>
          {standfirst ? (
            <p
              data-reading="90"
              className="reading-settle max-w-[62ch] text-[0.98rem] leading-[1.72] text-ink-2 md:col-span-5 md:col-start-8"
            >
              {standfirst}
            </p>
          ) : null}
        </header>
        {children}
      </div>
    </section>
  );
}

/**
 * A command's text, breakable only between its arguments.
 *
 * `.cmd` wraps rather than scrolls, and left to itself a wrap splits "--chain"
 * after its dashes, which reads as two arguments. Each argument is set as an
 * atomic inline box, so lines break at spaces; an argument longer than the whole
 * column still breaks inside itself rather than running off the sheet. The spaces
 * stay real text, so a selection copies the command unchanged.
 */
export function CommandText({ command }: { command: string }) {
  return command.split(/( +)/).map((part, i) =>
    part.trim() === "" ? (
      part
    ) : (
      // `indent-0`: text-indent inherits, and the hanging indent belongs to the
      // line, not to every argument on it.
      <span key={i} className="inline-block max-w-full indent-0">
        {part}
      </span>
    ),
  );
}

/**
 * A repro command, set as what it is: a line you run.
 *
 * Every claim on this page carries one, so it is a first-class element of the
 * sheet rather than a footnote. Selectable whole; never truncated.
 */
export function Repro({ command, note }: { command: string; note?: string }) {
  return (
    <div className="mt-7 border-t border-rule pt-4">
      <pre className="reading cmd text-[0.8rem] leading-relaxed text-field select-all">
        <code>
          <CommandText command={command} />
        </code>
      </pre>
      {note ? <p className="mt-2 text-xs leading-snug text-ink-3">{note}</p> : null}
    </div>
  );
}
