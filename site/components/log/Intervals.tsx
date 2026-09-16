import { CommandText, Interval, Lithology, Repro } from "./Sheet";
import { CopyButton } from "../Copyable";
import {
  EVIDENCE,
  LIMITATIONS,
  PIPELINE,
  PRIOR_ART,
  PRIOR_ART_INTRO,
  PROBLEM,
  RUN_IT,
  type TableSpec,
} from "@/content/site-content";
import type { DiagnosisLabel } from "@/lib/types";

/** Class names appear in running copy; the hatch travels with them. */
const CLASSES: DiagnosisLabel[] = [
  "truncated_msb",
  "modular_reduction",
  "short_period_prng",
  "weak_seed",
  "clean",
];

function findClass(text: string): DiagnosisLabel | null {
  return CLASSES.find((c) => text.includes(c)) ?? null;
}

/** A results table, ruled the way a log sheet rules its readings. */
function Readings({ spec }: { spec: TableSpec }) {
  return (
    <div className="mt-6">
      <table className="stack-table w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-stock-rule">
            {spec.columns.map((c) => (
              <th
                key={c}
                scope="col"
                className="reading py-2 pr-6 text-[0.68rem] font-500 text-stock-ink/55"
              >
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {spec.rows.map((row) => {
            const lith = findClass(row.cells[0]);
            return (
              <tr
                key={row.cells[0]}
                className="logged-row border-b border-stock-rule/60 last:border-0"
              >
                {row.cells.map((cell, i) => (
                  <td
                    key={i}
                    data-label={spec.columns[i]}
                    className={`reading py-2.5 pr-6 text-[0.82rem] ${
                      i === 0 ? "text-stock-ink" : "text-stock-ink/70"
                    } ${row.emphasis && i > 0 ? "text-field-deep" : ""}`}
                  >
                    {i === 0 && lith ? (
                      <span className="inline-flex items-center gap-2">
                        <Lithology label={lith} size={11} />
                        {cell}
                      </span>
                    ) : (
                      cell
                    )}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function TheSeam() {
  return (
    <Interval
      id="problem"
      depth="the seam"
      title="The randomness was the weak part, not the key"
      standfirst={PROBLEM.statement}
    >
      <div className="grid gap-12 md:grid-cols-12">
        <div className="md:col-span-7">
          {PROBLEM.body.map((p, i) => (
            <p
              key={p.slice(0, 40)}
              data-reading={String(i * 70)}
              className="reading-settle mb-6 max-w-[68ch] text-[1.05rem] leading-[1.75] text-ink/90"
            >
              {p}
            </p>
          ))}
        </div>

        {/* Why the unit of analysis has to be the population. Three readings, not
            a stat card: the numbers are the argument. */}
        <aside
          data-reading="180"
          className="reading-settle sheet on-stock ruled md:col-span-4 md:col-start-9"
        >
          {/* Ruled stock sets the pitch: every line box is leading-9 and every gap
              a whole number of them, so every rule falls on a boundary the type
              actually has and none of them crosses a glyph. See `.ruled`. */}
          <div className="p-9">
            <h3 className="mb-9 text-[0.95rem] leading-9 font-600 text-stock-ink">
              Why per-key recovery does not scale
            </h3>
            <dl className="space-y-9">
              {(
                [
                  ["50–100", "signatures a classical HNP recovery wants from one key"],
                  ["2–5", "signatures a typical key in a real corpus actually carries"],
                  ["1", "cracked member needed to diagnose a whole collision-linked cohort"],
                ] as const
              ).map(([value, label]) => (
                <div key={value} className="flex gap-5">
                  {/* The mono figure sits 3px lower in its box than the label
                      beside it; lifted so the two share a baseline. */}
                  <dt className="reading relative -top-[0.1875rem] w-20 shrink-0 text-xl leading-9 font-700 text-field-deep">
                    {value}
                  </dt>
                  <dd className="text-[0.86rem] leading-9 text-stock-ink/75">{label}</dd>
                </div>
              ))}
            </dl>
          </div>
        </aside>
      </div>
    </Interval>
  );
}

export function TheMethod() {
  return (
    <Interval
      id="pipeline"
      depth="method"
      title="Four stages, three lanes"
      standfirst={PIPELINE.statement}
    >
      {/* The stages are a sequence, so they are logged as one, each carrying the
          operation it performs rather than sitting in a card. */}
      <ol className="border-t border-rule">
        {PIPELINE.stages.map((stage, i) => (
          <li
            key={stage.no}
            data-reading={String(i * 80)}
            className="reading-settle logged-row grid gap-x-10 gap-y-3 border-b border-rule px-2 py-7 md:grid-cols-12"
          >
            <h3 className="text-[1.25rem] leading-tight font-600 tracking-[-0.02em] md:col-span-3">
              {stage.name}
            </h3>
            <p className="reading text-[0.78rem] leading-relaxed text-field md:col-span-4">
              {stage.line}
            </p>
            <p className="max-w-[62ch] text-[0.92rem] leading-[1.7] text-ink-2 md:col-span-5">
              {stage.detail}
            </p>
          </li>
        ))}
      </ol>

      <div className="mt-12 grid gap-10 md:grid-cols-3">
        {PIPELINE.lanes.map((lane, i) => (
          <div key={lane.name} data-reading={String(i * 80)} className="reading-settle">
            <h3 className="text-[1rem] font-600 text-ink">{lane.name}</h3>
            <p className="reading mt-1.5 text-[0.76rem] text-ink-3">{lane.method}</p>
            <p className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[0.78rem] text-ink-2">
              {lane.classes.split(", ").map((c) => {
                const lith = findClass(c);
                return (
                  <span key={c} className="inline-flex items-center gap-1.5">
                    {lith ? <Lithology label={lith} size={11} /> : null}
                    <span className="reading">{c}</span>
                  </span>
                );
              })}
            </p>
            <p className="mt-4 max-w-[52ch] text-[0.9rem] leading-[1.7] text-ink-2">
              {lane.detail}
            </p>
          </div>
        ))}
      </div>

      <p
        data-reading="240"
        className="reading-settle mt-12 max-w-[72ch] border-t border-clean pt-5 text-[0.92rem] leading-[1.7] text-ink-2"
      >
        {PIPELINE.blindSpot}
      </p>
    </Interval>
  );
}

export function Assays() {
  return (
    <Interval
      id="evidence"
      depth="assays"
      title="What the audits actually found"
      standfirst={`${EVIDENCE.length} adversarial self-audits run against this pipeline to find where it works and where it does not. Negative results are logged as negative results, and every assay carries the command that reproduces it.`}
    >
      {/* Assays are results, so they are logged on stock, in a ruled run. A grid
          of equal cards would say every finding weighs the same; a ruled run says
          they were taken in order and each stands on its own reading. */}
      <div className="sheet on-stock">
        {EVIDENCE.map((card, i) => (
          <article
            key={card.index}
            data-reading={String(i * 60)}
            className="reading-settle grid gap-x-12 gap-y-6 border-b border-stock-rule px-7 py-10 last:border-0 md:grid-cols-12 md:px-10"
          >
            <div className="md:col-span-3">
              <div className="reading text-[2.1rem] leading-none font-700 text-field-deep">
                {card.headline.value}
              </div>
              <div className="mt-2.5 max-w-[26ch] text-[0.8rem] leading-snug text-stock-ink/65">
                {card.headline.label}
              </div>
            </div>

            <div className="min-w-0 md:col-span-9">
              <h3 className="max-w-[52ch] text-[1.15rem] leading-tight font-600 tracking-[-0.015em] text-stock-ink text-balance">
                {card.title}
              </h3>
              {card.body.map((p) => (
                <p
                  key={p.slice(0, 40)}
                  className="mt-4 max-w-[74ch] text-[0.92rem] leading-[1.72] text-stock-ink/80"
                >
                  {p}
                </p>
              ))}
              {card.table ? <Readings spec={card.table} /> : null}

              <div className="group mt-7 flex items-start gap-4 border-t border-stock-rule pt-4">
                <pre className="reading cmd min-w-0 flex-1 text-[0.78rem] leading-relaxed text-field-deep select-all">
                  <code>
                    <CommandText command={card.command} />
                  </code>
                </pre>
                <CopyButton value={card.command} onStock />
              </div>
            </div>
          </article>
        ))}
      </div>
    </Interval>
  );
}

export function LostCore() {
  return (
    <Interval
      id="limitations"
      depth="lost core"
      title="What did not come up"
      standfirst="The intervals this system cannot recover, logged as lost core. A survey that hides its gaps is worth less than one that marks them."
    >
      <ul className="border-t border-rule">
        {LIMITATIONS.map((limit, i) => (
          <li
            key={limit.index}
            data-reading={String(i * 55)}
            className="reading-settle logged-row grid gap-x-12 gap-y-3 border-b border-rule px-2 py-7 md:grid-cols-12"
          >
            <h3
              className={`text-[1rem] leading-snug font-600 md:col-span-4 ${
                limit.primary ? "text-ink" : "text-ink"
              }`}
            >
              {limit.title}
            </h3>
            <p className="max-w-[74ch] text-[0.92rem] leading-[1.72] text-ink-2 md:col-span-8">
              {limit.body}
              {limit.primary ? (
                <span className="mt-3 block border-t border-rule-strong pt-3 text-ink">
                  This is the limit that qualifies every accuracy figure above. The pipeline
                  solves a corpus its own generator produced.
                </span>
              ) : null}
            </p>
          </li>
        ))}
      </ul>
    </Interval>
  );
}

export function PriorSurveys() {
  return (
    <Interval
      id="prior-art"
      depth="prior surveys"
      title="Who cored this ground before"
      standfirst={PRIOR_ART_INTRO}
    >
      <ul className="border-t border-rule">
        {PRIOR_ART.map((entry, i) => (
          <li
            key={entry.name}
            data-reading={String(i * 45)}
            className="reading-settle logged-row grid gap-x-12 gap-y-3 border-b border-rule px-2 py-7 md:grid-cols-12"
          >
            <div className="md:col-span-4">
              <h3 className="text-[1rem] leading-snug font-600 text-ink">{entry.name}</h3>
              <div className="reading mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[0.74rem] text-ink-3">
                <span>{entry.year}</span>
                {(entry.links ?? []).map((link) => (
                  <a
                    key={link.href}
                    href={link.href}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-field underline decoration-field/40 hover:decoration-field"
                  >
                    {link.label}
                  </a>
                ))}
              </div>
              {entry.nearest ? (
                <p className="reading mt-3 text-[0.7rem] text-field">closest to this work</p>
              ) : null}
            </div>
            <p className="max-w-[74ch] text-[0.92rem] leading-[1.72] text-ink-2 md:col-span-8">
              {entry.body}
            </p>
          </li>
        ))}
      </ul>
    </Interval>
  );
}

/** The sheet's own title block: who logged it, with what, and how to re-run it. */
export function TitleBlock({ seed, curve }: { seed: number; curve: string }) {
  return (
    <footer className="border-t border-rule px-6 py-16 md:px-12 lg:pl-40">
      <div className="mx-auto grid max-w-[1500px] gap-x-12 gap-y-10 md:grid-cols-12">
        <div className="md:col-span-5">
          <h2 className="text-[1rem] font-600 text-ink">Run it yourself</h2>
          <p className="mt-2 max-w-[52ch] text-[0.86rem] leading-relaxed text-ink-3">
            {RUN_IT.intro}
          </p>
          <ul className="mt-6 space-y-4">
            {RUN_IT.commands.map((c) => (
              <li key={c.cmd} className="group">
                <div className="flex items-start gap-3">
                  <code className="reading cmd min-w-0 flex-1 text-[0.76rem] leading-relaxed text-field select-all">
                    <CommandText command={c.cmd} />
                  </code>
                  <CopyButton value={c.cmd} />
                </div>
                {c.note ? (
                  <span className="mt-1 block text-[0.72rem] text-ink-3">{c.note}</span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>

        <div className="md:col-span-4">
          <h2 className="text-[1rem] font-600 text-ink">Where these figures came from</h2>
          <p className="mt-2 max-w-[46ch] text-[0.86rem] leading-relaxed text-ink-3">
            {RUN_IT.siteData.intro}
          </p>
          <code className="reading cmd mt-5 block text-[0.76rem] text-field select-all">
            <CommandText command={RUN_IT.siteData.cmd} />
          </code>
          <p className="mt-5 max-w-[46ch] text-[0.78rem] leading-relaxed text-ink-3">
            Every reading on this sheet was produced by that command, from seed {seed} on{" "}
            {curve}. Nothing here is illustrative.
          </p>
        </div>

        <div className="md:col-span-3">
          <div className="text-[1.15rem] font-700 tracking-[-0.02em] text-ink">QI-Fingerprint</div>
          <p className="mt-3 max-w-[34ch] text-[0.8rem] leading-relaxed text-ink-2">
            Labels synthetic, recovery real. Validated against a reused-nonce key from block
            252,474.
          </p>
          <p className="mt-4 max-w-[34ch] text-[0.78rem] leading-relaxed text-ink-3">
            A key recovered from real chain data is never printed, logged or written to
            disk, and no code path here can construct or broadcast a transaction. The
            scalars shown in the recovered-core interval belong to a corpus this project
            generated, so they are its own to show.
          </p>
        </div>
      </div>
    </footer>
  );
}

/**
 * The assay: the one moment the descent gives the whole viewport.
 *
 * Every other interval is a run of readings. This one stops, because it is the
 * only place on the sheet where the pipeline touched real chain data and a real
 * key fell out. The beat costs nothing in decoration -- what takes the frame is
 * the block height, the txid, the address and the gate, at the scale their
 * importance actually warrants.
 *
 * It is also the page's single use of the assay colour. Once, here, on the one
 * real recovery.
 */
export function Assay() {
  return (
    <section
      id="assay"
      aria-labelledby="assay-h"
      data-interval="assay"
      className="relative flex min-h-[100svh] flex-col justify-center border-t border-rule px-6 py-24 md:px-12 lg:pl-40"
    >
      <div className="mx-auto w-full max-w-[1500px]">
        <div className="assay-mark mb-10 h-px w-full bg-assay" aria-hidden="true" />

        <div className="grid gap-x-16 gap-y-10 md:grid-cols-12">
          <div className="md:col-span-5">
            <h2
              id="assay-h"
              data-reading="0"
              className="reading-settle text-[clamp(2rem,4.2vw,3.6rem)] leading-[1.02] font-700 tracking-[-0.04em] text-balance text-ink"
            >
              One real key, found by scanning
            </h2>
            <p
              data-reading="90"
              className="reading-settle mt-7 max-w-[52ch] text-[1rem] leading-[1.72] text-ink-2"
            >
              Everything above is measured on a corpus this project generated, where the
              labels are known and accuracy can be scored. This is the one reading taken
              from the chain itself. It was discovered by scanning 1,026 blocks, not looked
              up, and it satisfies the same gate every other recovery on this sheet does.
            </p>
          </div>

          <dl
            data-reading="180"
            className="reading-settle border-t border-rule md:col-span-7"
          >
            {(
              [
                ["block", "252,474", "2013-08-16, five days after the Android SecureRandom advisory"],
                ["scanned", "1,026 blocks · 719,121 signatures", "to find exactly one same-key r-collision"],
                ["address", "19qnLpn9it7csR9sEay1XrFyfAmUNoXYk4", "derived from the recovered public point"],
                ["gate", "d·G == Q", "satisfied; the scalar itself is never printed, logged or written to disk"],
              ] as const
            ).map(([field, value, note]) => (
              <div key={field} className="border-b border-rule py-5">
                <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1">
                  <dt className="reading w-24 shrink-0 text-[0.7rem] text-ink-3">{field}</dt>
                  <dd className="reading min-w-0 flex-1 text-[1.05rem] break-all text-ink">
                    {value}
                  </dd>
                </div>
                <p className="mt-2 pl-0 text-[0.82rem] leading-snug text-ink-3 md:pl-[7.5rem]">
                  {note}
                </p>
              </div>
            ))}
          </dl>
        </div>

        <p
          data-reading="260"
          className="reading-settle mt-10 max-w-[74ch] text-[0.88rem] leading-relaxed text-ink-3"
        >
          Pinned offline as a regression fixture and recovered on every test run, so the
          claim is checked rather than remembered. The six scalars shown in the
          recovered-core interval are a different matter: those keys belong to a corpus
          this project generated, and are its own to show.
        </p>
      </div>
    </section>
  );
}
