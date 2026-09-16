import { Interval } from "../log/Sheet";
import { CohortScrubber } from "./CohortScrubber";
import { DIAGNOSIS_COLOR, type RunData } from "@/lib/types";

/**
 * N°004 -- the centrepiece.
 *
 * The section is a server component; only the scrubber inside it is client-side.
 * The graph and the attribution table are both rendered here as resolved markup,
 * so the section is complete and readable before any JavaScript runs.
 */
export function CohortSection({ run }: { run: RunData }) {
  const propagated = run.attributions.filter((a) => a.source === "propagated");

  return (
    <Interval
      id="cohort"
      depth="correlation"
      title="One crack colours the cohort"
      standfirst="Cohort membership comes purely from shared r values — no ground truth, no metadata. Crack one member, fingerprint it, and the diagnosis carries to every key linked to it. The keys with no observable link stay grey, because guessing them would be the one thing this pipeline refuses to do."
    >
      <CohortScrubber run={run}>
        {/* Summary and table sit side by side only from `xl`. The table's cells are
            unbreakable class names, so it needs 542px however it is squeezed, and
            a 7/12 column is narrower than that until ~1180px -- which put a
            scrollbar across it from 768 to 1279. Below `xl` it takes the full
            width; below `md` it stacks. `min-w-0` on both items, because a grid
            item defaults to `min-width: auto` and will not shrink below content. */}
        <div className="mt-8 grid gap-10 md:mt-16 xl:grid-cols-12">
          <div className="min-w-0 max-w-2xl xl:col-span-5 xl:max-w-none">
            <h3 className="font-[family-name:var(--font-display)] mb-4 text-2xl font-bold">
              {run.stats.nCracked} cracked &rarr; {run.stats.nAttributed} attributed
            </h3>
            <p className="mb-6 text-sm leading-relaxed text-ink-2">
              {propagated.length} of these keys were never cracked. Their diagnosis is
              inherited from a cohort-mate that was, and it is correct for every one of them —
              scored against ground truth the pipeline never loaded.
            </p>
            <dl className="space-y-4 border-t border-rule pt-6">
              {Object.entries(run.attributedByClass).map(([label, count]) => (
                <div key={label} className="flex items-baseline justify-between gap-4">
                  <dt className="reading inline-flex items-center gap-2 text-sm">
                    <span
                      aria-hidden="true"
                      className="inline-block h-2 w-2"
                      style={{
                        background: DIAGNOSIS_COLOR[label as keyof typeof DIAGNOSIS_COLOR],
                      }}
                    />
                    <span className="text-ink-2">{label}</span>
                  </dt>
                  <dd className="reading text-lg font-bold text-ink">{count}</dd>
                </div>
              ))}
            </dl>
          </div>

          <div className="min-w-0 xl:col-span-7">
            <div>
              <table className="stack-table w-full border-collapse text-left">
                <caption className="reading mb-3 text-left text-[0.65rem] tracking-[0.16em] text-ink-3">
                  attribution — every key the pipeline labelled
                </caption>
                <thead>
                  <tr className="border-y border-rule-strong">
                    {["key", "diagnosis", "source", "conf.", "truth", "correct"].map((c, i) => (
                      <th
                        key={i}
                        scope="col"
                        className="reading py-3 pr-5 text-[0.65rem] font-medium tracking-[0.16em] text-ink-3"
                      >
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {run.attributions.map((a) => (
                    <tr
                      key={a.keyId}
                      data-attr-row=""
                      className="logged-row border-b border-rule/60"
                    >
                      <td data-label="key" className="reading py-2.5 pr-5 text-sm font-bold text-ink">{a.keyId}</td>
                      <td data-label="diagnosis" className="reading py-2.5 pr-5 text-xs">
                        <span className="inline-flex items-center gap-2">
                          <span
                            aria-hidden="true"
                            className="inline-block h-2 w-2 shrink-0"
                            style={{ background: DIAGNOSIS_COLOR[a.diagnosis] }}
                          />
                          <span className="text-ink-2">{a.diagnosis}</span>
                        </span>
                      </td>
                      <td
                        data-label="source"
                        className={`reading py-2.5 pr-5 text-xs ${
                          a.source === "cracked" ? "text-field" : "text-ink-3"
                        }`}
                      >
                        {a.source}
                      </td>
                      <td data-label="conf." className="reading py-2.5 pr-5 text-sm text-ink-2">
                        {a.confidence.toFixed(2)}
                      </td>
                      <td data-label="truth" className="reading py-2.5 pr-5 text-xs text-ink-2">{a.truth}</td>
                      <td data-label="correct" className="reading py-2.5 pr-5 text-sm">
                        <span className={a.correct ? "text-field" : "text-short_period_prng"}>
                          {a.correct ? "✓" : "✗"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </CohortScrubber>
    </Interval>
  );
}
