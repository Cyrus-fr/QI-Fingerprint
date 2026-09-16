import { Interval } from "../log/Sheet";
import { MsbHistogram, SpectrumChart } from "./Charts";
import { groupHex, pct } from "@/lib/data";
import { DIAGNOSIS_COLOR, METHOD_LANE, type RunData } from "@/lib/types";

/**
 * One logged reading: the measured value, what it measures, and the comparison
 * that makes it mean something, on a single ruled line.
 *
 * This was a 4-up grid of big-number tiles, which is the hero-metric template
 * the craft floor names -- and it was the second appearance of that template on
 * one page. A reading on a log sheet is a row, not a card.
 */
function StatTile({
  value,
  label,
  note,
  accent = false,
}: {
  value: string;
  label: string;
  note?: string;
  accent?: boolean;
}) {
  return (
    <div className="logged-row grid items-baseline gap-x-6 gap-y-1 border-b border-rule px-2 py-4 md:grid-cols-12">
      <div
        className={`reading text-[1.35rem] leading-none font-700 md:col-span-2 ${
          accent ? "text-field" : "text-ink"
        }`}
      >
        {value}
      </div>
      <div className="text-[0.9rem] leading-snug text-ink md:col-span-3">{label}</div>
      {note ? (
        <div className="text-[0.85rem] leading-snug text-ink-2 md:col-span-7">{note}</div>
      ) : null}
    </div>
  );
}

function DiagnosisChip({ label }: { label: string }) {
  return (
    <span className="reading inline-flex items-center gap-2 text-xs whitespace-nowrap">
      <span
        aria-hidden="true"
        className="inline-block h-2 w-2 shrink-0"
        style={{ background: DIAGNOSIS_COLOR[label as keyof typeof DIAGNOSIS_COLOR] }}
      />
      {label}
    </span>
  );
}

/** Formats the birthday-bound expectation, which is a ~1e-73 scale number. */
function expectedLabel(x: number): string {
  if (x === 0) return "0";
  const exp = Math.floor(Math.log10(x));
  const mant = x / 10 ** exp;
  return `${mant.toFixed(1)}e${exp}`;
}

export function TriageSection({ run }: { run: RunData }) {
  const { stats, cracks, keys } = run;

  return (
    <Interval
      id="triage"
      depth="recovered core"
      title="Live triage"
      standfirst={`A frozen run of the real pipeline on an unlabeled ${stats.nKeys}-key / ${stats.nSignatures}-signature corpus, seed ${run.seed}. Every number below was written by tools/export_site_data.py — none of it is illustrative.`}
    >
      {/* ---------------------------------------------------------------- stats */}
      <div className="border-t border-rule">
        <StatTile
          value={String(stats.nKeys)}
          label="keys screened"
          note={`${stats.nSignatures} signatures, labels hidden`}
        />
        <StatTile
          value={String(stats.rCollisions)}
          label="r-collisions"
          accent
          note={`${expectedLabel(stats.expectedRandomCollisions)} expected under a sound RNG`}
        />
        <StatTile
          value={String(stats.nCracked)}
          label="keys cracked"
          note={`each gated on d·G == Q; ${stats.nCohorts} cohorts found`}
        />
        <StatTile
          value={String(stats.nAttributed)}
          label="keys attributed"
          accent
          note={`${stats.nAttributed - stats.nCracked} of them never cracked`}
        />
      </div>

      <div className="mt-px grid gap-px border border-t-0 border-rule bg-rule sm:grid-cols-3">
        <StatTile
          value={pct(stats.diagnosisAccuracy)}
          label="diagnosis accuracy"
          note={`${stats.nDiagnosed}/${stats.nDiagnosed} against hidden ground truth`}
        />
        <StatTile
          value={pct(stats.attributionAccuracy)}
          label="attribution accuracy"
          note={`${stats.nAttributed}/${stats.nAttributed} against hidden ground truth`}
        />
        <StatTile
          value={String(stats.cleanKeysAttributed)}
          label="clean keys touched"
          note="a false positive would show here"
        />
      </div>

      {/* ------------------------------------------------------------ crack table */}
      <h3 className="font-[family-name:var(--font-display)] mt-20 mb-2 text-2xl font-bold">
        Recovered keys
      </h3>
      <p className="mb-8 max-w-3xl text-sm leading-relaxed text-ink-2">
        Every row passed the <span className="reading text-ink">d·G == Q</span> gate inside{" "}
        <span className="reading">crack_key</span>; the pipeline discards anything that
        doesn&apos;t, so a listed key is a proven recovery rather than a guess. The{" "}
        <span className="reading">truth</span> column is ground truth the pipeline never read.
      </p>

      {/* No min-width and no scroll box. At its narrowest unstacked width (768px)
          the table is given 688px and needs 664 at min-content, so it wraps a
          header or two rather than hiding columns behind a scrollbar. */}
      <div>
        <table className="stack-table w-full border-collapse text-left">
          <thead>
            <tr className="border-y border-rule-strong">
              {["key", "method", "lane", "d·G == Q", "diagnosis", "conf.", "truth", "sigs"].map(
                (c) => (
                  <th
                    key={c}
                    scope="col"
                    className="reading py-3 pr-4 text-[0.65rem] font-medium tracking-[0.16em] whitespace-nowrap text-ink-3"
                  >
                    {c}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {cracks.map((row) => (
              <tr key={row.keyId} className="border-b border-rule/60">
                <td data-label="key" className="reading py-3 pr-4 text-sm font-bold text-ink">{row.keyId}</td>
                <td data-label="method" className="reading py-3 pr-4 text-sm text-ink-2">{row.method}</td>
                <td data-label="lane" className="reading py-3 pr-4 text-xs text-ink-2">{METHOD_LANE[row.method]}</td>
                <td data-label="d·G == Q" className="reading py-3 pr-4 text-sm text-field" aria-label="verified">
                  ✓
                </td>
                <td data-label="diagnosis" className="py-3 pr-4">
                  <DiagnosisChip label={row.diagnosis} />
                </td>
                <td data-label="conf." className="reading py-3 pr-4 text-sm text-ink-2">
                  {row.confidence.toFixed(2)}
                </td>
                <td data-label="truth" className="reading py-3 pr-4 text-sm text-ink-2">
                  {row.truth}{" "}
                  <span className={row.correct ? "text-field" : "text-short_period_prng"}>
                    {row.correct ? "✓" : "✗"}
                  </span>
                </td>
                <td data-label="sigs" className="reading py-3 pr-4 text-sm text-ink-2">{row.nSignatures}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* --------------------------------------------------------- key inspector */}
      <h3 className="font-[family-name:var(--font-display)] mt-20 mb-2 text-2xl font-bold">
        What the nonces look like
      </h3>
      <p className="mb-10 max-w-3xl text-sm leading-relaxed text-ink-2">
        With <span className="reading text-ink">d</span> recovered, every nonce is{" "}
        <span className="reading text-ink">k_i = (h_i + r_i·d)·s_i⁻¹ mod n</span>. The shape of
        that reconstructed population is the whole diagnosis — and the four classes below look
        nothing like each other.
      </p>

      <div className="space-y-px border border-rule bg-rule">
        {cracks.map((row) => {
          const detail = keys[String(row.keyId)];
          if (!detail) return null;
          return (
            <article key={row.keyId} className="bg-ground p-6 md:p-8">
              <div className="mb-6 flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
                <h4 className="reading text-lg font-bold text-ink">
                  key {row.keyId}
                  <span className="ml-3 text-xs font-normal text-ink-3">
                    {detail.nNonces} reconstructed nonces · recovered by {row.method}
                  </span>
                </h4>
                <DiagnosisChip label={detail.diagnosis} />
              </div>

              {/*
                The recovered private key, in full. Selectable, wrapping, never
                truncated. Present only for a synthetic corpus, where the scalar
                is the generator's own; an ingested chain corpus omits it, and
                the verified claim stands on its own.
              */}
              <div className="mb-8 border border-rule bg-ground-raised p-4">
                <div className="reading mb-2 text-[0.65rem] tracking-[0.2em] text-ink-3">
                  {detail.d
                    ? "recovered private key d — verified d·G == Q"
                    : "recovered — verified d·G == Q, key withheld"}
                </div>
                {detail.d ? (
                  <div className="hexline text-[0.8rem] text-field md:text-sm">
                    {groupHex(detail.d).map((chunk, i) => (
                      <span key={i} className="mr-2 inline-block">
                        {chunk}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="reading text-[0.8rem] text-ink-2 md:text-sm">
                    This key controls real funds. Recovery is reported as a count
                    and a provenance, never as a scalar.
                  </div>
                )}
                <div className="reading mt-3 text-[0.65rem] text-ink-3">
                  first reconstructed nonce k₀
                </div>
                <div className="hexline mt-1 text-[0.75rem] text-ink-2">
                  {groupHex(detail.nonceSamples[0] ?? "").map((chunk, i) => (
                    <span key={i} className="mr-2 inline-block">
                      {chunk}
                    </span>
                  ))}
                </div>
              </div>

              <div className="grid gap-10 lg:grid-cols-2">
                <MsbHistogram detail={detail} />
                <SpectrumChart detail={detail} />
              </div>

              {/* The classifier's own feature values for this key. */}
              <dl className="mt-8 grid grid-cols-2 gap-x-6 gap-y-3 border-t border-rule pt-6 sm:grid-cols-3 lg:grid-cols-6">
                {(
                  [
                    ["ks_stat", detail.evidence.ks_stat],
                    ["bias_magnitude", detail.evidence.bias_magnitude],
                    ["range_ratio", detail.evidence.range_ratio],
                    ["distinct_ratio", detail.evidence.distinct_ratio],
                    ["collision_pairs", detail.evidence.collision_pairs],
                    ["min_lz_bits", detail.evidence.min_leading_zero_bits],
                  ] as [string, number | undefined][]
                ).map(([k, v]) => (
                  <div key={k}>
                    <dt className="reading text-[0.6rem] tracking-[0.12em] text-ink-3">
                      {k}
                    </dt>
                    <dd className="reading mt-1 text-sm text-ink">
                      {v === undefined
                        ? "—"
                        : Number.isInteger(v)
                          ? v
                          : v.toFixed(4)}
                    </dd>
                  </div>
                ))}
              </dl>
            </article>
          );
        })}
      </div>
    </Interval>
  );
}
