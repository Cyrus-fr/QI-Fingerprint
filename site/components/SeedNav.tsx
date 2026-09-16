import Link from "next/link";
import { manifest, DEFAULT_SEED } from "@/lib/data";

/**
 * Which hole this sheet logs.
 *
 * Each exported run is its own prerendered route, so switching seeds is a plain
 * document navigation to another fully static page: no client refetch, no
 * spinner, and the data intervals stay server components. Different seeds are
 * genuinely different corpora, which is the point -- the result holds across them.
 */
export function SeedNav({ current }: { current: number }) {
  return (
    <nav aria-label="Corpus seed" className="reading flex items-baseline gap-1 text-[0.72rem]">
      <span className="mr-2 text-ink-3">seed</span>
      {manifest.runs.map((r, i) => {
        const active = r.seed === current;
        const href = r.seed === DEFAULT_SEED ? "/" : `/run/${r.seed}`;
        return (
          <span key={r.seed} className="flex items-baseline">
            {i > 0 ? (
              <span className="mx-2 text-rule-strong" aria-hidden="true">
                /
              </span>
            ) : null}
            <Link
              href={href}
              // Next 16 static export emits the dynamic route's segment-prefetch
              // payload at __next.run/$d$seed/__PAGE__.txt but the client prefetch
              // requests it dot-joined, so every prefetch 404s. These are full
              // document navigations to prerendered HTML anyway.
              prefetch={false}
              aria-current={active ? "page" : undefined}
              className={
                active
                  ? "border-b border-field pb-0.5 text-field"
                  : "border-b border-transparent pb-0.5 text-ink-2 transition-colors hover:text-ink"
              }
            >
              {r.seed}
            </Link>
          </span>
        );
      })}
    </nav>
  );
}
