import { RunPage } from "@/components/RunPage";
import { allSeeds, getRun, DEFAULT_SEED } from "@/lib/data";
import type { Metadata } from "next";

/** One prerendered route per exported seed, minus the canonical one at `/`. */
export function generateStaticParams() {
  return allSeeds
    .filter((seed) => seed !== DEFAULT_SEED)
    .map((seed) => ({ seed: String(seed) }));
}

export const dynamicParams = false;

export async function generateMetadata({
  params,
}: {
  params: Promise<{ seed: string }>;
}): Promise<Metadata> {
  const { seed } = await params;
  return {
    title: `QI-Fingerprint — seed ${seed}`,
    description: `ECDSA nonce-bias triage on a synthetic corpus, seed ${seed}. Validated on synthetic corpora only.`,
  };
}

export default async function SeedRun({ params }: { params: Promise<{ seed: string }> }) {
  const { seed } = await params;
  return <RunPage run={getRun(Number(seed))} />;
}
