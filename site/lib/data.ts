/**
 * Build-time data access.
 *
 * Every exported run is imported statically and consumed by a Server Component,
 * so the numbers are inlined into prerendered HTML at build time: the first paint
 * already carries real data, with no fetch, no spinner, and no chart JavaScript.
 * These imports never reach the client bundle.
 */

import manifestJson from "@/public/data/index.json";
import run7 from "@/public/data/run-7.json";
import run11 from "@/public/data/run-11.json";
import run23 from "@/public/data/run-23.json";
import type { RunData, RunManifest } from "./types";

export const manifest = manifestJson as RunManifest;

const RUNS: Record<number, RunData> = {
  7: run7 as unknown as RunData,
  11: run11 as unknown as RunData,
  23: run23 as unknown as RunData,
};

/** Seed 7 is the canonical run -- it is the one the README's headline output uses. */
export const DEFAULT_SEED = 7;
export const defaultRun = RUNS[DEFAULT_SEED];

export const allSeeds = manifest.runs.map((r) => r.seed);

export function getRun(seed: number): RunData {
  const run = RUNS[seed];
  if (!run) throw new Error(`no exported run for seed ${seed}`);
  return run;
}

/** 0.9 -> "90%". Accuracies are exported as exact ratios. */
export function pct(x: number, digits = 0): string {
  return `${(x * 100).toFixed(digits)}%`;
}

/** Group a 64-char hex key into readable 8-char columns. */
export function groupHex(hex: string, size = 8): string[] {
  const out: string[] = [];
  for (let i = 0; i < hex.length; i += size) out.push(hex.slice(i, i + size));
  return out;
}
