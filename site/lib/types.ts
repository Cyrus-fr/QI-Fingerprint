/**
 * Shape of `site/public/data/run-<seed>.json`, written by
 * `tools/export_site_data.py`. Keep this in step with that script -- it is the
 * only producer, and these files are the site's only data source.
 */

export type DiagnosisLabel =
  | "truncated_msb"
  | "modular_reduction"
  | "short_period_prng"
  | "weak_seed"
  | "clean";

export type CrackMethod = "reuse" | "seed" | "lattice";

export interface RunStats {
  nKeys: number;
  nSignatures: number;
  rCollisions: number;
  expectedRandomCollisions: number;
  nIntraKeyReuse: number;
  nLatticeCandidates: number;
  nCohorts: number;
  nCracked: number;
  nDiagnosed: number;
  nAttributed: number;
  diagnosisAccuracy: number;
  attributionAccuracy: number;
  cleanKeysAttributed: number;
}

export interface CrackRow {
  keyId: number;
  method: CrackMethod;
  /** True by construction: `crack_key` only returns d once d*G == Q holds. */
  verified: boolean;
  /**
   * Recovered private key, fixed-width 64-char hex (no 0x prefix).
   *
   * Present only for a synthetic corpus, where the scalar is the generator's
   * own and publishing it is the demonstration. The exporter omits it for an
   * ingested corpus (real Bitcoin), where it would be a live spending key --
   * `verified` still carries the claim that d*G == Q held.
   */
  d?: string;
  diagnosis: DiagnosisLabel;
  confidence: number;
  truth: DiagnosisLabel;
  correct: boolean;
  nSignatures: number;
}

export interface KeyDetail {
  keyId: number;
  /** See `CrackRow.d` -- omitted for corpora ingested from a real chain. */
  d?: string;
  diagnosis: DiagnosisLabel;
  confidence: number;
  nNonces: number;
  /** P(bit = 1) for the top 32 MSBs. A run of exact zeros is the dead-bit signature. */
  msbBitMeans: number[];
  deadMsbBits: number;
  /** Bleichenbacher bias magnitude at frequencies w = 1..64. */
  spectrum: number[];
  nonceSamples: string[];
  evidence: Record<string, number>;
}

export interface AttributionRow {
  keyId: number;
  diagnosis: DiagnosisLabel;
  source: "cracked" | "propagated";
  confidence: number;
  truth: DiagnosisLabel;
  correct: boolean;
}

export interface GraphNode {
  id: number;
  label: DiagnosisLabel;
  source: "cracked" | "propagated";
  confidence: number;
  correct: boolean;
  /** Deterministic unit-box position, precomputed so the graph never re-settles. */
  x: number;
  y: number;
  cohort: number | null;
}

export interface GraphEdge {
  source: number;
  target: number;
}

/** One collision-linked cohort, with the geometry needed to caption it. */
export interface GraphCluster {
  cohort: number;
  x: number;
  y: number;
  r: number;
  size: number;
  members: number[];
  label: DiagnosisLabel | null;
}

export interface PropagationStep {
  step: number;
  from: number;
  to: number;
}

/** One cohort's BFS traversal from its cracked member -- the scrubber's timeline. */
export interface PropagationCohort {
  cohort: number;
  root: number;
  label: DiagnosisLabel;
  members: number[];
  steps: PropagationStep[];
}

export interface RunData {
  seed: number;
  curve: string;
  stats: RunStats;
  attributedByClass: Record<string, number>;
  perClassDiagnosis: Record<string, { n: number; correct: number; accuracy: number }>;
  cracks: CrackRow[];
  keys: Record<string, KeyDetail>;
  attributions: AttributionRow[];
  cohortGraph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    clusters: GraphCluster[];
    /** Keys the screen could not link to any cohort. */
    singletons: number[];
    bandDividerY: number;
  };
  propagation: PropagationCohort[];
  section: Lamina[];
  chain: ChainData;
}

/**
 * One lamina of the cored section: a single key in the corpus, in key order.
 *
 * Every field is measured. `label` is null where the pipeline refused to guess
 * rather than where data is missing, and the section draws that refusal as
 * unmarked host rock -- which is the honest picture of a corpus where 56 of 70
 * keys carry too few signatures to say anything about.
 */
export interface Lamina {
  keyId: number;
  nSignatures: number;
  label: DiagnosisLabel | null;
  source: "cracked" | "propagated" | null;
  cracked: boolean;
}

/**
 * Stage 2c, exported alongside the baseline rather than replacing it.
 *
 * A hop carries provenance and nothing else: which key opened this one, over
 * which on-chain `r`, and how many hops from the originally cracked key. There
 * is deliberately no field for the recovered scalar -- the same rule
 * `Confirmation` enforces in the Python, expressed here as a type the site
 * could not render a key from even if it tried.
 */
export interface ChainHop {
  keyId: number;
  viaKeyId: number;
  /** The shared nonce edge that was walked. Public: it is on chain. */
  r: string;
  /** Hops from the seed key. A direct neighbour is 1. */
  depth: number;
  truth: DiagnosisLabel;
  /**
   * False when the key was recovered but carries too few nonces to classify.
   * Those keep a cohort attribution instead of an invented `clean` label.
   */
  selfDiagnosable: boolean;
}

export interface ChainData {
  nCracked: number;
  nDiagnosed: number;
  nAttributed: number;
  diagnosisAccuracy: number;
  attributionAccuracy: number;
  nUndiagnosable: number;
  /** Shared-r edges the baseline run declined to walk. */
  unwalkedEdges: number;
  hops: ChainHop[];
}

export interface RunManifestEntry {
  seed: number;
  curve: string;
  file: string;
  nKeys: number;
  nSignatures: number;
  nCracked: number;
  nAttributed: number;
}

export interface RunManifest {
  defaultSeed: number;
  runs: RunManifestEntry[];
}

export const DIAGNOSIS_COLOR: Record<DiagnosisLabel, string> = {
  truncated_msb: "var(--color-truncated_msb)",
  modular_reduction: "var(--color-modular_reduction)",
  short_period_prng: "var(--color-short_period_prng)",
  weak_seed: "var(--color-weak_seed)",
  clean: "var(--color-clean)",
};

export const METHOD_LANE: Record<CrackMethod, string> = {
  lattice: "MSB-bias lane",
  reuse: "repeat lane",
  seed: "repeat lane",
};
