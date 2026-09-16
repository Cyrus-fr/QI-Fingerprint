import { Collar } from "@/components/log/Collar";
import { DepthRail } from "@/components/log/DepthRail";
import {
  Assay,
  Assays,
  LostCore,
  PriorSurveys,
  TheMethod,
  TheSeam,
  TitleBlock,
} from "@/components/log/Intervals";
import { TriageSection } from "@/components/data/TriageSection";
import { CohortSection } from "@/components/data/CohortSection";
import { CascadeSection } from "@/components/data/CascadeSection";
import type { RunData } from "@/lib/types";

/**
 * The sheet, top to bottom: the collar, then the logged intervals in descent
 * order. One continuous section, never a stack of panels -- the reader moves by
 * going down, and the depth rail is the only navigation.
 */
export function RunPage({ run }: { run: RunData }) {
  return (
    <>
      <Collar run={run} />
      <DepthRail />
      <main id="log">
        <TheSeam />
        <TheMethod />
        <TriageSection run={run} />
        <CohortSection run={run} />
        <CascadeSection run={run} />
        <Assay />
        <Assays />
        <LostCore />
        <PriorSurveys />
      </main>
      <TitleBlock seed={run.seed} curve={run.curve} />
    </>
  );
}
