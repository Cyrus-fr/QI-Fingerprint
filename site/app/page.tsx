import { RunPage } from "@/components/RunPage";
import { defaultRun } from "@/lib/data";

export default function Home() {
  return <RunPage run={defaultRun} />;
}
