// Driftwatch-specific microcopy. Stable per key so a screen does not change its joke on every render.
import { quipFor } from "@portfolio/aegis-ui";

export const EMPTY = {
  allPassed: "All tests passed. Either you're a genius, or the agent is dead.",
  noDrift: "Zero drift. The baseline hasn't moved an inch. Suspiciously stable.",
  noAgents: "No agents enrolled. The lab is a very expensive screensaver.",
  noRuns: "No runs yet. Detection coverage: Schrödinger's.",
  noDrafts: "No drafts awaiting review. The AI is either shy or out of ideas.",
  noSchedules: "No schedules. Attacks, famously, also only happen when you remember to test.",
  noFindings: "The EDRs and Driftwatch agree on everything. Mark this date.",
};

const LOADING = [
  "Bribing the SIEM for answers…",
  "Counting Sigma rules on our fingers…",
  "Asking the agent nicely…",
  "Diffing yesterday's baseline against today's excuses…",
  "Verifying Ed25519 signatures with great ceremony…",
];

export const loadingQuip = (key: string) => quipFor(key, LOADING);
