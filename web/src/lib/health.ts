// One vocabulary for "how healthy is this", shared by every page so the numbers and colours agree.
//
//  * regression: the latest run fails and a pass -> fail test drift event exists for that test on that agent
//  * known gap:  the latest run fails and it never flipped from passing (it has always failed)
//  * drifted control: a baseline check whose latest drift event moved it to fail
import type { DriftEvent, Run } from "./types";

export type Tone = "green" | "amber" | "crimson" | "cyan" | "muted";
export const TEXT: Record<Tone, string> = {
  green: "text-green", amber: "text-amber", crimson: "text-crimson", cyan: "text-cyan", muted: "text-muted",
};
export const BORDER: Record<Tone, string> = {
  green: "border-green/60 text-green", amber: "border-amber/60 text-amber", crimson: "border-crimson/60 text-crimson",
  cyan: "border-cyan/60 text-cyan", muted: "border-line text-muted",
};

export const isRegression = (r: Pick<Run, "test_id" | "agent_id">, drift: DriftEvent[]) =>
  drift.some((d) => d.kind === "test" && d.subject === r.test_id && d.agent_id === r.agent_id && d.to_state === "fail");

export interface Failure { run: Run; kind: "regression" | "gap" }

export function failures(latest: Run[], drift: DriftEvent[]): Failure[] {
  return latest
    .filter((r) => r.passed === false)
    .map((run) => ({ run, kind: isRegression(run, drift) ? "regression" as const : "gap" as const }))
    .sort((a, b) => (a.kind === b.kind ? 0 : a.kind === "regression" ? -1 : 1));
}

/** Latest drift state per (agent, subject): only events still in the fail state count as open. */
export function openDrift(drift: DriftEvent[]): DriftEvent[] {
  const latest = new Map<string, DriftEvent>();
  for (const d of [...drift].sort((a, b) => a.detected_at.localeCompare(b.detected_at))) latest.set(`${d.agent_id}|${d.subject}`, d);
  return [...latest.values()].filter((d) => d.to_state === "fail");
}

export interface Verdict {
  label: "DEFENDED" | "DEGRADED" | "EXPOSED"; tone: Tone; passed: number; total: number; percent: number | null;
  regressions: number; gaps: number; controls: number;
}

/** The one-word answer to "is the lab still defended?" and the fraction behind it. */
export function verdict(latest: Run[], drift: DriftEvent[]): Verdict {
  const scored = latest.filter((r) => r.passed !== null);
  const passed = scored.filter((r) => r.passed).length;
  const fails = failures(latest, drift);
  const open = openDrift(drift);
  const percent = scored.length ? (100 * passed) / scored.length : null;
  const regressions = fails.filter((f) => f.kind === "regression").length;
  const gaps = fails.length - regressions;
  const controls = open.filter((d) => d.kind === "control").length;
  const label = percent !== null && percent < 60 ? "EXPOSED" : regressions || gaps || controls ? "DEGRADED" : "DEFENDED";
  return { label, tone: label === "DEFENDED" ? "green" : label === "DEGRADED" ? "amber" : "crimson", passed,
    total: scored.length, percent, regressions, gaps, controls };
}

/** Transparent weighted sum, shown with its parts. Weights are deliberately simple. */
export const EXPOSURE_WEIGHTS = { regressions: 10, gaps: 5, controls: 4 } as const;
export function exposure(v: Verdict) {
  const parts = [
    { key: "regressions", label: v.regressions === 1 ? "regression" : "regressions", count: v.regressions, points: v.regressions * EXPOSURE_WEIGHTS.regressions, tone: "crimson" as Tone },
    { key: "gaps", label: v.gaps === 1 ? "known gap" : "known gaps", count: v.gaps, points: v.gaps * EXPOSURE_WEIGHTS.gaps, tone: "amber" as Tone },
    { key: "controls", label: v.controls === 1 ? "drifted control" : "drifted controls", count: v.controls, points: v.controls * EXPOSURE_WEIGHTS.controls, tone: "amber" as Tone },
  ];
  return { parts, total: Math.min(100, parts.reduce((s, p) => s + p.points, 0)) };
}

export const pct = (n: number | null, digits = 1) => (n === null ? "—" : `${n.toFixed(digits).replace(/\.0$/, "")}%`);
