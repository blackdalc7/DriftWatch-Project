// Drift timeline maths: what did each host's baseline look like at time t, and how "drifted" is the
// fleet at that moment? Pure functions so the scrubber stays smooth and testable.
import type { Check, DriftEvent, HygieneSnapshot } from "./types";
import { ms } from "./time";

export interface ControlState { check: Check; since: string; drifted: boolean }

/** The latest snapshot collected at or before `t` (snapshots in any order). */
export function snapshotAt(history: HygieneSnapshot[], t: number): HygieneSnapshot | null {
  let best: HygieneSnapshot | null = null;
  for (const s of history) {
    const at = ms(s.collected_at);
    if (at <= t && (!best || at > ms(best.collected_at))) best = s;
  }
  return best;
}

/**
 * Control states at `t`. A control counts as drifted when a control drift event for it has started
 * (its exact change time if known, otherwise the first bad snapshot) at or before `t` and the snapshot
 * at `t` still shows it failing.
 */
export function controlsAt(history: HygieneSnapshot[], events: DriftEvent[], agentId: string, t: number): ControlState[] {
  const snap = snapshotAt(history, t);
  if (!snap) return [];
  const started = new Map<string, number>();
  for (const e of events) {
    if (e.agent_id !== agentId || e.kind !== "control" || e.to_state !== "fail") continue;
    const at = ms(e.exact_change_at ?? e.first_bad_at);
    if (at <= t) started.set(e.subject, Math.max(started.get(e.subject) ?? 0, at));
  }
  return snap.report.checks.map((check) => ({
    check,
    since: snap.collected_at,
    drifted: check.status === "fail" && started.has(check.id),
  }));
}

/** Instant at which an event is drawn on the timeline: exact change if Elastic pinpointed it. */
export const eventTime = (e: DriftEvent): number => ms(e.exact_change_at ?? e.first_bad_at);

/** Events that have happened by `t`, newest first. */
export function eventsUntil(events: DriftEvent[], t: number): DriftEvent[] {
  return events.filter((e) => eventTime(e) <= t).sort((a, b) => eventTime(b) - eventTime(a));
}

/**
 * 0 = clean baseline (green), 1 = badly drifted (amber). Saturates so one high-severity drift is already
 * clearly visible but the colour never pins at full amber unless several controls are off.
 */
export function driftLevel(states: ControlState[]): number {
  const weight = { high: 1, medium: 0.6, low: 0.3 } as const;
  const sum = states.filter((s) => s.drifted).reduce((acc, s) => acc + weight[s.check.severity ?? "medium"], 0);
  return 1 - Math.exp(-sum / 0.9);
}

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
}

/** Interpolate terminal green -> CRT amber for the UI tint. */
export function tint(level: number, from = "#39ff88", to = "#ffb224"): string {
  const k = Math.min(1, Math.max(0, level));
  const a = hexToRgb(from);
  const b = hexToRgb(to);
  const c = a.map((v, i) => Math.round(v + (b[i] - v) * k));
  return `#${c.map((v) => v.toString(16).padStart(2, "0")).join("")}`;
}

/** Snap a time to the nearest event within `radius` ms (for the "magnetic" scrubber). */
export function snap(t: number, events: DriftEvent[], radius: number): { t: number; event: DriftEvent | null } {
  let best: DriftEvent | null = null;
  let dist = radius;
  for (const e of events) {
    const d = Math.abs(eventTime(e) - t);
    if (d <= dist) { dist = d; best = e; }
  }
  return best ? { t: eventTime(best), event: best } : { t, event: null };
}
