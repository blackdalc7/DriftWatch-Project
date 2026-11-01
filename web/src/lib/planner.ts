// Client-side mirror of driftwatch.server.scheduler.plan_day for replay mode, where there is no server
// to ask for a preview. Same rules: weekday filter, window, verified tests only, random (seeded) or evenly
// spaced times, at least 5 minutes apart per agent.
import type { Agent, PlannedRun, Schedule, TestView } from "./types";

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const minutes = (hhmm: string) => {
  const [h, m] = hhmm.split(":").map(Number);
  return h * 60 + m;
};

/** Python weekday: Monday = 0. */
export const pyWeekday = (d: Date) => (d.getUTCDay() + 6) % 7;

export function planDay(sched: Pick<Schedule, "id" | "test_ids" | "target_tags" | "days" | "window_start" | "window_end" | "randomize">,
  dayIso: string, agents: Agent[], tests: Record<string, TestView>, seed = 1, verifiedOnly = true): PlannedRun[] {
  const day = new Date(`${dayIso}T00:00:00Z`);
  if (!sched.days.includes(pyWeekday(day))) return [];
  const start = minutes(sched.window_start);
  const end = minutes(sched.window_end);
  if (end <= start) return [];
  const rand = mulberry32(seed);
  const pool = agents.filter((a) => a.status === "active" && sched.target_tags.every((t) => a.tags.includes(t)));
  const out: PlannedRun[] = [];
  for (const agent of pool) {
    const runnable = sched.test_ids
      .map((id) => tests[id])
      .filter((t): t is TestView => Boolean(t) && t.platforms.includes(agent.platform) && (!verifiedOnly || t.status === "verified"));
    const n = runnable.length;
    const slots: number[] = [];
    runnable.forEach((_, i) => {
      if (!sched.randomize) slots.push(start + ((end - start) * (i + 1)) / (n + 1));
      else {
        let m = 0;
        for (let tries = 0; tries < 20; tries++) {
          m = start + rand() * (end - start);
          if (slots.every((s) => Math.abs(s - m) >= 5)) break;
        }
        slots.push(m);
      }
    });
    runnable.forEach((t, i) => {
      const at = new Date(day.getTime() + Math.round(slots[i] * 60) * 1000);
      out.push({ schedule_id: sched.id, test_id: t.id, agent_id: agent.id, at: at.toISOString() });
    });
  }
  return out.sort((a, b) => a.at.localeCompare(b.at));
}
