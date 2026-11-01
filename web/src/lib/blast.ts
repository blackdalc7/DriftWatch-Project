// Campaign replay: what happens if this threat actor's techniques land on that server? Built from the latest
// scored run of each test on each agent, so the animation replays real results rather than inventing them.
// (This is adversary-emulation replay, not lateral-movement "blast radius" analysis.)
import type { Agent, Outcome, Run, TestView } from "./types";

export interface Actor { id: string; name: string; blurb: string; techniques: string[] }

/** Archetypes built only from techniques the Safe Action Catalog can emulate. */
export const ACTORS: Actor[] = [
  { id: "actor-recon", name: "Quiet Recon Crew", blurb: "Lives off the land: whoami, admin groups, a DNS beacon.",
    techniques: ["T1033", "T1069.001", "T1071.004", "T1082"] },
  { id: "actor-persist", name: "Sticky Persistence Kit", blurb: "Run keys, scheduled tasks, XDG autostart.",
    techniques: ["T1547.001", "T1053.005", "T1547.013"] },
  { id: "actor-loader", name: "Commodity Loader", blurb: "Encoded PowerShell, a dropped file, a credential grab.",
    techniques: ["T1059.001", "T1027", "T1105", "T1552.001"] },
];

export interface Hit { test: TestView; outcome: Outcome | "untested"; passed: boolean | null; runId: string | null }

export function hitsFor(actor: Actor, agent: Agent, tests: TestView[], latest: Run[]): Hit[] {
  const wanted = new Set(actor.techniques);
  return tests
    .filter((t) => t.platforms.includes(agent.platform) && t.attack.techniques.some((x) => wanted.has(x) || wanted.has(x.split(".")[0])))
    .map((test) => {
      const run = latest.find((r) => r.test_id === test.id && r.agent_id === agent.id);
      return { test, outcome: run?.outcome ?? "untested", passed: run?.passed ?? null, runId: run?.id ?? null };
    });
}

export interface Verdict { label: string; tone: "green" | "amber" | "crimson" | "muted"; score: number }

const covers = (t: TestView, technique: string) => t.attack.techniques.some((x) => x === technique || x.split(".")[0] === technique);

/** Platforms on which the library can emulate a technique at all. */
export function platformsFor(technique: string, tests: TestView[]): Agent["platform"][] {
  return [...new Set(tests.filter((t) => covers(t, technique)).flatMap((t) => t.platforms))].sort();
}

/** The actor's techniques that no test can emulate on this host's OS. */
export function notApplicable(actor: Actor, agent: Agent, tests: TestView[]): string[] {
  return actor.techniques.filter((x) => !platformsFor(x, tests).includes(agent.platform));
}

/** Headline for a drop: share of techniques that were stopped or seen. */
export function verdict(hits: Hit[]): Verdict {
  if (!hits.length) return { label: "Nothing in the catalog emulates this actor on this OS", tone: "muted", score: 0 };
  const covered = hits.filter((h) => h.outcome === "prevented" || h.outcome === "detected").length;
  const score = Math.round((100 * covered) / hits.length);
  if (hits.every((h) => h.outcome === "untested")) return { label: "Never tested. Schrödinger's SOC.", tone: "muted", score };
  if (score === 100) return { label: "Contained. The actor goes home sad.", tone: "green", score };
  if (score >= 50) return { label: "Partially seen. Some of it walks straight through.", tone: "amber", score };
  return { label: "Wide open. Most of the campaign walks straight through.", tone: "crimson", score };
}

/** Axis-aligned overlap of two node rectangles (React Flow positions are top-left). */
export function overlaps(a: { x: number; y: number; w: number; h: number }, b: { x: number; y: number; w: number; h: number }): boolean {
  return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;
}
