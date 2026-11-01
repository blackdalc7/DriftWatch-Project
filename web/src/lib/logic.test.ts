import { describe, expect, it } from "vitest";
import { ACTORS, hitsFor, overlaps, verdict } from "./blast";
import { replayPath } from "./api";
import { planDay, pyWeekday } from "./planner";
import { resolvePage, tagsFrom } from "./commands";
import type { Agent, Run, TestView } from "./types";

const agent = (id: string, platform: "windows" | "linux", tags = ["lab"]): Agent => ({
  id, hostname: id, platform, os_version: "", agent_version: "", tags, cert_expires_at: "", enrolled_at: "",
  last_seen: null, metrics: {}, status: "active", connection: "online", lab_scope: "lab",
});
const test = (id: string, platforms: ("windows" | "linux")[], techniques: string[], status: TestView["status"] = "verified") =>
  ({ id, name: id, platforms, status, attack: { tactic: "discovery", techniques } }) as unknown as TestView;

describe("replay paths", () => {
  it("maps API paths to snapshot files", () => {
    expect(replayPath("/api/v1/runs?limit=10")).toBe("./demo/runs.json");
    expect(replayPath("/api/v1/results/latest")).toBe("./demo/results-latest.json");
    expect(replayPath("/api/v1/agents/agt_1")).toBe("./demo/agents/agt_1.json");
  });
});

describe("planner", () => {
  const tests = { a: test("a", ["windows"], ["T1033"]), b: test("b", ["windows"], ["T1082"], "approved"), c: test("c", ["linux"], ["T1033"]) };
  const sched = { id: "s", test_ids: ["a", "b", "c"], target_tags: ["lab"], days: [0, 1, 2, 3, 4], window_start: "09:00", window_end: "17:00", randomize: true };
  it("plans verified tests inside the window on matching platforms only", () => {
    const plan = planDay(sched, "2026-11-02", [agent("w", "windows"), agent("l", "linux"), agent("x", "windows", ["prod"])], tests, 3);
    expect(plan.map((p) => `${p.agent_id}:${p.test_id}`).sort()).toEqual(["l:c", "w:a"]);
    for (const p of plan) {
      const h = new Date(p.at).getUTCHours();
      expect(h >= 9 && h < 17).toBe(true);
    }
  });
  it("skips non-scheduled weekdays and spaces evenly without randomness", () => {
    expect(pyWeekday(new Date("2026-11-01T00:00:00Z"))).toBe(6);
    expect(planDay(sched, "2026-11-01", [agent("w", "windows")], tests)).toEqual([]);
    const even = planDay({ ...sched, randomize: false }, "2026-11-02", [agent("w", "windows")], tests);
    expect(even[0].at).toBe("2026-11-02T13:00:00.000Z");
  });
});

describe("blast radius", () => {
  const latest = [{ id: "r1", test_id: "who", agent_id: "w", outcome: "detected", passed: true },
    { id: "r2", test_id: "adm", agent_id: "w", outcome: "missed", passed: false }] as Run[];
  const lib = [test("who", ["windows"], ["T1033"]), test("adm", ["windows"], ["T1069.001"]), test("id", ["linux"], ["T1033"])];
  it("replays latest outcomes for the actor's techniques on that OS", () => {
    const hits = hitsFor(ACTORS[0], agent("w", "windows"), lib, latest);
    expect(hits.map((h) => h.outcome)).toEqual(["detected", "missed"]);
    expect(verdict(hits)).toMatchObject({ tone: "amber", score: 50 });
    expect(verdict(hitsFor(ACTORS[0], agent("l", "linux"), lib, latest)).label).toContain("Never tested");
    expect(verdict([]).tone).toBe("muted");
  });
  it("detects overlap", () => {
    expect(overlaps({ x: 0, y: 0, w: 10, h: 10 }, { x: 5, y: 5, w: 10, h: 10 })).toBe(true);
    expect(overlaps({ x: 0, y: 0, w: 10, h: 10 }, { x: 11, y: 0, w: 10, h: 10 })).toBe(false);
  });
});

describe("terminal helpers", () => {
  it("resolves pages and tags", () => {
    expect(resolvePage("~/drift")).toBe("/drift");
    expect(resolvePage("nowhere")).toBeNull();
    expect(tagsFrom({ tag: "lab,windows" })).toEqual(["lab", "windows"]);
    expect(tagsFrom({})).toEqual(["lab"]);
  });
});
