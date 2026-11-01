import { describe, expect, it } from "vitest";
import { controlsAt, driftLevel, eventsUntil, snap, snapshotAt, tint } from "./drift";
import type { DriftEvent, HygieneSnapshot } from "./types";

const snapAt = (iso: string, asr: "pass" | "fail"): HygieneSnapshot => ({
  agent_id: "a1", collected_at: iso,
  report: { schema: "driftwatch.hygiene/v1", platform: "windows", collected_at: iso, checks: [
    { id: "win.asr.block_obfuscated_scripts", title: "ASR", severity: "high", status: asr },
    { id: "win.credential_guard.running", title: "CG", severity: "medium", status: "fail" },
  ] },
});
const history = [snapAt("2026-10-25T09:00:00Z", "pass"), snapAt("2026-10-25T13:00:00Z", "fail")];
const event: DriftEvent = {
  id: 1, agent_id: "a1", kind: "control", subject: "win.asr.block_obfuscated_scripts", from_state: "pass",
  to_state: "fail", last_good_at: "2026-10-25T09:00:00Z", first_bad_at: "2026-10-25T13:00:00Z",
  exact_change_at: "2026-10-25T11:42:07Z", detected_at: "2026-10-25T13:00:05Z", details: {},
};
const t = (iso: string) => Date.parse(iso);

describe("drift timeline", () => {
  it("picks the snapshot in force at a time", () => {
    expect(snapshotAt(history, t("2026-10-25T08:00:00Z"))).toBeNull();
    expect(snapshotAt(history, t("2026-10-25T12:00:00Z"))?.collected_at).toBe("2026-10-25T09:00:00Z");
  });

  it("marks only controls with a drift event as drifted (pre-existing failures are not drift)", () => {
    const before = controlsAt(history, [event], "a1", t("2026-10-25T12:00:00Z"));
    expect(before.some((c) => c.drifted)).toBe(false);
    const after = controlsAt(history, [event], "a1", t("2026-10-25T14:00:00Z"));
    expect(after.find((c) => c.check.id.includes("asr"))?.drifted).toBe(true);
    expect(after.find((c) => c.check.id.includes("credential"))?.drifted).toBe(false);
  });

  it("tints from green to amber and saturates", () => {
    expect(tint(0)).toBe("#39ff88");
    expect(tint(1)).toBe("#ffb224");
    const one = driftLevel(controlsAt(history, [event], "a1", t("2026-10-26T00:00:00Z")));
    expect(one).toBeGreaterThan(0.6);
    expect(one).toBeLessThan(1);
  });

  it("snaps to the exact change time and lists events", () => {
    expect(snap(t("2026-10-25T11:40:00Z"), [event], 10 * 60_000).t).toBe(t("2026-10-25T11:42:07Z"));
    expect(snap(t("2026-10-25T08:00:00Z"), [event], 60_000).event).toBeNull();
    expect(eventsUntil([event], t("2026-10-25T11:00:00Z"))).toHaveLength(0);
  });
});
