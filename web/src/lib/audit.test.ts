import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyChain } from "./audit";
import type { AuditEntry } from "./types";

// Written by driftwatch.server.store.Store.audit (Python), including a non-ASCII value and nested details.
const entries = JSON.parse(readFileSync(new URL("./__fixtures__/audit-chain.json", import.meta.url), "utf8")) as AuditEntry[];

describe("audit chain", () => {
  it("recomputes the Python hashes byte for byte", async () => {
    const r = await verifyChain(entries);
    expect(r).toMatchObject({ ok: true, checked: 3, complete: true, brokenAt: null });
    expect(r.head).toBe(entries[0].hash);
  });

  it("names the first entry that was edited", async () => {
    const tampered = entries.map((e) => (e.id === 2 ? { ...e, actor: "someone-else" } : e));
    expect(await verifyChain(tampered)).toMatchObject({ ok: false, brokenAt: 2 });
  });

  it("notices a deleted entry", async () => {
    expect(await verifyChain(entries.filter((e) => e.id !== 2))).toMatchObject({ ok: false, brokenAt: 3 });
  });
});
