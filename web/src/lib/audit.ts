// Recomputes the server's audit hash chain in the browser, so the "verified" badge is not just the server
// vouching for itself. Mirrors driftwatch.server.store.audit_hash:
//   sha256(canonical_json([prev_hash, ts, actor, action, details]))
import { canonicalJson, sha256Hex } from "./evidence";
import type { AuditEntry } from "./types";

export const GENESIS = "0".repeat(64);

export async function auditHash(prev: string, e: Pick<AuditEntry, "ts" | "actor" | "action" | "details">): Promise<string> {
  return sha256Hex(new TextEncoder().encode(canonicalJson([prev, e.ts, e.actor, e.action, e.details])));
}

export interface ChainCheck { ok: boolean; checked: number; head: string | null; brokenAt: number | null; complete: boolean }

/** Entries in any order. `complete` is false when the oldest entry shown is not the first one ever written. */
export async function verifyChain(entries: AuditEntry[]): Promise<ChainCheck> {
  const rows = [...entries].sort((a, b) => a.id - b.id);
  if (!rows.length) return { ok: true, checked: 0, head: null, brokenAt: null, complete: true };
  const complete = rows[0].id === 1;
  let prev = complete ? GENESIS : rows[0].prev_hash ?? "";
  for (const row of rows) {
    if (row.prev_hash !== prev || (await auditHash(prev, row)) !== row.hash) {
      return { ok: false, checked: rows.length, head: rows.at(-1)!.hash ?? null, brokenAt: row.id, complete };
    }
    prev = row.hash!;
  }
  return { ok: true, checked: rows.length, head: prev, brokenAt: null, complete };
}
