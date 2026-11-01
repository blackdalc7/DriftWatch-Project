import { Panel, cn } from "@portfolio/aegis-ui";
import { useEffect, useMemo, useState } from "react";
import { useApi } from "../lib/api";
import { verifyChain, type ChainCheck } from "../lib/audit";
import { stamp } from "../lib/time";
import type { AuditEntry } from "../lib/types";
import { Async, Mono, SectionTitle } from "../components/ui";

const tone = (action: string) =>
  /revoke|delete|reject/.test(action) ? "text-crimson" : /verif|approv/.test(action) ? "text-green" : /dispatch|run|schedule/.test(action) ? "text-cyan" : "text-muted";

const KINDS = {
  all: () => true,
  approvals: (a: string) => a === "test.approved",
  verifications: (a: string) => a === "test.verified",
  agents: (a: string) => a.startsWith("agent.") || a.startsWith("token."),
  schedules: (a: string) => a.startsWith("schedule.") || a.startsWith("runs."),
} as const;
type Kind = keyof typeof KINDS;

export function Audit() {
  const log = useApi<AuditEntry[]>("/api/v1/audit?limit=2000", 20_000);
  const [filter, setFilter] = useState("");
  const [kind, setKind] = useState<Kind>("all");
  const [open, setOpen] = useState<number | null>(null);
  const [chain, setChain] = useState<ChainCheck | "checking" | null>(null);

  useEffect(() => {
    if (!log.data) return;
    let cancelled = false;
    setChain("checking");
    verifyChain(log.data).then((r) => { if (!cancelled) setChain(r); }, () => { if (!cancelled) setChain(null); });
    return () => { cancelled = true; };
  }, [log.data]);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (log.data ?? []).filter((e) => KINDS[kind](e.action)
      && (!q || `${e.actor} ${e.action} ${JSON.stringify(e.details)}`.toLowerCase().includes(q)));
  }, [log.data, filter, kind]);

  return (
    <div>
      <SectionTitle kicker="audit://append-only" title="Who did what, and when">
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="search actor, action, id…" aria-label="search audit log"
          className="w-64 border border-line bg-transparent px-2 py-1.5 font-mono text-xs focus:border-cyan focus:outline-none" />
      </SectionTitle>
      <div className="mb-4 flex flex-wrap gap-1" role="toolbar" aria-label="filter by kind">
        {(Object.keys(KINDS) as Kind[]).map((k) => (
          <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(k)}
            className={cn("border px-2 py-1 font-mono text-[11px] uppercase", kind === k ? "border-cyan text-cyan" : "border-line text-muted hover:text-ink")}>
            {k} {(log.data ?? []).filter((e) => KINDS[k](e.action)).length}
          </button>
        ))}
      </div>
      <Async q={log} label="audit" emptyWhen={(l) => l.length === 0} empty="The audit log is empty. Nobody has done anything, which is its own kind of suspicious.">
        {() => (
          <Panel title={`${rows.length} entries`} subtitle="approvals, verifications, enrollments, revocations, tokens and schedule changes">
            {rows.length === 0 ? <p className="font-mono text-xs text-muted">Nothing matches.</p> : (
              <ol className="divide-y divide-line">
                {rows.map((e) => (
                  <li key={e.id}>
                    <button type="button" onClick={() => setOpen(open === e.id ? null : e.id)} aria-expanded={open === e.id}
                      className="grid w-full grid-cols-[44px_150px_170px_1fr_auto] gap-3 py-2 text-left font-mono text-xs hover:bg-white/[0.02]">
                      <span className="text-muted">#{e.id}</span>
                      <span className="text-muted">{stamp(e.ts)}</span>
                      <span className="truncate">{e.actor}</span>
                      <span className={tone(e.action)}>{e.action} <span className="text-muted">{summary(e)}</span></span>
                      <span className="hidden text-[10px] text-muted/70 md:inline" title={e.hash}>{e.hash?.slice(0, 10)}</span>
                    </button>
                    {open === e.id && (
                      <pre className="mb-2 overflow-x-auto border border-line bg-black/30 p-3 font-mono text-[11px] text-muted">
                        {JSON.stringify({ details: e.details, prev_hash: e.prev_hash, hash: e.hash }, null, 2)}
                      </pre>
                    )}
                  </li>
                ))}
              </ol>
            )}
            <ChainBadge chain={chain} />
          </Panel>
        )}
      </Async>
    </div>
  );
}

function summary(e: AuditEntry): string {
  const d = e.details as Record<string, unknown>;
  return String(d.test_id ?? d.hostname ?? d.name ?? d.label ?? d.agent_id ?? "");
}

function ChainBadge({ chain }: { chain: ChainCheck | "checking" | null }) {
  if (chain === null) return null;
  if (chain === "checking") return <div className="mt-3 border-t border-line pt-2"><Mono className="text-muted">recomputing the hash chain in your browser…</Mono></div>;
  return (
    <div className={cn("mt-3 border-t pt-2 font-mono text-[11px]", chain.ok ? "border-line text-green" : "border-crimson/60 text-crimson")} role="status">
      {chain.ok
        ? <>✓ hash chain recomputed in your browser · {chain.checked} entries{chain.complete ? " from genesis" : " (window; older entries not loaded)"} · head <span title={chain.head ?? ""}>{chain.head?.slice(0, 16)}…</span></>
        : <>✕ chain broken at entry #{chain.brokenAt}: it was edited, removed or inserted after the fact</>}
      <span className="ml-2 text-muted">each entry is SHA-256 over the previous entry's hash and its own content</span>
    </div>
  );
}
