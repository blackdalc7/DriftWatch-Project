import { HoldToConfirm, Panel, TextScramble, Button } from "@portfolio/aegis-ui";
import { useState } from "react";
import { send, useApi } from "../lib/api";
import { EMPTY } from "../lib/quips";
import { TEXT } from "../lib/health";
import { ago, clock, ms, stamp } from "../lib/time";
import type { Agent, AgentDetail, Check } from "../lib/types";
import { Async, Meter, Sparkline, SectionTitle, useToast } from "../components/ui";

export function Fleet() {
  const agents = useApi<Agent[]>("/api/v1/agents", 10_000);
  return (
    <div>
      <SectionTitle kicker="fleet://agents" title="Two VMs, zero remote shells"><EnrollToken onDone={agents.reload} /></SectionTitle>
      <Async q={agents} label="agents" emptyWhen={(a) => a.length === 0} empty={EMPTY.noAgents}>
        {(list) => <div className="grid gap-6 lg:grid-cols-2">{list.map((a) => <AgentCard key={a.id} agent={a} onChange={agents.reload} />)}</div>}
      </Async>
    </div>
  );
}

const STALE_AFTER_MS = 15 * 60_000;

/** Which telemetry sources the baseline shows as working. Derived, never claimed. */
function sensors(checks: Check[]): string[] {
  const ok = (id: string) => checks.some((c) => c.id === id && c.status === "pass");
  return [
    ok("win.defender.realtime_protection") && "Defender AV",
    ok("win.sysmon.process_creation") && "Sysmon",
    ok("win.powershell.scriptblock_logging") && "PS script block",
    ok("linux.auditd.running") && "auditd",
    ok("linux.auditd.execve_rule") && "auditd execve",
  ].filter((x): x is string => Boolean(x));
}

function AgentCard({ agent, onChange }: { agent: Agent; onChange: () => void }) {
  const detail = useApi<AgentDetail>(`/api/v1/agents/${agent.id}`, 15_000);
  const toast = useToast();
  const hb = detail.data?.heartbeats ?? [];
  const checks = detail.data?.hygiene?.checks ?? [];
  const failing = checks.filter((c) => c.status !== "pass");
  const age = clock.now() - ms(agent.last_seen);
  const state = agent.status === "revoked" ? "revoked" : agent.connection !== "online" ? "offline" : age > STALE_AFTER_MS ? "stale" : "online";
  const tone = { online: "green", stale: "amber", offline: "crimson", revoked: "crimson" }[state] as "green" | "amber" | "crimson";
  const revoke = async () => {
    const res = await send("POST", `/api/v1/agents/${agent.id}/revoke`);
    toast(res.simulated ? "Replay mode: the agent lives to heartbeat another day." : `${agent.hostname} revoked. Its certificate is now worthless.`, res.simulated ? "warn" : "bad");
    onChange();
  };
  const m = agent.metrics;
  return (
    <Panel scanlines label={agent.hostname}
      title={<span className="flex items-center gap-2"><span className={`h-2 w-2 ${state === "online" ? "ae-live bg-green" : tone === "amber" ? "bg-amber" : "bg-crimson"}`} />{agent.hostname}</span>}
      subtitle={<span className="font-mono">{agent.id} · {agent.platform} · agent {agent.agent_version}</span>}
      actions={<span className={`font-mono text-[10px] uppercase ${TEXT[tone]}`}>{state === "revoked" ? "revoked" : `${state} · seen ${ago(agent.last_seen)}`}</span>}>
      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
        <dt className="text-muted">ip</dt><dd>{m.ip_addresses?.join(", ") || "not reported"}</dd>
        <dt className="text-muted">os</dt><dd>{agent.os_version}{m.kernel_version ? ` · ${m.kernel_version}` : ""}</dd>
        <dt className="text-muted">telemetry</dt><dd>{sensors(checks).join(" · ") || "unknown until a baseline arrives"}</dd>
        <dt className="text-muted">client cert</dt>
        <dd className="truncate" title={agent.cert_sha256 ?? undefined}>sha256 {agent.cert_sha256 ? `${agent.cert_sha256.slice(0, 16)}…` : "—"} · expires {stamp(agent.cert_expires_at).slice(0, 10)}</dd>
        <dt className="text-muted">lab scope</dt><dd className={agent.lab_scope ? "text-green" : "text-crimson"}>{agent.lab_scope ? `#${agent.lab_scope}` : "none (never dispatched to)"}</dd>
      </dl>
      <div className="mt-4 grid gap-4 border-t border-line pt-3 sm:grid-cols-[1fr_1fr_1fr_auto] sm:items-end">
        <Meter label="cpu" value={m.cpu_percent} />
        <Meter label="memory" value={m.memory_percent} />
        <Meter label="disk" value={m.disk_percent} warn={80} />
        <div className="font-mono text-[10px] text-muted">
          <div>cpu · last {hb.length} heartbeats</div>
          <Sparkline values={hb.map((h) => h.cpu_percent)} width={150} height={26} />
        </div>
      </div>
      <div className="mt-4 border-t border-line pt-3">
        <div className="mb-2 flex flex-wrap justify-between gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-muted">
          <span>baseline · {checks.length - failing.length}/{checks.length} passing</span>
          <span>{detail.data?.hygiene ? `collected ${ago(detail.data.hygiene.collected_at)}` : "not collected yet"}</span>
        </div>
        <ul className="flex flex-wrap gap-1.5" aria-label="baseline checks">
          {[...failing, ...checks.filter((c) => c.status === "pass")].map((c) => (
            <li key={c.id} title={`${c.id} · expected ${c.expected ?? "—"} · actual ${c.actual ?? "—"}`}
              className={`border px-1.5 py-0.5 font-mono text-[10px] ${c.status === "pass" ? "border-green/40 text-green/90" : c.status === "fail" ? "border-amber/70 bg-amber/10 text-amber" : "border-line text-muted"}`}>
              {c.status === "pass" ? "✓" : c.status === "fail" ? "!" : "?"} {c.title}{c.status === "fail" ? ` · ${c.actual}` : ""}
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3">
        <div className="flex flex-wrap gap-1">{agent.tags.map((t) => <span key={t} className="border border-line px-1.5 py-0.5 font-mono text-[10px] text-muted">#{t}</span>)}</div>
        <HoldToConfirm label="Hold to revoke" holdingLabel="Revoking its certificate…" onConfirm={revoke} duration={1800}
          disabled={agent.status === "revoked"} disabledReason="already revoked" />
      </div>
    </Panel>
  );
}

function EnrollToken({ onDone }: { onDone: () => void }) {
  const [token, setToken] = useState<string | null>(null);
  const toast = useToast();
  const create = async () => {
    const res = await send<{ token: string; expires_at: string }>("POST", "/api/v1/tokens", { label: "ui", ttl_seconds: 1800, max_uses: 1, tags: ["lab"] });
    if (res.simulated) { toast("Replay mode: this token is as real as the cake.", "warn"); setToken("dwt_replay-mode-not-a-real-token"); return; }
    setToken(res.data?.token ?? null);
    onDone();
  };
  return (
    <div className="flex items-center gap-2">
      {token && (
        <code className="max-w-[320px] truncate border border-amber/60 bg-amber/10 px-2 py-1 font-mono text-[11px] text-amber" title="shown once, valid 30 minutes, single use">
          <TextScramble text={token} />
        </code>
      )}
      <Button variant="primary" glitch="New enrollment token" onClick={create} />
    </div>
  );
}
