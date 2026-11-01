import { Panel } from "@portfolio/aegis-ui";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "../lib/api";
import { pct, verdict } from "../lib/health";
import { EMPTY } from "../lib/quips";
import { ago } from "../lib/time";
import type { Agent, AgentDetail, Correlation, DriftEvent, Finding, Run, TestDetail } from "../lib/types";
import { Async, Meter, Mono, OutcomeBadge, SectionTitle } from "../components/ui";

export function Posture() {
  const corr = useApi<Correlation>("/api/v1/correlation", 60_000);
  const latest = useApi<Run[]>("/api/v1/results/latest", 60_000);
  const drift = useApi<DriftEvent[]>("/api/v1/drift", 60_000);
  const agents = useApi<Agent[]>("/api/v1/agents");
  return (
    <div className="pb-10">
      <SectionTitle kicker="posture://edr" title="What the EDR says vs. what the lab proved" />
      <p className="mb-5 max-w-3xl text-sm text-muted">
        Vendor posture scores are read-only context. Driftwatch never trusts them over a test result; it lists where the two disagree,
        because that disagreement is usually the most interesting thing on the page. Driftwatch never changes host configuration.
      </p>
      <Async q={corr} label="posture">
        {(c) => (
          <div className="space-y-6">
            {c.configured === false && (
              <p className="border border-line px-3 py-2 font-mono text-xs text-muted">No EDR connector configured. Set the Defender or CrowdStrike variables in .env to light this page up.</p>
            )}
            {c.errors?.length ? (
              <div className="border border-crimson/60 px-3 py-2 font-mono text-xs text-crimson">{c.errors.map((e) => <div key={e}>{e}</div>)}</div>
            ) : null}
            {latest.data && drift.data && <DeltaBanner c={c} validated={verdict(latest.data, drift.data).percent} />}
            <div className="grid gap-6 lg:grid-cols-2">
              <Panel title="Microsoft Defender" subtitle={c.defender ? `Secure Score · ${ago(c.defender.created)}` : "not connected"}>
                {c.defender ? <DefenderCard d={c.defender} /> : <p className="text-sm text-muted">No tenant, no score. Probably for the best on a lab budget.</p>}
              </Panel>
              <Panel title="CrowdStrike Falcon" subtitle="Zero Trust Assessment per host">
                {Object.keys(c.crowdstrike).length ? (
                  <div className="grid gap-4 sm:grid-cols-2">
                    {Object.entries(c.crowdstrike).map(([host, s]) => (
                      <div key={host} className="space-y-2 border border-line p-3">
                        <div className="flex items-baseline justify-between"><Mono className="text-ink">{host}</Mono><span className="font-mono text-lg">{s.overall}</span></div>
                        <Meter label="sensor config" value={s.sensor_config} warn={101} crit={102} />
                        <Meter label="os" value={s.os} warn={101} crit={102} />
                      </div>
                    ))}
                  </div>
                ) : <p className="text-sm text-muted">Falcon is not connected.</p>}
              </Panel>
            </div>
            <Panel title="Findings" subtitle={`${c.findings.length} places where posture and reality part ways · click one for the evidence`}>
              {c.findings.length === 0 ? <p className="font-mono text-xs text-muted">{EMPTY.noFindings}</p> : (
                <ul className="divide-y divide-line">
                  {c.findings.map((f, i) => <FindingRow key={`${f.type}-${f.host}-${i}`} f={f} agents={agents.data ?? []} latest={latest.data ?? []} />)}
                </ul>
              )}
            </Panel>
          </div>
        )}
      </Async>
    </div>
  );
}

/** Vendor claims vs. lab results, side by side. They measure different things, and the banner says so. */
function DeltaBanner({ c, validated }: { c: Correlation; validated: number | null }) {
  const vendor = [c.defender?.percent, ...Object.values(c.crowdstrike).map((s) => s.overall)].filter((x): x is number => typeof x === "number");
  if (!vendor.length || validated === null) return null;
  const claim = vendor.reduce((a, b) => a + b, 0) / vendor.length;
  const delta = claim - validated;
  return (
    <section className="grid gap-px border border-line bg-line sm:grid-cols-3" aria-label="posture delta">
      <Stat label="vendor posture (average of scores)" value={pct(claim, 0)} />
      <Stat label="driftwatch validated (tests passing)" value={pct(validated, 0)} />
      <Stat label="delta" value={`${delta > 0 ? "+" : ""}${delta.toFixed(0)} pts`} tone={Math.abs(delta) >= 10 ? "text-amber" : "text-green"}
        note={delta > 0 ? "vendors are more optimistic than the lab" : "the lab is at least as good as vendors claim"} />
    </section>
  );
}

function Stat({ label, value, tone = "text-ink", note }: { label: string; value: string; tone?: string; note?: string }) {
  return (
    <div className="bg-bg p-3">
      <div className="font-mono text-[10px] uppercase tracking-[0.15em] text-muted">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-bold ${tone}`}>{value}</div>
      {note && <div className="font-mono text-[10px] text-muted">{note}</div>}
    </div>
  );
}

function DefenderCard({ d }: { d: NonNullable<Correlation["defender"]> }) {
  const controls = d.controls ?? [];
  const implemented = controls.filter((x) => x.percent >= 100).length;
  return (
    <div>
      <div className="flex items-center gap-5">
        <ScoreRing percent={d.percent} />
        <div className="space-y-1 font-mono text-[11px] text-muted">
          <div>points <span className="text-ink">{d.current_score} / {d.max_score}</span></div>
          {controls.length > 0 && <div>controls fully implemented <span className="text-ink">{implemented}/{controls.length}</span></div>}
        </div>
      </div>
      {controls.length > 0 && (
        <ul className="mt-3 space-y-1.5">
          {[...controls].sort((a, b) => a.percent - b.percent).map((x) => (
            <li key={x.name} title={x.name}><Meter label={x.description} value={x.percent} warn={101} crit={102} /></li>
          ))}
        </ul>
      )}
    </div>
  );
}

function FindingRow({ f, agents, latest }: { f: Finding; agents: Agent[]; latest: Run[] }) {
  const [open, setOpen] = useState(false);
  const disagreement = f.type === "posture_disagreement";
  const summary = f.edr_context?.length ? f.summary.split("; EDR also flags")[0] + "." : f.summary;
  return (
    <li>
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open}
        className="grid w-full gap-2 py-3 text-left hover:bg-white/[0.02] md:grid-cols-[170px_1fr_20px]">
        <span className="space-y-1">
          <span className={`inline-block border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${disagreement ? "border-amber/60 text-amber" : "border-crimson/60 text-crimson"}`}>
            {disagreement ? "disagreement" : "blind spot"}
          </span>
          <span className="block font-mono text-[11px] text-muted">{f.host}{f.vendor ? ` · ${f.vendor}` : ""}</span>
        </span>
        <span className="space-y-1">
          <span className="block text-sm">{summary}</span>
          {f.edr_context && f.edr_context.length > 0 && (
            <span className="block border-l border-line pl-3 font-mono text-[11px] text-muted">EDR also flags: {f.edr_context.join("; ")}</span>
          )}
        </span>
        <span aria-hidden="true" className="font-mono text-muted">{open ? "−" : "+"}</span>
      </button>
      {open && <Evidence f={f} agent={agents.find((a) => a.hostname === f.host)} latest={latest} />}
    </li>
  );
}

/** The lab side of a finding: the baseline check, or the test's last run and the controls that would stop it. */
function Evidence({ f, agent, latest }: { f: Finding; agent?: Agent; latest: Run[] }) {
  const detail = useApi<AgentDetail>(agent && f.control ? `/api/v1/agents/${agent.id}` : null);
  const test = useApi<TestDetail>(f.test ? `/api/v1/library/${f.test}` : null);
  const run = latest.find((r) => r.test_id === f.test && r.agent_id === agent?.id);
  const check = detail.data?.hygiene?.checks.find((c) => c.id === f.control);
  return (
    <div className="mb-3 grid gap-3 border border-line bg-black/30 p-3 font-mono text-[11px] md:grid-cols-2">
      {f.control && (
        <>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted">EDR says</div>
            <div className="mt-1">{f.edr ? Object.entries(f.edr).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`).join(" · ") : "—"}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted">Driftwatch baseline on {f.host}</div>
            <div className="mt-1">{check ? <><span className={check.status === "pass" ? "text-green" : "text-amber"}>{check.status}</span> · {check.title} · expected {check.expected} · actual <span className="text-ink">{check.actual}</span></> : "loading…"}</div>
          </div>
        </>
      )}
      {f.test && (
        <>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted">latest lab run</div>
            <div className="mt-1 flex items-center gap-2">{run ? <><OutcomeBadge outcome={run.outcome} /><Link to={`/runs/${run.id}`} className="hover:text-cyan">DW-{run.id} · {ago(run.finished_at)}</Link></> : "none"}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted">controls that should stop or reveal it</div>
            <div className="mt-1">{test.data ? (test.data.hardening.length ? test.data.hardening.join(", ") : "none listed in the test") : "loading…"}</div>
            <Link to={`/library/${f.test}`} className="mt-1 inline-block text-cyan hover:underline">open test →</Link>
          </div>
        </>
      )}
      <p className="text-muted md:col-span-2">Fix it on the host or in the EDR console, then let the next scheduled run prove it. Driftwatch only measures.</p>
    </div>
  );
}

function ScoreRing({ percent }: { percent: number }) {
  const r = 34;
  const len = 2 * Math.PI * r;
  const color = percent >= 75 ? "var(--ae-green)" : percent >= 50 ? "var(--ae-amber)" : "var(--ae-crimson)";
  return (
    <svg width="88" height="88" viewBox="0 0 88 88" role="img" aria-label={`secure score ${percent.toFixed(0)} percent`}>
      <circle cx="44" cy="44" r={r} fill="none" stroke="var(--ae-line, #27272a)" strokeWidth="6" />
      <circle cx="44" cy="44" r={r} fill="none" stroke={color} strokeWidth="6" strokeDasharray={`${(percent / 100) * len} ${len}`}
        transform="rotate(-90 44 44)" />
      <text x="44" y="49" textAnchor="middle" className="fill-current font-mono text-[15px]">{percent.toFixed(0)}%</text>
    </svg>
  );
}
