import { HexCascade, Panel, cn } from "@portfolio/aegis-ui";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, download, get, useApi } from "../lib/api";
import { sha256Hex, verifyBundle, type Verification } from "../lib/evidence";
import { EMPTY } from "../lib/quips";
import { day, stamp } from "../lib/time";
import type { Agent, Run, Summary, TestView } from "../lib/types";
import { HexReveal } from "../components/HexReveal";
import { Async, OutcomeBadge, SectionTitle, useToast } from "../components/ui";

type OutcomeFilter = "all" | "failing" | "missed" | "detected" | "prevented" | "error";

export function Runs() {
  const { runId } = useParams();
  const runs = useApi<Run[]>("/api/v1/runs?limit=300", 10_000);
  const tests = useApi<TestView[]>("/api/v1/library");
  const agents = useApi<Agent[]>("/api/v1/agents");
  const [hideHygiene, setHideHygiene] = useState(true);
  const [outcome, setOutcome] = useState<OutcomeFilter>("all");
  const [host, setHost] = useState("all");
  const names = Object.fromEntries((tests.data ?? []).map((t) => [t.id, t.name]));
  const hosts = Object.fromEntries((agents.data ?? []).map((a) => [a.id, a.hostname]));
  const list = (runs.data ?? []).filter((r) => (!hideHygiene || r.test_id !== "builtin.hygiene")
    && (host === "all" || r.agent_id === host)
    && (outcome === "all" || (outcome === "failing" ? r.passed === false : r.outcome === outcome)));
  const batches = useMemo(() => {
    const out: { day: string; runs: Run[] }[] = [];
    for (const r of list) {
      const d = (r.created_at ?? "").slice(0, 10);
      if (out.at(-1)?.day !== d) out.push({ day: d, runs: [] });
      out.at(-1)!.runs.push(r);
    }
    return out;
  }, [list]);
  const selected = runId ?? list[0]?.id;
  const pill = (active: boolean) => cn("border px-2 py-1 font-mono text-[11px] uppercase", active ? "border-cyan text-cyan" : "border-line text-muted hover:text-ink");
  return (
    <div>
      <SectionTitle kicker="runs://evidence" title="Every run, scored and signed" />
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2" role="toolbar" aria-label="filters">
        <div className="flex flex-wrap items-center gap-1">
          <span className="mr-1 font-mono text-[10px] uppercase tracking-wider text-muted">outcome</span>
          {(["all", "failing", "missed", "detected", "prevented", "error"] as const).map((o) => (
            <button key={o} type="button" aria-pressed={outcome === o} onClick={() => setOutcome(o)} className={pill(outcome === o)}>{o}</button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <span className="mr-1 font-mono text-[10px] uppercase tracking-wider text-muted">host</span>
          {[["all", "all"], ...(agents.data ?? []).map((a) => [a.id, a.hostname])].map(([id, label]) => (
            <button key={id} type="button" aria-pressed={host === id} onClick={() => setHost(id)} className={pill(host === id)}>{label}</button>
          ))}
        </div>
        <label className="flex items-center gap-2 font-mono text-[11px] text-muted">
          <input type="checkbox" checked={hideHygiene} onChange={(e) => setHideHygiene(e.target.checked)} className="accent-cyan" /> hide hygiene collections
        </label>
      </div>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Async q={runs} label="runs" emptyWhen={() => list.length === 0} empty={runs.data?.length ? "No run matches those filters." : EMPTY.noRuns}>
          {() => (
            <div className="border border-line lg:max-h-[calc(100vh-220px)] lg:overflow-y-auto">
              {batches.map((b) => {
                const scored = b.runs.filter((r) => r.passed !== null);
                const ok = scored.filter((r) => r.passed).length;
                return (
                  <section key={b.day} aria-label={`runs on ${b.day}`}>
                    <h2 className="sticky top-0 z-10 flex justify-between border-b border-line bg-bg/95 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-muted backdrop-blur">
                      <span>{b.day ? day(`${b.day}T00:00:00Z`) : "undated"} batch</span>
                      <span className={ok < scored.length ? "text-amber" : "text-green"}>{ok}/{scored.length} passed</span>
                    </h2>
                    <ol>
                      {b.runs.map((r) => (
                        <li key={r.id}>
                          <Link to={`/runs/${r.id}`} aria-current={r.id === selected ? "true" : undefined}
                            className={cn("grid grid-cols-[100px_minmax(0,1fr)_auto] items-center gap-3 border-b border-line/60 px-3 py-2 hover:bg-white/[0.03]", r.id === selected && "bg-cyan/[0.06] shadow-[inset_2px_0_0_var(--ae-cyan)]")}>
                            <span className="flex">{r.status === "evaluated" ? <OutcomeBadge outcome={r.outcome} /> : <span className="border border-line px-1.5 py-0.5 font-mono text-[10px] uppercase text-cyan">{r.status}</span>}</span>
                            <span className="min-w-0">
                              <span className="block truncate text-sm" title={names[r.test_id] ?? r.test_id}>{names[r.test_id] ?? r.test_id}</span>
                              <span className="block truncate font-mono text-[10px] text-muted">{hosts[r.agent_id] ?? r.agent_id} · {r.source} · DW-{r.id}</span>
                            </span>
                            <span className="text-right font-mono text-[10px] text-muted">{stamp(r.finished_at ?? r.created_at).slice(11, 16)}{r.passed === false && <span className="block text-crimson">fail</span>}</span>
                          </Link>
                        </li>
                      ))}
                    </ol>
                  </section>
                );
              })}
            </div>
          )}
        </Async>
        <div className="lg:sticky lg:top-16 lg:self-start">
          {selected ? <RunDetail id={selected} name={names} /> : <Panel title="Pick a run"><p className="font-mono text-xs text-muted">Select a run to see its steps, the scoring, and to open its signed evidence bundle.</p></Panel>}
        </div>
      </div>
    </div>
  );
}

function RunDetail({ id, name }: { id: string; name: Record<string, string> }) {
  const q = useApi<Run>(`/api/v1/runs/${id}`);
  return (
    <Async q={q} label={`run-${id}`}>
      {(r) => (
        <div className="space-y-6">
          <Panel title={name[r.test_id] ?? r.test_id} subtitle={<span className="font-mono">DW-{r.id} · {r.agent_id} · {r.status}</span>}
            actions={r.status === "evaluated" ? <OutcomeBadge outcome={r.outcome} /> : undefined}>
            <dl className="grid grid-cols-2 gap-px border border-line bg-line font-mono text-[11px] sm:grid-cols-4">
              {(["created_at", "dispatched_at", "finished_at", "evaluated_at"] as const).map((k) => (
                <div key={k} className="bg-bg p-2"><dt className="text-[10px] uppercase text-muted">{k.replace("_at", "")}</dt><dd className="mt-1">{stamp(r[k] ?? null).slice(5)}</dd></div>
              ))}
            </dl>
            <h3 className="mt-4 font-mono text-[10px] uppercase tracking-[0.2em] text-muted">steps</h3>
            <ul className="mt-2 space-y-1">
              {(r.step_results ?? []).map((s) => (
                <li key={s.index} className="border border-line px-2 py-1.5 font-mono text-[11px]">
                  <span className={s.status === "executed" ? "text-cyan" : s.status === "blocked" ? "text-[var(--ae-status-prevented)]" : "text-crimson"}>{s.status}</span>
                  <span className="ml-2 text-ink">{s.action}</span>
                  <span className="ml-2 text-muted">cleanup {s.cleanup ?? "—"}</span>
                  {s.observables && Object.entries(s.observables).map(([k, v]) => <div key={k} className="mt-0.5 truncate text-muted">{k}: <span className="text-ink/80">{String(v)}</span></div>)}
                </li>
              ))}
            </ul>
            {r.evaluation && (
              <>
                <h3 className="mt-4 font-mono text-[10px] uppercase tracking-[0.2em] text-muted">scoring</h3>
                <div className="mt-2 grid gap-2 font-mono text-[11px] sm:grid-cols-3">
                  <div className="border border-line p-2">telemetry <span className={r.evaluation.telemetry_seen ? "text-green" : "text-crimson"}>{r.evaluation.telemetry_seen ? `${r.evaluation.telemetry_hits} hits` : "none"}</span></div>
                  <div className="border border-line p-2">quality <span className="text-ink">{r.evaluation.detection_quality ?? "—"}</span></div>
                  <div className="border border-line p-2">alerts <span className="text-ink">{r.evaluation.alerts?.length ?? 0}</span>{r.evaluation.missing_detections?.length ? <span className="text-crimson"> · {r.evaluation.missing_detections.length} expected rule(s) silent</span> : null}</div>
                </div>
                {r.evaluation.notes?.map((n) => <p key={n} className="mt-2 font-mono text-[11px] text-amber">› {n}</p>)}
              </>
            )}
          </Panel>
          {r.status === "evaluated" && r.test_id !== "builtin.hygiene" && <EvidencePanel run={r} />}
        </div>
      )}
    </Async>
  );
}

function EvidencePanel({ run }: { run: Run }) {
  const toast = useToast();
  const [state, setState] = useState<{ v: Verification; url: string } | "loading" | null>(null);
  const open = async () => {
    setState("loading");
    try {
      const blob = await download(`/api/v1/runs/${run.id}/evidence`);
      const v = await verifyBundle(await blob.arrayBuffer());
      // The bundle carries its public key; check it is the key this server signs with (same key id).
      const keyId = (await sha256Hex(new TextEncoder().encode(v.publicKey))).slice(0, 16);
      const serverKey = (await get<Summary>("/api/v1/summary")).signing_key_id;
      v.keyMatchesServer = keyId === serverKey;
      await new Promise((res) => setTimeout(res, 650)); // let the hex cascade breathe; it is the fun part
      setState({ v, url: URL.createObjectURL(blob) });
    } catch (e) {
      setState(null);
      toast(e instanceof ApiError ? e.message : String(e), "bad");
    }
  };
  return (
    <Panel title="Evidence bundle" subtitle="manifest + SHA-256 per file + Ed25519 signature, verified in your browser" scanlines
      actions={state && state !== "loading" ? <a href={state.url} download={`evidence-${run.id}.zip`} className="border border-line px-2 py-1 font-mono text-[10px] uppercase hover:border-cyan hover:text-cyan">download .zip</a> : undefined}>
      {state === null && (
        <button type="button" onClick={open} className="w-full border border-dashed border-line py-6 font-mono text-xs text-muted hover:border-cyan hover:text-cyan">
          open & verify signed evidence for DW-{run.id}
        </button>
      )}
      {state === "loading" && <HexCascade rows={7} label="decrypting… (it is not encrypted, it is just dramatic)" />}
      {state && state !== "loading" && <EvidenceView v={state.v} />}
    </Panel>
  );
}

function EvidenceView({ v }: { v: Verification }) {
  const m = v.manifest;
  const allOk = v.hashes.every((h) => h.ok) && v.unexpected.length === 0;
  const sigTone = v.signature === "valid" ? "text-green border-green/60" : v.signature === "invalid" ? "text-crimson border-crimson/60" : "text-amber border-amber/60";
  return (
    <div className="space-y-3 font-mono text-[11px]">
      <div className="grid gap-2 sm:grid-cols-2">
        <div className={cn("border p-2", sigTone)}>signature · {v.signature === "valid" ? "valid ✓" : v.signature === "invalid" ? "INVALID ✕" : "browser lacks Ed25519; run driftwatch evidence verify"}</div>
        <div className={cn("border p-2", allOk ? "border-green/60 text-green" : "border-crimson/60 text-crimson")}>file hashes · {allOk ? `${v.hashes.length}/${v.hashes.length} match` : "MISMATCH"}</div>
      </div>
      <div className="border border-line bg-black/60 p-3 leading-relaxed">
        <div><span className="text-muted">run     </span><HexReveal text={m.marker} /></div>
        <div><span className="text-muted">test    </span><HexReveal text={`${m.test.id} v${m.test.version}`} delay={80} /></div>
        <div><span className="text-muted">agent   </span><HexReveal text={`${m.agent.hostname} (${m.agent.id})`} delay={160} /></div>
        <div><span className="text-muted">outcome </span><HexReveal text={`${m.outcome} · ${m.passed ? "pass" : "fail"} · quality ${m.detection_quality ?? "n/a"}`} delay={240} /></div>
        <div><span className="text-muted">bundle  </span><HexReveal text={`sha256 ${v.bundleSha256}`} delay={320} className="break-all" /></div>
        <div><span className="text-muted">key     </span><HexReveal text={v.publicKey} delay={400} className="break-all" />
          <span className={v.keyMatchesServer ? "text-green" : "text-crimson"}> {v.keyMatchesServer ? "· this server's signing key ✓" : "· NOT this server's key"}</span></div>
      </div>
      <ul className="space-y-1">
        {v.hashes.map((h, i) => (
          <li key={h.name} className="grid grid-cols-[1fr_auto] gap-2 border border-line px-2 py-1">
            <span className="truncate text-ink">{h.name}</span>
            <span className={h.ok ? "text-green" : "text-crimson"}>{h.ok ? "✓" : "✕"}</span>
            <HexReveal text={h.actual} delay={450 + i * 70} className="col-span-2 break-all text-[10px] text-muted" />
          </li>
        ))}
      </ul>
      {m.alerts.length > 0 && <div className="text-muted">alerts: {m.alerts.map((a) => <span key={a.rule_id + a.timestamp} className="mr-2 text-green">{a.rule_name}</span>)}</div>}
    </div>
  );
}
