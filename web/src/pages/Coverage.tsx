import { Button, Panel } from "@portfolio/aegis-ui";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "../lib/api";
import { stamp } from "../lib/time";
import type { Agent, NavigatorLayer, Run, TestView } from "../lib/types";
import { Async, Mono, OutcomeBadge, SectionTitle, useToast } from "../components/ui";

type Cell = NavigatorLayer["techniques"][number];
type Band = "detected" | "partial" | "missed";

const band = (score: number): Band => (score >= 100 ? "detected" : score > 0 ? "partial" : "missed");
// Same semantics as every other page: green works, amber is partial, crimson is a miss.
const BAND_STYLE: Record<Band, string> = {
  detected: "border-green/60 bg-green/10 text-green",
  partial: "border-amber/60 bg-amber/15 text-amber",
  missed: "border-crimson/60 bg-crimson/15 text-crimson",
};

// Enterprise ATT&CK tactics in matrix order, and the tactics each catalog-emulated technique belongs to.
// A technique can sit under several tactics, exactly as it does in the ATT&CK matrix.
const TACTICS = [
  ["TA0002", "execution"], ["TA0003", "persistence"], ["TA0004", "privilege-escalation"], ["TA0005", "defense-evasion"],
  ["TA0006", "credential-access"], ["TA0007", "discovery"], ["TA0011", "command-and-control"],
] as const;
const TECHNIQUE_TACTICS: Record<string, string[]> = {
  T1027: ["defense-evasion"],
  T1033: ["discovery"], T1016: ["discovery"], T1057: ["discovery"], T1069: ["discovery"], T1082: ["discovery"],
  T1053: ["execution", "persistence", "privilege-escalation"],
  T1059: ["execution"],
  T1071: ["command-and-control"], T1105: ["command-and-control"],
  T1547: ["persistence", "privilege-escalation"],
  T1552: ["credential-access"],
};

const tacticsOf = (id: string) => TECHNIQUE_TACTICS[id.split(".")[0]] ?? ["unmapped"];

export function Coverage() {
  const layer = useApi<NavigatorLayer>("/api/v1/coverage/navigator");
  const tests = useApi<TestView[]>("/api/v1/library");
  const runs = useApi<Run[]>("/api/v1/runs?limit=300");
  const agents = useApi<Agent[]>("/api/v1/agents");
  const toast = useToast();
  const [focus, setFocus] = useState<Cell | null>(null);

  const columns = useMemo(() => {
    const cells = layer.data?.techniques ?? [];
    return TACTICS.map(([id, name]) => ({ id, name, cells: cells.filter((c) => tacticsOf(c.techniqueID).includes(name)) }))
      .filter((col) => col.cells.length);
  }, [layer.data]);

  const counts = useMemo(() => {
    const c: Record<Band, number> = { detected: 0, partial: 0, missed: 0 };
    for (const t of layer.data?.techniques ?? []) c[band(t.score)] += 1;
    return c;
  }, [layer.data]);

  const exportLayer = () => {
    if (!layer.data) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(layer.data, null, 2)], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "driftwatch-navigator-layer.json" });
    a.click();
    URL.revokeObjectURL(url);
    toast("Layer saved. Drop it into ATT&CK Navigator → Open Existing Layer.", "ok");
  };

  return (
    <div>
      <SectionTitle kicker="coverage://att&ck" title="Measured, not claimed">
        <Button variant="ghost" onClick={exportLayer} disabled={!layer.data}>Export Navigator layer</Button>
      </SectionTitle>
      <p className="mb-5 max-w-3xl text-sm text-muted">
        Every cell is a technique a test actually executed in the lab, scored from the latest evaluated run on each agent.
        A technique nobody tested is not here at all, because a blank cell is more honest than a hopeful one.
      </p>
      <Async q={layer} label="coverage" emptyWhen={(l) => l.techniques.length === 0}
        empty="No coverage yet. The ATT&CK matrix is a lovely wallpaper until something runs.">
        {() => (
          <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
            <div className="min-w-0">
              <div className="mb-3 flex flex-wrap gap-4 font-mono text-[11px] text-muted">
                {(Object.keys(counts) as Band[]).map((b) => (
                  <span key={b} className="flex items-center gap-2"><span className={`h-3 w-3 border ${BAND_STYLE[b]}`} />{b} <span className="text-ink">{counts[b]}</span></span>
                ))}
                <span>· techniques under several tactics appear in each</span>
              </div>
              <div className="pb-2">
                <div className="grid grid-cols-[repeat(auto-fill,minmax(128px,1fr))] gap-x-2 gap-y-5">
                  {columns.map((col) => (
                    <section key={col.id} aria-label={col.name} className="min-w-0">
                      <h2 className="mb-2 border-b border-line pb-1.5 font-mono text-[10px] uppercase tracking-[0.15em] text-muted">
                        {col.name.replace(/-/g, " ")}<span className="block text-[9px] text-muted/60">{col.id} · {col.cells.length}</span>
                      </h2>
                      <div className="grid gap-1.5">
                        {col.cells.map((c) => (
                          <button key={c.techniqueID} type="button" onClick={() => setFocus(c)} aria-pressed={focus?.techniqueID === c.techniqueID}
                            className={`border px-2 py-1.5 text-left font-mono text-xs transition-transform hover:-translate-y-0.5 ${BAND_STYLE[band(c.score)]} ${focus?.techniqueID === c.techniqueID ? "ring-1 ring-current" : ""}`}>
                            <div>{c.techniqueID}</div>
                            <div className="text-[10px] opacity-80">score {c.score}</div>
                          </button>
                        ))}
                      </div>
                    </section>
                  ))}
                </div>
              </div>
            </div>
            <TechniquePanel focus={focus} tests={tests.data ?? []} runs={runs.data ?? []}
              hosts={Object.fromEntries((agents.data ?? []).map((a) => [a.id, a.hostname]))} />
          </div>
        )}
      </Async>
    </div>
  );
}

function TechniquePanel({ focus, tests, runs, hosts }: { focus: Cell | null; tests: TestView[]; runs: Run[]; hosts: Record<string, string> }) {
  if (!focus) {
    return (
      <Panel title="Pick a technique" subtitle="click any cell for the runs behind it" className="h-fit xl:sticky xl:top-16">
        <p className="text-sm text-muted">Green was detected or prevented everywhere it ran. Amber is caught on one host and missed on another. Crimson is the reading list.</p>
      </Panel>
    );
  }
  const id = focus.techniqueID;
  const related = tests.filter((t) => t.attack.techniques.some((x) => x === id || x.startsWith(`${id}.`) || id.startsWith(`${x}.`)));
  const ids = new Set(related.map((t) => t.id));
  const history = runs.filter((r) => ids.has(r.test_id) && r.status === "evaluated").slice(0, 12);
  return (
    <Panel title={id} subtitle={`${band(focus.score)} · ${tacticsOf(id).join(", ")}`} className="h-fit xl:sticky xl:top-16">
      <h3 className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted">tests</h3>
      <ul className="mt-1 space-y-1">
        {related.map((t) => <li key={t.id}><Link to={`/library/${t.id}`} className="text-sm hover:text-cyan">{t.name}</Link></li>)}
      </ul>
      <h3 className="mt-4 font-mono text-[10px] uppercase tracking-[0.2em] text-muted">latest runs</h3>
      {history.length === 0 ? <p className="mt-1 font-mono text-xs text-muted">No evaluated runs in this window.</p> : (
        <ul className="mt-1 divide-y divide-line">
          {history.map((r) => (
            <li key={r.id}>
              <Link to={`/runs/${r.id}`} className="grid grid-cols-[96px_1fr] items-center gap-2 py-1.5 hover:bg-white/[0.03]">
                <span className="flex"><OutcomeBadge outcome={r.outcome} /></span>
                <Mono className="truncate text-muted">{stamp(r.finished_at).slice(5, 16)} · {hosts[r.agent_id] ?? r.agent_id}</Mono>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <ul className="mt-4 space-y-1 border-t border-line pt-3">
        {focus.comment.split("\n").filter(Boolean).map((line) => <li key={line}><Mono className="text-ink/80">{line}</Mono></li>)}
      </ul>
    </Panel>
  );
}
