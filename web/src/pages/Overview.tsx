import { CountUp, Panel, TextScramble } from "@portfolio/aegis-ui";
import { Link } from "react-router-dom";
import { useApi } from "../lib/api";
import { BORDER, EXPOSURE_WEIGHTS, TEXT, exposure, failures, pct, verdict, type Tone } from "../lib/health";
import { EMPTY } from "../lib/quips";
import { ago, stamp } from "../lib/time";
import type { Agent, DriftEvent, Run, Summary, TestView } from "../lib/types";
import { Async, OutcomeBadge, SectionTitle } from "../components/ui";

export function Overview() {
  const summary = useApi<Summary>("/api/v1/summary", 15_000);
  const latest = useApi<Run[]>("/api/v1/results/latest", 15_000);
  const drift = useApi<DriftEvent[]>("/api/v1/drift", 30_000);
  const tests = useApi<TestView[]>("/api/v1/library");
  const agents = useApi<Agent[]>("/api/v1/agents", 30_000);
  const byTest = Object.fromEntries((tests.data ?? []).map((t) => [t.id, t]));
  const hosts = Object.fromEntries((agents.data ?? []).map((a) => [a.id, a.hostname]));
  const ready = latest.data && drift.data;
  const v = ready ? verdict(latest.data!, drift.data!) : null;
  const fails = ready ? failures(latest.data!, drift.data!) : [];

  return (
    <div>
      <SectionTitle kicker="console://overview" title="Is the lab still defended?">
        {v && (
          <span className={`border px-3 py-1.5 font-mono text-xs uppercase tracking-wider ${BORDER[v.tone]}`} role="status">
            {v.label}
            {v.label !== "DEFENDED" && ` · ${[v.regressions && `${v.regressions} regressed`, v.gaps && `${v.gaps} known gap${v.gaps > 1 ? "s" : ""}`,
              v.controls && `${v.controls} control${v.controls > 1 ? "s" : ""} drifted`].filter(Boolean).join(" · ")}`}
          </span>
        )}
      </SectionTitle>

      <Async q={summary} label="summary">
        {(s) => (
          <div className="grid grid-cols-2 gap-px border border-line bg-line lg:grid-cols-5">
            <Kpi label="pass rate" text={v ? pct(v.percent) : "—"} suffix={v ? `${v.passed}/${v.total} test × agent pairs` : undefined}
              tone={!v ? "muted" : v.tone} />
            <Kpi label="agents online" value={s.agents.online} suffix={`/ ${s.agents.total}`} tone={s.agents.online < s.agents.total ? "amber" : "green"} />
            <Kpi label="failing now" value={v ? v.regressions + v.gaps : null} suffix={v ? `${v.regressions} regressed · ${v.gaps} gap` : undefined}
              tone={v && v.regressions + v.gaps ? "crimson" : "green"} />
            <Kpi label="verified tests" value={s.tests.verified} suffix={`+${s.tests.approved} awaiting a lab run`} />
            <Kpi label="drafts awaiting a human" value={s.tests.draft} tone={s.tests.draft ? "cyan" : undefined} />
          </div>
        )}
      </Async>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Panel title="Failing now" subtitle="latest run per test and agent that missed its expectation" className="lg:col-span-2">
          <Async q={latest} label="regressions" emptyWhen={() => fails.length === 0} empty={EMPTY.allPassed}>
            {() => (
              <ul className="divide-y divide-line">
                {fails.map(({ run: r, kind }) => (
                  <li key={r.id} className="grid gap-x-4 gap-y-1 py-3 md:grid-cols-[112px_1fr_auto] md:items-start">
                    <OutcomeBadge outcome={r.outcome} className="w-fit" />
                    <div className="min-w-0">
                      <Link to={`/runs/${r.id}`} className="text-sm hover:text-cyan">{byTest[r.test_id]?.name ?? r.test_id}</Link>
                      <div className="mt-0.5 flex flex-wrap gap-x-3 font-mono text-[11px] text-muted">
                        <span>{hosts[r.agent_id] ?? r.agent_id}</span>
                        <span>{byTest[r.test_id]?.attack.techniques.join(" ")}</span>
                        <span>{ago(r.finished_at)}</span>
                      </div>
                    </div>
                    <span className={`w-fit border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${kind === "regression" ? BORDER.crimson : BORDER.amber}`}
                      title={kind === "regression" ? "passed before, fails now" : "has never passed on this agent"}>
                      {kind === "regression" ? "regression" : "known gap"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Async>
        </Panel>
        <Panel title="Drift exposure index" subtitle="a weighted sum you can check by hand">
          {v ? <Exposure v={v} /> : null}
        </Panel>
      </div>

      <Panel title="Latest drift" subtitle="baseline controls and tests that changed state" className="mt-6">
        <Async q={drift} label="drift-overview" emptyWhen={(d) => d.length === 0} empty={EMPTY.noDrift}>
          {(events) => (
            <ul className="divide-y divide-line">
              {events.slice(0, 5).map((e) => (
                <li key={e.id} className="grid gap-1 py-3 md:grid-cols-[180px_90px_1fr_auto] md:items-center md:gap-4">
                  <span className="font-mono text-xs text-amber">{stamp(e.exact_change_at ?? e.first_bad_at)}</span>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-muted">{e.kind === "control" ? "control" : "test"}</span>
                  <span className="text-sm">
                    <span className="text-muted">{e.hostname}</span> · <TextScramble text={e.details.title ?? e.subject} />
                    {e.details.change_event?.user && <span className="text-muted"> · changed by <span className="font-mono text-ink">{e.details.change_event.user}</span></span>}
                  </span>
                  <Link to="/drift" className="font-mono text-[11px] text-muted hover:text-amber">{e.exact_change_at ? "exact moment known →" : "window only →"}</Link>
                </li>
              ))}
            </ul>
          )}
        </Async>
      </Panel>
    </div>
  );
}

function Exposure({ v }: { v: NonNullable<ReturnType<typeof verdict>> }) {
  const e = exposure(v);
  const tone: Tone = e.total === 0 ? "green" : e.total < 30 ? "amber" : "crimson";
  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-2">
        <span className={`font-mono text-4xl font-bold ${TEXT[tone]}`}>{e.total}</span>
        <span className="font-mono text-xs text-muted">/ 100 · lower is better</span>
      </div>
      <div className="flex h-2 border border-line" aria-hidden="true">
        {e.parts.filter((p) => p.points).map((p) => (
          <div key={p.key} style={{ width: `${p.points}%` }} className={p.tone === "crimson" ? "bg-crimson/70" : "bg-amber/60"} />
        ))}
      </div>
      <dl className="space-y-1.5 font-mono text-xs">
        {e.parts.map((p) => (
          <div key={p.key} className="flex justify-between gap-3">
            <dt className="text-muted">{p.count} {p.label} × {EXPOSURE_WEIGHTS[p.key as keyof typeof EXPOSURE_WEIGHTS]}</dt>
            <dd className={p.points ? TEXT[p.tone] : "text-muted"}>+{p.points}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function Kpi({ label, value, text, suffix, tone }: { label: string; value?: number | null; text?: string; suffix?: string; tone?: Tone }) {
  return (
    <div className="bg-bg/90 p-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted">{label}</div>
      <div className={`mt-2 font-mono text-3xl font-bold ${tone ? TEXT[tone] : "text-ink"}`}>
        {text ?? (value === null || value === undefined ? "—" : <CountUp value={value} />)}
      </div>
      {suffix && <div className="mt-1 font-mono text-[11px] text-muted">{suffix}</div>}
    </div>
  );
}
