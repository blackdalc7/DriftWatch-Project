import { GhostAnnotation, HoldToConfirm, Panel, SlideToExecute, StatusBadge, cn } from "@portfolio/aegis-ui";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { send, useApi } from "../lib/api";
import { EMPTY } from "../lib/quips";
import { stamp } from "../lib/time";
import type { Run, TestDetail, TestView } from "../lib/types";
import { StepFlow } from "../components/StepFlow";
import { Async, SectionTitle, useToast } from "../components/ui";

const STAGES = ["draft", "approved", "verified"] as const;

type Health = "passing" | "failing" | "untested";
const health = (t: TestView): Health => (!t.results.runs ? "untested" : t.results.passed === t.results.runs ? "passing" : "failing");

export function Library() {
  const { testId } = useParams();
  const tests = useApi<TestView[]>("/api/v1/library", 30_000);
  const [stage, setStage] = useState<"all" | TestView["status"]>("all");
  const [os, setOs] = useState<"all" | "windows" | "linux">("all");
  const [result, setResult] = useState<"all" | Health>("all");
  const all = tests.data ?? [];
  const list = all.filter((t) => (stage === "all" || t.status === stage) && (os === "all" || t.platforms.includes(os))
    && (result === "all" || health(t) === result));
  return (
    <div>
      <SectionTitle kicker="library://tests" title="Tests, gated by humans and lab runs" />
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2" role="toolbar" aria-label="filters">
        <Filter label="lifecycle" value={stage} onChange={setStage} options={["all", ...STAGES]}
          count={(f) => (f === "all" ? all.length : all.filter((t) => t.status === f).length)} />
        <Filter label="os" value={os} onChange={setOs} options={["all", "windows", "linux"] as const} />
        <Filter label="result" value={result} onChange={setResult} options={["all", "failing", "passing", "untested"] as const}
          count={(f) => (f === "all" ? undefined : all.filter((t) => health(t) === f).length)} />
      </div>
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <Async q={tests} label="library" emptyWhen={() => list.length === 0} empty={stage === "draft" ? EMPTY.noDrafts : "Nothing matches those filters."}>
          {() => (
            <ul className="grid content-start gap-1.5">
              {list.map((t) => (
                <li key={t.id}>
                  <Link to={`/library/${t.id}`} aria-current={t.id === testId ? "true" : undefined}
                    className={cn("grid grid-cols-[76px_minmax(0,1fr)_auto] items-center gap-3 border bg-black/30 px-3 py-2.5 transition hover:border-cyan/60",
                      t.id === testId ? "border-cyan/70 dw-tint-bg" : "border-line")}>
                    <Stage status={t.status} />
                    <span className="min-w-0">
                      <span className="block text-sm font-medium leading-snug">{t.name}</span>
                      <span className="grid grid-cols-[minmax(0,1fr)_120px_64px] gap-2 font-mono text-[10px] text-muted">
                        <span className="truncate">{t.id}</span>
                        <span className="truncate text-cyan/80">{t.attack.techniques.join(" ")}</span>
                        <span>{t.platforms.map((p) => (p === "windows" ? "win" : "lin")).join("+")}</span>
                      </span>
                    </span>
                    <HealthPill t={t} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Async>
        <div className="xl:sticky xl:top-16 xl:self-start">{testId ? <Detail id={testId} onChange={tests.reload} /> : <Hint />}</div>
      </div>
    </div>
  );
}

function Filter<T extends string>({ label, value, onChange, options, count }: {
  label: string; value: T; onChange: (v: T) => void; options: readonly T[]; count?: (v: T) => number | undefined;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="mr-1 font-mono text-[10px] uppercase tracking-wider text-muted">{label}</span>
      {options.map((f) => (
        <button key={f} type="button" onClick={() => onChange(f)} aria-pressed={value === f}
          className={cn("border px-2 py-1 font-mono text-[11px] uppercase", value === f ? "border-cyan text-cyan" : "border-line text-muted hover:text-ink")}>
          {f}{count?.(f) !== undefined && ` ${count(f)}`}
        </button>
      ))}
    </div>
  );
}

function HealthPill({ t }: { t: TestView }) {
  const h = health(t);
  const text = h === "untested" ? (t.status === "draft" ? "cannot run" : "awaiting run") : `${t.results.passed}/${t.results.runs} agents pass`;
  const tone = h === "passing" ? "border-green/50 text-green" : h === "failing" ? "border-crimson/70 bg-crimson/10 text-crimson" : "border-line text-muted";
  return <span className={cn("w-[118px] border px-1.5 py-0.5 text-center font-mono text-[10px] uppercase tracking-wider", tone)}>{text}</span>;
}

function Stage({ status }: { status: TestView["status"] }) {
  const tone = { draft: "border-dashed border-line text-muted", approved: "border-cyan/60 text-cyan", verified: "border-ink/40 text-ink/90" }[status];
  return <span className={cn("border px-1.5 py-0.5 text-center font-mono text-[9px] uppercase tracking-wider", tone)}>{status}</span>;
}

function Hint() {
  return (
    <Panel title="Lifecycle" subtitle="how a test earns the right to run unattended">
      <ol className="space-y-3 font-mono text-xs text-muted">
        <li><span className="text-muted">draft</span> · written by a person or drafted by Claude from a CISA advisory. Mapped only to Safe Action Catalog steps. Cannot run.</li>
        <li><span className="text-cyan">approved</span> · a named human held the button. Can run on lab agents for verification.</li>
        <li><span className="text-ink">verified</span> · one clean lab run with every step executed. Only now can schedules pick it.</li>
      </ol>
    </Panel>
  );
}

function Detail({ id, onChange }: { id: string; onChange: () => void }) {
  const q = useApi<TestDetail>(`/api/v1/library/${id}`);
  const toast = useToast();
  const navigate = useNavigate();
  const [tab, setTab] = useState<"flow" | "yaml" | "rules">("flow");
  const [reviewer, setReviewer] = useState("");

  const approve = async () => {
    const res = await send<TestDetail>("POST", `/api/v1/library/${id}/approve`, { reviewer: reviewer.trim(), notes: "approved in the UI" });
    toast(res.simulated ? "Replay mode: approval simulated. The draft remains a draft." : `${id} approved by ${reviewer}. Next stop: a clean lab run.`, res.simulated ? "warn" : "ok");
    q.reload(); onChange();
  };
  const queue = async () => {
    const res = await send<Run[]>("POST", "/api/v1/runs", { test_id: id, tags: ["lab"] });
    if (res.simulated) toast("Replay mode: bundles stay unsigned and unsent.", "warn");
    else { toast(`Queued on ${res.data?.length ?? 0} agent(s). Signed bundles go out on the next heartbeat.`, "ok"); navigate("/runs"); }
  };

  return (
    <Async q={q} label={`test-${id}`}>
      {(t) => (
        <Panel label={t.name} title={t.name} subtitle={<span className="font-mono">{t.id} · v{t.version} · {t.attack.tactic} · severity {t.severity}</span>}>
          <p className="text-sm text-muted">{t.description}</p>

          <ol className="mt-4 grid grid-cols-3 gap-px border border-line bg-line" aria-label="Lifecycle">
            {STAGES.map((s, i) => {
              const reached = STAGES.indexOf(t.status) >= i;
              return (
                <li key={s} className={cn("bg-bg p-2 font-mono text-[10px] uppercase", reached ? "text-ink" : "text-muted/50")}>
                  <span className={reached ? "dw-tint" : ""}>{reached ? "■" : "□"}</span> {s}
                  <div className="mt-1 normal-case text-muted">
                    {s === "draft" && (t.provenance.generated_by ?? t.provenance.source)}
                    {s === "approved" && (t.review?.approved_by ? `${t.review.approved_by} · ${stamp(t.review.approved_at).slice(0, 10)}` : "needs a human")}
                    {s === "verified" && (t.verification?.run_id ? `run ${t.verification.run_id}` : "needs a clean lab run")}
                  </div>
                </li>
              );
            })}
          </ol>

          {t.provenance.generated_by?.startsWith("claude") && (
            <GhostAnnotation className="mt-4" source={t.provenance.generated_by} verified={t.status !== "draft"}
              text={`Drafted from ${t.provenance.reference ?? "a CISA advisory"}. Every step was re-validated against the Safe Action Catalog; a human still has to approve it.`}
              citations={t.provenance.reference ? [{ ref: t.provenance.reference, quote: t.description }] : []} />
          )}

          <div className="mt-5 flex gap-1 border-b border-line" role="tablist">
            {(["flow", "yaml", "rules"] as const).map((x) => (
              <button key={x} role="tab" aria-selected={tab === x} type="button" onClick={() => setTab(x)}
                className={cn("-mb-px border-b px-3 py-1.5 font-mono text-[11px] uppercase", tab === x ? "border-cyan text-cyan" : "border-transparent text-muted")}>{x}</button>
            ))}
          </div>
          <div className="mt-3">
            {tab === "flow" && <StepFlow test={t} />}
            {tab === "yaml" && <pre className="max-h-[420px] overflow-auto border border-line bg-black/60 p-3 font-mono text-[11px] leading-relaxed text-ink/90">{t.yaml}</pre>}
            {tab === "rules" && (
              <div className="space-y-3">
                {t.rules.length === 0 && <p className="font-mono text-xs text-muted">No expected rule. Prevention tests are scored on the block alone.</p>}
                {t.rules.map((r) => (
                  <div key={r.id} className="border border-line p-3">
                    <div className="flex items-center gap-2 text-sm">{r.title}<StatusBadge status="detected" className="ml-auto" /></div>
                    <div className="mt-1 font-mono text-[10px] text-muted">{r.id} · {r.path}</div>
                    <pre className="mt-2 overflow-x-auto bg-black/60 p-2 font-mono text-[11px] text-green/90">{r.kql}</pre>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-5 grid gap-4 border-t border-line pt-4 md:grid-cols-2">
            {t.status === "draft" ? (
              <div className="space-y-2">
                <label className="block font-mono text-[10px] uppercase tracking-wider text-muted" htmlFor="reviewer">reviewer (your name goes in the YAML)</label>
                <input id="reviewer" value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="e.g. alvin"
                  className="w-full border border-line bg-black/40 px-2 py-1.5 font-mono text-xs focus:border-cyan focus:outline-none" />
                <HoldToConfirm label="Hold to approve" holdingLabel="Signing off with your name…" tone="cyan" duration={2000} onConfirm={approve}
                  disabled={!reviewer.trim()} disabledReason="type your name first: approvals are attributed" />
              </div>
            ) : (
              <div className="font-mono text-xs text-muted">Reviewed by <span className="text-ink">{t.review?.approved_by}</span>{t.review?.notes && <> · “{t.review.notes}”</>}</div>
            )}
            <div className="space-y-2">
              <div className="font-mono text-[10px] uppercase tracking-wider text-muted">{t.status === "approved" ? "first run verifies it" : "run on every #lab agent"}</div>
              <SlideToExecute label="slide to dispatch" doneLabel="Signed & queued" tone="cyan" onExecute={queue}
                disabled={!t.dispatchable} disabledReason="drafts cannot run until a human approves them" />
            </div>
          </div>
        </Panel>
      )}
    </Async>
  );
}
