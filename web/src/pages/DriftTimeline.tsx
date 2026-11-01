import { Panel, TextScramble, cn } from "@portfolio/aegis-ui";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { get, useApi } from "../lib/api";
import { controlsAt, driftLevel, eventTime, eventsUntil, snap, tint, type ControlState } from "../lib/drift";
import { EMPTY } from "../lib/quips";
import { failures } from "../lib/health";
import { clock, dur, ms, stamp } from "../lib/time";
import type { Agent, DriftEvent, HygieneSnapshot, Run } from "../lib/types";
import { Async, SectionTitle, useLab } from "../components/ui";

/**
 * The drift timeline scrubber. Drag (or use ← → and [ ]) through time: every host's baseline is shown as
 * it was at that instant, the drift events light up as you pass them, and the whole console's accent
 * shifts from terminal green to CRT amber as controls break. The scrubber is magnetic near the exact
 * moment a change was pinpointed from Elastic (Defender 5007, Sysmon registry writes, auditd).
 */
export function DriftTimeline() {
  const agents = useApi<Agent[]>("/api/v1/agents");
  const drift = useApi<DriftEvent[]>("/api/v1/drift", 30_000);
  const latest = useApi<Run[]>("/api/v1/results/latest", 30_000);
  const [params] = useSearchParams();
  const host = params.get("host");
  const [history, setHistory] = useState<Record<string, HygieneSnapshot[]>>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const out: Record<string, HygieneSnapshot[]> = {};
      for (const a of agents.data ?? []) {
        try { out[a.id] = await get<HygieneSnapshot[]>(`/api/v1/hygiene/${a.id}?limit=200`); } catch { out[a.id] = []; }
      }
      if (!cancelled) setHistory(out);
    })();
    return () => { cancelled = true; };
  }, [agents.data]);

  const shown = (agents.data ?? []).filter((a) => !host || a.hostname === host);
  return (
    <div>
      <SectionTitle kicker="drift://timeline" title="Scrub to the moment the baseline broke">
        {host && <span className="border border-amber/60 px-2 py-1 font-mono text-[11px] text-amber">host: {host}</span>}
      </SectionTitle>
      <Async q={drift} label="drift">
        {(events) => {
          const gaps = failures(latest.data ?? [], events).filter((f) => f.kind === "gap").map((f) => f.run);
          return <Scrubber agents={shown} events={events.filter((e) => !host || e.hostname === host)} history={history} gaps={gaps} />;
        }}
      </Async>
    </div>
  );
}

/** Control change -> the test drift it caused, for the lag annotation on the track. */
function lags(events: DriftEvent[]) {
  return events.filter((e) => e.kind === "test" && e.details.likely_causes?.length).flatMap((test) => {
    const control = events.find((c) => c.kind === "control" && c.agent_id === test.agent_id && test.details.likely_causes!.includes(c.subject));
    if (!control) return [];
    const from = eventTime(control);
    const to = ms(test.first_bad_at);
    return to > from ? [{ id: `${control.id}-${test.id}`, from, to, host: test.hostname }] : [];
  });
}

function Scrubber({ agents, events, history, gaps }: { agents: Agent[]; events: DriftEvent[]; history: Record<string, HygieneSnapshot[]>; gaps: Run[] }) {
  const { setTint } = useLab();
  const allSnaps = Object.values(history).flat();
  const times = [...allSnaps.map((s) => ms(s.collected_at)), ...events.map(eventTime)].filter((t) => !Number.isNaN(t));
  const start = times.length ? Math.min(...times) : clock.now() - 86_400_000;
  const end = times.length ? Math.max(...times) + 3_600_000 : clock.now();
  const span = Math.max(1, end - start);
  const before = start - span * 0.04; // a little runway before the first snapshot (easter egg lives there)
  const [t, setT] = useState(end);
  const [playing, setPlaying] = useState(false);
  const [selected, setSelected] = useState<DriftEvent | null>(null);
  const raf = useRef(0);

  useEffect(() => { setT(end); }, [end]);

  const states = useMemo(() => Object.fromEntries(agents.map((a) => [a.id, controlsAt(history[a.id] ?? [], events, a.id, t)])), [agents, history, events, t]);
  const level = driftLevel(Object.values(states).flat());
  const passed = eventsUntil(events, t);
  const controlsDrifted = Object.values(states).flat().filter((x) => x.drifted).length;
  const testsRegressed = passed.filter((e) => e.kind === "test" && e.to_state === "fail").length;

  useEffect(() => { setTint(tint(level)); }, [level, setTint]);
  useEffect(() => () => setTint(null), [setTint]);

  // Play: sweep the whole range in ~6 seconds.
  useEffect(() => {
    if (!playing) return;
    let last = performance.now();
    const step = (now: number) => {
      const dt = now - last;
      last = now;
      setT((cur) => {
        const next = cur + (span / 6000) * dt;
        if (next >= end) { setPlaying(false); return end; }
        return next;
      });
      raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [playing, span, end]);

  const onScrub = (value: number) => {
    const snapped = snap(value, events, span * 0.015);
    setT(snapped.t);
    if (snapped.event) setSelected(snapped.event);
  };

  const jump = (dir: 1 | -1) => {
    const sorted = [...events].sort((a, b) => eventTime(a) - eventTime(b));
    const next = dir > 0 ? sorted.find((e) => eventTime(e) > t + 1) : [...sorted].reverse().find((e) => eventTime(e) < t - 1);
    if (next) { setT(eventTime(next)); setSelected(next); }
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "]") { e.preventDefault(); jump(1); }
    if (e.key === "[") { e.preventDefault(); jump(-1); }
  };

  const pct = (x: number) => `${(((x - before) / (end - before)) * 100).toFixed(2)}%`;
  const beforeEverything = t < start;

  return (
    <div onKeyDown={onKey}>
      <section className="border border-line bg-black/40 p-4 dw-tint-border" aria-label="Timeline scrubber">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.25em] text-muted">baseline as of</div>
            <div className="font-mono text-2xl font-bold dw-tint" aria-live="polite">{stamp(new Date(t).toISOString())}</div>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-muted" aria-live="polite">
            <span><span className={controlsDrifted ? "text-amber" : "text-green"}>{controlsDrifted}</span> control{controlsDrifted === 1 ? "" : "s"} drifted</span>
            <span><span className={testsRegressed ? "text-crimson" : "text-green"}>{testsRegressed}</span> test{testsRegressed === 1 ? "" : "s"} regressed</span>
            <span title="tests that have never passed on that agent; not drift, but still a hole"><span className={gaps.length ? "text-amber" : "text-green"}>{gaps.length}</span> known detection gap{gaps.length === 1 ? "" : "s"} (now)</span>
            <span>{passed.length}/{events.length} events so far</span>
          </div>
        </div>

        <div className="relative mt-4">
          <div className="pointer-events-none absolute inset-x-0 top-[13px] h-[2px]" style={{ background: `linear-gradient(90deg, var(--ae-green), ${tint(level)})` }} />
          {lags(events).map((l) => (
            <div key={l.id} className="pointer-events-none absolute -top-5 h-12 border-x border-dashed border-amber/50 bg-amber/[0.07]"
              style={{ left: pct(l.from), width: `calc(${pct(l.to)} - ${pct(l.from)})` }}>
              <span className="absolute left-1 top-0 whitespace-nowrap font-mono text-[9px] text-amber">{dur((l.to - l.from) / 1000)} until a test noticed · {l.host}</span>
            </div>
          ))}
          {events.map((e) => (
            <button key={e.id} type="button" onClick={() => { setT(eventTime(e)); setSelected(e); }}
              title={`${e.hostname} · ${e.details.title ?? e.subject}`} aria-label={`Jump to ${e.details.title ?? e.subject} on ${e.hostname}`}
              className={cn("absolute top-0 z-10 h-7 w-[3px] -translate-x-1/2 transition", e.kind === "control" ? "bg-amber" : "bg-crimson", eventTime(e) <= t ? "opacity-100" : "opacity-40")}
              style={{ left: pct(eventTime(e)) }} />
          ))}
          <input type="range" className="dw-scrubber relative" min={before} max={end} step={1000} value={t}
            onChange={(e) => onScrub(Number(e.target.value))} aria-label="Scrub through time"
            aria-valuetext={stamp(new Date(t).toISOString())} />
        </div>

        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] text-muted">
          <span>{stamp(new Date(start).toISOString())}</span>
          <div className="flex gap-1">
            <Ctl onClick={() => jump(-1)} label="previous drift ( [ )">⏮</Ctl>
            <Ctl onClick={() => { if (t >= end) setT(before); setPlaying((p) => !p); }} label={playing ? "pause" : "play the week"}>{playing ? "❚❚" : "▶"}</Ctl>
            <Ctl onClick={() => jump(1)} label="next drift ( ] )">⏭</Ctl>
            <Ctl onClick={() => { setT(end); setSelected(null); }} label="now">now</Ctl>
          </div>
          <span>{stamp(new Date(end).toISOString())}</span>
        </div>
        {beforeEverything && (
          <p className="mt-3 font-mono text-xs text-green">Before Driftwatch existed, everything was compliant. Allegedly.</p>
        )}
      </section>

      {selected && <EventCard event={selected} />}

      <Panel title="Event log" subtitle="as of the scrubber position" className="mt-4">
        {passed.length === 0 ? <p className="font-mono text-xs text-muted">{EMPTY.noDrift}</p> : (
          <ol className="divide-y divide-line">
            {passed.map((e) => (
              <li key={e.id}>
                <button type="button" onClick={() => { setT(eventTime(e)); setSelected(e); }} className="grid w-full gap-1 py-2 text-left hover:bg-white/[0.02] md:grid-cols-[180px_90px_1fr]">
                  <span className="font-mono text-xs text-amber">{stamp(e.exact_change_at ?? e.first_bad_at)}</span>
                  <span className={cn("font-mono text-[10px] uppercase", e.kind === "control" ? "text-amber" : "text-crimson")}>{e.kind} drift</span>
                  <span className="text-sm">{e.hostname} · {e.details.title ?? e.subject} <span className="font-mono text-[11px] text-muted">{e.from_state} → {e.to_state}</span></span>
                </button>
              </li>
            ))}
          </ol>
        )}
      </Panel>

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        {agents.map((a) => <HostBaseline key={a.id} agent={a} states={states[a.id] ?? []} gaps={gaps.filter((g) => g.agent_id === a.id).length} />)}
      </div>

    </div>
  );
}

function Ctl({ children, onClick, label }: { children: React.ReactNode; onClick: () => void; label: string }) {
  return <button type="button" onClick={onClick} title={label} aria-label={label} className="border border-line px-2 py-1 hover:border-[var(--dw-tint)] hover:text-ink">{children}</button>;
}

function EventCard({ event: e }: { event: DriftEvent }) {
  const ce = e.details.change_event;
  return (
    <section className="mt-4 border border-amber/50 bg-amber/[0.06] p-4" aria-label="Selected drift event">
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn("border px-1.5 py-0.5 font-mono text-[10px] uppercase", e.kind === "control" ? "border-amber/60 text-amber" : "border-crimson/60 text-crimson")}>{e.kind} drift</span>
        <h2 className="text-base font-semibold"><TextScramble text={`${e.hostname} · ${e.details.title ?? e.subject}`} /></h2>
      </div>
      <div className="mt-3 grid gap-px border border-line bg-line font-mono text-xs sm:grid-cols-3">
        <Cell label="last known good" value={stamp(e.last_good_at)} />
        <Cell label="exact change" value={e.exact_change_at ? stamp(e.exact_change_at) : "not in Elastic"} strong={Boolean(e.exact_change_at)} />
        <Cell label="first seen bad" value={stamp(e.first_bad_at)} />
      </div>
      {ce && (
        <p className="mt-3 font-mono text-xs text-muted">
          event {ce.code} · by <span className="text-ink">{ce.user ?? "unknown"}</span> · <span className="text-ink/80">{ce.message}</span>
        </p>
      )}
      {e.details.likely_causes?.length ? (
        <p className="mt-2 font-mono text-xs text-muted">likely cause: <span className="text-amber">{e.details.likely_causes.join(", ")}</span> (a linked baseline control is failing)</p>
      ) : null}
      {e.details.previous_outcome && <p className="mt-2 font-mono text-xs text-muted">test went from <span className="text-green">{e.details.previous_outcome}</span> to <span className="text-crimson">{e.details.outcome}</span></p>}
    </section>
  );
}

function Cell({ label, value, strong }: { label: string; value: string; strong?: boolean }) {
  return (
    <div className="bg-bg p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted">{label}</div>
      <div className={cn("mt-1", strong ? "text-amber" : "text-ink")}>{value}</div>
    </div>
  );
}

function HostBaseline({ agent, states, gaps }: { agent: Agent; states: ControlState[]; gaps: number }) {
  const drifted = states.filter((s) => s.drifted).length;
  const gapText = gaps ? ` · ${gaps} known detection gap${gaps > 1 ? "s" : ""}` : "";
  return (
    <Panel title={agent.hostname} subtitle={<span className="font-mono">{agent.platform} · {states.length ? `snapshot ${stamp(states[0].since)}` : "no snapshot yet at this time"}</span>}
      actions={<span className={cn("font-mono text-[11px]", drifted || gaps ? "text-amber" : "text-green")}>{drifted ? `${drifted} drifted` : "baseline intact"}{gapText}</span>}>
      {states.length === 0 ? <p className="font-mono text-xs text-muted">Nothing collected yet. The agent had not reported a baseline by this time.</p> : (
        <ul className="grid gap-1 2xl:grid-cols-2">
          {states.map(({ check, drifted: d }) => (
            <li key={check.id} className={cn("flex items-center gap-2 border px-2 py-1.5 font-mono text-[11px] transition-colors duration-300",
              d ? "border-amber/70 bg-amber/10 text-amber" : check.status === "pass" ? "border-line text-ink/80" : check.status === "fail" ? "border-line text-muted" : "border-line text-muted/60")}>
              <span aria-hidden="true">{d ? "~" : check.status === "pass" ? "✓" : check.status === "fail" ? "·" : "?"}</span>
              <span className="min-w-0 flex-1 truncate" title={check.id}>{check.title}</span>
              <span className="shrink-0 text-[10px] text-muted" title={`expected ${check.expected ?? "—"}`}>{check.status === "fail" && !d ? `${check.actual ?? "fail"} · known` : check.actual ?? ""}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
