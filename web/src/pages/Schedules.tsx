import { HoldToConfirm, Panel } from "@portfolio/aegis-ui";
import { useEffect, useMemo, useState } from "react";
import { send, session, useApi } from "../lib/api";
import { planDay, pyWeekday } from "../lib/planner";
import { EMPTY } from "../lib/quips";
import { todayIso } from "../lib/time";
import type { Agent, PlannedRun, Schedule, TestView } from "../lib/types";
import { Async, Mono, SectionTitle, useToast } from "../components/ui";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const LONG_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const field = "border border-line bg-black/40 px-2 py-1 font-mono text-xs text-ink [color-scheme:dark] focus:border-cyan focus:outline-none";

const minuteOfDay = (iso: string) => {
  const d = new Date(iso);
  return d.getUTCHours() * 60 + d.getUTCMinutes();
};
const toMinutes = (hhmm: string) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3));

/** "Mon–Fri", "Mon, Wed, Fri", "every day". */
function dayRange(days: number[]): string {
  const d = [...days].sort();
  if (d.length === 7) return "every day";
  const contiguous = d.every((x, i) => i === 0 || x === d[i - 1] + 1);
  return contiguous && d.length > 2 ? `${DAYS[d[0]]}–${DAYS[d.at(-1)!]}` : d.map((x) => DAYS[x]).join(", ");
}

/** Today if the schedule runs today, otherwise the next day it does (so the preview opens on something). */
function nextScheduledDay(from: string, days: number[]): string {
  const d = new Date(`${from}T00:00:00Z`);
  for (let i = 0; i < 7 && days.length; i++, d.setUTCDate(d.getUTCDate() + 1)) {
    if (days.includes(pyWeekday(d))) return d.toISOString().slice(0, 10);
  }
  return from;
}

type Draft = Omit<Schedule, "id" | "created_at" | "last_planned_date">;
const blank = (tests: TestView[]): Draft => ({
  name: "", test_ids: tests.filter((t) => t.status === "verified").map((t) => t.id), target_tags: ["lab"], days: [0, 1, 2, 3, 4],
  window_start: "09:00", window_end: "17:00", timezone: "UTC", randomize: true, enabled: true,
});

export function Schedules() {
  const schedules = useApi<Schedule[]>("/api/v1/schedules", 30_000);
  const agents = useApi<Agent[]>("/api/v1/agents");
  const tests = useApi<TestView[]>("/api/v1/library");
  const [editing, setEditing] = useState<{ id: string | null; draft: Draft } | null>(null);
  return (
    <div>
      <SectionTitle kicker="schedule://timetables" title="Tests on a timetable">
        <button type="button" onClick={() => setEditing({ id: null, draft: blank(tests.data ?? []) })}
          className="border border-cyan/60 px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-cyan hover:bg-cyan/10">+ new schedule</button>
      </SectionTitle>
      <p className="mb-5 max-w-3xl text-sm text-muted">
        A schedule picks a time window and the agents carrying its tags, whatever their OS; each agent only gets the tests written for
        its platform. Only verified tests are ever planned. Drafts and approved-but-unproven tests are skipped and listed.
      </p>
      {editing && (
        <ScheduleForm key={editing.id ?? "new"} id={editing.id} initial={editing.draft} tests={tests.data ?? []}
          onDone={() => { setEditing(null); schedules.reload(); }} onCancel={() => setEditing(null)} />
      )}
      <Async q={schedules} label="schedules" emptyWhen={(s) => s.length === 0} empty={EMPTY.noSchedules}>
        {(list) => (
          <div className="space-y-6">
            {list.map((s) => (
              <ScheduleCard key={s.id} sched={s} agents={agents.data ?? []} tests={tests.data ?? []} onChange={schedules.reload}
                onEdit={() => setEditing({ id: s.id, draft: { name: s.name, test_ids: s.test_ids, target_tags: s.target_tags, days: s.days,
                  window_start: s.window_start, window_end: s.window_end, timezone: s.timezone, randomize: s.randomize, enabled: s.enabled } })} />
            ))}
          </div>
        )}
      </Async>
    </div>
  );
}

function ScheduleForm({ id, initial, tests, onDone, onCancel }: {
  id: string | null; initial: Draft; tests: TestView[]; onDone: () => void; onCancel: () => void;
}) {
  const toast = useToast();
  const [d, setD] = useState<Draft>(initial);
  const [tags, setTags] = useState(initial.target_tags.join(" "));
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const toggle = <T,>(list: T[], v: T) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const valid = d.name.trim() && d.test_ids.length && d.days.length && toMinutes(d.window_end) > toMinutes(d.window_start) && tags.trim();
  const save = async () => {
    const body = { ...d, name: d.name.trim(), target_tags: tags.split(/[\s,#]+/).filter(Boolean) };
    try {
      const res = await send<Schedule>(id ? "PUT" : "POST", id ? `/api/v1/schedules/${id}` : "/api/v1/schedules", body);
      toast(res.simulated ? "Replay mode: the schedule exists only in your imagination." : `${body.name} ${id ? "updated" : "created"}.`, res.simulated ? "warn" : "ok");
      onDone();
    } catch (e) {
      toast(`Not saved: ${e instanceof Error ? e.message : String(e)}`, "bad");
    }
  };
  return (
    <Panel title={id ? `Edit ${initial.name}` : "New schedule"} subtitle="validated again by the server before it is stored" className="mb-6">
      <div className="grid gap-4 md:grid-cols-2">
        <label className="grid gap-1 font-mono text-[11px] text-muted">name
          <input className={field} value={d.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. Nightly persistence sweep" />
        </label>
        <label className="grid gap-1 font-mono text-[11px] text-muted">agent tags (all must match)
          <input className={field} value={tags} onChange={(e) => setTags(e.target.value)} placeholder="lab" />
        </label>
        <div className="grid gap-1 font-mono text-[11px] text-muted">days
          <div className="flex flex-wrap gap-1">
            {DAYS.map((x, i) => (
              <button key={x} type="button" aria-pressed={d.days.includes(i)} onClick={() => set("days", toggle(d.days, i).sort())}
                className={`border px-2 py-1 ${d.days.includes(i) ? "border-cyan/60 text-cyan" : "border-line text-muted"}`}>{x}</button>
            ))}
          </div>
        </div>
        <div className="grid gap-1 font-mono text-[11px] text-muted">window ({d.timezone})
          <div className="flex flex-wrap items-center gap-2">
            <input type="time" className={field} value={d.window_start} onChange={(e) => set("window_start", e.target.value)} aria-label="window start" />
            <span>to</span>
            <input type="time" className={field} value={d.window_end} onChange={(e) => set("window_end", e.target.value)} aria-label="window end" />
            <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-cyan" checked={d.randomize} onChange={(e) => set("randomize", e.target.checked)} />random times</label>
          </div>
        </div>
      </div>
      <fieldset className="mt-4">
        <legend className="font-mono text-[11px] text-muted">tests ({d.test_ids.length} selected; unverified ones are skipped until verified)</legend>
        <div className="mt-1 grid gap-1 sm:grid-cols-2">
          {tests.filter((t) => t.status !== "draft").map((t) => (
            <label key={t.id} className="flex items-center gap-2 border border-line px-2 py-1 text-xs">
              <input type="checkbox" className="accent-cyan" checked={d.test_ids.includes(t.id)} onChange={() => set("test_ids", toggle(d.test_ids, t.id))} />
              <span className="min-w-0 flex-1 truncate">{t.name}</span>
              <span className={`font-mono text-[10px] ${t.status === "verified" ? "text-muted" : "text-amber"}`}>{t.status === "verified" ? t.platforms.map((p) => p.slice(0, 3)).join("+") : "not verified"}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <div className="mt-4 flex justify-end gap-2 border-t border-line pt-3">
        <button type="button" onClick={onCancel} className="border border-line px-3 py-1.5 font-mono text-xs uppercase text-muted hover:text-ink">cancel</button>
        <button type="button" onClick={save} disabled={!valid}
          className="border border-cyan/60 px-3 py-1.5 font-mono text-xs uppercase text-cyan hover:bg-cyan/10 disabled:opacity-40">{id ? "save changes" : "create"}</button>
      </div>
    </Panel>
  );
}

function ScheduleCard({ sched, agents, tests, onChange, onEdit }: {
  sched: Schedule; agents: Agent[]; tests: TestView[]; onChange: () => void; onEdit: () => void;
}) {
  const toast = useToast();
  const [day, setDay] = useState(() => nextScheduledDay(todayIso(), sched.days));
  const [seed, setSeed] = useState(1);
  const [plan, setPlan] = useState<{ runs: PlannedRun[]; skipped: string[] } | null>(null);
  const byId = useMemo(() => Object.fromEntries(tests.map((t) => [t.id, t])), [tests]);
  const hosts = useMemo(() => Object.fromEntries(agents.map((a) => [a.id, a.hostname])), [agents]);
  const weekday = pyWeekday(new Date(`${day}T00:00:00Z`));
  const offDay = !sched.days.includes(weekday);

  useEffect(() => {
    let cancelled = false;
    const skipped = sched.test_ids.filter((id) => byId[id] && byId[id].status !== "verified");
    if (session.mode === "replay") {
      setPlan({ runs: planDay(sched, day, agents, byId, seed), skipped });
      return;
    }
    const { id: _id, created_at: _c, last_planned_date: _l, ...body } = sched;
    send<{ runs: PlannedRun[]; unverified_tests_skipped: string[] }>("POST", "/api/v1/schedules/preview", { ...body, day, seed })
      .then((res) => { if (!cancelled && res.data) setPlan({ runs: res.data.runs, skipped: res.data.unverified_tests_skipped }); })
      .catch((e: unknown) => { if (!cancelled) toast(`Preview failed: ${e instanceof Error ? e.message : String(e)}`, "bad"); });
    return () => { cancelled = true; };
  }, [sched, day, seed, agents, byId, toast]);

  const toggle = async () => {
    const res = await send("POST", `/api/v1/schedules/${sched.id}/enabled?enabled=${!sched.enabled}`);
    toast(res.simulated ? "Replay mode: the schedule pretends to care." : `${sched.name} ${sched.enabled ? "paused" : "resumed"}.`, res.simulated ? "warn" : "ok");
    onChange();
  };
  const remove = async () => {
    const res = await send("DELETE", `/api/v1/schedules/${sched.id}`);
    toast(res.simulated ? "Replay mode: deleted in spirit only." : `${sched.name} deleted. Queued runs stay queued.`, res.simulated ? "warn" : "bad");
    onChange();
  };

  const start = toMinutes(sched.window_start);
  const end = toMinutes(sched.window_end);
  const rows = [...new Set((plan?.runs ?? []).map((r) => r.agent_id))];
  const platforms = [...new Set(sched.test_ids.flatMap((id) => byId[id]?.platforms ?? []))];

  return (
    <Panel title={sched.name} label={sched.name}
      subtitle={<Mono>{dayRange(sched.days)} · {sched.window_start}–{sched.window_end} {sched.timezone} · {sched.randomize ? "random times" : "evenly spaced"} · agents tagged {sched.target_tags.map((t) => `#${t}`).join(" ")} · {platforms.join(" + ")}</Mono>}
      actions={<span className={`font-mono text-[10px] uppercase ${sched.enabled ? "text-green" : "text-muted"}`}>{sched.enabled ? "enabled" : "paused"}</span>}>
      <div className="flex flex-wrap items-center gap-1">
        {DAYS.map((d, i) => (
          <span key={d} className={`border px-2 py-0.5 font-mono text-[10px] ${sched.days.includes(i) ? "border-cyan/60 text-cyan" : "border-line text-muted/60"}`}>{d}</span>
        ))}
        <span className="ml-3 font-mono text-[10px] text-muted">{sched.test_ids.length} tests</span>
      </div>

      <div className="mt-4 flex flex-wrap items-end gap-3 border-t border-line pt-3 font-mono text-[11px]">
        <label className="flex flex-col gap-1 text-muted">preview day
          <span className="flex items-center gap-2">
            <input type="date" value={day} onChange={(e) => setDay(e.target.value || todayIso())} className={field} />
            <span className="text-ink">{LONG_DAYS[weekday]}</span>
          </span>
        </label>
        {sched.randomize && (
          <button type="button" onClick={() => setSeed((s) => s + 1)} className="border border-line px-2 py-1 text-muted hover:border-cyan hover:text-cyan">
            reroll times (seed {seed})
          </button>
        )}
        <span className="text-muted">{plan ? `${plan.runs.length} runs planned` : "planning…"}</span>
      </div>

      <div className="mt-3 space-y-2" aria-label="planned runs">
        {plan && plan.runs.length === 0 && (
          <p className="border-l-2 border-line pl-3 font-mono text-xs text-muted">
            {offDay ? `${LONG_DAYS[weekday]}: this schedule only runs ${dayRange(sched.days)}. Pick a weekday to preview.`
              : "No verified test matches the platforms of the tagged agents on this day."}
          </p>
        )}
        {rows.map((agentId) => (
          <div key={agentId} className="grid grid-cols-[110px_1fr] items-center gap-3">
            <Mono className="truncate text-muted">{hosts[agentId] ?? agentId}</Mono>
            <div className="relative h-6 border border-line">
              <div className="absolute inset-y-0 bg-cyan/5" style={{ left: `${(start / 1440) * 100}%`, width: `${((end - start) / 1440) * 100}%` }} />
              {plan!.runs.filter((r) => r.agent_id === agentId).map((r) => (
                <span key={`${r.test_id}-${r.at}`} title={`${r.at.slice(11, 16)} UTC · ${byId[r.test_id]?.name ?? r.test_id}`}
                  className="absolute top-0.5 h-4 w-1 bg-cyan" style={{ left: `${(minuteOfDay(r.at) / 1440) * 100}%` }} />
              ))}
            </div>
          </div>
        ))}
        {rows.length > 0 && <div className="grid grid-cols-[110px_1fr] gap-3 font-mono text-[9px] text-muted"><span /><div className="flex justify-between"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>24:00</span></div></div>}
      </div>

      {plan && plan.skipped.length > 0 && (
        <p className="mt-3 border-l-2 border-amber/70 pl-3 font-mono text-[11px] text-amber">skipped until verified: {plan.skipped.join(", ")}</p>
      )}

      <div className="mt-4 flex flex-wrap items-center justify-end gap-3 border-t border-line pt-3">
        <button type="button" onClick={onEdit} className="border border-line px-3 py-1.5 font-mono text-xs uppercase tracking-wider hover:border-cyan hover:text-cyan">edit</button>
        <button type="button" onClick={toggle} className="border border-line px-3 py-1.5 font-mono text-xs uppercase tracking-wider hover:border-amber hover:text-amber">
          {sched.enabled ? "pause" : "resume"}
        </button>
        <HoldToConfirm label="Hold to delete" holdingLabel="Deleting schedule…" onConfirm={remove} duration={1500} />
      </div>
    </Panel>
  );
}
