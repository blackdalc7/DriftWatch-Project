import {
  ModeProvider, SettingsSheet, TerminalPalette, TerminalIcon, Kbd, Button, useTerminalHotkey, ok, err, info, warn,
  type TerminalCommand,
} from "@portfolio/aegis-ui";
import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { ApiError, get, send, session, useApi } from "./lib/api";
import { FORTUNES, resolvePage, tagsFrom } from "./lib/commands";
import { tint } from "./lib/drift";
import type { Agent, DriftEvent, Run, Summary, TestView } from "./lib/types";
import { LabProvider, ToastProvider, useLab, useToast } from "./components/ui";
import { Overview } from "./pages/Overview";
import { Fleet } from "./pages/Fleet";
import { Library } from "./pages/Library";
import { DriftTimeline } from "./pages/DriftTimeline";
import { BlastRadius } from "./pages/BlastRadius";
import { Runs } from "./pages/Runs";
import { Coverage } from "./pages/Coverage";
import { Schedules } from "./pages/Schedules";
import { Posture } from "./pages/Posture";
import { Audit } from "./pages/Audit";

const NAV = [
  { to: "/", label: "Console", key: "01" }, { to: "/fleet", label: "Fleet", key: "02" },
  { to: "/library", label: "Test library", key: "03" }, { to: "/drift", label: "Drift timeline", key: "04" },
  { to: "/blast", label: "Campaign replay", key: "05" }, { to: "/runs", label: "Runs & evidence", key: "06" },
  { to: "/coverage", label: "ATT&CK coverage", key: "07" }, { to: "/schedule", label: "Schedules", key: "08" },
  { to: "/posture", label: "EDR posture", key: "09" }, { to: "/audit", label: "Audit log", key: "10" },
];

function useSession() {
  return useSyncExternalStore(session.subscribe, () => `${session.mode}:${session.apiKey ? 1 : 0}`);
}

export function App() {
  const summary = useApi<Summary>("/api/v1/summary", 30_000);
  const drifted = summary.data?.drift_open ?? 0;
  return (
    <ModeProvider product="Driftwatch">
      <ToastProvider>
        <LabProvider baseTint={tint(1 - Math.exp(-drifted / 1.5))}>
          <Shell summary={summary.data} />
        </LabProvider>
      </ToastProvider>
    </ModeProvider>
  );
}

function Shell({ summary }: { summary: Summary | undefined }) {
  useSession();
  const navigate = useNavigate();
  const toast = useToast();
  const { duck, setDuck } = useLab();
  const [term, setTerm] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const clicks = useRef<number[]>([]);
  useTerminalHotkey(setTerm);
  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);

  // Easter egg: click the logo seven times within three seconds.
  const onLogo = () => {
    const now = Date.now();
    clicks.current = [...clicks.current.filter((t) => now - t < 3000), now];
    if (clicks.current.length >= 7) {
      clicks.current = [];
      setDuck(!duck);
      toast(duck ? "Rubber-duck adversary dismissed. Back to real threat actors." :
        "🦆 Rubber-duck adversary engaged. It will explain your misconfigurations back to you, slowly.", "warn");
    }
  };

  const commands = useCommands();
  const needsKey = session.mode === "live" && !session.apiKey;

  return (
    <div className="flex min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-black focus:p-2">Skip to content</a>
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-black/30 md:flex">
        <button type="button" onClick={onLogo} className="flex items-center gap-3 border-b border-line px-4 py-4 text-left" aria-label="Driftwatch">
          <svg viewBox="0 0 32 32" className="h-7 w-7" aria-hidden="true"><path d="M3 20h6l3-8 4 12 3-6h10" stroke="var(--dw-tint)" strokeWidth="2" fill="none" strokeLinejoin="bevel" /></svg>
          <span>
            <span className="block font-mono text-sm font-bold tracking-[0.25em]">DRIFTWATCH</span>
            <span className="block font-mono text-[9px] uppercase tracking-[0.2em] text-muted">{duck ? "duck-driven validation" : "midnight lab · csv"}</span>
          </span>
        </button>
        <nav className="flex-1 overflow-y-auto p-2" aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}
              className="dw-rail-link mb-px flex items-center gap-3 border-l-2 border-transparent px-3 py-2 text-sm text-muted transition hover:text-ink">
              <span className="font-mono text-[10px] text-muted/60">{n.key}</span>{n.label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-2 border-t border-line p-3 font-mono text-[10px] text-muted">
          <ModeChip />
          <div>signing key <span className="text-ink">{summary?.signing_key_id ?? "…"}</span></div>
          <button type="button" onClick={() => setTerm(true)} className="flex w-full items-center justify-between border border-line px-2 py-1.5 hover:border-cyan/60 hover:text-cyan">
            <span className="flex items-center gap-1.5"><TerminalIcon className="h-3 w-3" /> terminal</span><Kbd>Ctrl K</Kbd>
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-black/50 px-4 py-2 backdrop-blur md:px-6">
          <select aria-label="Navigate" className="border border-line bg-black px-2 py-1 font-mono text-xs md:hidden"
            onChange={(e) => navigate(e.target.value)} value={location.hash.slice(1) || "/"}>
            {NAV.map((n) => <option key={n.to} value={n.to}>{n.label}</option>)}
          </select>
          <div className="hidden font-mono text-[11px] text-muted md:block">
            <span className="dw-tint">●</span> {summary ? `${summary.agents.online}/${summary.agents.total} agents online · ${summary.drift_open} open drift · pass rate ${summary.pass_rate ?? "—"}%${summary.scored ? ` (${summary.passed}/${summary.scored})` : ""}` : "connecting…"}
          </div>
          <div className="ml-auto flex items-center gap-1">
            <button type="button" onClick={() => setTerm(true)} className="p-2 text-muted hover:text-cyan md:hidden" aria-label="Open terminal"><TerminalIcon className="h-4 w-4" /></button>
            <SettingsSheet theme={theme} onTheme={setTheme} version="driftwatch ui 1.0.0">
              <DataSettings />
            </SettingsSheet>
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 md:px-8">
          {needsKey ? <KeyGate /> : (
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/fleet" element={<Fleet />} />
              <Route path="/library" element={<Library />} />
              <Route path="/library/:testId" element={<Library />} />
              <Route path="/drift" element={<DriftTimeline />} />
              <Route path="/blast" element={<BlastRadius />} />
              <Route path="/runs" element={<Runs />} />
              <Route path="/runs/:runId" element={<Runs />} />
              <Route path="/coverage" element={<Coverage />} />
              <Route path="/schedule" element={<Schedules />} />
              <Route path="/posture" element={<Posture />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          )}
        </main>
        <footer className="border-t border-line px-6 py-3 font-mono text-[10px] text-muted">
          lab-only · every agent action is benign, typed and Ed25519-signed · no remote shell, by design
        </footer>
      </div>

      <TerminalPalette open={term} onOpenChange={setTerm} commands={commands} navigate={navigate} host="driftwatch" user="purple"
        suggestions={NAV.map((n) => ({ label: n.label, hint: n.to, to: n.to }))}
        motd={["Driftwatch terminal. Typed, signed, benign. Try /help, /run, /drift lab-win01, /blast, /fortune."]} />
    </div>
  );
}

function ModeChip() {
  return session.mode === "live"
    ? <div className="flex items-center gap-1.5"><span className="ae-live h-1.5 w-1.5 bg-green" /> LIVE · server API</div>
    : <div className="flex items-center gap-1.5 text-amber"><span className="h-1.5 w-1.5 bg-amber" /> REPLAY · seeded demo week</div>;
}

function DataSettings() {
  const [key, setKey] = useState("");
  return (
    <div className="space-y-2 py-3 text-sm">
      <div>Data source<span className="block text-[11px] text-muted">replay reads a seeded week bundled with the UI; live talks to your server</span></div>
      <div className="flex gap-2">
        {(["live", "replay"] as const).map((m) => (
          <button key={m} type="button" disabled={session.locked && m === "live"} onClick={() => session.setMode(m)}
            className={`border px-2 py-1 font-mono text-[11px] uppercase ${session.mode === m ? "border-cyan text-cyan" : "border-line text-muted"} disabled:opacity-40`}>{m}</button>
        ))}
      </div>
      {session.mode === "live" && (
        <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); session.setKey(key.trim() || null); setKey(""); }}>
          <input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder={session.apiKey ? "key set · paste to replace" : "operator API key"}
            className="min-w-0 flex-1 border border-line bg-black/40 px-2 py-1 font-mono text-xs" aria-label="Operator API key" />
          <button type="submit" className="border border-line px-2 font-mono text-[11px] hover:border-cyan">set</button>
        </form>
      )}
    </div>
  );
}

function KeyGate() {
  const [key, setKey] = useState("");
  return (
    <div className="mx-auto mt-16 max-w-lg border border-line bg-black/40 p-6">
      <div className="font-mono text-[10px] uppercase tracking-[0.3em] dw-tint">auth://operator</div>
      <h1 className="mt-2 text-xl font-semibold">Paste the operator API key</h1>
      <p className="mt-2 text-sm text-muted">It is the <code className="font-mono">DRIFTWATCH_ADMIN_TOKEN</code> from your <code className="font-mono">.env</code>. It stays in this tab's session storage and nowhere else.</p>
      <form className="mt-4 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (key.trim()) session.setKey(key.trim()); }}>
        <input type="password" autoFocus autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} aria-label="Operator API key"
          className="min-w-0 flex-1 border border-line bg-black/60 px-3 py-2 font-mono text-sm focus:border-cyan focus:outline-none" />
        <Button variant="primary" type="submit">connect</Button>
      </form>
      <button type="button" onClick={() => session.setMode("replay")} className="mt-4 font-mono text-xs text-muted underline-offset-4 hover:text-amber hover:underline">
        no server? replay the seeded demo week instead →</button>
    </div>
  );
}

function NotFound(): ReactNode {
  return (
    <div className="mt-20 text-center font-mono">
      <div className="text-6xl dw-tint">404</div>
      <p className="mt-3 text-sm text-muted">This page drifted out of the baseline. Try Ctrl+K.</p>
    </div>
  );
}

/** Terminal commands. Anything that changes state returns a hold-to-confirm step. */
function useCommands(): TerminalCommand[] {
  const tests = useApi<TestView[]>("/api/v1/library");
  const agents = useApi<Agent[]>("/api/v1/agents");
  const { setDuck } = useLab();
  return useMemo<TerminalCommand[]>(() => [
    {
      name: "run", usage: "run <test-id> [--tag lab]", description: "queue a test on every agent with the tags (signed bundle)",
      complete: () => (tests.data ?? []).map((t) => t.id),
      run: (args, flags) => {
        const id = args[0];
        const test = tests.data?.find((t) => t.id === id);
        if (!id) return [err("usage: run <test-id> [--tag lab]")];
        if (!test) return [err(`no such test: ${id}`), info("ls tests  # to see what exists")];
        if (!test.dispatchable) return [err(`${id} is a draft. A human approves it first (Test library → hold to approve).`)];
        const tags = tagsFrom(flags);
        return {
          lines: [info(`${test.name} · ${test.steps.length} step(s) · platforms ${test.platforms.join(", ")}`), warn(`targets: every active agent tagged ${tags.join("+")}`)],
          confirm: {
            label: `Queue ${id}`, warning: "The server signs one bundle per agent. Agents re-check it against their catalog.", tone: "amber",
            run: async () => {
              const res = await send<Run[]>("POST", "/api/v1/runs", { test_id: id, tags });
              if (res.simulated) return [warn("replay mode: nothing was queued. (it would have been glorious)")];
              return res.data?.length ? res.data.map((r) => ok(`queued run ${r.id} on ${r.agent_id}`)) : [warn("no agent matched those tags")];
            },
          },
        };
      },
    },
    {
      name: "drift", usage: "drift [host]", description: "open the drift timeline, optionally for one host",
      complete: () => (agents.data ?? []).map((a) => a.hostname),
      run: async (args) => {
        const events = await get<DriftEvent[]>("/api/v1/drift");
        const host = args[0];
        const mine = host ? events.filter((e) => e.hostname === host) : events;
        const lines = mine.slice(0, 6).map((e) => warn(`${e.hostname} ${e.kind} ${e.subject}: ${e.from_state} → ${e.to_state} @ ${e.exact_change_at ?? e.first_bad_at}`));
        return { lines: lines.length ? lines : [ok("no drift. suspiciously calm.")], navigate: `/drift${host ? `?host=${encodeURIComponent(host)}` : ""}` };
      },
    },
    {
      name: "ls", usage: "ls tests|agents|rules", description: "list things",
      complete: () => ["tests", "agents"],
      run: (args) => {
        if (args[0] === "agents") return (agents.data ?? []).map((a) => info(`${a.hostname.padEnd(14)} ${a.platform.padEnd(8)} ${a.connection.padEnd(8)} ${a.tags.join(",")}`));
        return (tests.data ?? []).map((t) => info(`${t.id.padEnd(34)} ${t.status.padEnd(9)} ${t.attack.techniques.join(",")}`));
      },
    },
    {
      name: "cd", usage: "cd <page>", description: "go to a page (fleet, drift, blast, runs, coverage…)",
      complete: () => ["fleet", "library", "drift", "blast", "runs", "coverage", "schedule", "posture", "audit"],
      run: (args) => { const to = resolvePage(args[0]); return to ? { navigate: to } : [err(`cd: no such page: ${args[0] ?? ""}`)]; },
    },
    { name: "blast", description: "open the blast-radius sandbox", run: () => ({ navigate: "/blast" }) },
    {
      name: "status", description: "fleet and gate status",
      run: async () => {
        try {
          const s = await get<Summary>("/api/v1/summary");
          return [ok(`agents ${s.agents.online}/${s.agents.total} online`), info(`tests: ${s.tests.verified} verified, ${s.tests.approved} approved, ${s.tests.draft} drafts`),
            s.drift_open ? warn(`${s.drift_open} open drift event(s)`) : ok("no open drift"), info(`pass rate ${s.pass_rate ?? "—"}% · signing key ${s.signing_key_id}`)];
        } catch (e) {
          return [err(e instanceof ApiError ? e.message : String(e))];
        }
      },
    },
    { name: "fortune", description: "security wisdom of questionable provenance", run: () => [info(FORTUNES[Math.floor(Math.random() * FORTUNES.length)])] },
    { name: "quack", description: "toggle the rubber-duck adversary", run: () => { setDuck(true); return [ok("🦆 quack. the duck is now your threat actor.")]; } },
    { name: "shell", description: "remote shell on an agent", run: () => [err("there is no remote shell. there never was. that is the whole point."), info("agents only run Safe Action Catalog steps, signed by the server.")] },
  ], [tests.data, agents.data, setDuck]);
}
