import { Panel, SlideToExecute, cn } from "@portfolio/aegis-ui";
import {
  Background, Handle, Position, ReactFlow, useNodesState, type Edge, type Node, type NodeProps, type ReactFlowInstance,
} from "@xyflow/react";
import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { send, useApi } from "../lib/api";
import { ACTORS, hitsFor, notApplicable, platformsFor, verdict, type Actor, type Hit } from "../lib/blast";
import type { Agent, Run, TestView } from "../lib/types";
import { Async, OutcomeBadge, SectionTitle, useLab, useToast } from "../components/ui";

type ActorData = { actor: Actor; duck: boolean; tests: TestView[] };
type ServerData = { agent: Agent; hot: boolean; struck: string | null };

function ActorNode({ data }: NodeProps<Node<ActorData>>) {
  return (
    <div className="w-[210px] cursor-grab border border-crimson/70 bg-black/90 p-3 active:cursor-grabbing" style={{ boxShadow: "0 0 30px -10px var(--ae-crimson)" }}>
      <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-crimson">
        <span aria-hidden="true">{data.duck ? "🦆" : "☠"}</span>{data.duck ? "rubber duck apt" : "threat actor"}
      </div>
      <div className="mt-1 text-sm font-semibold text-ink">{data.duck ? `Quackers (${data.actor.name})` : data.actor.name}</div>
      <div className="mt-1 text-[11px] leading-snug text-muted">{data.duck ? "Waddles in, asks why your ASR rule is in Audit mode, waddles out." : data.actor.blurb}</div>
      <div className="mt-2 flex flex-wrap gap-1">
        {data.actor.techniques.map((t) => {
          const os = platformsFor(t, data.tests);
          return (
            <span key={t} className="border border-line px-1 font-mono text-[9px] text-muted" title={os.length ? `emulated on ${os.join(" and ")}` : "no test emulates this yet"}>
              {t} <span className="text-ink/60">{os.length === 2 ? "W+L" : os[0] === "windows" ? "W" : os[0] === "linux" ? "L" : "—"}</span>
            </span>
          );
        })}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} className="!h-0 !w-0 !border-0 !bg-transparent" />
    </div>
  );
}

function ServerNode({ data }: NodeProps<Node<ServerData>>) {
  return (
    <div className={cn("w-[220px] border bg-black/90 p-3 transition", data.hot ? "border-crimson" : "border-line")}
      style={data.hot ? { boxShadow: "0 0 0 1px var(--ae-crimson), 0 0 36px -6px var(--ae-crimson)" } : undefined}>
      <Handle type="target" position={Position.Left} isConnectable={false} className="!h-0 !w-0 !border-0 !bg-transparent" />
      <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-muted">
        <span className={cn("h-1.5 w-1.5", data.agent.connection === "online" ? "bg-green" : "bg-crimson")} />{data.agent.platform} server
      </div>
      <div className="mt-1 font-mono text-sm text-ink">{data.agent.hostname}</div>
      <pre aria-hidden="true" className="mt-2 font-mono text-[9px] leading-tight text-muted/70">{data.agent.platform === "windows" ? "┌──────────┐\n│ ▒▒ ▒▒ ▒▒ │\n│ ▒▒ ▒▒ ▒▒ │\n└──────────┘" : "┌──────────┐\n│ $ _      │\n│          │\n└──────────┘"}</pre>
      <div className="mt-1 font-mono text-[10px] text-muted">{data.hot ? "release to strike" : data.struck ? `struck by ${data.struck}` : "drop an actor here"}</div>
    </div>
  );
}

const nodeTypes = { actor: ActorNode, server: ServerNode };
const home = (i: number) => ({ x: 0, y: i * 175 });

export function BlastRadius() {
  const agents = useApi<Agent[]>("/api/v1/agents");
  const tests = useApi<TestView[]>("/api/v1/library");
  const latest = useApi<Run[]>("/api/v1/results/latest");
  return (
    <div>
      <SectionTitle kicker="campaign://replay" title="Campaign replay: drop an actor on a server">
        <span className="max-w-md text-right font-mono text-[11px] text-muted">replays each technique's latest real result on that host. Dispatching new runs is a separate, explicit step.</span>
      </SectionTitle>
      <Async q={agents} label="blast">
        {(list) => <Board agents={list} tests={tests.data ?? []} latest={latest.data ?? []} />}
      </Async>
    </div>
  );
}

interface Strike { actor: Actor; agent: Agent; hits: Hit[]; at: number }

function Board({ agents, tests, latest }: { agents: Agent[]; tests: TestView[]; latest: Run[] }) {
  const { duck } = useLab();
  const toast = useToast();
  const initial = useMemo<Node[]>(() => [
    ...ACTORS.map((a, i) => ({ id: a.id, type: "actor", position: home(i), data: { actor: a, duck, tests } satisfies ActorData })),
    ...agents.map((g, i) => ({ id: g.id, type: "server", position: { x: 420, y: 60 + i * 220 }, draggable: false, data: { agent: g, hot: false, struck: null } satisfies ServerData })),
  ], [agents, duck, tests]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initial);
  useEffect(() => { setNodes(initial); }, [initial, setNodes]);
  const [rf, setRf] = useState<ReactFlowInstance | null>(null);
  const [strike, setStrike] = useState<Strike | null>(null);
  const [edges, setEdges] = useState<Edge[]>([]);

  const play = useCallback((actor: Actor, agent: Agent) => {
    setStrike({ actor, agent, hits: hitsFor(actor, agent, tests, latest), at: Date.now() });
    setEdges([{ id: `strike-${actor.id}-${agent.id}`, source: actor.id, target: agent.id, animated: true, className: "dw-strike",
      style: { stroke: "var(--ae-crimson)", strokeWidth: 1.5 } }]);
    setNodes((ns) => ns.map((n) => n.type === "server" ? { ...n, data: { ...(n.data as ServerData), struck: n.id === agent.id ? actor.name : (n.data as ServerData).struck } } : n));
  }, [tests, latest, setNodes]);

  // Arrive pre-wired: the commodity loader against the first Windows host, so the page shows a result at once.
  useEffect(() => {
    if (strike || !tests.length || !latest.length) return;
    const win = agents.find((a) => a.platform === "windows") ?? agents[0];
    const loader = ACTORS.find((a) => a.id === "actor-loader");
    if (win && loader) play(loader, win);
  }, [agents, tests, latest, strike, play]);

  const target = useCallback((node: Node) => rf?.getIntersectingNodes(node).find((n) => n.type === "server") ?? null, [rf]);

  const onDrag = useCallback((_: unknown, node: Node) => {
    if (node.type !== "actor") return;
    const hit = target(node);
    setNodes((ns) => ns.map((n) => n.type === "server" ? { ...n, data: { ...(n.data as ServerData), hot: n.id === hit?.id } } : n));
  }, [target, setNodes]);

  const onStop = useCallback((_: unknown, node: Node) => {
    if (node.type !== "actor") return;
    const hit = target(node);
    const actor = (node.data as ActorData).actor;
    const idx = ACTORS.findIndex((a) => a.id === actor.id);
    setNodes((ns) => ns.map((n) => {
      if (n.id === node.id) return { ...n, position: home(idx) }; // spring back to the bench
      if (n.type === "server") return { ...n, data: { ...(n.data as ServerData), hot: false, struck: n.id === hit?.id ? actor.name : (n.data as ServerData).struck } };
      return n;
    }));
    if (hit) play(actor, (hit.data as ServerData).agent);
  }, [target, setNodes, play]);

  const runForReal = async () => {
    if (!strike) return;
    const ids = strike.hits.filter((h) => h.test.dispatchable).map((h) => h.test.id);
    let queued = 0;
    for (const id of ids) {
      const res = await send<Run[]>("POST", "/api/v1/runs", { test_id: id, agent_ids: [strike.agent.id] });
      if (res.simulated) { toast("Replay mode: the actor was only imaginary this time.", "warn"); return; }
      queued += res.data?.length ?? 0;
    }
    toast(`${queued} signed bundle(s) queued for ${strike.agent.hostname}. Results land in Runs.`, "ok");
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
      <div className="h-[540px] border border-line bg-black/30" aria-label="Campaign board: drag a threat actor card onto a server">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onInit={setRf}
          onNodeDrag={onDrag} onNodeDragStop={onStop} fitView fitViewOptions={{ padding: 0.15 }} proOptions={{ hideAttribution: true }}
          nodesConnectable={false} minZoom={0.4} maxZoom={1.5}>
          <Background gap={22} size={1} color="#27272a" />
        </ReactFlow>
      </div>
      <Panel title="Impact" subtitle="latest scored outcome per technique on that host" scanlines>
        <AnimatePresence mode="wait">
          {!strike ? (
            <motion.p key="idle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="font-mono text-xs text-muted">
              Grab an actor from the left and drop it on a server. Driftwatch replays the most recent real result for every technique that actor uses.
            </motion.p>
          ) : (
            <motion.div key={strike.at} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              <StrikeReport strike={strike} na={notApplicable(strike.actor, strike.agent, tests)} />
              <div className="mt-5 border-t border-line pt-4">
                <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted">replay it for real on {strike.agent.hostname}</div>
                <SlideToExecute label="slide to dispatch" doneLabel="Signed & queued" onExecute={runForReal}
                  disabled={!strike.hits.some((h) => h.test.dispatchable)} disabledReason="no approved test emulates this actor here" />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Panel>
    </div>
  );
}

function StrikeReport({ strike, na }: { strike: Strike; na: string[] }) {
  const v = verdict(strike.hits);
  const tone = { green: "text-green border-green/60", amber: "text-amber border-amber/60", crimson: "text-crimson border-crimson/60", muted: "text-muted border-line" }[v.tone];
  return (
    <div>
      <div className={cn("border p-3", tone)}>
        <div className="font-mono text-[10px] uppercase tracking-[0.2em]">{strike.actor.name} → {strike.agent.hostname}</div>
        <div className="mt-1 text-lg font-semibold">{v.label}</div>
        <div className="mt-1 font-mono text-xs">{v.score}% of the {strike.hits.length} applicable test{strike.hits.length === 1 ? "" : "s"} prevented or detected</div>
      </div>
      {na.length > 0 && (
        <p className="mt-2 font-mono text-[11px] text-muted">not applicable on {strike.agent.platform}: {na.join(", ")}</p>
      )}
      <ul className="mt-3 space-y-1.5">
        {strike.hits.map((h, i) => (
          <motion.li key={h.test.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.15 + i * 0.18 }}
            className="flex items-center gap-2 border border-line px-2 py-1.5">
            <OutcomeBadge outcome={h.outcome} />
            <span className="min-w-0 flex-1 truncate text-sm">{h.test.name}</span>
            <span className="font-mono text-[10px] text-muted">{h.test.attack.techniques.join(" ")}</span>
          </motion.li>
        ))}
      </ul>
    </div>
  );
}
