// The test as a flow: catalog steps -> what they leave in telemetry -> the Sigma rules expected to fire.
import { Background, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { useMemo } from "react";
import type { TestDetail } from "../lib/types";

type Box = { title: string; sub?: string; tone: "step" | "obs" | "rule" };

function BoxNode({ data }: NodeProps<Node<Box>>) {
  const tone = { step: "border-cyan/60 text-cyan", obs: "border-line text-muted", rule: "border-green/60 text-green" }[data.tone];
  return (
    <div className={`w-[210px] border bg-black/80 px-3 py-2 font-mono text-[11px] ${tone}`}>
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !rounded-none !border-0 !bg-line" />
      <div className="truncate text-ink">{data.title}</div>
      {data.sub && <div className="mt-0.5 truncate text-[10px]">{data.sub}</div>}
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !rounded-none !border-0 !bg-line" />
    </div>
  );
}

const nodeTypes = { box: BoxNode };

export function StepFlow({ test }: { test: TestDetail }) {
  const { nodes, edges } = useMemo(() => {
    const nodes: Node<Box>[] = [];
    const edges: Edge[] = [];
    const observables = [...new Set(test.flow.flatMap((s) => s.observables))];
    test.flow.forEach((s, i) => nodes.push({ id: `s${i}`, type: "box", position: { x: 0, y: i * 70 },
      data: { title: `${i + 1}. ${s.action}`, sub: s.techniques.join(" "), tone: "step" } }));
    observables.forEach((o, i) => nodes.push({ id: `o-${o}`, type: "box", position: { x: 280, y: i * 70 }, data: { title: o, sub: "observable · marker DW-<run>", tone: "obs" } }));
    test.rules.forEach((r, i) => nodes.push({ id: `r-${r.id}`, type: "box", position: { x: 560, y: i * 70 }, data: { title: r.title, sub: `sigma · ${r.level}`, tone: "rule" } }));
    test.flow.forEach((s, i) => s.observables.forEach((o) => edges.push({ id: `s${i}-${o}`, source: `s${i}`, target: `o-${o}`, animated: true })));
    observables.forEach((o) => test.rules.forEach((r) => edges.push({ id: `${o}-${r.id}`, source: `o-${o}`, target: `r-${r.id}`, style: { strokeDasharray: "4 3" } })));
    return { nodes, edges };
  }, [test]);
  const height = Math.max(test.flow.length, test.rules.length, 2) * 70 + 40;
  return (
    <div style={{ height }} className="border border-line bg-black/30" aria-label="Test flow diagram">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView proOptions={{ hideAttribution: true }}
        nodesDraggable={false} nodesConnectable={false} panOnDrag={false} zoomOnScroll={false} preventScrolling={false}>
        <Background gap={16} size={1} color="#27272a" />
      </ReactFlow>
    </div>
  );
}
