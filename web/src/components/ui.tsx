// Small Driftwatch-specific building blocks on top of @portfolio/aegis-ui.
import { AsciiLoader, SnarkyEmpty, SnarkyError, StatusBadge, cn, type StatusName } from "@portfolio/aegis-ui";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "motion/react";
import type { Query } from "../lib/api";
import { loadingQuip } from "../lib/quips";
import type { Outcome } from "../lib/types";

/** Loading / error / empty handling for one query, with the shared voice. */
export function Async<T>({ q, children, empty, emptyWhen, label }: {
  q: Query<T>; children: (data: T) => ReactNode; empty?: string; emptyWhen?: (d: T) => boolean; label: string;
}) {
  if (q.error) return <SnarkyError error={q.error} />;
  if (q.data === undefined) return <AsciiLoader label={loadingQuip(label)} />;
  if (emptyWhen?.(q.data)) return <SnarkyEmpty quipKey={label} quip={empty} />;
  return <>{children(q.data)}</>;
}

export function OutcomeBadge({ outcome, className }: { outcome: Outcome | "untested" | null | undefined; className?: string }) {
  if (!outcome || outcome === "untested") return <span className={cn("border border-line px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted", className)}>untested</span>;
  if (outcome === "collected") return <span className={cn("border border-cyan/50 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-cyan", className)}>collected</span>;
  return <StatusBadge status={outcome as StatusName} className={className} />;
}

export function Meter({ value, label, warn = 75, crit = 90 }: { value: number | undefined; label: string; warn?: number; crit?: number }) {
  const v = value ?? 0;
  const color = v >= crit ? "var(--ae-crimson)" : v >= warn ? "var(--ae-amber)" : "var(--ae-cyan)";
  return (
    <div className="font-mono text-[10px] text-muted">
      <div className="flex justify-between"><span>{label}</span><span className="text-ink">{value === undefined ? "—" : `${v.toFixed(0)}%`}</span></div>
      <div className="mt-1 h-1 border border-line"><div className="h-full" style={{ width: `${Math.min(100, v)}%`, background: color }} /></div>
    </div>
  );
}

export function Sparkline({ values, width = 140, height = 28, color = "var(--ae-cyan)" }: { values: (number | null)[]; width?: number; height?: number; color?: string }) {
  const pts = values.map((v) => v ?? 0);
  if (pts.length < 2) return <svg width={width} height={height} aria-hidden="true" />;
  const max = Math.max(100, ...pts);
  const d = pts.map((v, i) => `${i === 0 ? "M" : "L"}${((i / (pts.length - 1)) * width).toFixed(1)},${(height - (v / max) * height).toFixed(1)}`).join(" ");
  return (
    <svg width={width} height={height} aria-hidden="true" className="overflow-visible">
      <path d={d} fill="none" stroke={color} strokeWidth="1" />
    </svg>
  );
}

export function SectionTitle({ kicker, title, children }: { kicker: string; title: string; children?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-3 border-b border-line pb-3">
      <div>
        <div className="font-mono text-[10px] uppercase tracking-[0.3em] dw-tint">{kicker}</div>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">{title}</h1>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-xs", className)}>{children}</span>;
}

// --- toasts -------------------------------------------------------------------------------------------

interface Toast { id: number; text: string; tone: "info" | "ok" | "warn" | "bad" }
const ToastCtx = createContext<(text: string, tone?: Toast["tone"]) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Toast["tone"] = "info") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, text, tone }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5200);
  }, []);
  const tones = { info: "border-cyan/60 text-cyan", ok: "border-green/60 text-green", warn: "border-amber/60 text-amber", bad: "border-crimson/60 text-crimson" };
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(92vw,380px)] flex-col gap-2" role="status" aria-live="polite">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div key={t.id} initial={{ opacity: 0, x: 30 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 30 }}
              className={cn("ae-glass border px-3 py-2 font-mono text-xs", tones[t.tone])}>{t.text}</motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}

// --- lab-wide cosmetic state (tint, duck mode) --------------------------------------------------------

interface Lab { duck: boolean; setDuck: (v: boolean) => void; setTint: (hex: string | null) => void }
const LabCtx = createContext<Lab>({ duck: false, setDuck: () => {}, setTint: () => {} });
export const useLab = () => useContext(LabCtx);

export function LabProvider({ children, baseTint }: { children: ReactNode; baseTint: string }) {
  const [duck, setDuck] = useState(false);
  const [override, setOverride] = useState<string | null>(null);
  const tint = override ?? baseTint;
  useEffect(() => { document.documentElement.style.setProperty("--dw-tint", tint); }, [tint]);
  const value = useMemo(() => ({ duck, setDuck, setTint: setOverride }), [duck]);
  return <LabCtx.Provider value={value}>{children}</LabCtx.Provider>;
}
