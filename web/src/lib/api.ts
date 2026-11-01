// Data access. Two modes:
//  * live:   calls the Driftwatch operator API with the X-API-Key the operator typed in (kept in
//            sessionStorage only, so closing the tab forgets it).
//  * replay: reads the static snapshot in public/demo/ (exported from a seeded database). Writes are
//            simulated and say so; nothing leaves the browser.
import { useCallback, useEffect, useRef, useState } from "react";
import { clock } from "./time";

export type DataMode = "live" | "replay";
const KEY_STORAGE = "driftwatch.apiKey";
const MODE_STORAGE = "driftwatch.mode";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** Map an API path to its file in the replay snapshot. Query strings are ignored. */
export function replayPath(path: string): string {
  const clean = path.split("?")[0].replace(/^\/api\/v1\//, "").replace(/\/+$/, "");
  const special: Record<string, string> = { "results/latest": "results-latest", "coverage/navigator": "navigator", "audit/verify": "audit-verify" };
  return `./demo/${special[clean] ?? clean}.json`;
}

function safeGet(store: Storage, key: string): string | null {
  try {
    return store.getItem(key);
  } catch {
    return null;
  }
}

function safeSet(store: Storage, key: string, value: string | null): void {
  try {
    if (value === null) store.removeItem(key);
    else store.setItem(key, value);
  } catch {
    /* private mode: the key simply is not remembered */
  }
}

export function initialMode(): DataMode {
  if (__DATA_MODE__ === "replay") return "replay";
  if (__DATA_MODE__ === "live") return "live";
  const stored = safeGet(sessionStorage, MODE_STORAGE);
  return stored === "replay" ? "replay" : "live";
}

let mode: DataMode = typeof window === "undefined" ? "replay" : initialMode();
const listeners = new Set<() => void>();

export const session = {
  get mode(): DataMode { return mode; },
  get apiKey(): string | null { return safeGet(sessionStorage, KEY_STORAGE); },
  /** Replay is forced in the static demo build. */
  get locked(): boolean { return __DATA_MODE__ === "replay"; },
  setMode(next: DataMode) {
    mode = next;
    safeSet(sessionStorage, MODE_STORAGE, next);
    void syncClock().then(() => listeners.forEach((l) => l()));
  },
  setKey(key: string | null) {
    safeSet(sessionStorage, KEY_STORAGE, key);
    listeners.forEach((l) => l());
  },
  subscribe(fn: () => void) {
    listeners.add(fn);
    return () => { listeners.delete(fn); };
  },
};

/** Anchor the UI clock to the snapshot in replay mode; real time in live mode. */
export async function syncClock(): Promise<void> {
  if (mode !== "replay") { clock.anchorTo(null); return; }
  try {
    const meta = (await (await fetch("./demo/meta.json")).json()) as { exported_at?: string };
    clock.anchorTo(meta.exported_at ?? null);
  } catch {
    clock.anchorTo(null);
  }
}

async function parse(resp: Response): Promise<unknown> {
  const text = await resp.text();
  let body: unknown = text;
  try { body = text ? JSON.parse(text) : null; } catch { /* plain text error */ }
  if (!resp.ok) {
    const detail = typeof body === "object" && body && "detail" in body ? String((body as { detail: unknown }).detail) : text;
    throw new ApiError(resp.status, detail || `${resp.status} ${resp.statusText}`);
  }
  return body;
}

export async function get<T>(path: string): Promise<T> {
  if (mode === "replay") {
    const resp = await fetch(replayPath(path));
    if (!resp.ok) throw new ApiError(404, "not in the demo snapshot (replay mode only has the seeded week)");
    return (await resp.json()) as T;
  }
  const key = session.apiKey;
  if (!key) throw new ApiError(401, "no operator API key yet");
  return (await parse(await fetch(path, { headers: { "X-API-Key": key } }))) as T;
}

export interface WriteResult<T> { data: T | null; simulated: boolean }

/** POST/PUT/DELETE. In replay mode nothing is sent and `simulated` is true. */
export async function send<T>(method: "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<WriteResult<T>> {
  if (mode === "replay") return { data: null, simulated: true };
  const key = session.apiKey;
  if (!key) throw new ApiError(401, "no operator API key yet");
  const resp = await fetch(path, {
    method, headers: { "X-API-Key": key, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { data: (await parse(resp)) as T, simulated: false };
}

export async function download(path: string): Promise<Blob> {
  if (mode === "replay") {
    const m = path.match(/runs\/([a-f0-9]{16})\/evidence/);
    const resp = m ? await fetch(`./demo/evidence/${m[1]}.zip`) : null;
    if (!resp?.ok) throw new ApiError(404, "only the 60 most recent demo runs ship with an evidence bundle");
    return resp.blob();
  }
  const key = session.apiKey;
  const resp = await fetch(path, { headers: { "X-API-Key": key ?? "" } });
  if (!resp.ok) await parse(resp);
  return resp.blob();
}

export interface Query<T> { data: T | undefined; error: unknown; loading: boolean; reload: () => void }

/** Fetch on mount, on mode/key change and every `refreshMs` (live mode only). */
export function useApi<T>(path: string | null, refreshMs = 0): Query<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(Boolean(path));
  const [tick, setTick] = useState(0);
  const latest = useRef(path);
  latest.current = path;
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => session.subscribe(reload), [reload]);
  useEffect(() => {
    if (!path) return;
    let cancelled = false;
    setLoading(true);
    get<T>(path)
      .then((d) => { if (!cancelled && latest.current === path) { setData(d); setError(null); } })
      .catch((e) => { if (!cancelled) setError(e); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [path, tick]);
  useEffect(() => {
    if (!refreshMs || mode === "replay") return;
    const id = window.setInterval(reload, refreshMs);
    return () => window.clearInterval(id);
  }, [refreshMs, reload]);
  return { data, error, loading, reload };
}
