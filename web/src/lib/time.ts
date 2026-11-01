// Time helpers. The API returns UTC ISO strings ending in Z with microseconds.

export const ms = (iso: string | null | undefined): number => (iso ? Date.parse(iso) : NaN);

// In replay mode "now" is the moment the demo snapshot was exported, so a week-old snapshot still reads
// "seen 2m ago" instead of drifting further into the past every time someone opens it.
let anchor: { snapshot: number; loadedAt: number } | null = null;

export const clock = {
  now(): number {
    return anchor ? anchor.snapshot + (Date.now() - anchor.loadedAt) : Date.now();
  },
  anchorTo(iso: string | null) {
    const t = ms(iso);
    anchor = Number.isNaN(t) ? null : { snapshot: t, loadedAt: Date.now() };
  },
  get replaying(): boolean { return anchor !== null; },
};

export const todayIso = () => new Date(clock.now()).toISOString().slice(0, 10);

export function ago(iso: string | null | undefined, now = clock.now()): string {
  const t = ms(iso);
  if (Number.isNaN(t)) return "never";
  const s = Math.round((now - t) / 1000);
  if (s < 0) return `in ${dur(-s)}`;
  if (s < 5) return "just now";
  return `${dur(s)} ago`;
}

export function dur(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

/** "2026-10-25 11:42:07Z" — compact, sortable, unambiguous. */
export function stamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function day(iso: string): string {
  return new Date(iso).toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short", timeZone: "UTC" });
}
