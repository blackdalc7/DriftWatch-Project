// Pure helpers behind the terminal palette commands (kept out of React so they can be unit tested).

export const PAGES: Record<string, string> = {
  console: "/", fleet: "/fleet", library: "/library", tests: "/library", drift: "/drift", timeline: "/drift",
  blast: "/blast", radius: "/blast", runs: "/runs", evidence: "/runs", coverage: "/coverage", attack: "/coverage",
  schedule: "/schedule", schedules: "/schedule", posture: "/posture", edr: "/posture", audit: "/audit",
};

export function resolvePage(arg: string | undefined): string | null {
  if (!arg) return null;
  const k = arg.replace(/^[~/.]+/, "").toLowerCase();
  return PAGES[k] ?? null;
}

/** "--tag lab" or "--tag=lab,windows" -> ["lab", "windows"]; default ["lab"]. */
export function tagsFrom(flags: Record<string, string | true>): string[] {
  const raw = flags.tag ?? flags.tags;
  if (typeof raw !== "string" || !raw.trim()) return ["lab"];
  return raw.split(",").map((t) => t.trim()).filter(Boolean);
}

export const FORTUNES = [
  "A rule that has never fired is either perfect or broken. Driftwatch suspects the second.",
  "Today's baseline is tomorrow's drift.",
  "You will meet a mysterious ASR rule. It will be set to Audit.",
  "The EICAR file is the only malware that politely announces itself.",
  "Compliance is a snapshot. Drift is a movie.",
  "If the agent is silent, it is either fine or on fire. Check the heartbeat.",
  "Every 'temporary' exclusion is permanent.",
];
