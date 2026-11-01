// Read and verify a Driftwatch evidence bundle entirely in the browser: unzip (stored or deflate),
// SHA-256 every file against the manifest, and check the manifest's Ed25519 signature with WebCrypto.
// `driftwatch evidence verify` does the same offline; this is for the analyst who just clicked download.

export type Files = Map<string, Uint8Array>;

const u16 = (b: Uint8Array, o: number) => b[o] | (b[o + 1] << 8);
const u32 = (b: Uint8Array, o: number) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Minimal ZIP reader (central directory based; no zip64, no encryption, which bundles never use). */
export async function readZip(buf: ArrayBuffer): Promise<Files> {
  const b = new Uint8Array(buf);
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65_557); i--) {
    if (u32(b, i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a zip file");
  const count = u16(b, eocd + 10);
  let p = u32(b, eocd + 16);
  const files: Files = new Map();
  const dec = new TextDecoder();
  for (let n = 0; n < count; n++) {
    if (u32(b, p) !== 0x02014b50) throw new Error("corrupt central directory");
    const method = u16(b, p + 10);
    const size = u32(b, p + 20);
    const nameLen = u16(b, p + 28);
    const extraLen = u16(b, p + 30);
    const commentLen = u16(b, p + 32);
    const local = u32(b, p + 42);
    const name = dec.decode(b.subarray(p + 46, p + 46 + nameLen));
    const dataStart = local + 30 + u16(b, local + 26) + u16(b, local + 28);
    const raw = b.subarray(dataStart, dataStart + size);
    if (method === 0) files.set(name, raw.slice());
    else if (method === 8) files.set(name, await inflateRaw(raw));
    else throw new Error(`unsupported compression method ${method} for ${name}`);
    p += 46 + nameLen + extraLen + commentLen;
  }
  return files;
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Same bytes as Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False). */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

function b64(s: string): Uint8Array {
  const bin = atob(s.trim());
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export interface Manifest {
  run_id: string; marker: string; outcome: string; passed: boolean; detection_quality: string | null;
  test: { id: string; name: string; version: number; techniques: string[] };
  agent: { id: string; hostname: string; platform: string };
  timestamps: Record<string, string | null>; alerts: { rule_id: string; rule_name: string; timestamp: string }[];
  files: Record<string, string>;
}

export interface Verification {
  manifest: Manifest; publicKey: string;
  signature: "valid" | "invalid" | "unsupported";
  hashes: { name: string; expected: string; actual: string; ok: boolean }[];
  unexpected: string[]; bundleSha256: string;
  /** Set by the caller after comparing the key id with the server's. */
  keyMatchesServer?: boolean;
}

export async function verifyBundle(buf: ArrayBuffer, pinnedKey?: string): Promise<Verification> {
  const files = await readZip(buf);
  const text = (n: string) => {
    const f = files.get(n);
    if (!f) throw new Error(`bundle has no ${n}`);
    return new TextDecoder().decode(f);
  };
  const manifest = JSON.parse(text("manifest.json")) as Manifest;
  const sig = text("manifest.sig").trim();
  const publicKey = (pinnedKey ?? text("public_key.txt")).trim();
  let signature: Verification["signature"] = "unsupported";
  try {
    const key = await crypto.subtle.importKey("raw", b64(publicKey) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, b64(sig) as BufferSource, new TextEncoder().encode(canonicalJson(manifest)) as BufferSource);
    signature = ok ? "valid" : "invalid";
  } catch {
    signature = "unsupported"; // older browsers without WebCrypto Ed25519: use the CLI
  }
  const hashes = await Promise.all(Object.entries(manifest.files).map(async ([name, expected]) => {
    const f = files.get(name);
    const actual = f ? await sha256Hex(f) : "missing";
    return { name, expected, actual, ok: actual === expected };
  }));
  const known = new Set([...Object.keys(manifest.files), "manifest.json", "manifest.sig", "public_key.txt"]);
  return { manifest, publicKey, signature, hashes, unexpected: [...files.keys()].filter((n) => !known.has(n)),
    bundleSha256: await sha256Hex(new Uint8Array(buf)) };
}
