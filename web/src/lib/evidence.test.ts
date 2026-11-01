import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalJson, readZip, verifyBundle } from "./evidence";

const zip = readFileSync(new URL("./__fixtures__/evidence.zip", import.meta.url));
const pub = readFileSync(new URL("./__fixtures__/evidence.pub", import.meta.url), "utf8");
const buf = () => zip.buffer.slice(zip.byteOffset, zip.byteOffset + zip.byteLength) as ArrayBuffer;

describe("evidence bundles (signed by the Python server)", () => {
  it("unzips deflated entries", async () => {
    const files = await readZip(buf());
    expect([...files.keys()]).toContain("manifest.json");
  });

  it("verifies hashes and the Ed25519 signature in-browser", async () => {
    const v = await verifyBundle(buf(), pub);
    expect(v.manifest.run_id).toBe("0123456789abcdef");
    expect(v.hashes.every((h) => h.ok)).toBe(true);
    expect(v.unexpected).toEqual([]);
    expect(["valid", "unsupported"]).toContain(v.signature);
    expect(v.signature).toBe("valid"); // Node 22 ships WebCrypto Ed25519
  });

  it("rejects a signature from another key", async () => {
    const v = await verifyBundle(buf(), "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=");
    expect(v.signature === "invalid" || v.signature === "unsupported").toBe(true);
  });

  it("matches Python canonical JSON", () => {
    expect(canonicalJson({ b: 1, a: [true, null, "é — x"] })).toBe('{"a":[true,null,"é — x"],"b":1}');
  });
});
