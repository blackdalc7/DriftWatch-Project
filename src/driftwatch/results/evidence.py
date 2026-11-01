"""Evidence bundles: a signed, self-verifying record of what one run proved.

A bundle is a zip with:

* ``manifest.json``: run id, test, agent, timestamps, outcome, and the SHA-256 of every other file
* ``manifest.sig``: Ed25519 signature over the canonical manifest
* ``run.json``: the run row (step results from the agent, evaluation)
* ``agent.log``: the agent's own log of the run
* ``test.yml``: the exact test definition that was dispatched
* ``elastic_query.json``: the query the results engine ran, and against which indices
* ``alerts.json`` / ``telemetry.json``: the matching alert and telemetry documents
* ``hygiene.json``: the agent's latest baseline snapshot at evaluation time

Anyone holding the public key can check the bundle offline with ``driftwatch evidence verify``.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

from driftwatch.crypto import Signer, canonical_json, sha256_hex, verify_signature
from driftwatch.library import dump_test
from driftwatch.schema import DriftwatchTest

MANIFEST_VERSION = 1


class EvidenceError(Exception):
    """Raised when a bundle cannot be built or fails verification."""


def _files(run: dict[str, Any], test: DriftwatchTest, agent: dict[str, Any],
           hygiene: dict[str, Any] | None) -> dict[str, bytes]:
    evaluation = run.get("evaluation") or {}
    raw = evaluation.get("raw") or {}
    run_doc = {k: v for k, v in run.items() if k != "agent_log"}
    if isinstance(run_doc.get("evaluation"), dict):
        run_doc["evaluation"] = {k: v for k, v in run_doc["evaluation"].items() if k != "raw"}
    return {
        "run.json": json.dumps(run_doc, indent=2, sort_keys=True).encode(),
        "agent.log": (run.get("agent_log") or "").encode(),
        "test.yml": dump_test(test).encode(),
        "agent.json": json.dumps({k: agent.get(k) for k in ("id", "hostname", "platform", "os_version",
                                                           "agent_version", "tags")}, indent=2).encode(),
        "elastic_query.json": json.dumps({"indices": evaluation.get("indices"), "window": evaluation.get("window"),
                                          "query": evaluation.get("query")}, indent=2).encode(),
        "alerts.json": json.dumps(raw.get("alerts", []), indent=2).encode(),
        "telemetry.json": json.dumps(raw.get("telemetry", []), indent=2).encode(),
        "hygiene.json": json.dumps(hygiene or {}, indent=2).encode(),
    }


def build_manifest(run: dict[str, Any], test: DriftwatchTest, agent: dict[str, Any],
                   files: dict[str, bytes]) -> dict[str, Any]:
    """The manifest that gets signed."""
    evaluation = run.get("evaluation") or {}
    return {
        "version": MANIFEST_VERSION,
        "run_id": run["id"],
        "marker": f"DW-{run['id']}",
        "test": {"id": test.id, "version": test.version, "name": test.name, "techniques": test.attack.techniques},
        "agent": {"id": agent["id"], "hostname": agent["hostname"], "platform": agent["platform"]},
        "timestamps": {k: run.get(k) for k in ("created_at", "dispatched_at", "started_at", "finished_at",
                                               "evaluated_at")},
        "outcome": run.get("outcome"),
        "passed": run.get("passed"),
        "detection_quality": evaluation.get("detection_quality"),
        "alerts": [{"rule_id": a.get("rule_id"), "rule_name": a.get("rule_name"), "timestamp": a.get("timestamp")}
                   for a in evaluation.get("alerts", [])],
        "files": {name: sha256_hex(data) for name, data in sorted(files.items())},
    }


def build_bundle(run: dict[str, Any], test: DriftwatchTest, agent: dict[str, Any], hygiene: dict[str, Any] | None,
                 signer: Signer) -> bytes:
    """Return the zip bytes of a signed evidence bundle for an evaluated run."""
    if run.get("status") != "evaluated":
        raise EvidenceError(f"run {run['id']} is {run.get('status')}; evidence needs an evaluated run")
    files = _files(run, test, agent, hygiene)
    manifest = build_manifest(run, test, agent, files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        zf.writestr("manifest.sig", signer.sign(manifest) + "\n")
        zf.writestr("public_key.txt", signer.public_key_b64() + "\n")
    return buf.getvalue()


def write_bundle(data: bytes, out_dir: Path, run_id: str) -> Path:
    """Save bundle bytes as ``<out_dir>/evidence-<run>.zip``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"evidence-{run_id}.zip"
    path.write_bytes(data)
    return path


def verify_bundle(data: bytes, public_key_b64: str) -> dict[str, Any]:
    """Check the signature and every file hash; return the manifest or raise :class:`EvidenceError`.

    The public key must come from the operator (for example ``bundle-signing.pub``), not from the bundle's
    own ``public_key.txt``, which is informational only.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            manifest = json.loads(zf.read("manifest.json"))
            signature = zf.read("manifest.sig").decode().strip()
            contents = {n: zf.read(n) for n in names}
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"not a valid evidence bundle: {exc}") from exc
    if not verify_signature(public_key_b64, manifest, signature):
        raise EvidenceError("manifest signature is invalid")
    for name, digest in manifest.get("files", {}).items():
        if name not in contents:
            raise EvidenceError(f"file {name} listed in the manifest is missing")
        if sha256_hex(contents[name]) != digest:
            raise EvidenceError(f"file {name} was modified after signing")
    unexpected = names - set(manifest.get("files", {})) - {"manifest.json", "manifest.sig", "public_key.txt"}
    if unexpected:
        raise EvidenceError(f"bundle contains unsigned files: {sorted(unexpected)}")
    canonical_json(manifest)
    return manifest
