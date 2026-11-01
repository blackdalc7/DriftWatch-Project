"""End to end through the HTTP API: enroll, heartbeat, signed bundles, results, scoring, drift, evidence."""

import base64
import io
import json
import zipfile
from datetime import timedelta

from conftest import ADMIN, PROXY, admin, enroll, make_csr

from driftwatch.crypto import verify_signature
from driftwatch.results.evidence import verify_bundle
from driftwatch.server import store as store_mod


def decode(bundle):
    payload = json.loads(base64.b64decode(bundle["payload"]))
    return payload


def hygiene_report(collected_at, asr="pass"):
    return {"schema": "driftwatch.hygiene/v1", "platform": "windows", "collected_at": collected_at,
            "checks": [{"id": "win.asr.block_obfuscated_scripts", "title": "ASR obfuscated scripts",
                        "status": asr, "expected": "block", "actual": "block" if asr == "pass" else "off"},
                       {"id": "win.defender.realtime_protection", "title": "RTP", "status": "pass"}]}


def submit(client, agent, payload, steps, log="ok"):
    return client.post("/api/v1/agent/results", headers=agent["headers"], json={
        "run_id": payload["run_id"], "started_at": "2026-10-30T14:00:00.000000Z",
        "finished_at": "2026-10-30T14:00:20.000000Z", "steps": steps, "log": log})


def test_health_and_auth(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/api/v1/agents").status_code == 401
    assert client.get("/api/v1/agents", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/agent/tasks").status_code == 401
    assert client.get("/api/v1/agent/tasks", headers={"X-Driftwatch-Proxy": PROXY}).status_code == 401
    bad_cert = {"X-Driftwatch-Proxy": PROXY, "X-Client-Verify": "SUCCESS", "X-Client-Cert": "garbage"}
    assert client.get("/api/v1/agent/tasks", headers=bad_cert).status_code == 401
    csr, _ = make_csr()
    assert client.post("/api/v1/enroll", json={"token": "x" * 20, "csr_pem": csr, "hostname": "h",
                                               "platform": "windows"}).status_code == 401


def test_enrollment_token_rules(client):
    agent = enroll(client)
    csr, _ = make_csr()
    again = client.post("/api/v1/enroll", headers={"X-Driftwatch-Proxy": PROXY}, json={
        "token": agent["token"]["token"], "csr_pem": csr, "hostname": "lab-win02", "platform": "windows"})
    assert again.status_code == 403 and "no uses left" in again.text
    bad = client.post("/api/v1/enroll", headers={"X-Driftwatch-Proxy": PROXY}, json={
        "token": "dwe_" + "x" * 30, "csr_pem": csr, "hostname": "h", "platform": "windows"})
    assert bad.status_code == 403
    assert client.post("/api/v1/enroll", headers={"X-Driftwatch-Proxy": PROXY}, json={
        "token": "dwe_" + "x" * 30, "csr_pem": csr, "hostname": "h", "platform": "beos"}).status_code == 400
    assert client.post("/api/v1/tokens", headers=admin(), json={"label": "x", "ttl_seconds": 5}).status_code == 409
    tokens = client.get("/api/v1/tokens", headers=admin()).json()
    assert tokens[0]["uses"] == 1 and "token_hash" not in tokens[0]
    assert client.delete(f"/api/v1/tokens/{tokens[0]['id']}", headers=admin()).json()["status"] == "revoked"
    assert client.delete("/api/v1/tokens/nope", headers=admin()).status_code == 404


def test_expired_token(client, platform, monkeypatch):
    tok = client.post("/api/v1/tokens", headers=admin(), json={"label": "t", "ttl_seconds": 60}).json()
    later = store_mod.utcnow() + timedelta(minutes=5)
    monkeypatch.setattr(store_mod, "utcnow", lambda: later)
    csr, _ = make_csr()
    resp = client.post("/api/v1/enroll", headers={"X-Driftwatch-Proxy": PROXY}, json={
        "token": tok["token"], "csr_pem": csr, "hostname": "h1", "platform": "windows"})
    assert resp.status_code == 403 and "expired" in resp.text


def test_full_validation_loop(client, platform, elastic):
    agent = enroll(client)
    assert agent["enroll"]["ca_pem"].startswith("-----BEGIN CERTIFICATE")
    hb = client.post("/api/v1/agent/heartbeat", headers=agent["headers"], json={
        "metrics": {"cpu_percent": 12.5, "memory_percent": 40, "disk_percent": 55, "uptime_seconds": 3600,
                    "ignored": 1}, "agent_version": "1.0.1"}).json()
    assert hb["next_heartbeat"] == platform.settings.heartbeat_interval
    detail = client.get(f"/api/v1/agents/{agent['agent_id']}", headers=admin()).json()
    assert detail["connection"] == "online" and detail["metrics"]["cpu_percent"] == 12.5
    assert "ignored" not in detail["metrics"] and detail["agent_version"] == "1.0.1"
    assert detail["heartbeats"][0]["cpu_percent"] == 12.5

    # First poll: a hygiene bundle, signed with the server key.
    bundles = client.get("/api/v1/agent/tasks", headers=agent["headers"]).json()["bundles"]
    assert len(bundles) == 1
    hyg = decode(bundles[0])
    assert hyg["kind"] == "hygiene" and hyg["scope"] == "lab"
    assert verify_signature(platform.signer.public_key_b64(), hyg, bundles[0]["signature"])
    t1 = "2026-10-30T09:00:00.000000Z"
    r = submit(client, agent, hyg, [{"index": 0, "action": "hygiene.collect", "status": "executed",
                                      "output": hygiene_report(t1)}])
    assert r.json()["status"] == "evaluated"
    assert client.get("/api/v1/agent/tasks", headers=agent["headers"]).json()["bundles"] == []

    # Queue the encoded PowerShell test (approved -> verification run).
    runs = client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-win-encoded-powershell",
                                                              "tags": ["lab"]}).json()
    assert runs[0]["source"] == "verification"
    bundles = client.get("/api/v1/agent/tasks", headers=agent["headers"]).json()["bundles"]
    payload = decode(bundles[0])
    assert payload["steps"] == [{"index": 0, "action": "powershell.encoded_marker", "params": {}}]
    assert payload["marker"] == f"DW-{payload['run_id']}"

    # Elastic sees telemetry and the expected alert -> detected, pass, test becomes verified.
    elastic.hits = {
        "logs-*": [{"_id": "t1", "_index": "logs", "_source": {"process": {"command_line": "powershell -enc"}}}],
        ".alerts-security.alerts-*": [{"_id": "a1", "_index": ".alerts", "_source": {
            "@timestamp": "2026-10-30T14:00:40Z", "kibana.alert.rule.name": "PowerShell encoded",
            "kibana.alert.rule.parameters.rule_id": "5f2b1c0e-6a41-4c7e-9b8a-1d2e3f4a5b05",
            "kibana.alert.severity": "high",
            "kibana.alert.rule.threat": [{"tactic": {"name": "Execution"},
                                          "technique": [{"id": "T1059", "subtechnique": [{"id": "T1059.001"}]}]}]}}],
    }
    steps = [{"index": 0, "action": "powershell.encoded_marker", "status": "executed",
              "observables": {"process.command_line": "powershell -EncodedCommand AAA"}, "cleanup": "not_needed"}]
    assert submit(client, agent, payload, steps).json()["status"] == "completed"
    assert submit(client, agent, payload, steps).status_code == 409
    run = client.post(f"/api/v1/runs/{payload['run_id']}/evaluate", headers=admin()).json()
    assert run["outcome"] == "detected" and run["passed"] is True
    assert run["evaluation"]["detection_quality"] == "technique"
    assert client.get("/api/v1/library/dw-win-encoded-powershell", headers=admin()).json()["status"] == "verified"
    assert (platform.settings.evidence_dir / f"evidence-{payload['run_id']}.zip").exists()

    # Someone turns the ASR rule off: next hygiene snapshot drifts, the next run is missed.
    platform.store.save_evaluation
    later = "2026-10-30T15:00:00.000000Z"
    run2 = platform.store.create_run("builtin.hygiene", 1, agent["agent_id"], "hygiene")
    platform.store.mark_dispatched(run2["id"], store_mod.utcnow() + timedelta(minutes=5))
    elastic.hits = {"logs-*": [{"_id": "c", "_source": {"@timestamp": "2026-10-30T14:31:02Z",
                                                        "event": {"code": "5007"}, "message": "ASR changed",
                                                        "user": {"name": "LAB\\admin"}}}]}
    submit(client, agent, {"run_id": run2["id"]}, [{"index": 0, "action": "hygiene.collect", "status": "executed",
                                                    "output": hygiene_report(later, asr="fail")}])
    drift = client.get("/api/v1/drift", headers=admin()).json()
    control = next(d for d in drift if d["kind"] == "control")
    assert control["subject"] == "win.asr.block_obfuscated_scripts"
    assert control["last_good_at"] == t1 and control["first_bad_at"] == later
    assert control["exact_change_at"] == "2026-10-30T14:31:02Z"
    assert control["details"]["change_event"]["user"] == "LAB\\admin"

    runs = client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-win-encoded-powershell",
                                                              "agent_ids": [agent["agent_id"]]}).json()
    assert runs[0]["source"] == "manual"
    payload2 = decode(client.get("/api/v1/agent/tasks", headers=agent["headers"]).json()["bundles"][0])
    elastic.hits = {"logs-*": [{"_id": "t2", "_source": {}}]}
    with platform.store.tx() as c:
        c.execute("UPDATE runs SET finished_at = '2026-10-30T13:00:00.000000Z' WHERE id = ?", (payload["run_id"],))
    submit(client, agent, payload2, steps)
    assert platform.evaluate_due() == [payload2["run_id"]]
    run2 = client.get(f"/api/v1/runs/{payload2['run_id']}", headers=admin()).json()
    assert run2["outcome"] == "missed" and run2["passed"] is False
    assert "no rule fired" in " ".join(run2["evaluation"]["notes"])
    test_drift = next(d for d in client.get("/api/v1/drift", headers=admin()).json() if d["kind"] == "test")
    assert test_drift["details"]["likely_causes"] == ["win.asr.block_obfuscated_scripts"]

    # Evidence download verifies with the server's public key and detects tampering.
    zip_bytes = client.get(f"/api/v1/runs/{payload2['run_id']}/evidence", headers=admin()).content
    manifest = verify_bundle(zip_bytes, platform.signer.public_key_b64())
    assert manifest["outcome"] == "missed"

    # Coverage, summary, latest results, listing.
    layer = client.get("/api/v1/coverage/navigator", headers=admin()).json()
    t1059 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059.001")
    assert t1059["color"] == "#da3633" and t1059["score"] == 0
    summary = client.get("/api/v1/summary", headers=admin()).json()
    assert summary["agents"] == {"total": 1, "online": 1} and summary["drift_open"] == 2
    assert summary["tests"]["verified"] == 1
    latest = client.get("/api/v1/results/latest", headers=admin()).json()
    assert len(latest) == 1 and "agent_log" not in latest[0]
    listing = client.get("/api/v1/runs", headers=admin()).json()
    assert all("raw" not in (r.get("evaluation") or {}) for r in listing)
    assert client.get(f"/api/v1/hygiene/{agent['agent_id']}", headers=admin()).json()[0]["collected_at"] == later
    assert client.get("/api/v1/audit", headers=admin()).json()[0]["action"]


def test_evidence_tamper_detection(client, platform, elastic):
    agent = enroll(client)
    client.get("/api/v1/agent/tasks", headers=agent["headers"])
    client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-win-whoami-discovery", "tags": ["lab"]})
    payload = decode(client.get("/api/v1/agent/tasks", headers=agent["headers"]).json()["bundles"][0])
    submit(client, agent, payload, [{"index": 0, "action": "process.discovery", "status": "error",
                                     "detail": "cmd.exe not found"}])
    run = client.post(f"/api/v1/runs/{payload['run_id']}/evaluate", headers=admin()).json()
    assert run["outcome"] == "error"
    assert client.get("/api/v1/library/dw-win-whoami-discovery", headers=admin()).json()["status"] == "approved"
    data = client.get(f"/api/v1/runs/{payload['run_id']}/evidence", headers=admin()).content
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            content = src.read(name)
            if name == "agent.log":
                content = b"nothing to see here"
            dst.writestr(name, content)
    import pytest

    from driftwatch.results.evidence import EvidenceError

    with pytest.raises(EvidenceError, match="modified"):
        verify_bundle(out.getvalue(), platform.signer.public_key_b64())


def test_dispatch_guards(client, platform):
    win = enroll(client)
    out_of_scope = enroll(client, hostname="prod-01", tags=["prod"])
    lin = enroll(client, hostname="lab-lin01", platform="linux")
    assert client.get("/api/v1/agent/tasks", headers=out_of_scope["headers"]).json()["bundles"] == []
    resp = client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-win-whoami-discovery",
                                                              "agent_ids": [out_of_scope["agent_id"]]})
    assert resp.status_code == 409
    resp = client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-win-whoami-discovery",
                                                              "agent_ids": [lin["agent_id"]]})
    assert resp.status_code == 409
    assert client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-nope", "tags": ["lab"]}).status_code == 404
    assert client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-win-whoami-discovery"}).status_code == 400
    assert client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-win-whoami-discovery",
                                                              "agent_ids": ["agt_x"]}).status_code == 404
    # A draft can never be queued.
    draft_dir = platform.settings.library_dirs[1]
    draft_dir.mkdir(parents=True, exist_ok=True)
    src = (platform.settings.library_dirs[0] / "dw-win-whoami-discovery.yml").read_text()
    draft = src.replace("id: dw-win-whoami-discovery", "id: dw-draft-whoami")
    draft = draft.replace("status: approved", "status: draft")
    (draft_dir / "dw-draft-whoami.yml").write_text(draft)
    assert client.post("/api/v1/library/reload", headers=admin()).json()["tests"] == 11
    resp = client.post("/api/v1/runs", headers=admin(), json={"test_id": "dw-draft-whoami", "tags": ["lab"]})
    assert resp.status_code == 409 and "approve" in resp.text
    approved = client.post("/api/v1/library/dw-draft-whoami/approve", headers=admin(),
                           json={"reviewer": "alvin", "notes": "ok"}).json()
    assert approved["status"] == "approved" and approved["flow"][0]["title"]
    assert client.post("/api/v1/library/dw-draft-whoami/approve", headers=admin(),
                       json={"reviewer": "alvin"}).status_code == 409
    # Revoked agents lose access immediately.
    assert client.post(f"/api/v1/agents/{win['agent_id']}/revoke", headers=admin()).json()["status"] == "revoked"
    assert client.get("/api/v1/agent/tasks", headers=win["headers"]).status_code == 403
    tagged = client.put(f"/api/v1/agents/{lin['agent_id']}/tags", headers=admin(), json={"tags": ["lab", "linux"]})
    assert tagged.json()["tags"] == ["lab", "linux"]
    assert client.get("/api/v1/agents/agt_missing", headers=admin()).status_code == 404


def test_cancelled_when_test_becomes_invalid(client, platform):
    agent = enroll(client)
    client.get("/api/v1/agent/tasks", headers=agent["headers"])
    run = platform.store.create_run("dw-removed-test", 1, agent["agent_id"], "manual")
    assert client.get("/api/v1/agent/tasks", headers=agent["headers"]).json()["bundles"] == []
    assert platform.store.get_run(run["id"])["status"] == "cancelled"


def test_hygiene_without_report_and_stale_dispatch(client, platform, monkeypatch):
    agent = enroll(client)
    payload = decode(client.get("/api/v1/agent/tasks", headers=agent["headers"]).json()["bundles"][0])
    submit(client, agent, payload, [{"index": 0, "action": "hygiene.collect", "status": "error"}])
    assert platform.store.get_run(payload["run_id"])["outcome"] == "error"
    run = platform.store.create_run("dw-win-whoami-discovery", 1, agent["agent_id"], "manual")
    client.get("/api/v1/agent/tasks", headers=agent["headers"])
    later = store_mod.utcnow() + timedelta(hours=2)
    monkeypatch.setattr(store_mod, "utcnow", lambda: later)
    assert platform.store.expire_stale_dispatches() >= 1
    assert platform.store.get_run(run["id"])["status"] == "expired"


def test_rules_catalog_and_library_views(client):
    rules = client.get("/api/v1/rules", headers=admin()).json()
    assert len(rules) == 10 and all(r["kql"] for r in rules)
    assert len(client.get("/api/v1/catalog", headers=admin()).json()) >= 9
    lib = client.get("/api/v1/library", headers=admin()).json()
    assert len(lib) == 10 and lib[0]["results"] == {"runs": 0, "passed": 0}
    detail = client.get("/api/v1/library/dw-win-run-key-persistence", headers=admin()).json()
    assert "registry.run_key_canary" in detail["yaml"] and detail["rules"][0]["title"].startswith("New value")
    assert client.get("/api/v1/library/dw-nope", headers=admin()).status_code == 404
    assert ADMIN not in json.dumps(detail)
