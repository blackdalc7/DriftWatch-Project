"""Audit hash chain, schedule edits, and the host details agents may report in heartbeats."""

import sqlite3
from datetime import datetime, timedelta, timezone

from conftest import admin, enroll

from driftwatch.server.store import GENESIS_HASH, Store, audit_hash

BASE = {"name": "sweep", "test_ids": ["dw-win-whoami-discovery"], "target_tags": ["lab"]}


def test_audit_chain_links_and_detects_tampering(tmp_path):
    store = Store(tmp_path / "a.sqlite3")
    t = datetime(2026, 10, 30, 9, tzinfo=timezone.utc)
    store.audit("ops", "token.created", {"label": "x"}, ts=t)
    store.audit("system", "test.verified", {"test_id": "dw-a"}, ts=t + timedelta(hours=1))
    rows = list(reversed(store.audit_log()))
    assert rows[0]["prev_hash"] == GENESIS_HASH and rows[1]["prev_hash"] == rows[0]["hash"]
    assert rows[0]["hash"] == audit_hash(GENESIS_HASH, rows[0]["ts"], "ops", "token.created", {"label": "x"})
    assert store.verify_audit_chain() == {"ok": True, "entries": 2, "head": rows[1]["hash"], "broken_at": None}
    with store.tx() as c:
        c.execute("UPDATE audit_log SET actor = 'someone-else' WHERE id = 1")
    assert store.verify_audit_chain()["broken_at"] == 1
    store.close()


def test_audit_columns_are_added_to_old_databases(tmp_path):
    path = tmp_path / "old.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,"
                 " action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}')")
    conn.commit()
    conn.close()
    store = Store(path)
    store.audit("ops", "x", {})
    assert store.verify_audit_chain()["ok"] is True
    store.close()


def test_audit_verify_endpoint(client):
    client.post("/api/v1/tokens", headers=admin(),
                json={"label": "t", "ttl_seconds": 600, "max_uses": 1, "tags": ["lab"]})
    body = client.get("/api/v1/audit/verify", headers=admin()).json()
    assert body["ok"] is True and body["entries"] >= 1
    assert client.get("/api/v1/audit", headers=admin()).json()[0]["hash"] == body["head"]


def test_schedule_update(client):
    created = client.post("/api/v1/schedules", headers=admin(), json=BASE).json()
    updated = client.put(f"/api/v1/schedules/{created['id']}", headers=admin(),
                         json={**BASE, "name": "evening sweep", "window_start": "18:00", "window_end": "22:00"}).json()
    assert (updated["name"], updated["window_start"]) == ("evening sweep", "18:00")
    assert updated["created_at"] == created["created_at"]
    assert client.put(f"/api/v1/schedules/{created['id']}", headers=admin(),
                      json={**BASE, "window_end": "01:00"}).status_code == 422
    assert client.put("/api/v1/schedules/nope", headers=admin(), json=BASE).status_code == 404
    assert client.get("/api/v1/audit", headers=admin()).json()[0]["action"] == "schedule.updated"


def test_heartbeat_host_details_are_validated(client):
    agent = enroll(client)
    client.post("/api/v1/agent/heartbeat", headers=agent["headers"], json={"metrics": {
        "cpu_percent": 1.0, "kernel_version": "6.1.0-26-amd64",
        "ip_addresses": ["10.24.0.12", "not-an-ip", "fe80::1", "::1"],
        "shell": "rm -rf /"}})
    detail = client.get(f"/api/v1/agents/{agent['agent_id']}", headers=admin()).json()
    assert detail["metrics"]["ip_addresses"] == ["10.24.0.12", "fe80::1", "::1"]
    assert detail["metrics"]["kernel_version"] == "6.1.0-26-amd64"
    assert "shell" not in detail["metrics"]
    assert len(detail["cert_sha256"]) == 64
    summary = client.get("/api/v1/summary", headers=admin()).json()
    assert summary["scored"] == 0 and summary["passed"] == 0
