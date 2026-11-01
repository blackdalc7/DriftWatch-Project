"""SQLite persistence for the control server.

One file, WAL mode, parameterised SQL only. JSON columns hold structured blobs (metrics, step results,
evaluations, hygiene reports). A single lock serialises writes because FastAPI runs sync endpoints in a
thread pool.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def audit_hash(prev: str, ts: str, actor: str, action: str, details: dict[str, Any]) -> str:
    """SHA-256 over the previous hash and the entry, as canonical JSON."""
    body = json.dumps([prev, ts, actor, action, details], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    os_version TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    cert_fingerprint TEXT NOT NULL UNIQUE,
    cert_expires_at TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_seen TEXT,
    metrics TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    cpu_percent REAL, memory_percent REAL, disk_percent REAL, uptime_seconds INTEGER
);
CREATE INDEX IF NOT EXISTS heartbeats_agent_ts ON heartbeats(agent_id, ts);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    test_id TEXT NOT NULL,
    test_version INTEGER NOT NULL,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    schedule_id TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    dispatched_at TEXT,
    expires_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    step_results TEXT NOT NULL DEFAULT '[]',
    agent_log TEXT NOT NULL DEFAULT '',
    outcome TEXT,
    passed INTEGER,
    evaluation TEXT,
    evaluated_at TEXT
);
CREATE INDEX IF NOT EXISTS runs_agent_status ON runs(agent_id, status);
CREATE INDEX IF NOT EXISTS runs_test ON runs(test_id, finished_at);
CREATE TABLE IF NOT EXISTS hygiene_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    collected_at TEXT NOT NULL,
    report TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS hygiene_agent_ts ON hygiene_snapshots(agent_id, collected_at);
CREATE TABLE IF NOT EXISTS drift_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    last_good_at TEXT,
    first_bad_at TEXT NOT NULL,
    exact_change_at TEXT,
    detected_at TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS drift_ts ON drift_events(first_bad_at);
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    test_ids TEXT NOT NULL,
    target_tags TEXT NOT NULL,
    days TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    timezone TEXT NOT NULL,
    randomize INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_planned_date TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL DEFAULT ''
);
"""

JSON_COLUMNS = {"tags", "metrics", "step_results", "evaluation", "report", "details", "test_ids", "target_tags", "days"}
HEARTBEAT_HISTORY = 500


def utcnow() -> datetime:
    """Timezone-aware now; patched in tests."""
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    """ISO-8601 in UTC with a trailing Z."""
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(text: str | None) -> datetime | None:
    """Inverse of :func:`iso` (also accepts +00:00 offsets)."""
    if not text:
        return None
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def hash_token(token: str) -> str:
    """Enrollment tokens are stored only as SHA-256 hashes."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_run_id() -> str:
    """16 lowercase hex characters, the format the catalog marker requires."""
    return secrets.token_hex(8)


class StoreError(Exception):
    """Raised for missing rows and rejected state changes."""


class Store:
    """All database access for the server."""

    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(SCHEMA)
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(audit_log)")}
            for col in sorted({"prev_hash", "hash"} - cols):  # databases created before the audit chain existed
                self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """A serialised write transaction."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [self._decode(r) for r in cur.fetchall()]

    def _row(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self._rows(sql, params)
        return rows[0] if rows else None

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        out = dict(row)
        for key in JSON_COLUMNS & out.keys():
            if isinstance(out[key], str):
                out[key] = json.loads(out[key])
        for key in ("randomize", "enabled", "revoked"):
            if key in out and out[key] is not None:
                out[key] = bool(out[key])
        if "passed" in out and out["passed"] is not None:
            out["passed"] = bool(out["passed"])
        return out

    # --- audit ---------------------------------------------------------------------------------------

    def audit(self, actor: str, action: str, details: dict[str, Any] | None = None,
              ts: datetime | None = None) -> None:
        """Append an entry. Each entry's hash covers the previous entry's hash, so edits break the chain."""
        stamp = iso(ts or utcnow())
        body = details or {}
        with self.tx() as c:
            last = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = last[0] if last else GENESIS_HASH
            c.execute("INSERT INTO audit_log(ts, actor, action, details, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                      (stamp, actor, action, json.dumps(body), prev, audit_hash(prev, stamp, actor, action, body)))

    def audit_log(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    def verify_audit_chain(self) -> dict[str, Any]:
        """Recompute every hash from the first entry. Reports the first entry that does not match."""
        prev = GENESIS_HASH
        rows = self._rows("SELECT * FROM audit_log ORDER BY id")
        for row in rows:
            expected = audit_hash(prev, row["ts"], row["actor"], row["action"], row["details"])
            if row["prev_hash"] != prev or row["hash"] != expected:
                return {"ok": False, "entries": len(rows), "head": rows[-1]["hash"], "broken_at": row["id"]}
            prev = row["hash"]
        return {"ok": True, "entries": len(rows), "head": prev, "broken_at": None}

    # --- enrollment tokens ---------------------------------------------------------------------------

    def create_token(self, label: str, ttl_seconds: int, max_uses: int, tags: list[str]) -> tuple[str, dict[str, Any]]:
        """Create an enrollment token; the plaintext is returned once and never stored."""
        if ttl_seconds < 60 or ttl_seconds > 7 * 86400:
            raise StoreError("token TTL must be between 60 seconds and 7 days")
        if max_uses < 1 or max_uses > 1000:
            raise StoreError("max_uses must be between 1 and 1000")
        token = "dwe_" + secrets.token_urlsafe(32)
        now = utcnow()
        row = {
            "id": secrets.token_hex(6),
            "label": label,
            "tags": tags,
            "created_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=ttl_seconds)),
            "max_uses": max_uses,
            "uses": 0,
            "revoked": False,
        }
        with self.tx() as c:
            c.execute(
                "INSERT INTO enrollment_tokens(id, token_hash, label, tags, created_at, expires_at, max_uses)"
                " VALUES (?,?,?,?,?,?,?)",
                (row["id"], hash_token(token), label, json.dumps(tags), row["created_at"], row["expires_at"], max_uses),
            )
        return token, row

    def list_tokens(self) -> list[dict[str, Any]]:
        return self._rows("SELECT id, label, tags, created_at, expires_at, max_uses, uses, revoked"
                          " FROM enrollment_tokens ORDER BY created_at DESC")

    def revoke_token(self, token_id: str) -> None:
        with self.tx() as c:
            if c.execute("UPDATE enrollment_tokens SET revoked = 1 WHERE id = ?", (token_id,)).rowcount == 0:
                raise StoreError(f"unknown token {token_id}")

    def consume_token(self, conn: sqlite3.Connection, token: str) -> dict[str, Any]:
        """Validate and use up one enrollment. Must run inside :meth:`tx`."""
        row = conn.execute("SELECT * FROM enrollment_tokens WHERE token_hash = ?", (hash_token(token),)).fetchone()
        if row is None:
            raise StoreError("invalid enrollment token")
        tok = self._decode(row)
        if tok["revoked"]:
            raise StoreError("enrollment token was revoked")
        if parse_iso(tok["expires_at"]) <= utcnow():  # type: ignore[operator]
            raise StoreError("enrollment token has expired")
        if tok["uses"] >= tok["max_uses"]:
            raise StoreError("enrollment token has no uses left")
        conn.execute("UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ?", (tok["id"],))
        return tok

    # --- agents --------------------------------------------------------------------------------------

    def insert_agent(self, conn: sqlite3.Connection, agent: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO agents(id, hostname, platform, os_version, agent_version, tags, cert_fingerprint,"
            " cert_expires_at, enrolled_at, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (agent["id"], agent["hostname"], agent["platform"], agent.get("os_version", ""),
             agent.get("agent_version", ""), json.dumps(agent.get("tags", [])), agent["cert_fingerprint"],
             agent["cert_expires_at"], agent["enrolled_at"], agent.get("last_seen")),
        )

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        row = self._row("SELECT * FROM agents WHERE id = ?", (agent_id,))
        if row is None:
            raise StoreError(f"unknown agent {agent_id}")
        return row

    def agent_by_fingerprint(self, fp: str) -> dict[str, Any] | None:
        return self._row("SELECT * FROM agents WHERE cert_fingerprint = ? AND status = 'active'", (fp,))

    def list_agents(self) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM agents ORDER BY hostname")

    def revoke_agent(self, agent_id: str) -> None:
        with self.tx() as c:
            if c.execute("UPDATE agents SET status = 'revoked' WHERE id = ?", (agent_id,)).rowcount == 0:
                raise StoreError(f"unknown agent {agent_id}")
            c.execute("UPDATE runs SET status = 'cancelled' WHERE agent_id = ? AND status IN ('queued','dispatched')",
                      (agent_id,))

    def set_agent_tags(self, agent_id: str, tags: list[str]) -> None:
        with self.tx() as c:
            if c.execute("UPDATE agents SET tags = ? WHERE id = ?", (json.dumps(tags), agent_id)).rowcount == 0:
                raise StoreError(f"unknown agent {agent_id}")

    def record_heartbeat(self, agent_id: str, metrics: dict[str, Any], agent_version: str | None = None,
                         ts: datetime | None = None) -> str:
        now = iso(ts or utcnow())
        with self.tx() as c:
            c.execute("UPDATE agents SET last_seen = ?, metrics = ?, agent_version = COALESCE(?, agent_version)"
                      " WHERE id = ?", (now, json.dumps(metrics), agent_version, agent_id))
            c.execute("INSERT INTO heartbeats(agent_id, ts, cpu_percent, memory_percent, disk_percent, uptime_seconds)"
                      " VALUES (?,?,?,?,?,?)",
                      (agent_id, now, metrics.get("cpu_percent"), metrics.get("memory_percent"),
                       metrics.get("disk_percent"), metrics.get("uptime_seconds")))
            c.execute("DELETE FROM heartbeats WHERE agent_id = ? AND id NOT IN"
                      " (SELECT id FROM heartbeats WHERE agent_id = ? ORDER BY id DESC LIMIT ?)",
                      (agent_id, agent_id, HEARTBEAT_HISTORY))
        return now  # type: ignore[return-value]

    def heartbeats(self, agent_id: str, limit: int = 120) -> list[dict[str, Any]]:
        rows = self._rows("SELECT ts, cpu_percent, memory_percent, disk_percent, uptime_seconds FROM heartbeats"
                          " WHERE agent_id = ? ORDER BY id DESC LIMIT ?", (agent_id, limit))
        return list(reversed(rows))

    # --- runs ----------------------------------------------------------------------------------------

    def create_run(self, test_id: str, test_version: int, agent_id: str, source: str,
                   not_before: datetime | None = None, schedule_id: str | None = None) -> dict[str, Any]:
        now = utcnow()
        run = {
            "id": new_run_id(),
            "test_id": test_id,
            "test_version": test_version,
            "agent_id": agent_id,
            "source": source,
            "schedule_id": schedule_id,
            "status": "queued",
            "created_at": iso(now),
            "not_before": iso(not_before or now),
        }
        with self.tx() as c:
            c.execute(
                "INSERT INTO runs(id, test_id, test_version, agent_id, source, schedule_id, status, created_at,"
                " not_before) VALUES (?,?,?,?,?,?,?,?,?)",
                (run["id"], test_id, test_version, agent_id, source, schedule_id, "queued", run["created_at"],
                 run["not_before"]),
            )
        return self.get_run(run["id"])

    def get_run(self, run_id: str) -> dict[str, Any]:
        row = self._row("SELECT * FROM runs WHERE id = ?", (run_id,))
        if row is None:
            raise StoreError(f"unknown run {run_id}")
        return row

    def list_runs(self, limit: int = 200, test_id: str | None = None,
                  agent_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM runs WHERE 1=1"
        params: list[Any] = []
        if test_id:
            sql += " AND test_id = ?"
            params.append(test_id)
        if agent_id:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return self._rows(sql, tuple(params))

    def due_runs(self, agent_id: str, limit: int = 5) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM runs WHERE agent_id = ? AND status = 'queued' AND not_before <= ?"
                          " ORDER BY not_before LIMIT ?", (agent_id, iso(utcnow()), limit))

    def mark_dispatched(self, run_id: str, expires_at: datetime) -> None:
        with self.tx() as c:
            c.execute("UPDATE runs SET status = 'dispatched', dispatched_at = ?, expires_at = ? WHERE id = ?"
                      " AND status = 'queued'", (iso(utcnow()), iso(expires_at), run_id))

    def complete_run(self, run_id: str, agent_id: str, started_at: str, finished_at: str,
                     step_results: list[dict[str, Any]], agent_log: str) -> dict[str, Any]:
        with self.tx() as c:
            row = c.execute("SELECT agent_id, status FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise StoreError(f"unknown run {run_id}")
            if row["agent_id"] != agent_id:
                raise StoreError("run belongs to a different agent")
            if row["status"] != "dispatched":
                raise StoreError(f"run is {row['status']}, not dispatched")
            c.execute("UPDATE runs SET status = 'completed', started_at = ?, finished_at = ?, step_results = ?,"
                      " agent_log = ? WHERE id = ?",
                      (started_at, finished_at, json.dumps(step_results), agent_log[:200_000], run_id))
        return self.get_run(run_id)

    def save_evaluation(self, run_id: str, outcome: str, passed: bool, evaluation: dict[str, Any]) -> dict[str, Any]:
        with self.tx() as c:
            c.execute("UPDATE runs SET status = 'evaluated', outcome = ?, passed = ?, evaluation = ?, evaluated_at = ?"
                      " WHERE id = ?", (outcome, int(passed), json.dumps(evaluation), iso(utcnow()), run_id))
        return self.get_run(run_id)

    def runs_awaiting_evaluation(self, older_than: datetime) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM runs WHERE status = 'completed' AND finished_at <= ? ORDER BY finished_at",
                          (iso(older_than),))

    def expire_stale_dispatches(self) -> int:
        with self.tx() as c:
            return c.execute("UPDATE runs SET status = 'expired' WHERE status = 'dispatched' AND expires_at < ?",
                             (iso(utcnow()),)).rowcount

    def previous_evaluated_run(self, test_id: str, agent_id: str, before: str) -> dict[str, Any] | None:
        return self._row("SELECT * FROM runs WHERE test_id = ? AND agent_id = ? AND status = 'evaluated'"
                         " AND finished_at < ? ORDER BY finished_at DESC LIMIT 1", (test_id, agent_id, before))

    def latest_results(self) -> list[dict[str, Any]]:
        """The most recent evaluated run per (test, agent)."""
        return self._rows(
            "SELECT r.* FROM runs r JOIN (SELECT test_id, agent_id, MAX(finished_at) AS f FROM runs"
            " WHERE status = 'evaluated' AND test_id != 'builtin.hygiene' GROUP BY test_id, agent_id) m"
            " ON r.test_id = m.test_id AND r.agent_id = m.agent_id AND r.finished_at = m.f"
        )

    # --- hygiene and drift ---------------------------------------------------------------------------

    def add_hygiene(self, agent_id: str, collected_at: str, report: dict[str, Any]) -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO hygiene_snapshots(agent_id, collected_at, report) VALUES (?,?,?)",
                            (agent_id, collected_at, json.dumps(report)))
            return int(cur.lastrowid or 0)

    def latest_hygiene(self, agent_id: str, before: str | None = None) -> dict[str, Any] | None:
        if before:
            return self._row("SELECT * FROM hygiene_snapshots WHERE agent_id = ? AND collected_at < ?"
                             " ORDER BY collected_at DESC LIMIT 1", (agent_id, before))
        return self._row("SELECT * FROM hygiene_snapshots WHERE agent_id = ? ORDER BY collected_at DESC LIMIT 1",
                         (agent_id,))

    def hygiene_history(self, agent_id: str, limit: int = 50) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM hygiene_snapshots WHERE agent_id = ? ORDER BY collected_at DESC LIMIT ?",
                          (agent_id, limit))

    def add_drift(self, event: dict[str, Any]) -> dict[str, Any]:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO drift_events(agent_id, kind, subject, from_state, to_state, last_good_at, first_bad_at,"
                " exact_change_at, detected_at, details) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (event["agent_id"], event["kind"], event["subject"], event["from_state"], event["to_state"],
                 event.get("last_good_at"), event["first_bad_at"], event.get("exact_change_at"),
                 event.get("detected_at") or iso(utcnow()), json.dumps(event.get("details", {}))),
            )
            event_id = cur.lastrowid
        row = self._row("SELECT * FROM drift_events WHERE id = ?", (event_id,))
        assert row is not None
        return row

    def drift_events(self, agent_id: str | None = None, since: str | None = None,
                     limit: int = 500) -> list[dict[str, Any]]:
        sql = "SELECT d.*, a.hostname FROM drift_events d JOIN agents a ON a.id = d.agent_id WHERE 1=1"
        params: list[Any] = []
        if agent_id:
            sql += " AND d.agent_id = ?"
            params.append(agent_id)
        if since:
            sql += " AND d.first_bad_at >= ?"
            params.append(since)
        sql += " ORDER BY d.first_bad_at DESC LIMIT ?"
        params.append(limit)
        return self._rows(sql, tuple(params))

    # --- schedules -----------------------------------------------------------------------------------

    def create_schedule(self, sched: dict[str, Any]) -> dict[str, Any]:
        sched_id = secrets.token_hex(6)
        with self.tx() as c:
            c.execute(
                "INSERT INTO schedules(id, name, test_ids, target_tags, days, window_start, window_end, timezone,"
                " randomize, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sched_id, sched["name"], json.dumps(sched["test_ids"]), json.dumps(sched["target_tags"]),
                 json.dumps(sched["days"]), sched["window_start"], sched["window_end"], sched["timezone"],
                 int(sched.get("randomize", True)), int(sched.get("enabled", True)), iso(utcnow())),
            )
        return self.get_schedule(sched_id)

    def get_schedule(self, sched_id: str) -> dict[str, Any]:
        row = self._row("SELECT * FROM schedules WHERE id = ?", (sched_id,))
        if row is None:
            raise StoreError(f"unknown schedule {sched_id}")
        return row

    def list_schedules(self) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM schedules ORDER BY name")

    def update_schedule(self, sched_id: str, sched: dict[str, Any]) -> dict[str, Any]:
        """Replace a schedule's definition. Runs already planned for today stay; changes apply from the next plan."""
        with self.tx() as c:
            cur = c.execute(
                "UPDATE schedules SET name = ?, test_ids = ?, target_tags = ?, days = ?, window_start = ?,"
                " window_end = ?, timezone = ?, randomize = ?, enabled = ? WHERE id = ?",
                (sched["name"], json.dumps(sched["test_ids"]), json.dumps(sched["target_tags"]),
                 json.dumps(sched["days"]), sched["window_start"], sched["window_end"], sched["timezone"],
                 int(sched.get("randomize", True)), int(sched.get("enabled", True)), sched_id),
            )
            if cur.rowcount == 0:
                raise StoreError(f"unknown schedule {sched_id}")
        return self.get_schedule(sched_id)

    def set_schedule_enabled(self, sched_id: str, enabled: bool) -> dict[str, Any]:
        with self.tx() as c:
            if c.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (int(enabled), sched_id)).rowcount == 0:
                raise StoreError(f"unknown schedule {sched_id}")
        return self.get_schedule(sched_id)

    def delete_schedule(self, sched_id: str) -> None:
        with self.tx() as c:
            if c.execute("DELETE FROM schedules WHERE id = ?", (sched_id,)).rowcount == 0:
                raise StoreError(f"unknown schedule {sched_id}")

    def mark_schedule_planned(self, sched_id: str, day: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE schedules SET last_planned_date = ? WHERE id = ?", (day, sched_id))
