"""Seed a database with a realistic week of lab activity so the dashboard can be explored without VMs.

Everything written here is clearly synthetic: agents are tagged ``demo``, runs have source ``demo``, and
the seeded drift story is the one the README walks through (an ASR rule switched off on Tuesday, which
makes the encoded-PowerShell test flip from detected to missed).
"""

from __future__ import annotations

import json
import random
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from driftwatch.library import Library
from driftwatch.schema import Outcome
from driftwatch.server.store import Store, iso, parse_iso

# (id, title, severity, expected, actual when passing, actual when failing). Ids and titles mirror the real
# hygiene scripts in agent/internal/hygiene/scripts.
WIN_CHECKS = [
    ("win.defender.antivirus_enabled", "Defender antivirus enabled", "high", "enabled", "enabled", "disabled"),
    ("win.defender.realtime_protection", "Defender real-time protection", "high", "enabled", "enabled", "disabled"),
    ("win.defender.cloud_protection", "Defender cloud-delivered protection", "medium", "MAPS basic or advanced",
     "advanced", "disabled"),
    ("win.defender.tamper_protection", "Defender tamper protection", "high", "enabled", "enabled", "disabled"),
    ("win.defender.signature_age", "Defender signatures updated in the last 3 days", "medium", "<= 3 days",
     "0 days", "9 days"),
    ("win.asr.block_lsass_credential_theft", "ASR: block credential stealing from LSASS", "high", "block", "block",
     "not configured"),
    ("win.asr.block_obfuscated_scripts", "ASR: block potentially obfuscated scripts", "high", "block", "block",
     "off"),
    ("win.lsass.runasppl", "LSASS runs as a protected process (RunAsPPL)", "high", "1 or 2", "RunAsPPL=1",
     "not set"),
    ("win.credential_guard.running", "Credential Guard running", "medium", "running", "running", "not running"),
    ("win.powershell.scriptblock_logging", "PowerShell script block logging", "medium", "enabled", "enabled",
     "disabled"),
    ("win.sysmon.process_creation", "Sysmon service running (process creation)", "high", "running", "running",
     "stopped"),
    ("win.firewall.domain", "Windows Firewall Domain profile", "medium", "enabled", "enabled", "disabled"),
    ("win.smb1.disabled", "SMBv1 server protocol", "high", "disabled", "disabled", "enabled"),
]
LIN_CHECKS = [
    ("linux.auditd.running", "auditd service", "high", "active", "active", "inactive"),
    ("linux.auditd.execve_rule", "auditd execve rule", "high", "execve rule", "loaded", "no execve rule"),
    ("linux.auditd.config_watch", "auditd watches its own configuration", "medium", "watch on /etc/audit",
     "present", "absent"),
    ("linux.ssh.root_login_disabled", "SSH root login (PermitRootLogin)", "medium", "no", "no", "yes"),
    ("linux.ssh.password_auth_disabled", "SSH password authentication (PasswordAuthentication)", "medium", "no",
     "no", "yes"),
    ("linux.firewall.active", "Host firewall", "medium", "active", "active (nftables)", "inactive"),
    ("linux.mac.enforcing", "SELinux enforcing or AppArmor enabled", "medium", "enforcing", "apparmor enabled",
     "disabled"),
    ("linux.kernel.aslr", "Full ASLR (randomize_va_space)", "medium", "2", "2", "0"),
    ("linux.kernel.ptrace_restricted", "ptrace restricted (yama ptrace_scope)", "medium", ">= 1", "1", "0"),
    ("linux.time.synchronized", "System clock NTP-synchronized", "medium", "yes", "yes", "no"),
]
HOSTS = {
    "windows": {"ip_addresses": ["10.24.0.11"], "kernel_version": "10.0.22631.4317 Build 22631.4317"},
    "linux": {"ip_addresses": ["10.24.0.12"], "kernel_version": "6.1.0-26-amd64"},
}
LAB_OPERATOR = "blackdalc"


def _report(platform: str, collected: datetime, failing: set[str]) -> dict[str, Any]:
    checks = WIN_CHECKS if platform == "windows" else LIN_CHECKS
    return {
        "schema": "driftwatch.hygiene/v1",
        "platform": platform,
        "collected_at": iso(collected),
        "checks": [{"id": cid, "title": title, "severity": sev, "status": "fail" if cid in failing else "pass",
                    "expected": expected, "actual": bad if cid in failing else good}
                   for cid, title, sev, expected, good, bad in checks],
    }


def seed(store: Store, library: Library, now: datetime | None = None, days: int = 7, seed_value: int = 7,
         audit: bool = True) -> dict:
    """Insert two demo agents, a week of hygiene snapshots, evaluated runs and the matching drift events.

    With ``audit`` the enrollment and schedule entries are appended to the audit chain at their own times.
    Callers that add later events of their own (the demo exporter) pass False and use :func:`audit_events`.
    """
    now = now or datetime.now(timezone.utc)
    rng = random.Random(seed_value)
    agents = [
        {"id": "agt_demo_win01", "hostname": "lab-win01", "platform": "windows", "os_version": "Windows 11 23H2"},
        {"id": "agt_demo_lin01", "hostname": "lab-lin01", "platform": "linux", "os_version": "Debian 12"},
    ]
    with store.tx() as conn:
        for a in agents:
            conn.execute("DELETE FROM agents WHERE id = ?", (a["id"],))
            store.insert_agent(conn, {**a, "agent_version": "1.0.0", "tags": ["lab", "demo"],
                                      "cert_fingerprint": secrets.token_hex(32),
                                      "cert_expires_at": iso(now + timedelta(days=30)),
                                      "enrolled_at": iso(now - timedelta(days=days + 1)), "last_seen": iso(now)})
    for a in agents:  # a day of heartbeats, every 20 minutes, ending now
        for i in range(72, -1, -1):
            busy = 9 <= (now - timedelta(minutes=20 * i)).hour < 17
            store.record_heartbeat(a["id"], {"cpu_percent": round(rng.uniform(8, 35) if busy else rng.uniform(2, 9), 1),
                                             "memory_percent": round(rng.uniform(40, 55), 1),
                                             "disk_percent": round(rng.uniform(52, 54), 1),
                                             "uptime_seconds": 86400 * 3 - 1200 * i, **HOSTS[a["platform"]]},
                                   "1.0.0", ts=now - timedelta(minutes=20 * i))
    start = now - timedelta(days=days)
    asr_off_at = (start + timedelta(days=2)).replace(hour=11, minute=42, second=7, microsecond=0)
    tests = [t for t in library.all() if t.dispatchable]
    counts = {"runs": 0, "snapshots": 0, "drift": 0}
    previous: dict[str, dict[str, Any]] = {}
    for day in range(days + 1):
        for hour in (9, 13, 17):
            t = (start + timedelta(days=day)).replace(hour=hour, minute=0, second=0, microsecond=0)
            if t > now:
                continue
            for a in agents:
                failing = set()
                if a["platform"] == "windows" and t >= asr_off_at:
                    failing.add("win.asr.block_obfuscated_scripts")
                if a["platform"] == "windows":
                    failing.add("win.credential_guard.running")
                report = _report(a["platform"], t, failing)
                store.add_hygiene(a["id"], iso(t), report)  # type: ignore[arg-type]
                counts["snapshots"] += 1
                prev = previous.get(a["id"])
                if prev:
                    before = {c["id"]: c for c in prev["checks"]}
                    for c in report["checks"]:
                        if before[c["id"]]["status"] == "pass" and c["status"] == "fail":
                            store.add_drift({"agent_id": a["id"], "kind": "control", "subject": c["id"],
                                             "from_state": "pass", "to_state": "fail",
                                             "last_good_at": prev["collected_at"], "first_bad_at": iso(t),
                                             "exact_change_at": iso(asr_off_at),
                                             "details": {"title": c["title"], "severity": c["severity"],
                                                         "direction": "regressed",
                                                         "before": before[c["id"]]["actual"],
                                                         "after": c["actual"],
                                                         "change_event": {"code": "5007", "user": "LAB\\it-admin",
                                                                          "message": "Microsoft Defender Antivirus "
                                                                          "Configuration has changed. ASR rule "
                                                                          "5beb7efe... set to 0 (Off)"}}})
                            counts["drift"] += 1
                previous[a["id"]] = report
        for a in agents:
            for test in tests:
                if a["platform"] not in test.platforms:
                    continue
                t = (start + timedelta(days=day)).replace(hour=10, minute=rng.randint(0, 59), second=rng.randint(0, 59))
                if t > now:
                    continue
                outcome = test.expected.outcome.value
                if test.id == "dw-win-encoded-powershell" and t >= asr_off_at:
                    outcome = "missed"
                if test.id == "dw-credential-file-canary" and a["platform"] == "linux":
                    outcome = "missed"
                passed = test.expected.passes(Outcome(outcome))
                run = store.create_run(test.id, test.version, a["id"], "demo", not_before=t)
                evaluation = {"outcome": outcome, "passed": passed, "telemetry_seen": True,
                              "telemetry_hits": rng.randint(1, 6), "detection_quality":
                              "technique" if outcome != "missed" else "none",
                              "alerts": [] if outcome == "missed" else [
                                  {"rule_id": r, "rule_name": r, "timestamp": iso(t + timedelta(seconds=40))}
                                  for r in test.expected.detections],
                              "expected_detections": test.expected.detections,
                              "missing_detections": test.expected.detections if outcome == "missed" else [],
                              "notes": ["Telemetry arrived but no rule fired."] if outcome == "missed" else []}
                steps = [{"index": i, "action": s.action, "status": "blocked" if outcome == "prevented" else "executed",
                          "cleanup": "ok"} for i, s in enumerate(test.steps)]
                with store.tx() as conn:
                    conn.execute(
                        "UPDATE runs SET status='evaluated', created_at=?, dispatched_at=?, started_at=?,"
                        " finished_at=?,"
                        " step_results=?, outcome=?, passed=?, evaluation=?, evaluated_at=?,"
                        " agent_log='demo run (synthetic)' WHERE id=?",
                        (iso(t), iso(t), iso(t), iso(t + timedelta(seconds=20)), json.dumps(steps), outcome,
                         int(passed), json.dumps(evaluation), iso(t + timedelta(minutes=3)), run["id"]))
                counts["runs"] += 1
                if test.id == "dw-win-encoded-powershell" and outcome == "missed" and \
                        t - timedelta(days=1) < asr_off_at:
                    store.add_drift({"agent_id": a["id"], "kind": "test", "subject": test.id, "from_state": "pass",
                                     "to_state": "fail", "last_good_at": iso(t - timedelta(days=1)),
                                     "first_bad_at": iso(t + timedelta(seconds=20)),
                                     "details": {"title": test.name, "previous_outcome": "detected",
                                                 "outcome": "missed", "direction": "regressed",
                                                 "likely_causes": ["win.asr.block_obfuscated_scripts"]}})
                    counts["drift"] += 1
    sched = store.create_schedule({"name": "Weekday office-hours sweep (Windows + Linux)",
                                   "test_ids": [t.id for t in tests], "target_tags": ["lab"],
                                   "days": [0, 1, 2, 3, 4], "window_start": "09:00", "window_end": "17:00",
                                   "timezone": "UTC", "randomize": True, "enabled": True})
    with store.tx() as conn:
        conn.execute("UPDATE schedules SET created_at = ? WHERE id = ?",
                     (iso(start - timedelta(hours=20)), sched["id"]))
    if audit:
        append_audit(store, audit_events(store, start))
    return counts


def audit_events(store: Store, start: datetime) -> list[tuple[datetime, str, str, dict[str, Any]]]:
    """The audit entries a real server would have written for the seeded setup: token, enrollments, schedule."""
    events: list[tuple[datetime, str, str, dict[str, Any]]] = [
        (start - timedelta(days=1, minutes=12), LAB_OPERATOR, "token.created", {"label": "lab-vms", "uses": 2}),
    ]
    for agent in store.list_agents():
        if "demo" in agent["tags"]:
            events.append((parse_iso(agent["enrolled_at"]) or start, f"agent:{agent['id']}", "agent.enrolled",
                           {"hostname": agent["hostname"]}))
    for sched in store.list_schedules():
        events.append((parse_iso(sched["created_at"]) or start, LAB_OPERATOR, "schedule.created",
                       {"id": sched["id"], "name": sched["name"]}))
    return events


def append_audit(store: Store, events: list[tuple[datetime, str, str, dict[str, Any]]]) -> None:
    """Append events to the audit chain in time order, so ids and timestamps agree."""
    for ts, actor, action, details in sorted(events, key=lambda e: e[0]):
        store.audit(actor, action, details, ts=ts)
