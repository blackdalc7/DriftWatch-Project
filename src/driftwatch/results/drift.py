"""Configuration drift and detection drift.

Two kinds of drift are tracked per agent:

* **Control drift**: a baseline check (for example an ASR rule or LSASS protection) changed state between
  two hygiene snapshots. The change happened somewhere between ``last_good_at`` and ``first_bad_at``. When
  Elastic has the matching configuration-change event (Defender 5007, a Sysmon registry write to the Lsa
  key, an auditd configuration change), the engine narrows that interval to ``exact_change_at``.
* **Test drift**: a test that passed on its previous run now fails (or the reverse). The event lists the
  test's linked baseline controls that are failing in the latest snapshot as likely causes.
"""

from __future__ import annotations

from typing import Any

from driftwatch.results.elastic import ElasticClient, ElasticError

DRIFTED = "fail"
GOOD = "pass"

# Control id prefix -> ES query clauses that identify a configuration change for that control.
CHANGE_SIGNALS: dict[str, list[dict[str, Any]]] = {
    "win.defender.": [
        {"term": {"winlog.channel": "Microsoft-Windows-Windows Defender/Operational"}},
        {"terms": {"event.code": ["5001", "5004", "5007", "5010", "5012"]}},
    ],
    "win.asr.": [
        {"term": {"winlog.channel": "Microsoft-Windows-Windows Defender/Operational"}},
        {"term": {"event.code": "5007"}},
        {"wildcard": {"message": {"value": "*AttackSurfaceReduction*", "case_insensitive": True}}},
    ],
    "win.lsass.": [
        {"terms": {"event.code": ["12", "13", "14"]}},
        {"wildcard": {"registry.path": {"value": "*\\Control\\Lsa*", "case_insensitive": True}}},
    ],
    "win.credential_guard.": [
        {"terms": {"event.code": ["12", "13", "14"]}},
        {"wildcard": {"registry.path": {"value": "*DeviceGuard*", "case_insensitive": True}}},
    ],
    "win.powershell.": [
        {"terms": {"event.code": ["12", "13", "14"]}},
        {"wildcard": {"registry.path": {"value": "*PowerShell\\ScriptBlockLogging*", "case_insensitive": True}}},
    ],
    "linux.auditd.": [
        {"term": {"event.module": "auditd"}},
        {"terms": {"event.action": ["changed-audit-configuration", "stopped-service", "changed-configuration"]}},
    ],
}


def _checks(report: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not report:
        return {}
    return {c["id"]: c for c in report.get("checks", []) if isinstance(c, dict) and c.get("id")}


def compare_snapshots(agent_id: str, previous: dict[str, Any] | None, current: dict[str, Any]) -> list[dict[str, Any]]:
    """Control drift events between two snapshot rows (``collected_at`` + ``report``).

    ``unknown`` results are never treated as drift in either direction: a check that could not run is
    reported in the snapshot, but it does not prove the control changed.
    """
    if previous is None:
        return []
    before, after = _checks(previous["report"]), _checks(current["report"])
    events = []
    for check_id, now in sorted(after.items()):
        was = before.get(check_id)
        if was is None:
            continue
        old, new = was.get("status"), now.get("status")
        if old == new or GOOD not in (old, new) or DRIFTED not in (old, new):
            continue
        events.append({
            "agent_id": agent_id,
            "kind": "control",
            "subject": check_id,
            "from_state": old,
            "to_state": new,
            "last_good_at": previous["collected_at"],
            "first_bad_at": current["collected_at"],
            "exact_change_at": None,
            "details": {
                "title": now.get("title"),
                "severity": now.get("severity"),
                "expected": now.get("expected"),
                "before": was.get("actual"),
                "after": now.get("actual"),
                "direction": "regressed" if new == DRIFTED else "remediated",
            },
        })
    return events


def change_signal_query(check_id: str, hostname: str, start: str, end: str) -> dict[str, Any] | None:
    """The Elastic query that finds the configuration-change event behind a control drift, if one is known."""
    clauses = next((v for k, v in CHANGE_SIGNALS.items() if check_id.startswith(k)), None)
    if clauses is None:
        return None
    return {
        "size": 5,
        "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": start, "lte": end}}},
            {"bool": {"should": [{"term": {"host.name": hostname}}, {"term": {"host.hostname": hostname}}],
                      "minimum_should_match": 1}},
            *clauses,
        ]}},
    }


def pinpoint(event: dict[str, Any], hostname: str, elastic: ElasticClient | None, index: str) -> dict[str, Any]:
    """Narrow a control drift to the exact change time using Elastic, when possible. Returns the event."""
    if elastic is None or event["kind"] != "control" or not event.get("last_good_at"):
        return event
    query = change_signal_query(event["subject"], hostname, event["last_good_at"], event["first_bad_at"])
    if query is None:
        return event
    try:
        hits = elastic.search(index, query)
    except ElasticError as exc:
        event["details"]["pinpoint_error"] = str(exc)
        return event
    if hits:
        first = hits[0].get("_source", {})
        event["exact_change_at"] = first.get("@timestamp")
        event["details"]["change_event"] = {
            "code": (first.get("event") or {}).get("code"),
            "message": str(first.get("message", ""))[:500],
            "user": (first.get("user") or {}).get("name"),
        }
    return event


def detect_test_drift(agent_id: str, test: Any, previous_run: dict[str, Any] | None, run: dict[str, Any],
               latest_hygiene: dict[str, Any] | None) -> dict[str, Any] | None:
    """A drift event when a test flips between passing and failing on the same agent."""
    if previous_run is None or previous_run.get("passed") is None or run.get("passed") is None:
        return None
    if bool(previous_run["passed"]) == bool(run["passed"]):
        return None
    checks = _checks(latest_hygiene["report"] if latest_hygiene else None)
    suspects = [c for c in test.hygiene_controls if checks.get(c, {}).get("status") == DRIFTED]
    regressed = not run["passed"]
    return {
        "agent_id": agent_id,
        "kind": "test",
        "subject": test.id,
        "from_state": GOOD if previous_run["passed"] else DRIFTED,
        "to_state": DRIFTED if regressed else GOOD,
        "last_good_at": previous_run.get("finished_at") if regressed else None,
        "first_bad_at": run.get("finished_at"),
        "exact_change_at": None,
        "details": {
            "title": test.name,
            "previous_outcome": previous_run.get("outcome"),
            "outcome": run.get("outcome"),
            "previous_run": previous_run["id"],
            "run": run["id"],
            "likely_causes": suspects,
            "direction": "regressed" if regressed else "remediated",
        },
    }
