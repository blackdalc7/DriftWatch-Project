"""The results engine: decide whether each run was prevented, detected or missed.

Inputs are the agent's step results (did each action execute, get blocked, or fail?) and two Elastic
searches scoped to the run window and keyed on the run's unique marker:

1. **Telemetry** (``logs-*`` by default): did the SIEM receive any event carrying the marker? If not,
   a miss is a *blind spot* (no data), not just a missing rule.
2. **Alerts** (Kibana's ``.alerts-security.alerts-*`` by default): did any detection rule fire on an
   event carrying the marker, which rules, and at what ATT&CK granularity?

Scoring:

* any step **blocked** by a control                         -> ``prevented``
* otherwise any matching alert                               -> ``detected``
* otherwise, every step executed                             -> ``missed``
* a step failed for a non-security reason (and none blocked) -> ``error``

A run *passes* when the outcome meets the test's expectation and, unless prevented, every rule listed in
``expected.detections`` fired. Detection quality follows the MITRE ATT&CK Evaluations categories:
``technique`` (an alert names the exact technique), ``tactic``, ``general`` (some alert, no mapping) or
``none``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from driftwatch.catalog import MARKER_PREFIX
from driftwatch.results.elastic import ElasticClient, ElasticError
from driftwatch.schema import DriftwatchTest, Outcome
from driftwatch.server.store import iso, parse_iso

# Fields where the marker (or an observable) can appear, in telemetry and copied into alerts.
MARKER_FIELDS = (
    "process.command_line",
    "process.parent.command_line",
    "file.path",
    "registry.path",
    "registry.value",
    "registry.data.strings",
    "dns.question.name",
    "powershell.file.script_block_text",
    "message",
)
RULE_ID_FIELDS = ("kibana.alert.rule.parameters.rule_id", "kibana.alert.rule.rule_id", "signal.rule.rule_id")
MAX_HITS = 50
CLOCK_SKEW = timedelta(seconds=30)


@dataclass
class EngineConfig:
    """Where to look in Elastic."""

    telemetry_index: str = "logs-*"
    alerts_index: str = ".alerts-security.alerts-*"


def _get(doc: dict[str, Any], dotted: str) -> Any:
    if dotted in doc:
        return doc[dotted]
    node: Any = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def marker_query(marker: str, observables: list[str], start: str, end: str) -> dict[str, Any]:
    """Elasticsearch query for documents in [start, end] that contain the marker or an exact observable."""
    should: list[dict[str, Any]] = [
        {"wildcard": {f: {"value": f"*{marker}*", "case_insensitive": True}}} for f in MARKER_FIELDS
    ]
    should += [{"multi_match": {"query": o, "type": "phrase", "fields": list(MARKER_FIELDS), "lenient": True}}
               for o in observables if o and marker.lower() not in o.lower()]
    return {
        "size": MAX_HITS,
        "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": start, "lte": end}}}],
                "should": should,
                "minimum_should_match": 1,
            }
        },
    }


def _observables(step_results: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for step in step_results:
        for value in (step.get("observables") or {}).values():
            for v in value if isinstance(value, list) else [value]:
                if isinstance(v, str) and v and v not in found:
                    found.append(v)
    return found


def _alert_summary(hit: dict[str, Any]) -> dict[str, Any]:
    src = hit.get("_source", {})
    rule_id = next((str(_get(src, f)) for f in RULE_ID_FIELDS if _get(src, f)), None)
    techniques: list[str] = []
    tactics: list[str] = []
    for threat in _get(src, "kibana.alert.rule.threat") or []:
        tactic = (threat.get("tactic") or {}).get("name")
        if tactic:
            tactics.append(str(tactic).lower().replace(" ", "-"))
        for tech in threat.get("technique") or []:
            if tech.get("id"):
                techniques.append(tech["id"])
            for sub in tech.get("subtechnique") or []:
                if sub.get("id"):
                    techniques.append(sub["id"])
    return {
        "id": hit.get("_id"),
        "index": hit.get("_index"),
        "timestamp": src.get("@timestamp"),
        "rule_id": rule_id,
        "rule_name": _get(src, "kibana.alert.rule.name"),
        "severity": _get(src, "kibana.alert.severity"),
        "techniques": techniques,
        "tactics": tactics,
    }


def detection_quality(alerts: list[dict[str, Any]], test: DriftwatchTest) -> str:
    """ATT&CK Evaluations-style granularity of the best alert."""
    if not alerts:
        return "none"
    wanted = set(test.attack.techniques) | set(test.emulated_techniques())
    parents = {t.split(".")[0] for t in wanted}
    for alert in alerts:
        if any(t in wanted or t.split(".")[0] in parents for t in alert["techniques"]):
            return "technique"
    if any(test.attack.tactic in a["tactics"] for a in alerts):
        return "tactic"
    return "general"


def score(step_results: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> Outcome:
    """Pure outcome logic, separated for unit tests."""
    statuses = [s.get("status") for s in step_results]
    if not statuses:
        return Outcome.ERROR
    if "blocked" in statuses:
        return Outcome.PREVENTED
    if any(s not in ("executed", "blocked") for s in statuses):
        return Outcome.ERROR
    if alerts:
        return Outcome.DETECTED
    return Outcome.MISSED


class ResultsEngine:
    """Evaluates completed runs."""

    def __init__(self, elastic: ElasticClient | None, config: EngineConfig | None = None) -> None:
        self.elastic = elastic
        self.config = config or EngineConfig()

    def evaluate(self, run: dict[str, Any], test: DriftwatchTest) -> dict[str, Any]:
        """Score one run; returns the evaluation document stored on the run and in the evidence bundle."""
        marker = f"{MARKER_PREFIX}{run['id']}"
        started = parse_iso(run.get("started_at")) or parse_iso(run["created_at"])
        finished = parse_iso(run.get("finished_at")) or started
        assert started is not None and finished is not None
        start = iso(started - CLOCK_SKEW)
        end = iso(finished + timedelta(seconds=test.expected.window_seconds))
        steps = list(run.get("step_results") or [])
        observables = _observables(steps)
        query = marker_query(marker, observables, start, end)  # type: ignore[arg-type]
        notes: list[str] = []
        telemetry_hits: list[dict[str, Any]] = []
        alert_hits: list[dict[str, Any]] = []
        elastic_ok = self.elastic is not None
        if self.elastic is None:
            notes.append("No Elastic backend configured; detection could not be checked.")
        else:
            try:
                telemetry_hits = self.elastic.search(self.config.telemetry_index, query)
                alert_hits = self.elastic.search(self.config.alerts_index, query)
            except ElasticError as exc:
                elastic_ok = False
                notes.append(f"Elastic query failed: {exc}")
        alerts = [_alert_summary(h) for h in alert_hits]
        outcome = score(steps, alerts)
        if not elastic_ok and outcome in (Outcome.MISSED, Outcome.DETECTED):
            outcome = Outcome.ERROR
        fired = {a["rule_id"] for a in alerts if a["rule_id"]}
        expected = list(test.expected.detections)
        missing = [r for r in expected if r not in fired]
        passed = test.expected.passes(outcome) and (outcome is Outcome.PREVENTED or not missing)
        if outcome is Outcome.MISSED:
            notes.append("Telemetry arrived but no rule fired." if telemetry_hits
                         else "No telemetry carrying the marker reached Elastic: this is a blind spot.")
        if outcome is Outcome.DETECTED and missing:
            notes.append(f"Detected, but expected rules did not fire: {', '.join(missing)}")
        blocked = [s for s in steps if s.get("status") == "blocked"]
        for s in blocked:
            notes.append(f"Step {s.get('index')} ({s.get('action')}) was blocked: {s.get('detail', '')}".strip())
        return {
            "outcome": outcome.value,
            "passed": passed,
            "marker": marker,
            "window": {"start": start, "end": end},
            "telemetry_seen": bool(telemetry_hits),
            "telemetry_hits": len(telemetry_hits),
            "alerts": alerts,
            "expected_detections": expected,
            "missing_detections": missing if outcome is not Outcome.PREVENTED else [],
            "detection_quality": detection_quality(alerts, test),
            "steps": [{k: s.get(k) for k in ("index", "action", "status", "detail", "cleanup")} for s in steps],
            "query": query,
            "indices": {"telemetry": self.config.telemetry_index, "alerts": self.config.alerts_index},
            "notes": notes,
            "raw": {
                "telemetry": [h.get("_source", {}) for h in telemetry_hits[:20]],
                "alerts": [h.get("_source", {}) for h in alert_hits[:20]],
            },
        }
