"""Detection regression testing: prove every Sigma rule still fires on the attack it is meant to catch.

Offline mode (the default, used on every pull request) evaluates rules against ECS telemetry recorded from
real lab runs (``telemetry/<test id>.ndjson``) with Driftwatch's Sigma engine, so CI needs no SIEM:

* every rule a test lists in ``expected.detections`` must match at least one event of that test's
  recorded telemetry (**recall**), and
* no rule may match the recorded benign baseline (``telemetry/benign.ndjson``) (**precision**), and
* with ``require_coverage``, every rule must be linked to at least one test.

Live mode (``--live``, for a self-hosted runner inside the lab) additionally queues each affected test on
lab agents through the server API and waits for the results engine to score it.

Given the files a pull request changed, only the affected rules and tests are checked: a changed rule,
a changed test (its expected rules), or changed telemetry (that test's rules).
"""

from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from driftwatch.library import Library
from driftwatch.sigma import SigmaRule, load_rules

BENIGN_FILE = "benign.ndjson"


@dataclass
class CaseResult:
    """One rule checked against one test's telemetry (or the benign baseline)."""

    name: str
    rule_id: str
    test_id: str | None
    kind: str  # "recall" | "precision" | "coverage" | "live"
    passed: bool
    message: str
    matched_events: int = 0


@dataclass
class RegressionReport:
    cases: list[CaseResult] = field(default_factory=list)
    selected_rules: list[str] = field(default_factory=list)
    selected_tests: list[str] = field(default_factory=list)

    @property
    def failed(self) -> list[CaseResult]:
        return [c for c in self.cases if not c.passed]

    @property
    def ok(self) -> bool:
        return not self.failed

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "total": len(self.cases),
            "failed": len(self.failed),
            "selected_rules": self.selected_rules,
            "selected_tests": self.selected_tests,
            "cases": [c.__dict__ for c in self.cases],
        }


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    """Read newline-delimited JSON, skipping blank lines."""
    events = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{n}: invalid JSON: {exc}") from exc
    return events


def select(changed: list[str] | None, rules: dict[str, SigmaRule], library: Library,
           rules_dir: Path, telemetry_dir: Path) -> tuple[set[str], set[str]]:
    """Return (rule ids, test ids) affected by the changed paths; everything when ``changed`` is None."""
    tests = library.all()
    if changed is None:
        return set(rules), {t.id for t in tests if t.expected.detections}
    changed_paths = {Path(p).as_posix() for p in changed}
    rule_ids: set[str] = set()
    test_ids: set[str] = set()
    for rule in rules.values():
        if rule.path and any(rule.path.as_posix().endswith(p) or p.endswith(rule.path.as_posix())
                             for p in changed_paths):
            rule_ids.add(rule.id)
    for test in tests:
        test_path = library.path_of(test.id).as_posix()
        telemetry_path = (telemetry_dir / f"{test.id}.ndjson").as_posix()
        if any(test_path.endswith(p) or p.endswith(test_path) or telemetry_path.endswith(p)
               or p.endswith(telemetry_path) for p in changed_paths):
            test_ids.add(test.id)
            rule_ids.update(test.expected.detections)
    if any(p.endswith(BENIGN_FILE) for p in changed_paths):
        rule_ids.update(rules)
    for test in tests:
        if set(test.expected.detections) & rule_ids:
            test_ids.add(test.id)
    return rule_ids, test_ids


def run_offline(rules_dir: Path, library: Library, telemetry_dir: Path, changed: list[str] | None = None,
                require_coverage: bool = False) -> RegressionReport:
    """The CI gate."""
    rules = load_rules(rules_dir)
    rule_ids, test_ids = select(changed, rules, library, rules_dir, telemetry_dir)
    report = RegressionReport(selected_rules=sorted(rule_ids), selected_tests=sorted(test_ids))
    for test_id in sorted(test_ids):
        test = library.get(test_id)
        path = telemetry_dir / f"{test_id}.ndjson"
        events = read_ndjson(path) if path.exists() else []
        for rule_id in test.expected.detections:
            name = f"{test_id} -> {rule_id}"
            rule = rules.get(rule_id)
            if rule is None:
                report.cases.append(CaseResult(name, rule_id, test_id, "recall", False,
                                               "the test expects a rule id that does not exist in rules/"))
                continue
            if not events:
                report.cases.append(CaseResult(name, rule_id, test_id, "recall", False,
                                               f"no recorded telemetry at {path}; record a lab run first"))
                continue
            hits = sum(1 for e in events if rule.matches(e))
            report.cases.append(CaseResult(
                f"{test_id} -> {rule.title}", rule_id, test_id, "recall", hits > 0,
                f"matched {hits} of {len(events)} recorded events" if hits else
                f"rule no longer matches any of the {len(events)} events recorded for {test_id}", hits))
    benign_path = telemetry_dir / BENIGN_FILE
    benign = read_ndjson(benign_path) if benign_path.exists() else []
    for rule_id in sorted(rule_ids):
        rule = rules.get(rule_id)
        if rule is None:
            continue
        hits = [e for e in benign if rule.matches(e)]
        report.cases.append(CaseResult(
            f"benign baseline -> {rule.title}", rule_id, None, "precision", not hits,
            "no matches on the benign baseline" if not hits else
            f"matched {len(hits)} benign events, first: {json.dumps(hits[0])[:300]}", len(hits)))
    if require_coverage:
        linked = {r for t in library.all() for r in t.expected.detections}
        for rule_id in sorted(rule_ids):
            if rule_id in rules and rule_id not in linked:
                report.cases.append(CaseResult(f"coverage -> {rules[rule_id].title}", rule_id, None, "coverage",
                                               False, "no test lists this rule in expected.detections"))
    return report


def run_live(report: RegressionReport, server: str, api_key: str, tags: list[str], timeout: float = 900,
             poll: float = 10, verify: bool | str = True,
             transport: httpx.BaseTransport | None = None) -> RegressionReport:
    """Queue each selected test on lab agents and add one case per run with the scored outcome."""
    client = httpx.Client(base_url=server.rstrip("/"), headers={"X-API-Key": api_key}, verify=verify,
                          timeout=30, transport=transport)
    try:
        pending: dict[str, str] = {}
        for test_id in report.selected_tests:
            resp = client.post("/api/v1/runs", json={"test_id": test_id, "tags": tags})
            if resp.status_code >= 400:
                report.cases.append(CaseResult(f"live {test_id}", "", test_id, "live", False,
                                               f"could not queue: {resp.status_code} {resp.text[:200]}"))
                continue
            for run in resp.json():
                pending[run["id"]] = test_id
        deadline = time.monotonic() + timeout
        while pending and time.monotonic() < deadline:
            for run_id in list(pending):
                run = client.get(f"/api/v1/runs/{run_id}").json()
                if run["status"] in ("evaluated", "expired", "cancelled"):
                    test_id = pending.pop(run_id)
                    passed = run["status"] == "evaluated" and bool(run.get("passed"))
                    notes = "; ".join((run.get("evaluation") or {}).get("notes", []))
                    report.cases.append(CaseResult(f"live {test_id} ({run_id})", "", test_id, "live", passed,
                                                   f"{run['status']}: {run.get('outcome')} {notes}".strip()))
            if pending:
                time.sleep(poll)
        for run_id, test_id in pending.items():
            report.cases.append(CaseResult(f"live {test_id} ({run_id})", "", test_id, "live", False,
                                           f"not scored within {timeout:.0f}s"))
    finally:
        client.close()
    return report


def to_junit(report: RegressionReport) -> str:
    """JUnit XML for CI test reporters."""
    suite = ET.Element("testsuite", name="driftwatch-detection-regression", tests=str(len(report.cases)),
                       failures=str(len(report.failed)))
    for case in report.cases:
        tc = ET.SubElement(suite, "testcase", classname=f"driftwatch.{case.kind}", name=case.name)
        if not case.passed:
            ET.SubElement(tc, "failure", message=case.message).text = case.message
        else:
            ET.SubElement(tc, "system-out").text = case.message
    return ET.tostring(suite, encoding="unicode")


def to_markdown(report: RegressionReport) -> str:
    """A short summary for the PR job summary or a PR comment."""
    head = "Detection regression: **passed**" if report.ok else "Detection regression: **FAILED**"
    lines = [f"### {head}", "",
             f"{len(report.cases)} checks, {len(report.failed)} failed. "
             f"Rules checked: {len(report.selected_rules)}. Tests checked: {len(report.selected_tests)}.", ""]
    if report.cases:
        lines += ["| Result | Check | Detail |", "| --- | --- | --- |"]
        for c in sorted(report.cases, key=lambda c: (c.passed, c.name)):
            lines.append(f"| {'pass' if c.passed else 'FAIL'} | {c.name} | {c.message.replace('|', '/')} |")
    return "\n".join(lines) + "\n"
