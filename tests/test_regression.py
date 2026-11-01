import json
import xml.etree.ElementTree as ET

import httpx
import pytest

from driftwatch.library import Library
from driftwatch.regression import (
    RegressionReport,
    read_ndjson,
    run_live,
    run_offline,
    to_junit,
    to_markdown,
)

WHOAMI = "5f2b1c0e-6a41-4c7e-9b8a-1d2e3f4a5b01"


def lib(ws):
    return Library(ws / "library/tests")


def test_full_offline_gate_passes(workspace):
    report = run_offline(workspace / "rules", lib(workspace), workspace / "telemetry")
    assert report.ok and len(report.cases) == 20
    assert {c.kind for c in report.cases} == {"recall", "precision"}
    assert report.to_dict()["failed"] == 0


def test_breaking_a_rule_fails_the_gate(workspace):
    path = workspace / "rules/windows/whoami_all.yml"
    path.write_text(path.read_text().replace("/all", "/priv"))
    report = run_offline(workspace / "rules", lib(workspace), workspace / "telemetry",
                         changed=["rules/windows/whoami_all.yml"])
    assert report.selected_rules == [WHOAMI] and report.selected_tests == ["dw-win-whoami-discovery"]
    assert not report.ok
    fail = report.failed[0]
    assert fail.kind == "recall" and "no longer matches" in fail.message
    junit = ET.fromstring(to_junit(report))
    assert junit.get("failures") == "1" and junit.find("testcase/failure") is not None
    md = to_markdown(report)
    assert "**FAILED**" in md and md.index("| FAIL |") < md.index("| pass |")


def test_noisy_rule_fails_precision(workspace):
    benign = workspace / "telemetry/benign.ndjson"
    event = {"host": {"os": {"type": "windows"}}, "event": {"category": ["process"], "type": ["start"]},
             "process": {"executable": "C:\\Windows\\System32\\whoami.exe", "command_line": "whoami /all"}}
    benign.write_text(benign.read_text() + json.dumps(event) + "\n")
    report = run_offline(workspace / "rules", lib(workspace), workspace / "telemetry",
                         changed=["telemetry/benign.ndjson"])
    assert len(report.selected_rules) == 10
    noisy = [c for c in report.failed if c.kind == "precision"]
    assert [c.rule_id for c in noisy] == [WHOAMI] and "benign events" in noisy[0].message


def test_selection_by_test_and_telemetry(workspace):
    r = run_offline(workspace / "rules", lib(workspace), workspace / "telemetry",
                    changed=["telemetry/dw-lin-host-discovery.ndjson", "README.md"])
    assert r.selected_tests == ["dw-lin-host-discovery"] and r.ok
    r = run_offline(workspace / "rules", lib(workspace), workspace / "telemetry", changed=["docs/x.md"])
    assert r.cases == [] and r.ok and "0 checks" in to_markdown(r)


def test_missing_telemetry_rule_and_coverage(workspace):
    (workspace / "telemetry/dw-win-whoami-discovery.ndjson").unlink()
    test_path = workspace / "library/tests/dw-win-local-admin-enum.yml"
    text = test_path.read_text()
    test_path.write_text(text.replace("5f2b1c0e-6a41-4c7e-9b8a-1d2e3f4a5b02", "00000000-0000-0000-0000-000000000000"))
    report = run_offline(workspace / "rules", lib(workspace), workspace / "telemetry", require_coverage=True)
    messages = " ".join(c.message for c in report.failed)
    assert "no recorded telemetry" in messages and "does not exist" in messages
    assert any(c.kind == "coverage" for c in report.failed)


def test_read_ndjson_errors(tmp_path):
    p = tmp_path / "x.ndjson"
    p.write_text('{"a": 1}\n\n{bad\n')
    with pytest.raises(ValueError, match=":3: invalid JSON"):
        read_ndjson(p)


def test_run_live(monkeypatch):
    monkeypatch.setattr("driftwatch.regression.time.sleep", lambda s: None)
    state = {"polls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-API-Key"] == "k"
        if request.method == "POST":
            body = json.loads(request.content)
            if body["test_id"] == "dw-bad":
                return httpx.Response(409, text="draft")
            return httpx.Response(200, json=[{"id": "r1"}, {"id": "r2"}, {"id": "r3"}])
        run_id = request.url.path.rsplit("/", 1)[1]
        state["polls"] += 1
        if run_id == "r1":
            if state["polls"] < 3:
                return httpx.Response(200, json={"status": "dispatched"})
            return httpx.Response(200, json={"status": "evaluated", "passed": True, "outcome": "detected",
                                             "evaluation": {"notes": ["ok"]}})
        if run_id == "r2":
            return httpx.Response(200, json={"status": "expired", "outcome": None})
        return httpx.Response(200, json={"status": "dispatched"})

    report = RegressionReport(selected_tests=["dw-good", "dw-bad"])
    run_live(report, "https://dw", "k", ["lab"], timeout=0.5, poll=0, transport=httpx.MockTransport(handler))
    by = {c.name.split(" (")[0] + c.message.split(":")[0]: c for c in report.cases}
    assert any(c.passed and "detected ok" in c.message for c in report.cases)
    assert any("could not queue: 409" in c.message for c in report.cases)
    assert any(c.message.startswith("expired") and not c.passed for c in report.cases)
    assert any("not scored within" in c.message for c in report.cases)
    assert len(by) >= 3
