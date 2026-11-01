from pathlib import Path

import pytest

from driftwatch.sigma import SigmaError, load_rules, parse_rule, to_kql
from driftwatch.sigma.engine import get_field

ROOT = Path(__file__).resolve().parents[1]

PROC = {"host": {"os": {"type": "windows"}}, "event": {"category": ["process"], "type": ["start"]},
        "process": {"executable": "C:\\Windows\\System32\\whoami.exe", "command_line": "whoami /ALL"}}


def rule(detection, logsource=None, **extra):
    return parse_rule({"id": "r1", "title": "t", "logsource": logsource or {"product": "windows",
                                                                           "category": "process_creation"},
                       "detection": detection, **extra})


def test_modifiers_and_case_insensitivity():
    sel = {"Image|endswith": "\\whoami.exe", "CommandLine|contains": "/all"}
    assert rule({"s": sel, "condition": "s"}).matches(PROC)
    assert rule({"s": {"CommandLine|startswith": "WHOAMI"}, "condition": "s"}).matches(PROC)
    assert rule({"s": {"CommandLine|contains|all": ["whoami", "/all"]}, "condition": "s"}).matches(PROC)
    assert not rule({"s": {"CommandLine|contains|all": ["whoami", "/priv"]}, "condition": "s"}).matches(PROC)
    assert rule({"s": {"CommandLine|re": "who.mi /[A-Z]+"}, "condition": "s"}).matches(PROC)
    assert rule({"s": {"Image": "*\\who?mi.exe"}, "condition": "s"}).matches(PROC)
    assert rule({"s": {"ParentImage": None}, "condition": "s"}).matches(PROC)
    assert not rule({"s": {"CommandLine": None}, "condition": "s"}).matches(PROC)


def test_windash_matches_slash_and_dash():
    r = rule({"s": {"CommandLine|contains|windash": " -enc "}, "condition": "s"})
    assert r.matches({**PROC, "process": {"command_line": "powershell /enc AAA"}})
    assert r.matches({**PROC, "process": {"command_line": "powershell -enc AAA"}})


def test_conditions():
    det = {"a": {"CommandLine|contains": "whoami"}, "b": {"CommandLine|contains": "/priv"},
           "sel_x": {"Image|endswith": ".exe"}, "sel_y": {"Image|contains": "System32"}}
    assert rule({**det, "condition": "a and not b"}).matches(PROC)
    assert not rule({**det, "condition": "a and b"}).matches(PROC)
    assert rule({**det, "condition": "(a or b) and all of sel_*"}).matches(PROC)
    assert rule({**det, "condition": "1 of them"}).matches(PROC)
    assert rule({**det, "condition": ["b", "a"]}).matches(PROC)
    assert not rule({**det, "condition": "not 1 of sel_*"}).matches(PROC)


def test_list_of_maps_and_keywords():
    either = [{"CommandLine|contains": "nope"}, {"CommandLine|contains": "/all"}]
    assert rule({"s": either, "condition": "s"}).matches(PROC)
    assert rule({"k": ["WHOAMI"], "condition": "k"}).matches(PROC)


def test_logsource_filters():
    r = rule({"s": {"CommandLine|contains": "whoami"}, "condition": "s"})
    assert not r.matches({**PROC, "host": {"os": {"type": "linux"}}})
    assert not r.matches({**PROC, "event": {"category": ["file"], "type": ["creation"]}})
    svc = rule({"s": {"EventID": 1116}, "condition": "s"}, {"product": "windows", "service": "windefend"})
    ev = {"host": {"os": {"type": "windows"}}, "event": {"code": "1116"},
          "winlog": {"channel": "Microsoft-Windows-Windows Defender/Operational"}}
    assert svc.matches(ev)
    audit = rule({"s": {"exe|endswith": "/id"}, "condition": "s"}, {"service": "auditd"})
    assert audit.matches({"event": {"module": "auditd"}, "process": {"executable": "/usr/bin/id"}})


def test_errors():
    with pytest.raises(SigmaError, match="missing"):
        parse_rule({"title": "x"})
    with pytest.raises(SigmaError, match="unsupported modifiers"):
        rule({"s": {"Image|base64": "x"}, "condition": "s"})
    with pytest.raises(SigmaError, match="unknown selection"):
        rule({"s": {"Image": "x"}, "condition": "t"})
    with pytest.raises(SigmaError, match="no condition"):
        rule({"s": {"Image": "x"}})
    with pytest.raises(SigmaError, match="parenthesis"):
        rule({"s": {"Image": "x"}, "condition": "(s"})
    with pytest.raises(SigmaError, match="ended"):
        rule({"s": {"Image": "x"}, "condition": "s and"})
    with pytest.raises(SigmaError, match="unexpected token"):
        rule({"s": {"Image": "x"}, "condition": "s s"})
    with pytest.raises(SigmaError, match="no selection matches"):
        rule({"s": {"Image": "x"}, "condition": "1 of q*"})
    with pytest.raises(SigmaError, match="expected 'of'"):
        rule({"s": {"Image": "x"}, "condition": "all s"})
    with pytest.raises(SigmaError, match="cannot parse"):
        rule({"s": {"Image": "x"}, "condition": "s | count() > 5"})
    with pytest.raises(SigmaError, match="must be a map"):
        rule({"s": "x", "condition": "s"})
    with pytest.raises(SigmaError, match="empty value"):
        rule({"s": {"Image": []}, "condition": "s"})
    with pytest.raises(SigmaError, match="category"):
        rule({"s": {"Image": "x"}, "condition": "s"}, {"category": "network_connection"}).matches(PROC)
    with pytest.raises(SigmaError, match="service"):
        rule({"s": {"Image": "x"}, "condition": "s"}, {"service": "zeek"}).matches(PROC)


def test_load_rules_and_duplicates(tmp_path):
    rules = load_rules(ROOT / "rules")
    assert len(rules) == 10
    whoami = rules["5f2b1c0e-6a41-4c7e-9b8a-1d2e3f4a5b01"]
    assert whoami.techniques == ["T1033"]
    (tmp_path / "a.yml").write_text((ROOT / "rules/windows/whoami_all.yml").read_text())
    (tmp_path / "b.yml").write_text((ROOT / "rules/windows/whoami_all.yml").read_text())
    with pytest.raises(SigmaError, match="duplicate"):
        load_rules(tmp_path)
    (tmp_path / "b.yml").write_text("title: [")
    with pytest.raises(SigmaError, match="invalid YAML"):
        load_rules(tmp_path)


def test_kql_conversion():
    r = rule({"a": {"Image|endswith": "\\whoami.exe", "CommandLine|contains": "/all"},
              "f": {"User": None}, "k": ["evil thing"], "condition": "a and not f or k"})
    kql = to_kql(r)
    assert kql.startswith('host.os.type:"windows" and event.category:"process" and event.type:"start"')
    assert "process.executable:*\\\\whoami.exe" in kql
    assert "not (not user.name:*)" in kql or "not not user.name:*" in kql
    assert '"evil thing"' in kql
    exact = rule({"s": {"User": "SYSTEM"}, "condition": "s"})
    assert to_kql(exact).endswith('user.name:"SYSTEM"')
    with pytest.raises(SigmaError, match="regular expression"):
        to_kql(rule({"s": {"Image|re": "x"}, "condition": "s"}))
    svc = rule({"s": {"EventID": [1116, 1117]}, "condition": "s"}, {"service": "windefend"})
    assert 'winlog.channel:"Microsoft-Windows-Windows Defender/Operational"' in to_kql(svc)
    assert 'event.module:"auditd"' in to_kql(rule({"s": {"exe": "x"}, "condition": "s"}, {"service": "auditd"}))
    with pytest.raises(SigmaError):
        to_kql(rule({"s": {"exe": "x"}, "condition": "s"}, {"service": "zeek"}))
    with pytest.raises(SigmaError):
        to_kql(rule({"s": {"exe": "x"}, "condition": "s"}, {"category": "nope"}))


def test_get_field_flat_and_nested():
    assert get_field({"a.b": 1}, "a.b") == 1
    assert get_field({"a": {"b.c": 2}}, "a.b.c") == 2
    assert get_field({"a": "x"}, "a.b") is None
