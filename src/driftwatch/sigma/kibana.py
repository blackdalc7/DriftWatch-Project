"""Deploy Sigma rules to the Kibana detection engine as KQL custom query rules.

The Sigma rule id becomes the Kibana ``rule_id``, which is what the results engine reads back from alerts
(``kibana.alert.rule.parameters.rule_id``) to check that the *expected* rule fired.
"""

from __future__ import annotations

from typing import Any

import httpx

from driftwatch.sigma.engine import SigmaRule
from driftwatch.sigma.kql import to_kql

SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
RISK = {"low": 21, "medium": 47, "high": 73, "critical": 99}
TACTICS = {
    "reconnaissance": ("TA0043", "Reconnaissance"), "resource-development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"), "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"), "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"), "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"), "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"), "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"), "impact": ("TA0040", "Impact"),
}


def threat_mapping(rule: SigmaRule) -> list[dict[str, Any]]:
    """Kibana ``threat`` array from ``attack.<tactic>`` and ``attack.tXXXX`` tags."""
    tactics = [t.split(".", 1)[1] for t in rule.tags if t.lower().startswith("attack.") and
               t.split(".", 1)[1] in TACTICS]
    techniques = rule.techniques
    threat = []
    for tactic in tactics or []:
        tid, name = TACTICS[tactic]
        entries: dict[str, dict[str, Any]] = {}
        for tech in techniques:
            parent = tech.split(".")[0]
            entry = entries.setdefault(parent, {"id": parent, "name": parent,
                                                "reference": f"https://attack.mitre.org/techniques/{parent}/",
                                                "subtechnique": []})
            if "." in tech:
                entry["subtechnique"].append({"id": tech, "name": tech, "reference":
                                              f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"})
        threat.append({"framework": "MITRE ATT&CK",
                       "tactic": {"id": tid, "name": name, "reference": f"https://attack.mitre.org/tactics/{tid}/"},
                       "technique": list(entries.values())})
    return threat


def to_kibana_rule(rule: SigmaRule, index: list[str], interval: str = "1m") -> dict[str, Any]:
    severity = SEVERITY.get(rule.level, "medium")
    return {
        "rule_id": rule.id,
        "name": rule.title,
        "description": str(rule.source.get("description", rule.title)),
        "type": "query",
        "language": "kuery",
        "query": to_kql(rule),
        "index": index,
        "severity": severity,
        "risk_score": RISK[severity],
        "interval": interval,
        "from": "now-6m",
        "enabled": True,
        "tags": ["Driftwatch", *rule.tags],
        "threat": threat_mapping(rule),
        "false_positives": [str(f) for f in rule.source.get("falsepositives", [])],
        "author": [str(rule.source.get("author", "Driftwatch"))],
        "license": "MIT",
    }


def deploy(rules: list[SigmaRule], kibana_url: str, index: list[str], user: str | None = None,
           password: str | None = None, api_key: str | None = None, verify: bool | str = True,
           transport: httpx.BaseTransport | None = None) -> list[dict[str, Any]]:
    """Create or update each rule; returns one status entry per rule."""
    headers = {"kbn-xsrf": "driftwatch", "Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    auth = (user, password) if user and password and not api_key else None
    results = []
    with httpx.Client(base_url=kibana_url.rstrip("/"), headers=headers, auth=auth, verify=verify, timeout=30,
                      transport=transport) as client:
        for rule in rules:
            body = to_kibana_rule(rule, index)
            existing = client.get("/api/detection_engine/rules", params={"rule_id": rule.id})
            if existing.status_code == 200:
                resp = client.put("/api/detection_engine/rules", json=body)
                action = "updated"
            else:
                resp = client.post("/api/detection_engine/rules", json=body)
                action = "created"
            results.append({"rule_id": rule.id, "title": rule.title, "action": action,
                            "status": resp.status_code, "ok": resp.status_code < 300,
                            "error": None if resp.status_code < 300 else resp.text[:300]})
    return results
