"""Cross-correlate Driftwatch results with EDR posture data.

The interesting output is disagreement:

* **Posture says fine, Driftwatch says broken.** Secure Score or ZTA reports a control as implemented, but
  the host's own baseline check fails, or a test linked to that control was missed.
* **Driftwatch failure with EDR context.** A failed test, annotated with the failing EDR signals on the
  same host that plausibly explain it.

Controls are matched to vendor controls by keywords in their titles and signal names, because vendor
control identifiers are tenant- and version-specific. The keyword table is deliberately small and easy to
extend.
"""

from __future__ import annotations

import os
from typing import Any

from driftwatch.connectors.base import ConnectorError
from driftwatch.connectors.crowdstrike import CrowdStrikeConfig, CrowdStrikeZTA
from driftwatch.connectors.defender import DefenderConfig, DefenderSecureScore

# Driftwatch control id prefix -> keywords that identify the same control in vendor data.
CONTROL_KEYWORDS: dict[str, tuple[str, ...]] = {
    "win.asr.": ("attack surface reduction", "asr"),
    "win.lsass.": ("lsass", "credential stealing", "lsa protection"),
    "win.credential_guard": ("credential guard",),
    "win.defender.realtime_protection": ("real-time protection", "realtime protection", "real time protection"),
    "win.defender.cloud_protection": ("cloud-delivered protection", "cloud protection"),
    "win.defender.tamper_protection": ("tamper protection",),
    "win.powershell.": ("powershell", "script block"),
    "win.firewall.": ("firewall",),
    "win.bitlocker": ("bitlocker", "disk encryption"),
    "linux.auditd.": ("auditd", "audit"),
}


def keywords_for(control_id: str) -> tuple[str, ...]:
    return next((v for k, v in CONTROL_KEYWORDS.items() if control_id.startswith(k)), ())


def _matches(text: str | None, keywords: tuple[str, ...]) -> bool:
    lowered = (text or "").lower()
    return any(k in lowered for k in keywords)


def _defender_compliant(score: dict[str, Any], profiles: list[dict[str, Any]], control_id: str) -> dict | None:
    keywords = keywords_for(control_id)
    if not keywords:
        return None
    titles = {p["name"]: p.get("title") for p in profiles}
    for c in score.get("controls", []):
        title = titles.get(c["name"]) or c.get("description") or c["name"]
        if _matches(title, keywords) or _matches(c["name"], keywords):
            percent = c.get("percent") or 0
            return {"vendor_control": c["name"], "title": title, "compliant": percent >= 100,
                    "percent": percent, "status": c.get("status")}
    return None


def correlate(agents: list[dict[str, Any]], hygiene: dict[str, dict[str, Any] | None], results: list[dict[str, Any]],
              tests: dict[str, Any], defender: dict[str, Any] | None, defender_profiles: list[dict[str, Any]],
              zta: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    """Pure correlation over data already fetched (unit-testable without HTTP)."""
    findings: list[dict[str, Any]] = []
    by_id = {a["id"]: a for a in agents}
    for agent in agents:
        report = hygiene.get(agent["id"]) or {}
        for check in report.get("checks", []):
            if check.get("status") != "fail":
                continue
            if defender:
                match = _defender_compliant(defender, defender_profiles, check["id"])
                if match and match["compliant"]:
                    findings.append({
                        "type": "posture_disagreement", "vendor": "defender", "host": agent["hostname"],
                        "control": check["id"], "driftwatch": "fail", "edr": match,
                        "summary": f"Secure Score counts '{match['title']}' as implemented, but {agent['hostname']} "
                                   f"fails {check['id']} ({check.get('actual')}).",
                    })
            z = zta.get(agent["id"])
            if z:
                failing = {s["name"] for s in z["failing_signals"]}
                related = [s for s in z["signals"] if _matches(s.get("signal_name"), keywords_for(check["id"]))]
                if related and not any(s.get("signal_name") in failing for s in related):
                    findings.append({
                        "type": "posture_disagreement", "vendor": "crowdstrike", "host": agent["hostname"],
                        "control": check["id"], "driftwatch": "fail",
                        "edr": {"signals": [s.get("signal_name") for s in related], "overall": z["overall"]},
                        "summary": f"Falcon ZTA signals {', '.join(s.get('signal_name', '') for s in related)} meet "
                                   f"criteria on {agent['hostname']}, but Driftwatch sees {check['id']} failing.",
                    })
    for run in results:
        if run.get("passed") is not False:
            continue
        agent = by_id.get(run["agent_id"])
        test = tests.get(run["test_id"])
        if agent is None or test is None:
            continue
        context: list[str] = []
        z = zta.get(agent["id"])
        for control in test.hygiene_controls:
            kws = keywords_for(control)
            if z:
                context += [s["name"] for s in z["failing_signals"] if _matches(s["name"], kws)]
            if defender:
                match = _defender_compliant(defender, defender_profiles, control)
                if match and not match["compliant"]:
                    context.append(f"Secure Score: {match['title']} at {match['percent']}%")
        findings.append({
            "type": "test_failure_context", "host": agent["hostname"], "test": test.id, "outcome": run["outcome"],
            "edr_context": sorted(set(context)),
            "summary": f"{test.id} was {run['outcome']} on {agent['hostname']}"
                       + (f"; EDR also flags: {', '.join(sorted(set(context)))}" if context else
                          "; the EDR reports nothing related, so this gap is invisible to posture scores."),
        })
    return {
        "defender": {**{k: defender.get(k) for k in ("current_score", "max_score", "percent", "created")},
                     "controls": [{k: c.get(k) for k in ("name", "category", "percent", "status", "description")}
                                  for c in defender.get("controls", [])]}
        if defender else None,
        "crowdstrike": {by_id[k]["hostname"]: {kk: v.get(kk) for kk in ("overall", "sensor_config", "os")}
                        for k, v in zta.items() if v and k in by_id},
        "findings": findings,
    }


def correlate_from_env(platform: Any, env: dict[str, str] | None = None) -> dict[str, Any]:
    """Fetch posture from whichever vendors are configured and correlate against the platform's state."""
    env = dict(os.environ if env is None else env)
    errors: list[str] = []
    defender = None
    profiles: list[dict[str, Any]] = []
    if env.get("DRIFTWATCH_DEFENDER_CLIENT_ID"):
        client = DefenderSecureScore(DefenderConfig(
            tenant_id=env.get("DRIFTWATCH_DEFENDER_TENANT_ID", "lab-tenant"),
            client_id=env["DRIFTWATCH_DEFENDER_CLIENT_ID"],
            client_secret=env.get("DRIFTWATCH_DEFENDER_CLIENT_SECRET", ""),
            login_url=env.get("DRIFTWATCH_DEFENDER_LOGIN_URL", "https://login.microsoftonline.com"),
            graph_url=env.get("DRIFTWATCH_DEFENDER_GRAPH_URL", "https://graph.microsoft.com"),
        ))
        try:
            defender, profiles = client.latest_score(), client.control_profiles()
        except ConnectorError as exc:
            errors.append(f"defender: {exc}")
        finally:
            client.close()
    agents = platform.store.list_agents()
    zta: dict[str, dict[str, Any] | None] = {}
    if env.get("DRIFTWATCH_CROWDSTRIKE_CLIENT_ID"):
        cs = CrowdStrikeZTA(CrowdStrikeConfig(
            client_id=env["DRIFTWATCH_CROWDSTRIKE_CLIENT_ID"],
            client_secret=env.get("DRIFTWATCH_CROWDSTRIKE_CLIENT_SECRET", ""),
            base_url=env.get("DRIFTWATCH_CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"),
        ))
        try:
            for agent in agents:
                zta[agent["id"]] = cs.assessment(agent["hostname"])
        except ConnectorError as exc:
            errors.append(f"crowdstrike: {exc}")
        finally:
            cs.close()
    configured = bool(env.get("DRIFTWATCH_DEFENDER_CLIENT_ID") or env.get("DRIFTWATCH_CROWDSTRIKE_CLIENT_ID"))
    hygiene = {a["id"]: (h["report"] if (h := platform.store.latest_hygiene(a["id"])) else None) for a in agents}
    tests = {t.id: t for t in platform.library.all()}
    result = correlate(agents, hygiene, platform.store.latest_results(), tests, defender, profiles, zta)
    result["configured"] = configured
    result["errors"] = errors
    return result
