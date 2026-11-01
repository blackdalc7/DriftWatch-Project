"""Mock EDR posture APIs.

Implements just enough of two vendor APIs, with the same paths and response shapes as their public
documentation, for the Driftwatch connectors to run end to end without a tenant:

* Microsoft identity platform token endpoint and Graph ``secureScores`` / ``secureScoreControlProfiles``
* CrowdStrike ``/oauth2/token``, ``/devices/queries/devices/v1`` and ZTA ``assessments``

Scenarios let a demo flip posture on purpose (``POST /_mock/scenario``), for example disabling an ASR rule
so that Secure Score drops while the host keeps reporting "compliant" on another control.
"""

from __future__ import annotations

import copy
import hmac
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Form, Header, HTTPException, Query
from pydantic import BaseModel

CONTROL_PROFILES = [
    {"id": "scid_asr_lsass", "title": "Block credential stealing from the Windows local security authority subsystem"
     " (LSASS) with Attack Surface Reduction", "controlCategory": "Device", "maxScore": 9.0,
     "service": "MDATP", "threats": ["Credential theft"],
     "remediation": "Enable ASR rule 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"},
    {"id": "scid_asr_obfuscated",
     "title": "Block execution of potentially obfuscated scripts (Attack Surface Reduction)",
     "controlCategory": "Device", "maxScore": 9.0, "service": "MDATP", "threats": ["Malware"],
     "remediation": "Enable ASR rule 5beb7efe-fd9a-4556-801d-275e5ffc04cc"},
    {"id": "scid_av_realtime", "title": "Turn on real-time protection", "controlCategory": "Device", "maxScore": 10.0,
     "service": "MDATP", "threats": ["Malware"], "remediation": "Set-MpPreference -DisableRealtimeMonitoring $false"},
    {"id": "scid_av_cloud", "title": "Turn on cloud-delivered protection", "controlCategory": "Device", "maxScore": 8.0,
     "service": "MDATP", "threats": ["Malware"], "remediation": "Set-MpPreference -MAPSReporting Advanced"},
    {"id": "scid_tamper", "title": "Turn on tamper protection", "controlCategory": "Device", "maxScore": 8.0,
     "service": "MDATP", "threats": ["Defense evasion"], "remediation": "Enable tamper protection in the portal"},
    {"id": "scid_mfa_admins", "title": "Require MFA for administrative roles", "controlCategory": "Identity",
     "maxScore": 10.0, "service": "AzureAD", "threats": ["Account breach"], "remediation": "Conditional Access"},
]

BASE_STATE: dict[str, Any] = {
    "scores": {"scid_asr_lsass": 100.0, "scid_asr_obfuscated": 100.0, "scid_av_realtime": 100.0,
               "scid_av_cloud": 100.0, "scid_tamper": 100.0, "scid_mfa_admins": 50.0},
    "hosts": {
        "lab-win01": {"aid": "8f2a1c3d4e5b6a7f8091a2b3c4d5e6f7", "platform": "Windows", "sensor_config": 92, "os": 78,
                      "signals": {"Firewall Enabled": "yes", "Real-time Protection": "yes",
                                  "Attack Surface Reduction": "yes", "LSA Protection (RunAsPPL)": "yes",
                                  "Credential Guard": "no", "BitLocker": "no", "Sensor Tamper Protection": "yes"}},
        "lab-lin01": {"aid": "1a2b3c4d5e6f708192a3b4c5d6e7f809", "platform": "Linux", "sensor_config": 88, "os": 70,
                      "signals": {"Audit Daemon (auditd)": "yes", "SELinux/AppArmor enforcing": "yes",
                                  "Sensor Operational Mode": "yes", "Disk Encryption": "no"}},
    },
}

SCENARIOS: dict[str, dict[str, Any]] = {
    "baseline": {},
    # The ASR rule gets switched off on the host. Secure Score notices; Falcon's signal is cached as "yes".
    "asr_disabled": {"scores": {"scid_asr_lsass": 0.0, "scid_asr_obfuscated": 0.0}},
    # Real-time protection off: both vendors notice.
    "realtime_off": {"scores": {"scid_av_realtime": 0.0},
                     "hosts": {"lab-win01": {"sensor_config": 61, "signals": {"Real-time Protection": "no"}}}},
    # auditd stopped on Linux: Falcon still reports the stale "yes" signal (a disagreement to find).
    "auditd_stopped": {},
}


class ScenarioRequest(BaseModel):
    name: str


def _merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def create_app(client_id: str | None = None, client_secret: str | None = None) -> FastAPI:
    """Create the mock with credentials from arguments or MOCK_EDR_CLIENT_ID / MOCK_EDR_CLIENT_SECRET."""
    expected_id = client_id or os.environ.get("MOCK_EDR_CLIENT_ID", "driftwatch-lab")
    expected_secret = client_secret or os.environ.get("MOCK_EDR_CLIENT_SECRET", "lab-secret-change-me")
    app = FastAPI(title="Driftwatch mock EDR", docs_url="/docs")
    tokens: dict[str, float] = {}
    state: dict[str, Any] = {"scenario": "baseline", "data": copy.deepcopy(BASE_STATE)}

    def issue(cid: str, secret: str) -> dict[str, Any]:
        if not (hmac.compare_digest(cid, expected_id) and hmac.compare_digest(secret, expected_secret)):
            raise HTTPException(401, {"error": "invalid_client"})
        token = secrets.token_urlsafe(24)
        tokens[token] = time.time() + 1800
        return {"access_token": token, "token_type": "Bearer", "expires_in": 1800}

    def require(authorization: str) -> None:
        token = authorization.removeprefix("Bearer ").strip()
        if tokens.get(token, 0) < time.time():
            raise HTTPException(401, {"error": "invalid_token"})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "scenario": state["scenario"]}

    @app.post("/_mock/scenario")
    def set_scenario(body: ScenarioRequest) -> dict[str, Any]:
        if body.name not in SCENARIOS:
            raise HTTPException(404, f"unknown scenario; choose from {sorted(SCENARIOS)}")
        state["scenario"] = body.name
        state["data"] = _merge(BASE_STATE, SCENARIOS[body.name])
        return {"scenario": body.name}

    # --- Microsoft identity platform + Graph -----------------------------------------------------------

    @app.post("/{tenant}/oauth2/v2.0/token")
    def ms_token(tenant: str, client_id: str = Form(...), client_secret: str = Form(...),
                 grant_type: str = Form(...), scope: str = Form("")) -> dict[str, Any]:
        if grant_type != "client_credentials":
            raise HTTPException(400, {"error": "unsupported_grant_type"})
        return issue(client_id, client_secret)

    @app.get("/v1.0/security/secureScores")
    def secure_scores(authorization: str = Header(default=""), top: int = Query(1, alias="$top")) -> dict[str, Any]:
        require(authorization)
        scores = state["data"]["scores"]
        controls = []
        current = 0.0
        maximum = 0.0
        for p in CONTROL_PROFILES:
            pct = scores.get(p["id"], 0.0)
            pts = round(p["maxScore"] * pct / 100, 2)
            current += pts
            maximum += p["maxScore"]
            controls.append({"controlName": p["id"], "controlCategory": p["controlCategory"], "score": pts,
                             "scoreInPercentage": pct, "description": p["title"],
                             "implementationStatus": "Implemented" if pct >= 100 else
                             ("Partially implemented" if pct > 0 else "Not implemented")})
        return {"value": [{
            "id": f"lab-tenant_{datetime.now(timezone.utc):%Y-%m-%d}",
            "azureTenantId": "00000000-0000-0000-0000-00000000d00d",
            "createdDateTime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "currentScore": round(current, 2),
            "maxScore": maximum,
            "averageComparativeScores": [{"basis": "AllTenants", "averageScore": 41.2}],
            "controlScores": controls,
        }][:max(top, 0)]}

    @app.get("/v1.0/security/secureScoreControlProfiles")
    def control_profiles(authorization: str = Header(default="")) -> dict[str, Any]:
        require(authorization)
        return {"value": CONTROL_PROFILES}

    # --- CrowdStrike Falcon --------------------------------------------------------------------------

    @app.post("/oauth2/token")
    def cs_token(client_id: str = Form(...), client_secret: str = Form(...)) -> dict[str, Any]:
        return issue(client_id, client_secret)

    @app.get("/devices/queries/devices/v1")
    def cs_devices(authorization: str = Header(default=""), filter: str = Query("")) -> dict[str, Any]:
        require(authorization)
        m = re.fullmatch(r"hostname:'([^']+)'", filter)
        host = state["data"]["hosts"].get(m.group(1)) if m else None
        return {"meta": {"query_time": 0.01}, "resources": [host["aid"]] if host else [], "errors": []}

    @app.get("/zero-trust-assessment/entities/assessments/v1")
    def cs_zta(authorization: str = Header(default=""), ids: str = Query(...)) -> dict[str, Any]:
        require(authorization)
        out = []
        for name, host in state["data"]["hosts"].items():
            if host["aid"] != ids:
                continue
            signals = [{"signal_id": f"sig_{i}", "signal_name": sig,
                        "group_name": "sensor" if "Sensor" in sig else "os",
                        "criteria": f"{sig}: enabled", "meets_criteria": val}
                       for i, (sig, val) in enumerate(sorted(host["signals"].items()))]
            overall = round((host["sensor_config"] + host["os"]) / 2)
            out.append({
                "aid": host["aid"], "cid": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6", "event_platform": host["platform"],
                "product_type_desc": "Workstation", "system_serial_number": f"LAB-{name.upper()}",
                "modified_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "assessment": {"sensor_config": host["sensor_config"], "os": host["os"], "overall": overall,
                               "version": "3.6.0"},
                "assessment_items": {"os_signals": [s for s in signals if s["group_name"] == "os"],
                                     "sensor_signals": [s for s in signals if s["group_name"] == "sensor"]},
            })
        return {"meta": {"query_time": 0.01}, "resources": out, "errors": []}

    return app


app = create_app()
