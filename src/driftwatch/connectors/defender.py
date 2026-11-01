"""Microsoft Defender posture via Microsoft Graph Secure Score.

Uses the documented Graph endpoints ``GET /v1.0/security/secureScores`` and
``GET /v1.0/security/secureScoreControlProfiles`` with an Entra app registration (client credentials,
``SecurityEvents.Read.All``). Pointed at the bundled mock (``driftwatch.mock_edr``) by default, because a
real tenant is optional for this lab.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from driftwatch.connectors.base import OAuthClient


@dataclass
class DefenderConfig:
    """Entra app credentials and endpoints for Microsoft Graph."""
    tenant_id: str
    client_id: str
    client_secret: str
    login_url: str = "https://login.microsoftonline.com"
    graph_url: str = "https://graph.microsoft.com"


class DefenderSecureScore:
    """Read the tenant's latest Secure Score and its control profiles."""

    def __init__(self, config: DefenderConfig, transport: httpx.BaseTransport | None = None) -> None:
        token_url = f"{config.login_url.rstrip('/')}/{config.tenant_id}/oauth2/v2.0/token"
        self._client = OAuthClient(config.graph_url, token_url, config.client_id, config.client_secret,
                                   {"grant_type": "client_credentials",
                                    "scope": f"{config.graph_url.rstrip('/')}/.default"}, transport=transport)

    def close(self) -> None:
        self._client.close()

    def latest_score(self) -> dict[str, Any]:
        """The newest Secure Score as a percentage, with each control's score and status."""
        body = self._client.get("/v1.0/security/secureScores", params={"$top": "1"})
        scores = body.get("value") or []
        if not scores:
            return {"current_score": None, "max_score": None, "percent": None, "controls": []}
        s = scores[0]
        current, maximum = s.get("currentScore"), s.get("maxScore")
        return {
            "created": s.get("createdDateTime"),
            "current_score": current,
            "max_score": maximum,
            "percent": round(100 * current / maximum, 1) if current is not None and maximum else None,
            "controls": [
                {"name": c.get("controlName"), "category": c.get("controlCategory"), "score": c.get("score"),
                 "percent": c.get("scoreInPercentage"), "status": c.get("implementationStatus"),
                 "description": c.get("description")}
                for c in s.get("controlScores", [])
            ],
        }

    def control_profiles(self) -> list[dict[str, Any]]:
        body = self._client.get("/v1.0/security/secureScoreControlProfiles")
        return [
            {"name": p.get("id"), "title": p.get("title"), "category": p.get("controlCategory"),
             "max_score": p.get("maxScore"), "service": p.get("service"), "threats": p.get("threats", []),
             "remediation": p.get("remediation")}
            for p in body.get("value", [])
        ]
