"""CrowdStrike Falcon Zero Trust Assessment (ZTA) posture per host.

Uses the documented Falcon endpoints ``POST /oauth2/token``, ``GET /devices/queries/devices/v1`` (to
resolve a hostname to an agent id) and ``GET /zero-trust-assessment/entities/assessments/v1``. The API
client needs the *Zero Trust Assessment: Read* and *Hosts: Read* scopes. Pointed at the bundled mock by
default.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from driftwatch.connectors.base import OAuthClient


@dataclass
class CrowdStrikeConfig:
    client_id: str
    client_secret: str
    base_url: str = "https://api.crowdstrike.com"


class CrowdStrikeZTA:
    """Read ZTA scores and failing signals for hosts."""

    def __init__(self, config: CrowdStrikeConfig, transport: httpx.BaseTransport | None = None) -> None:
        self._client = OAuthClient(config.base_url, "/oauth2/token", config.client_id, config.client_secret,
                                   transport=transport)

    def close(self) -> None:
        self._client.close()

    def host_ids(self, hostname: str) -> list[str]:
        safe = hostname.replace("'", "")
        body = self._client.get("/devices/queries/devices/v1", params={"filter": f"hostname:'{safe}'"})
        return [str(r) for r in body.get("resources") or []]

    def assessment(self, hostname: str) -> dict[str, Any] | None:
        """The ZTA assessment for a host, or None when Falcon does not know it."""
        ids = self.host_ids(hostname)
        if not ids:
            return None
        body = self._client.get("/zero-trust-assessment/entities/assessments/v1", params={"ids": ids[0]})
        resources = body.get("resources") or []
        if not resources:
            return None
        r = resources[0]
        items = r.get("assessment_items") or {}
        signals = [*items.get("os_signals", []), *items.get("sensor_signals", [])]
        return {
            "aid": r.get("aid"),
            "hostname": hostname,
            "overall": (r.get("assessment") or {}).get("overall"),
            "sensor_config": (r.get("assessment") or {}).get("sensor_config"),
            "os": (r.get("assessment") or {}).get("os"),
            "modified": r.get("modified_time"),
            "failing_signals": [
                {"id": s.get("signal_id"), "name": s.get("signal_name"), "group": s.get("group_name"),
                 "criteria": s.get("criteria")}
                for s in signals if str(s.get("meets_criteria", "")).lower() == "no"
            ],
            "signals": signals,
        }
