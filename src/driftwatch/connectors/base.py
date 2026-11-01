"""OAuth2 client-credentials HTTP client shared by the EDR connectors."""

from __future__ import annotations

import time
from typing import Any

import httpx


class ConnectorError(Exception):
    """Raised when a vendor API is unreachable, refuses credentials or returns an error."""


class OAuthClient:
    """An httpx client that fetches and caches a bearer token with the client-credentials grant."""

    def __init__(self, base_url: str, token_url: str, client_id: str, client_secret: str,
                 extra_token_fields: dict[str, str] | None = None, timeout: float = 15.0,
                 transport: httpx.BaseTransport | None = None) -> None:
        self._http = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout, transport=transport)
        self._token_url = token_url
        self._form = {"client_id": client_id, "client_secret": client_secret, **(extra_token_fields or {})}
        self._token: str | None = None
        self._expires = 0.0

    def close(self) -> None:
        self._http.close()

    def _bearer(self) -> str:
        if self._token and time.monotonic() < self._expires - 60:
            return self._token
        try:
            resp = self._http.post(self._token_url, data=self._form)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"token request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise ConnectorError(f"token request refused with {resp.status_code}: {resp.text[:300]}")
        body = resp.json()
        token = body.get("access_token")
        if not token:
            raise ConnectorError("token response had no access_token")
        self._token = str(token)
        self._expires = time.monotonic() + float(body.get("expires_in", 1800))
        return self._token

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET a JSON resource with the bearer token, refreshing it once on a 401."""
        for attempt in (1, 2):
            try:
                resp = self._http.get(path, params=params, headers={"Authorization": f"Bearer {self._bearer()}"})
            except httpx.HTTPError as exc:
                raise ConnectorError(f"GET {path} failed: {exc}") from exc
            if resp.status_code == 401 and attempt == 1:
                self._token = None
                continue
            if resp.status_code >= 400:
                raise ConnectorError(f"GET {path} returned {resp.status_code}: {resp.text[:300]}")
            return resp.json()
        raise ConnectorError(f"GET {path} kept returning 401")  # pragma: no cover - loop always returns
