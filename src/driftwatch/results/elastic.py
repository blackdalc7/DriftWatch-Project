"""A minimal Elasticsearch client over httpx: search and bulk index, nothing else.

Using the REST API directly keeps the dependency surface small and makes every query the results engine
sends visible (and recordable in the evidence bundle) as plain JSON.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class ElasticError(Exception):
    """Raised when Elasticsearch is unreachable or returns an error."""


class ElasticClient:
    """Search and bulk-index against one Elasticsearch endpoint."""

    def __init__(self, url: str, user: str | None = None, password: str | None = None, api_key: str | None = None,
                 verify: bool | str = True, timeout: float = 15.0,
                 transport: httpx.BaseTransport | None = None) -> None:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        auth = (user, password) if user and password and not api_key else None
        self._client = httpx.Client(base_url=url.rstrip("/"), headers=headers, auth=auth, verify=verify,
                                    timeout=timeout, transport=transport)

    def close(self) -> None:
        self._client.close()

    def search(self, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        """Run a search and return the hits (each with ``_index``, ``_id`` and ``_source``)."""
        try:
            resp = self._client.post(f"/{index}/_search", params={"ignore_unavailable": "true",
                                                                   "allow_no_indices": "true"}, json=body)
        except httpx.HTTPError as exc:
            raise ElasticError(f"cannot reach Elasticsearch: {exc}") from exc
        if resp.status_code >= 400:
            raise ElasticError(f"search on {index} failed with {resp.status_code}: {resp.text[:500]}")
        return list(resp.json().get("hits", {}).get("hits", []))

    def bulk_index(self, index: str, docs: list[dict[str, Any]]) -> int:
        """Index documents into a data stream or index with ``create`` operations; returns the count accepted."""
        if not docs:
            return 0
        lines = []
        for doc in docs:
            lines.append(json.dumps({"create": {"_index": index}}))
            lines.append(json.dumps(doc))
        try:
            resp = self._client.post("/_bulk", params={"refresh": "true"}, content="\n".join(lines) + "\n",
                                     headers={"Content-Type": "application/x-ndjson"})
        except httpx.HTTPError as exc:
            raise ElasticError(f"cannot reach Elasticsearch: {exc}") from exc
        if resp.status_code >= 400:
            raise ElasticError(f"bulk index failed with {resp.status_code}: {resp.text[:500]}")
        body = resp.json()
        return sum(1 for item in body.get("items", []) if 200 <= next(iter(item.values())).get("status", 500) < 300)
