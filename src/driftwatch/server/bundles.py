"""Build signed test bundles for agents.

A bundle is the complete, self-describing instruction for one run: which catalog actions to perform,
with which validated parameters, under which marker, for which agent, until when. It is serialized to
canonical JSON, base64-encoded and signed with Ed25519. The agent verifies the signature over those exact
bytes with its pinned public key, then re-checks every action against its own compiled-in catalog.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta
from typing import Any

from driftwatch.catalog import validate_step
from driftwatch.crypto import Signer, canonical_json
from driftwatch.schema import DriftwatchTest
from driftwatch.server.store import iso

BUNDLE_VERSION = 1
HYGIENE_TEST_ID = "builtin.hygiene"


def key_id(signer: Signer) -> str:
    """Short identifier of the signing key, so an agent can say which key it expected."""
    return hashlib.sha256(signer.public_key_b64().encode("ascii")).hexdigest()[:16]


def _sign(payload: dict[str, Any], signer: Signer) -> dict[str, Any]:
    raw = canonical_json(payload)
    return {
        "payload": base64.b64encode(raw).decode("ascii"),
        "signature": signer.sign(payload),
        "key_id": key_id(signer),
    }


def build_test_bundle(run: dict[str, Any], test: DriftwatchTest, agent: dict[str, Any], signer: Signer,
                      scope: str, now: datetime, ttl_seconds: int) -> dict[str, Any]:
    """A signed bundle for a test run. Raises CatalogError if a step is not valid for the agent's platform."""
    if agent["platform"] not in test.platforms:
        raise ValueError(f"test {test.id} does not support platform {agent['platform']}")
    steps = [
        {"index": i, "action": s.action, "params": validate_step(s.action, s.params, agent["platform"])}
        for i, s in enumerate(test.steps)
    ]
    payload = {
        "version": BUNDLE_VERSION,
        "kind": "test",
        "run_id": run["id"],
        "marker": f"DW-{run['id']}",
        "agent_id": agent["id"],
        "platform": agent["platform"],
        "scope": scope,
        "test_id": test.id,
        "test_version": test.version,
        "steps": steps,
        "issued_at": iso(now),
        "expires_at": iso(now + timedelta(seconds=ttl_seconds)),
    }
    return _sign(payload, signer)


def build_hygiene_bundle(run: dict[str, Any], agent: dict[str, Any], signer: Signer, scope: str,
                         now: datetime, ttl_seconds: int) -> dict[str, Any]:
    """A signed bundle asking the agent to run its embedded baseline script."""
    payload = {
        "version": BUNDLE_VERSION,
        "kind": "hygiene",
        "run_id": run["id"],
        "marker": f"DW-{run['id']}",
        "agent_id": agent["id"],
        "platform": agent["platform"],
        "scope": scope,
        "test_id": HYGIENE_TEST_ID,
        "test_version": 1,
        "steps": [{"index": 0, "action": "hygiene.collect", "params": {}}],
        "issued_at": iso(now),
        "expires_at": iso(now + timedelta(seconds=ttl_seconds)),
    }
    return _sign(payload, signer)
