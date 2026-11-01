"""Shared fixtures: an isolated platform (temp library, rules, PKI, SQLite) and helpers to act as an agent."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from driftwatch.config import load_settings
from driftwatch.crypto import CertificateAuthority, Signer
from driftwatch.library import Library
from driftwatch.results.engine import ResultsEngine
from driftwatch.server.app import create_app
from driftwatch.server.service import Platform
from driftwatch.server.store import Store

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "admin-token-for-tests-0123456789"
PROXY = "proxy-secret-for-tests-0123456789"


class FakeElastic:
    """Stands in for ElasticClient: returns canned hits per index and records the queries."""

    def __init__(self) -> None:
        self.hits: dict[str, list[dict[str, Any]]] = {}
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.fail = False

    def search(self, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        from driftwatch.results.elastic import ElasticError

        self.queries.append((index, body))
        if self.fail:
            raise ElasticError("connection refused")
        return list(self.hits.get(index, []))


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A copy of the library, rules and telemetry that tests may modify."""
    for name in ("library", "rules", "telemetry"):
        shutil.copytree(ROOT / name, tmp_path / name)
    return tmp_path


@pytest.fixture
def settings(workspace: Path):
    env = {
        "DRIFTWATCH_DATA_DIR": str(workspace / "data"),
        "DRIFTWATCH_LIBRARY_DIRS": f"{workspace / 'library/tests'},{workspace / 'library/drafts'}",
        "DRIFTWATCH_RULES_DIR": str(workspace / "rules"),
        "DRIFTWATCH_ADMIN_TOKEN": ADMIN,
        "DRIFTWATCH_PROXY_SECRET": PROXY,
        "DRIFTWATCH_EVALUATION_DELAY": "0",
    }
    return load_settings(env)


@pytest.fixture
def elastic() -> FakeElastic:
    return FakeElastic()


@pytest.fixture
def platform(settings, elastic) -> Platform:
    store = Store(settings.db_path)
    library = Library(*settings.library_dirs)
    signer = Signer.load_or_create(settings.signing_key_path)
    ca = CertificateAuthority.create()
    ca.save(settings.ca_cert_path, settings.ca_key_path)
    engine = ResultsEngine(elastic)  # type: ignore[arg-type]
    p = Platform(settings, store, library, signer, ca, elastic, engine)  # type: ignore[arg-type]
    yield p
    store.close()


@pytest.fixture
def client(platform) -> TestClient:
    with TestClient(create_app(platform, run_background=False)) as c:
        yield c


def make_csr(cn: str = "ignored") -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


def admin() -> dict[str, str]:
    return {"X-API-Key": ADMIN}


def enroll(client: TestClient, hostname: str = "lab-win01", platform: str = "windows",
           tags: list[str] | None = None) -> dict[str, Any]:
    """Create a token, enroll an agent and return its id plus the mTLS headers the proxy would add."""
    tok = client.post("/api/v1/tokens", headers=admin(),
                      json={"label": "test", "ttl_seconds": 600, "max_uses": 1, "tags": tags or ["lab"]}).json()
    csr, _ = make_csr()
    resp = client.post("/api/v1/enroll", headers={"X-Driftwatch-Proxy": PROXY},
                       json={"token": tok["token"], "csr_pem": csr, "hostname": hostname, "platform": platform,
                             "os_version": "test", "agent_version": "1.0.0"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    headers = {"X-Driftwatch-Proxy": PROXY, "X-Client-Verify": "SUCCESS",
               "X-Client-Cert": body["certificate_pem"].replace("\n", "%0A")}
    return {"agent_id": body["agent_id"], "headers": headers, "enroll": body, "token": tok}
