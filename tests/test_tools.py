"""Kibana deploy, the Elasticsearch client, PKI helpers, settings, demo data and the CLI."""

import json
import zipfile

import httpx
import pytest
from conftest import ROOT

from driftwatch import cli
from driftwatch.config import ConfigError, load_settings
from driftwatch.crypto import (
    CertificateAuthority,
    CryptoError,
    Signer,
    fingerprint_from_pem,
    init_pki,
    verify_signature,
)
from driftwatch.demo import seed
from driftwatch.library import Library
from driftwatch.results.elastic import ElasticClient, ElasticError
from driftwatch.server.store import Store
from driftwatch.sigma import load_rules
from driftwatch.sigma.kibana import deploy, to_kibana_rule


def test_kibana_rule_and_deploy():
    rules = load_rules(ROOT / "rules")
    whoami = rules["5f2b1c0e-6a41-4c7e-9b8a-1d2e3f4a5b01"]
    body = to_kibana_rule(whoami, ["logs-*"])
    assert body["rule_id"] == whoami.id and body["language"] == "kuery" and body["risk_score"] in (21, 47, 73, 99)
    assert body["threat"][0]["tactic"]["id"] == "TA0007"
    assert body["threat"][0]["technique"][0]["id"] == "T1033"
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.headers.get("Authorization")))
        if request.method == "GET":
            return httpx.Response(200 if request.url.params["rule_id"] == whoami.id else 404)
        if request.method == "POST":
            return httpx.Response(400, text="bad query")
        return httpx.Response(200, json={})

    other = next(r for r in rules.values() if r.id != whoami.id)
    results = deploy([whoami, other], "http://kb", ["logs-*"], api_key="abc",
                     transport=httpx.MockTransport(handler))
    assert [r["action"] for r in results] == ["updated", "created"]
    assert results[0]["ok"] and not results[1]["ok"] and results[1]["error"] == "bad query"
    assert seen[0][1] == "ApiKey abc"
    sub = next(r for r in rules.values() if any("." in t for t in r.techniques))
    tech = to_kibana_rule(sub, ["x"])["threat"][0]["technique"][0]
    assert tech["subtechnique"][0]["id"].startswith(tech["id"] + ".")


def test_elastic_client():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("_search"):
            if "bad" in request.url.path:
                return httpx.Response(400, text="parse error")
            return httpx.Response(200, json={"hits": {"hits": [{"_id": "1", "_source": {}}]}})
        lines = request.content.decode().strip().splitlines()
        assert len(lines) == 4 and json.loads(lines[0]) == {"create": {"_index": "logs-x"}}
        return httpx.Response(200, json={"items": [{"create": {"status": 201}}, {"create": {"status": 409}}]})

    es = ElasticClient("http://es/", user="u", password="p", transport=httpx.MockTransport(handler))
    assert es.search("logs-*", {})[0]["_id"] == "1"
    with pytest.raises(ElasticError, match="400"):
        es.search("bad", {})
    assert es.bulk_index("logs-x", [{"a": 1}, {"a": 2}]) == 1
    assert es.bulk_index("logs-x", []) == 0
    es.close()

    def down(request):
        raise httpx.ConnectError("refused")

    dead = ElasticClient("http://es", api_key="k", transport=httpx.MockTransport(down))
    with pytest.raises(ElasticError, match="cannot reach"):
        dead.search("x", {})
    with pytest.raises(ElasticError, match="cannot reach"):
        dead.bulk_index("x", [{}])
    err = ElasticClient("http://es", transport=httpx.MockTransport(lambda r: httpx.Response(500, text="boom")))
    with pytest.raises(ElasticError, match="bulk index failed"):
        err.bulk_index("x", [{}])


def test_pki_and_signer(tmp_path):
    paths = init_pki(tmp_path / "pki", ["driftwatch.lab", "10.0.0.5"])
    assert all(p.exists() for p in paths.values())
    again = init_pki(tmp_path / "pki", ["driftwatch.lab"])  # idempotent
    assert again["ca_cert"].read_bytes() == paths["ca_cert"].read_bytes()
    signer = Signer.load(paths["signing_key"])
    assert paths["signing_pub"].read_text().strip() == signer.public_key_b64()
    sig = signer.sign({"b": 1, "a": [1, 2]})
    assert verify_signature(signer.public_key_b64(), {"a": [1, 2], "b": 1}, sig)
    assert not verify_signature(signer.public_key_b64(), {"a": [1, 2], "b": 2}, sig)
    assert not verify_signature("not base64!", {}, sig)
    with pytest.raises(CryptoError, match="cannot load"):
        Signer.load(tmp_path / "missing.key")
    with pytest.raises(CryptoError, match="not an Ed25519"):
        Signer.load(paths["ca_key"])
    with pytest.raises(CryptoError, match="EC private key"):
        CertificateAuthority.load(paths["ca_cert"], paths["signing_key"])
    with pytest.raises(CryptoError, match="cannot load CA"):
        CertificateAuthority.load(tmp_path / "nope.crt", paths["ca_key"])
    ca = CertificateAuthority.load(paths["ca_cert"], paths["ca_key"])
    with pytest.raises(CryptoError, match="invalid CSR"):
        ca.sign_agent_csr("garbage", "agt_x", 30)
    with pytest.raises(CryptoError, match="invalid client certificate"):
        fingerprint_from_pem("-----BEGIN CERTIFICATE-----%0Anope")


def test_csr_key_rules():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    ca = CertificateAuthority.create()

    def csr(key, algo):
        return x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin")])).sign(key, algo).public_bytes(
            serialization.Encoding.PEM).decode()

    with pytest.raises(CryptoError, match="ECDSA or Ed25519"):
        ca.sign_agent_csr(csr(rsa.generate_private_key(65537, 2048), hashes.SHA256()), "agt", 30)
    with pytest.raises(CryptoError, match="P-256"):
        ca.sign_agent_csr(csr(ec.generate_private_key(ec.SECP192R1()), hashes.SHA256()), "agt", 30)
    pem, fp = ca.sign_agent_csr(csr(ec.generate_private_key(ec.SECP384R1()), hashes.SHA256()), "agt_1", 30)
    cert = x509.load_pem_x509_certificate(pem.encode())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "agt_1"
    assert fingerprint_from_pem(pem) == fp


def test_settings_validation(tmp_path):
    with pytest.raises(ConfigError, match="ADMIN_TOKEN"):
        load_settings({})
    with pytest.raises(ConfigError, match="PROXY_SECRET"):
        load_settings({"DRIFTWATCH_ADMIN_TOKEN": "x" * 24})
    s = load_settings({}, require_secrets=False)
    assert s.heartbeat_interval == 30 and s.lab_tags == ["lab"]
    with pytest.raises(ConfigError, match="integer"):
        load_settings({"DRIFTWATCH_HEARTBEAT_INTERVAL": "soon"}, require_secrets=False)
    with pytest.raises(ConfigError, match=">= 5"):
        load_settings({"DRIFTWATCH_HEARTBEAT_INTERVAL": "1"}, require_secrets=False)


def test_demo_seed(tmp_path):
    from datetime import datetime, timezone

    store = Store(tmp_path / "db.sqlite3")
    counts = seed(store, Library(ROOT / "library/tests"), now=datetime(2026, 10, 30, 18, tzinfo=timezone.utc))
    assert counts["runs"] > 50 and counts["drift"] >= 2
    drift = store.drift_events()
    assert {d["kind"] for d in drift} == {"control", "test"}
    assert any(d["subject"] == "win.asr.block_obfuscated_scripts" for d in drift)
    assert len(store.list_schedules()) == 1
    store.close()


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_library_rules_schema_catalog(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    assert run(capsys, "library", "validate")[1].strip() == "10 tests valid"
    assert "dw-win-whoami-discovery" in run(capsys, "library", "list")[1]
    assert "10 rules valid" in run(capsys, "rules", "lint")[1]
    out = run(capsys, "rules", "kql", "--id", "5f2b1c0e-6a41-4c7e-9b8a-1d2e3f4a5b01")[1]
    assert out.count("# ") == 1 and "whoami" in out
    run(capsys, "schema", "--out", str(tmp_path / "s.json"))
    assert json.loads((tmp_path / "s.json").read_text())["title"]
    assert '"$defs"' in run(capsys, "schema")[1]
    assert "process.discovery" in run(capsys, "catalog")[1]
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "x.yml").write_text("id: BAD\n")
    assert run(capsys, "library", "validate", "--dirs", str(bad))[0] == 1
    (bad / "x.yml").write_text("title: x\n")
    assert run(capsys, "rules", "lint", "--rules", str(bad))[0] == 1


def test_cli_regress_and_evidence(capsys, workspace, monkeypatch, client, platform, elastic):
    monkeypatch.chdir(workspace)
    changed = workspace / "changed.txt"
    changed.write_text("rules/windows/whoami_all.yml\n")
    code, out, _ = run(capsys, "regress", "--changed-files", str(changed), "--junit", "j.xml", "--markdown", "s.md")
    assert code == 0 and "**passed**" in out and (workspace / "j.xml").exists()
    assert run(capsys, "regress", "--live")[0] == 2
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "rules/linux/x.yml\n"})())
    assert run(capsys, "regress", "--base-ref", "origin/main")[0] == 0

    from driftwatch.results.evidence import build_bundle

    signer = platform.signer
    run_row = {"id": "0123456789abcdef", "test_id": "dw-win-whoami-discovery", "test_version": 1,
               "agent_id": "a", "status": "evaluated", "outcome": "detected", "passed": True, "evaluation": {},
               "step_results": [], "created_at": "2026-10-30T09:00:00Z"}
    data = build_bundle(run_row, platform.library.get("dw-win-whoami-discovery"),
                        {"id": "a", "hostname": "lab-win01", "platform": "windows"}, None, signer)
    (workspace / "e.zip").write_bytes(data)
    (workspace / "k.pub").write_text(signer.public_key_b64())
    code, out, _ = run(capsys, "evidence", "verify", "e.zip", "--public-key", "k.pub")
    assert code == 0 and out.startswith("valid: run 0123456789abcdef")
    with zipfile.ZipFile(workspace / "e.zip", "a") as z:
        z.writestr("extra.txt", "x")
    assert run(capsys, "evidence", "verify", "e.zip", "--public-key", "k.pub")[0] == 1


def test_cli_approve_pki_demo_intel(capsys, workspace, monkeypatch):
    monkeypatch.chdir(workspace)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    html = workspace / "adv.html"
    html.write_text("<title>AA25-001A: Test</title><p>whoami (T1033) and T1190</p>")
    code, out, _ = run(capsys, "intel", "draft", "https://www.cisa.gov/aa25-001a", "--html", str(html))
    assert code == 0 and '"unsupported_techniques": [\n    "T1190"' in out
    draft = "dw-cisa-aa25-001a-t1033"
    assert (workspace / f"library/drafts/{draft}.yml").exists()
    code, out, _ = run(capsys, "library", "approve", draft, "--reviewer", "alvin", "--notes", "benign")
    assert code == 0 and (workspace / f"library/tests/{draft}.yml").exists()
    assert not (workspace / f"library/drafts/{draft}.yml").exists()
    assert run(capsys, "library", "approve", draft, "--reviewer", "alvin")[0] == 1
    code, out, _ = run(capsys, "pki", "init", "--dir", "pki", "--hosts", "a.lab,127.0.0.1")
    assert code == 0 and "pin this" in out
    code, out, _ = run(capsys, "demo", "seed", "--db", "demo.sqlite3", "--dirs", "library/tests")
    assert code == 0 and "seeded" in out
