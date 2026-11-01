import httpx
import pytest
from conftest import enroll
from fastapi.testclient import TestClient

from driftwatch.connectors import correlate as corr
from driftwatch.connectors.base import ConnectorError, OAuthClient
from driftwatch.connectors.crowdstrike import CrowdStrikeConfig, CrowdStrikeZTA
from driftwatch.connectors.defender import DefenderConfig, DefenderSecureScore
from driftwatch.mock_edr.app import create_app

CID, SECRET = "cid", "secret"


@pytest.fixture
def mock():
    with TestClient(create_app(CID, SECRET), base_url="http://mock") as c:
        yield c


def transport(mock):
    """An httpx transport that forwards every request to the in-process mock EDR."""

    def forward(request: httpx.Request) -> httpx.Response:
        resp = mock.request(request.method, request.url.raw_path.decode(), content=request.content,
                            headers={k: v for k, v in request.headers.items() if k.lower() != "host"})
        return httpx.Response(resp.status_code, headers=resp.headers, content=resp.content)

    return httpx.MockTransport(forward)


def defender(mock, secret=SECRET):
    return DefenderSecureScore(DefenderConfig("lab", CID, secret, login_url="http://mock", graph_url="http://mock"),
                               transport=transport(mock))


def falcon(mock, secret=SECRET):
    return CrowdStrikeZTA(CrowdStrikeConfig(CID, secret, base_url="http://mock"), transport=transport(mock))


def test_defender_secure_score_and_scenarios(mock):
    d = defender(mock)
    score = d.latest_score()
    assert score["max_score"] == 54.0 and score["percent"] == pytest.approx(90.7, abs=0.1)
    asr = next(c for c in score["controls"] if c["name"] == "scid_asr_obfuscated")
    assert asr["status"] == "Implemented"
    assert {p["name"] for p in d.control_profiles()} >= {"scid_asr_lsass", "scid_tamper"}
    assert mock.post("/_mock/scenario", json={"name": "asr_disabled"}).json()["scenario"] == "asr_disabled"
    asr = next(c for c in d.latest_score()["controls"] if c["name"] == "scid_asr_obfuscated")
    assert asr["status"] == "Not implemented" and asr["percent"] == 0.0
    assert mock.post("/_mock/scenario", json={"name": "nope"}).status_code == 404
    assert mock.get("/healthz").json()["scenario"] == "asr_disabled"
    d.close()


def test_bad_credentials_and_grant(mock):
    with pytest.raises(ConnectorError, match="refused with 401"):
        defender(mock, "wrong").latest_score()
    assert mock.post("/lab/oauth2/v2.0/token", data={"client_id": CID, "client_secret": SECRET,
                                                     "grant_type": "password"}).status_code == 400
    assert mock.get("/v1.0/security/secureScores", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_falcon_zta(mock):
    f = falcon(mock)
    zta = f.assessment("lab-win01")
    assert zta["overall"] == 85 and zta["aid"].startswith("8f2a")
    assert {s["name"] for s in zta["failing_signals"]} == {"Credential Guard", "BitLocker"}
    assert f.assessment("lab-unknown") is None
    mock.post("/_mock/scenario", json={"name": "realtime_off"})
    assert "Real-time Protection" in {s["name"] for s in f.assessment("lab-win01")["failing_signals"]}
    f.close()


def handler_factory(responses):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return responses.pop(0) if responses else httpx.Response(500)

    return handler, calls


def test_oauth_client_refresh_and_errors():
    handler, calls = handler_factory([
        httpx.Response(200, json={"access_token": "t1", "expires_in": 3600}),
        httpx.Response(401),
        httpx.Response(200, json={"access_token": "t2"}),
        httpx.Response(200, json={"ok": True}),
        httpx.Response(200, json={"ok": 2}),
        httpx.Response(503, text="down"),
    ])
    c = OAuthClient("http://x", "/token", "a", "b", transport=httpx.MockTransport(handler))
    assert c.get("/r") == {"ok": True}
    assert calls[3].headers["Authorization"] == "Bearer t2"
    assert c.get("/r") == {"ok": 2}  # cached token, no new token call
    with pytest.raises(ConnectorError, match="503"):
        c.get("/r")
    handler2, _ = handler_factory([httpx.Response(200, json={})])
    with pytest.raises(ConnectorError, match="no access_token"):
        OAuthClient("http://x", "/t", "a", "b", transport=httpx.MockTransport(handler2)).get("/r")

    def boom(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(ConnectorError, match="token request failed"):
        OAuthClient("http://x", "/t", "a", "b", transport=httpx.MockTransport(boom)).get("/r")
    seq = iter([httpx.Response(200, json={"access_token": "t"})])

    def half(request):
        if request.url.path == "/t":
            return next(seq)
        raise httpx.ReadTimeout("slow")

    with pytest.raises(ConnectorError, match="GET /r failed"):
        OAuthClient("http://x", "/t", "a", "b", transport=httpx.MockTransport(half)).get("/r")


def test_empty_vendor_responses():
    def handler(request):
        if "token" in request.url.path:
            return httpx.Response(200, json={"access_token": "t"})
        if "secureScores" in request.url.path:
            return httpx.Response(200, json={"value": []})
        if "devices" in request.url.path:
            return httpx.Response(200, json={"resources": ["aid1"]})
        return httpx.Response(200, json={"resources": []})

    t = httpx.MockTransport(handler)
    d = DefenderSecureScore(DefenderConfig("t", "a", "b", "http://x", "http://x"), transport=t)
    assert d.latest_score()["percent"] is None
    assert CrowdStrikeZTA(CrowdStrikeConfig("a", "b", "http://x"), transport=t).assessment("h") is None


class T:
    def __init__(self, id, controls):
        self.id, self.hygiene_controls = id, controls


def test_correlate_finds_disagreements():
    agents = [{"id": "a1", "hostname": "lab-win01"}]
    hygiene = {"a1": {"checks": [
        {"id": "win.asr.block_obfuscated_scripts", "status": "fail", "actual": "off"},
        {"id": "win.defender.realtime_protection", "status": "fail", "actual": "off"},
        {"id": "win.unmapped", "status": "fail"},
        {"id": "win.firewall.domain", "status": "pass"}]}}
    defender = {"current_score": 40, "max_score": 54, "percent": 74.1, "created": "x", "controls": [
        {"name": "scid_asr_obfuscated", "percent": 100, "status": "Implemented", "description": "ASR"},
        {"name": "scid_av_realtime", "percent": 0, "status": "Not implemented"}]}
    profiles = [{"name": "scid_asr_obfuscated", "title": "Block obfuscated scripts (Attack Surface Reduction)"},
                {"name": "scid_av_realtime", "title": "Turn on real-time protection"}]
    zta = {"a1": {"overall": 80, "sensor_config": 90, "os": 70,
                  "failing_signals": [{"name": "Real-time Protection"}],
                  "signals": [{"signal_name": "Attack Surface Reduction", "meets_criteria": "yes"},
                              {"signal_name": "Real-time Protection", "meets_criteria": "no"}]}}
    results = [{"agent_id": "a1", "test_id": "dw-x", "passed": False, "outcome": "missed"},
               {"agent_id": "a1", "test_id": "dw-y", "passed": False, "outcome": "missed"},
               {"agent_id": "a1", "test_id": "dw-x", "passed": True, "outcome": "detected"},
               {"agent_id": "zz", "test_id": "dw-x", "passed": False, "outcome": "missed"}]
    tests = {"dw-x": T("dw-x", ["win.defender.realtime_protection"]), "dw-y": T("dw-y", [])}
    out = corr.correlate(agents, hygiene, results, tests, defender, profiles, zta)
    kinds = [(f["type"], f.get("vendor"), f.get("control") or f.get("test")) for f in out["findings"]]
    assert ("posture_disagreement", "defender", "win.asr.block_obfuscated_scripts") in kinds
    assert ("posture_disagreement", "crowdstrike", "win.asr.block_obfuscated_scripts") in kinds
    assert not any(k[1] == "defender" and k[2] == "win.defender.realtime_protection" for k in kinds)
    ctx = next(f for f in out["findings"] if f.get("test") == "dw-x")
    assert ctx["edr_context"] == ["Real-time Protection", "Secure Score: Turn on real-time protection at 0%"]
    quiet = next(f for f in out["findings"] if f.get("test") == "dw-y")
    assert "invisible to posture scores" in quiet["summary"]
    assert out["defender"]["percent"] == 74.1 and out["crowdstrike"]["lab-win01"]["overall"] == 80
    assert corr.correlate(agents, {}, [], {}, None, [], {})["defender"] is None


def test_correlate_from_env_against_mock(client, platform, mock, monkeypatch):
    enroll(client)
    real = httpx.Client.__init__

    def patched(self, *a, **kw):
        if kw.get("transport") is None:
            kw["transport"] = transport(mock)
        real(self, *a, **kw)

    monkeypatch.setattr(httpx.Client, "__init__", patched)
    out = corr.correlate_from_env(platform, {})
    assert out["configured"] is False and out["defender"] is None
    env = {"DRIFTWATCH_DEFENDER_CLIENT_ID": CID, "DRIFTWATCH_DEFENDER_CLIENT_SECRET": SECRET,
           "DRIFTWATCH_DEFENDER_LOGIN_URL": "http://mock", "DRIFTWATCH_DEFENDER_GRAPH_URL": "http://mock",
           "DRIFTWATCH_CROWDSTRIKE_CLIENT_ID": CID, "DRIFTWATCH_CROWDSTRIKE_CLIENT_SECRET": SECRET,
           "DRIFTWATCH_CROWDSTRIKE_BASE_URL": "http://mock"}
    out = corr.correlate_from_env(platform, env)
    assert out["configured"] and out["errors"] == []
    assert out["defender"]["max_score"] == 54.0 and out["crowdstrike"]["lab-win01"]["overall"] == 85
    bad = corr.correlate_from_env(platform, {**env, "DRIFTWATCH_DEFENDER_CLIENT_SECRET": "x",
                                             "DRIFTWATCH_CROWDSTRIKE_CLIENT_SECRET": "x"})
    assert len(bad["errors"]) == 2
