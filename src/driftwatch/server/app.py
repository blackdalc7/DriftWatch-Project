"""FastAPI application: agent API (mTLS via the proxy) and operator API (API key).

Agent routes trust the client identity only from the TLS proxy (nginx), which verifies the client
certificate against the Driftwatch CA and forwards it with a shared secret header. The server recomputes
the SHA-256 fingerprint and maps it to an active agent, so a revoked agent is refused on its next call
even though its certificate is still valid.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import os
from collections.abc import AsyncIterator
from datetime import date
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from driftwatch import __version__
from driftwatch.catalog import CATALOG, catalog_as_dicts, techniques_for_step
from driftwatch.config import Settings, load_settings
from driftwatch.crypto import CertificateAuthority, CryptoError, Signer, fingerprint_from_pem
from driftwatch.library import Library, LibraryError, dump_test
from driftwatch.results.elastic import ElasticClient
from driftwatch.results.engine import EngineConfig, ResultsEngine
from driftwatch.results.evidence import EvidenceError, build_bundle
from driftwatch.results.navigator import build_layer
from driftwatch.schema import DriftwatchTest
from driftwatch.server.bundles import key_id
from driftwatch.server.scheduler import ScheduleError, plan_day, validate_schedule
from driftwatch.server.service import Platform, PlatformError
from driftwatch.server.store import Store, StoreError
from driftwatch.sigma import SigmaError, load_rules, to_kql

log = logging.getLogger("driftwatch.server")


# --- request models -------------------------------------------------------------------------------


class EnrollRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    csr_pem: str = Field(min_length=100, max_length=10_000)
    hostname: str = Field(min_length=1, max_length=253)
    platform: str
    os_version: str = ""
    agent_version: str = ""


class HeartbeatRequest(BaseModel):
    metrics: dict[str, Any] = Field(default_factory=dict)
    agent_version: str | None = None


class StepResult(BaseModel):
    index: int
    action: str
    status: str = Field(pattern=r"^(executed|blocked|error|skipped)$")
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    detail: str = ""
    cleanup: str = Field(default="ok", pattern=r"^(ok|failed|not_needed)$")
    observables: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] | None = None


class ResultsRequest(BaseModel):
    run_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    started_at: str
    finished_at: str
    steps: list[StepResult]
    log: str = Field(default="", max_length=200_000)


class TokenRequest(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    ttl_seconds: int = 3600
    max_uses: int = 1
    tags: list[str] = Field(default_factory=lambda: ["lab"])


class QueueRequest(BaseModel):
    test_id: str
    agent_ids: list[str] | None = None
    tags: list[str] | None = None


class ApproveRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    notes: str | None = Field(default=None, max_length=2000)


class TagsRequest(BaseModel):
    tags: list[str]


class ScheduleRequest(BaseModel):
    name: str
    test_ids: list[str]
    target_tags: list[str]
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])
    window_start: str = "09:00"
    window_end: str = "17:00"
    timezone: str = "UTC"
    randomize: bool = True
    enabled: bool = True


class PreviewRequest(ScheduleRequest):
    day: date | None = None
    seed: int | None = None


# --- application factory --------------------------------------------------------------------------


def build_platform(settings: Settings) -> Platform:
    """Wire the real dependencies from settings."""
    store = Store(settings.db_path)
    library = Library(*settings.library_dirs)
    signer = Signer.load_or_create(settings.signing_key_path)
    if settings.ca_cert_path.exists():
        ca = CertificateAuthority.load(settings.ca_cert_path, settings.ca_key_path)
    else:
        ca = CertificateAuthority.create()
        ca.save(settings.ca_cert_path, settings.ca_key_path)
    elastic = ElasticClient(settings.elastic_url, settings.elastic_user, settings.elastic_password,
                            verify=settings.elastic_verify_tls) if settings.elastic_url else None
    engine = ResultsEngine(elastic, EngineConfig(settings.telemetry_index, settings.alerts_index))
    return Platform(settings, store, library, signer, ca, elastic, engine)


def create_app(platform: Platform | None = None, run_background: bool = True) -> FastAPI:
    """Create the API. Tests pass a prepared :class:`Platform` and ``run_background=False``."""

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if app.state.platform is None:
            app.state.platform = build_platform(load_settings())
        task = None
        if run_background:
            task = asyncio.create_task(_background(app.state.platform))
        yield
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Driftwatch", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.platform = platform

    def plat(request: Request) -> Platform:
        return request.app.state.platform

    @app.exception_handler(PlatformError)
    async def _platform_error(_: Request, exc: PlatformError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    @app.exception_handler(StoreError)
    async def _store_error(_: Request, exc: StoreError) -> JSONResponse:
        status = 404 if str(exc).startswith("unknown") else 409
        return JSONResponse({"detail": str(exc)}, status_code=status)

    @app.exception_handler(LibraryError)
    async def _library_error(_: Request, exc: LibraryError) -> JSONResponse:
        status = 404 if str(exc).startswith("unknown") else 409
        return JSONResponse({"detail": str(exc)}, status_code=status)

    # --- auth dependencies ---------------------------------------------------------------------------

    def operator(request: Request, x_api_key: str = Header(default="")) -> str:
        p = plat(request)
        if not x_api_key or not hmac.compare_digest(x_api_key, p.settings.admin_token):
            raise HTTPException(401, "missing or invalid X-API-Key")
        return "operator"

    def agent_identity(request: Request, x_driftwatch_proxy: str = Header(default=""),
                       x_client_verify: str = Header(default=""), x_client_cert: str = Header(default="")) -> dict:
        p = plat(request)
        if not x_driftwatch_proxy or not hmac.compare_digest(x_driftwatch_proxy, p.settings.proxy_secret):
            raise HTTPException(401, "agent requests must come through the mTLS proxy")
        if x_client_verify != "SUCCESS" or not x_client_cert:
            raise HTTPException(401, "a verified client certificate is required")
        try:
            fp = fingerprint_from_pem(x_client_cert)
        except CryptoError as exc:
            raise HTTPException(401, str(exc)) from exc
        agent = p.store.agent_by_fingerprint(fp)
        if agent is None:
            raise HTTPException(403, "certificate is not bound to an active agent")
        return agent

    def proxied(request: Request, x_driftwatch_proxy: str = Header(default="")) -> None:
        p = plat(request)
        if not x_driftwatch_proxy or not hmac.compare_digest(x_driftwatch_proxy, p.settings.proxy_secret):
            raise HTTPException(401, "enrollment must come through the TLS proxy")

    # --- health --------------------------------------------------------------------------------------

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # --- agent API -----------------------------------------------------------------------------------

    @app.post("/api/v1/enroll", dependencies=[Depends(proxied)])
    def enroll(body: EnrollRequest, request: Request) -> dict[str, Any]:
        return plat(request).enroll(body.token, body.csr_pem, body.hostname, body.platform, body.os_version,
                                    body.agent_version)

    @app.post("/api/v1/agent/heartbeat")
    def heartbeat(body: HeartbeatRequest, request: Request, agent: dict = Depends(agent_identity)) -> dict[str, Any]:
        return plat(request).heartbeat(agent, body.metrics, body.agent_version)

    @app.get("/api/v1/agent/tasks")
    def tasks(request: Request, agent: dict = Depends(agent_identity)) -> dict[str, Any]:
        return {"bundles": plat(request).tasks_for(agent)}

    @app.post("/api/v1/agent/results")
    def results(body: ResultsRequest, request: Request, agent: dict = Depends(agent_identity)) -> dict[str, Any]:
        run = plat(request).submit_results(agent, body.model_dump())
        return {"run_id": run["id"], "status": run["status"]}

    # --- operator API: catalog, library, rules ----------------------------------------------------

    @app.get("/api/v1/catalog", dependencies=[Depends(operator)])
    def catalog() -> list[dict[str, Any]]:
        return catalog_as_dicts()

    def _test_view(p: Platform, test: DriftwatchTest, detail: bool = False) -> dict[str, Any]:
        view = test.model_dump(mode="json")
        view["emulated_techniques"] = test.emulated_techniques()
        view["dispatchable"] = test.dispatchable
        latest = [r for r in p.store.latest_results() if r["test_id"] == test.id]
        view["results"] = {"runs": len(latest), "passed": sum(1 for r in latest if r.get("passed"))}
        if detail:
            view["yaml"] = dump_test(test)
            view["flow"] = [
                {"index": i, "action": s.action, "title": CATALOG[s.action].title, "params": s.params,
                 "techniques": list(techniques_for_step(s.action, s.params)),
                 "observables": list(CATALOG[s.action].observables), "cleanup": CATALOG[s.action].cleanup}
                for i, s in enumerate(test.steps)
            ]
            rules = _rules(p)
            view["rules"] = [rules[r] for r in test.expected.detections if r in rules]
            view["hardening"] = test.hygiene_controls
        return view

    def _rules(p: Platform) -> dict[str, dict[str, Any]]:
        out = {}
        for rule in load_rules(p.settings.rules_dir).values():
            try:
                kql = to_kql(rule)
            except SigmaError as exc:
                kql = f"# not convertible: {exc}"
            out[rule.id] = {"id": rule.id, "title": rule.title, "level": rule.level, "techniques": rule.techniques,
                            "logsource": rule.logsource, "kql": kql,
                            "path": str(rule.path.relative_to(p.settings.rules_dir)) if rule.path else None}
        return out

    @app.get("/api/v1/library", dependencies=[Depends(operator)])
    def library(request: Request) -> list[dict[str, Any]]:
        p = plat(request)
        return [_test_view(p, t) for t in p.library.all()]

    @app.post("/api/v1/library/reload", dependencies=[Depends(operator)])
    def library_reload(request: Request) -> dict[str, int]:
        p = plat(request)
        p.library.reload()
        return {"tests": len(p.library)}

    @app.get("/api/v1/library/{test_id}", dependencies=[Depends(operator)])
    def library_test(test_id: str, request: Request) -> dict[str, Any]:
        p = plat(request)
        return _test_view(p, p.library.get(test_id), detail=True)

    @app.post("/api/v1/library/{test_id}/approve")
    def library_approve(test_id: str, body: ApproveRequest, request: Request,
                        actor: str = Depends(operator)) -> dict[str, Any]:
        p = plat(request)
        return _test_view(p, p.approve_test(test_id, body.reviewer, body.notes), detail=True)

    @app.get("/api/v1/rules", dependencies=[Depends(operator)])
    def rules(request: Request) -> list[dict[str, Any]]:
        return list(_rules(plat(request)).values())

    # --- operator API: fleet and enrollment ----------------------------------------------------------

    @app.get("/api/v1/agents", dependencies=[Depends(operator)])
    def agents(request: Request) -> list[dict[str, Any]]:
        p = plat(request)
        return [p.agent_view(a) for a in p.store.list_agents()]

    @app.get("/api/v1/agents/{agent_id}", dependencies=[Depends(operator)])
    def agent_detail(agent_id: str, request: Request) -> dict[str, Any]:
        p = plat(request)
        view = p.agent_view(p.store.get_agent(agent_id))
        view["heartbeats"] = p.store.heartbeats(agent_id)
        latest = p.store.latest_hygiene(agent_id)
        view["hygiene"] = latest["report"] if latest else None
        view["recent_runs"] = p.store.list_runs(limit=20, agent_id=agent_id)
        return view

    @app.post("/api/v1/agents/{agent_id}/revoke")
    def agent_revoke(agent_id: str, request: Request, actor: str = Depends(operator)) -> dict[str, str]:
        p = plat(request)
        p.store.revoke_agent(agent_id)
        p.store.audit(actor, "agent.revoked", {"agent_id": agent_id})
        return {"status": "revoked"}

    @app.put("/api/v1/agents/{agent_id}/tags")
    def agent_tags(agent_id: str, body: TagsRequest, request: Request, actor: str = Depends(operator)) -> dict:
        p = plat(request)
        p.store.set_agent_tags(agent_id, sorted(set(body.tags)))
        p.store.audit(actor, "agent.tags", {"agent_id": agent_id, "tags": body.tags})
        return p.agent_view(p.store.get_agent(agent_id))

    @app.post("/api/v1/tokens")
    def token_create(body: TokenRequest, request: Request, actor: str = Depends(operator)) -> dict[str, Any]:
        p = plat(request)
        token, row = p.store.create_token(body.label, body.ttl_seconds, body.max_uses, body.tags)
        p.store.audit(actor, "token.created", {"id": row["id"], "label": body.label})
        return {**row, "token": token, "signing_key": p.signer.public_key_b64(), "key_id": key_id(p.signer)}

    @app.get("/api/v1/tokens", dependencies=[Depends(operator)])
    def token_list(request: Request) -> list[dict[str, Any]]:
        return plat(request).store.list_tokens()

    @app.delete("/api/v1/tokens/{token_id}")
    def token_revoke(token_id: str, request: Request, actor: str = Depends(operator)) -> dict[str, str]:
        p = plat(request)
        p.store.revoke_token(token_id)
        p.store.audit(actor, "token.revoked", {"id": token_id})
        return {"status": "revoked"}

    # --- operator API: runs, results, evidence -------------------------------------------------------

    @app.post("/api/v1/runs")
    def run_queue(body: QueueRequest, request: Request, actor: str = Depends(operator)) -> list[dict[str, Any]]:
        return plat(request).queue_runs(body.test_id, body.agent_ids, body.tags, actor)

    @app.get("/api/v1/runs", dependencies=[Depends(operator)])
    def run_list(request: Request, test_id: str | None = None, agent_id: str | None = None,
                 limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, Any]]:
        rows = plat(request).store.list_runs(limit=limit, test_id=test_id, agent_id=agent_id)
        for r in rows:
            if isinstance(r.get("evaluation"), dict):
                r["evaluation"] = {k: v for k, v in r["evaluation"].items() if k not in ("raw", "query")}
            r.pop("agent_log", None)
        return rows

    @app.get("/api/v1/runs/{run_id}", dependencies=[Depends(operator)])
    def run_detail(run_id: str, request: Request) -> dict[str, Any]:
        return plat(request).store.get_run(run_id)

    @app.post("/api/v1/runs/{run_id}/evaluate", dependencies=[Depends(operator)])
    def run_evaluate(run_id: str, request: Request) -> dict[str, Any]:
        return plat(request).evaluate_run(run_id)

    @app.get("/api/v1/runs/{run_id}/evidence", dependencies=[Depends(operator)])
    def run_evidence(run_id: str, request: Request) -> Response:
        p = plat(request)
        run = p.store.get_run(run_id)
        agent = p.store.get_agent(run["agent_id"])
        try:
            data = build_bundle(run, p.library.get(run["test_id"]), agent, p.store.latest_hygiene(agent["id"]),
                                p.signer)
        except EvidenceError as exc:
            raise HTTPException(409, str(exc)) from exc
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="evidence-{run_id}.zip"'})

    @app.get("/api/v1/results/latest", dependencies=[Depends(operator)])
    def results_latest(request: Request) -> list[dict[str, Any]]:
        rows = plat(request).store.latest_results()
        for r in rows:
            r.pop("agent_log", None)
            if isinstance(r.get("evaluation"), dict):
                r["evaluation"] = {k: v for k, v in r["evaluation"].items() if k not in ("raw", "query")}
        return rows

    @app.get("/api/v1/coverage/navigator", dependencies=[Depends(operator)])
    def navigator(request: Request) -> dict[str, Any]:
        p = plat(request)
        agents_by_id = {a["id"]: a for a in p.store.list_agents()}
        return build_layer(p.library.all(), p.store.latest_results(), agents_by_id)

    # --- operator API: drift and hygiene -------------------------------------------------------------

    @app.get("/api/v1/drift", dependencies=[Depends(operator)])
    def drift(request: Request, agent_id: str | None = None, since: str | None = None,
              limit: int = Query(500, ge=1, le=5000)) -> list[dict[str, Any]]:
        return plat(request).store.drift_events(agent_id, since, limit)

    @app.get("/api/v1/hygiene/{agent_id}", dependencies=[Depends(operator)])
    def hygiene(agent_id: str, request: Request, limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
        p = plat(request)
        p.store.get_agent(agent_id)
        return p.store.hygiene_history(agent_id, limit)

    # --- operator API: schedules ---------------------------------------------------------------------

    def _validated(body: ScheduleRequest, p: Platform) -> dict[str, Any]:
        try:
            sched = validate_schedule(body.model_dump())
        except ScheduleError as exc:
            raise HTTPException(422, str(exc)) from exc
        unknown = [t for t in sched["test_ids"] if t not in p.library]
        if unknown:
            raise HTTPException(422, f"unknown tests: {unknown}")
        return sched

    @app.get("/api/v1/schedules", dependencies=[Depends(operator)])
    def schedules(request: Request) -> list[dict[str, Any]]:
        return plat(request).store.list_schedules()

    @app.post("/api/v1/schedules")
    def schedule_create(body: ScheduleRequest, request: Request, actor: str = Depends(operator)) -> dict:
        p = plat(request)
        sched = p.store.create_schedule(_validated(body, p))
        p.store.audit(actor, "schedule.created", {"id": sched["id"], "name": sched["name"]})
        return sched

    @app.put("/api/v1/schedules/{sched_id}")
    def schedule_update(sched_id: str, body: ScheduleRequest, request: Request,
                        actor: str = Depends(operator)) -> dict[str, Any]:
        p = plat(request)
        sched = p.store.update_schedule(sched_id, _validated(body, p))
        p.store.audit(actor, "schedule.updated", {"id": sched_id, "name": sched["name"]})
        return sched

    @app.post("/api/v1/schedules/preview", dependencies=[Depends(operator)])
    def schedule_preview(body: PreviewRequest, request: Request) -> dict[str, Any]:
        import random

        p = plat(request)
        sched = _validated(body, p)
        day = body.day or date.today()
        rng = random.Random(body.seed) if body.seed is not None else random.SystemRandom()
        agents_in = [a for a in p.store.list_agents() if p.lab_scope(a)]
        tests = {t.id: t for t in p.library.all()}
        plans = plan_day(sched, day, agents_in, tests, rng)
        skipped = [t for t in sched["test_ids"] if tests[t].status.value != "verified"]
        return {"day": day.isoformat(), "runs": [x.to_dict() for x in plans], "unverified_tests_skipped": skipped}

    @app.post("/api/v1/schedules/{sched_id}/enabled")
    def schedule_toggle(sched_id: str, request: Request, enabled: bool = Query(...),
                        actor: str = Depends(operator)) -> dict[str, Any]:
        p = plat(request)
        p.store.audit(actor, "schedule.toggled", {"id": sched_id, "enabled": enabled})
        return p.store.set_schedule_enabled(sched_id, enabled)

    @app.delete("/api/v1/schedules/{sched_id}")
    def schedule_delete(sched_id: str, request: Request, actor: str = Depends(operator)) -> dict[str, str]:
        p = plat(request)
        p.store.delete_schedule(sched_id)
        p.store.audit(actor, "schedule.deleted", {"id": sched_id})
        return {"status": "deleted"}

    # --- operator API: summary, audit, EDR correlation -----------------------------------------------

    @app.get("/api/v1/summary", dependencies=[Depends(operator)])
    def summary(request: Request) -> dict[str, Any]:
        p = plat(request)
        agents_all = [p.agent_view(a) for a in p.store.list_agents()]
        latest = p.store.latest_results()
        outcomes: dict[str, int] = {}
        for r in latest:
            outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        tests = p.library.all()
        return {
            "agents": {"total": len(agents_all), "online": sum(a["connection"] == "online" for a in agents_all)},
            "tests": {s: sum(t.status.value == s for t in tests) for s in ("draft", "approved", "verified")},
            "outcomes": outcomes,
            "pass_rate": round(100 * sum(1 for r in latest if r.get("passed")) / len(latest)) if latest else None,
            "passed": sum(1 for r in latest if r.get("passed")), "scored": len(latest),
            "drift_open": len([d for d in p.store.drift_events(limit=1000) if d["to_state"] == "fail"]),
            "signing_key_id": key_id(p.signer),
        }

    @app.get("/api/v1/audit", dependencies=[Depends(operator)])
    def audit(request: Request, limit: int = Query(200, ge=1, le=2000)) -> list[dict[str, Any]]:
        return plat(request).store.audit_log(limit)

    @app.get("/api/v1/audit/verify", dependencies=[Depends(operator)])
    def audit_verify(request: Request) -> dict[str, Any]:
        return plat(request).store.verify_audit_chain()

    @app.get("/api/v1/correlation", dependencies=[Depends(operator)])
    def correlation(request: Request) -> dict[str, Any]:
        from driftwatch.connectors.correlate import correlate_from_env

        p = plat(request)
        return correlate_from_env(p)

    # --- static UI -----------------------------------------------------------------------------------

    ui_dir = Path(os.environ.get("DRIFTWATCH_UI_DIR") or Path(__file__).resolve().parents[3] / "web" / "dist")
    if ui_dir.is_dir():  # pragma: no cover - only when the UI was built into the image
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")

    return app


async def _background(platform: Platform) -> None:
    """Run :meth:`Platform.tick` forever on a worker thread."""
    while True:
        try:
            result = await asyncio.to_thread(platform.tick)
            if any(result.values()):
                log.info("background tick: %s", result)
        except Exception:
            log.exception("background tick failed")
        await asyncio.sleep(platform.settings.scheduler_tick)
