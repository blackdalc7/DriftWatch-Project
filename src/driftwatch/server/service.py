"""Platform orchestration: everything the API routes and the background loop do, without HTTP.

Keeping this separate from FastAPI means every workflow (enroll, dispatch, score, detect drift, verify a
test, plan schedules) is a plain method that tests can call directly.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import re
import secrets
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization

from driftwatch.catalog import PLATFORMS, CatalogError
from driftwatch.config import Settings
from driftwatch.crypto import CertificateAuthority, CryptoError, Signer
from driftwatch.library import Library, LibraryError, approve, verify
from driftwatch.results import drift as drift_mod
from driftwatch.results.elastic import ElasticClient
from driftwatch.results.engine import ResultsEngine
from driftwatch.results.evidence import build_bundle, write_bundle
from driftwatch.schema import DriftwatchTest, ReviewStatus
from driftwatch.server.bundles import HYGIENE_TEST_ID, build_hygiene_bundle, build_test_bundle
from driftwatch.server.scheduler import PlannedRun, local_today, plan_day
from driftwatch.server.store import Store, StoreError, iso, parse_iso, utcnow

log = logging.getLogger("driftwatch.server")

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
CLEAN_STEP = {"executed", "blocked"}



def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True

class PlatformError(Exception):
    """A request the platform refuses, with an HTTP-ish status code."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class Platform:
    """The control plane."""

    def __init__(self, settings: Settings, store: Store, library: Library, signer: Signer,
                 ca: CertificateAuthority, elastic: ElasticClient | None, engine: ResultsEngine) -> None:
        self.settings = settings
        self.store = store
        self.library = library
        self.signer = signer
        self.ca = ca
        self.elastic = elastic
        self.engine = engine

    # --- helpers -----------------------------------------------------------------------------------

    def lab_scope(self, agent: dict[str, Any]) -> str | None:
        """The lab tag that authorises dispatch to this agent, or None if it is out of scope."""
        return next((t for t in agent.get("tags", []) if t in self.settings.lab_tags), None)

    def agent_status(self, agent: dict[str, Any], now: datetime | None = None) -> str:
        """online / offline / revoked, from the last heartbeat."""
        if agent["status"] != "active":
            return agent["status"]
        seen = parse_iso(agent.get("last_seen"))
        if seen is None:
            return "offline"
        age = ((now or utcnow()) - seen).total_seconds()
        return "online" if age <= self.settings.offline_after else "offline"

    def agent_view(self, agent: dict[str, Any]) -> dict[str, Any]:
        view = {k: v for k, v in agent.items() if k != "cert_fingerprint"}
        # The SHA-256 of the agent's public client certificate: not a secret, useful to match against the VM.
        view["cert_sha256"] = agent.get("cert_fingerprint")
        view["connection"] = self.agent_status(agent)
        view["lab_scope"] = self.lab_scope(agent)
        return view

    # --- enrollment and heartbeat --------------------------------------------------------------------

    def enroll(self, token: str, csr_pem: str, hostname: str, platform: str, os_version: str,
               agent_version: str) -> dict[str, Any]:
        """Exchange a TTL-bound enrollment token and a CSR for a client certificate."""
        if platform not in PLATFORMS:
            raise PlatformError(f"platform must be one of {PLATFORMS}")
        if not HOSTNAME_RE.match(hostname):
            raise PlatformError("invalid hostname")
        agent_id = "agt_" + secrets.token_hex(6)
        now = utcnow()
        try:
            cert_pem, fp = self.ca.sign_agent_csr(csr_pem, agent_id, self.settings.agent_cert_days)
        except CryptoError as exc:
            raise PlatformError(str(exc)) from exc
        try:
            with self.store.tx() as conn:
                token_row = self.store.consume_token(conn, token)
                self.store.insert_agent(conn, {
                    "id": agent_id, "hostname": hostname, "platform": platform, "os_version": os_version[:200],
                    "agent_version": agent_version[:50], "tags": token_row["tags"], "cert_fingerprint": fp,
                    "cert_expires_at": iso(now + timedelta(days=self.settings.agent_cert_days)),
                    "enrolled_at": iso(now), "last_seen": iso(now),
                })
        except StoreError as exc:
            raise PlatformError(str(exc), status=403) from exc
        self.store.audit("agent:" + agent_id, "agent.enrolled", {"hostname": hostname, "token": token_row["id"]})
        return {
            "agent_id": agent_id,
            "certificate_pem": cert_pem,
            "ca_pem": self.ca.cert.public_bytes(serialization.Encoding.PEM).decode(),
            "heartbeat_interval": self.settings.heartbeat_interval,
            "tags": token_row["tags"],
        }

    def heartbeat(self, agent: dict[str, Any], metrics: dict[str, Any], agent_version: str | None) -> dict[str, Any]:
        clean = {k: metrics[k] for k in ("cpu_percent", "memory_percent", "disk_percent", "uptime_seconds",
                                         "memory_total_bytes", "disk_total_bytes", "load_average")
                 if k in metrics}
        if isinstance(metrics.get("kernel_version"), str):
            clean["kernel_version"] = metrics["kernel_version"][:120]
        ips = metrics.get("ip_addresses")
        if isinstance(ips, list):
            clean["ip_addresses"] = [str(ipaddress.ip_address(ip)) for ip in ips[:8] if _is_ip(ip)]
        ts = self.store.record_heartbeat(agent["id"], clean, agent_version)
        pending = len(self.store.due_runs(agent["id"], limit=50))
        return {"server_time": ts, "next_heartbeat": self.settings.heartbeat_interval, "tasks_pending": pending}

    # --- dispatch ------------------------------------------------------------------------------------

    def _hygiene_due(self, agent: dict[str, Any]) -> bool:
        """Due when no hygiene run is open and the last useful one was created over an interval ago.

        Uses the server clock (run creation time), never the agent-reported collection time.
        """
        for run in self.store.list_runs(limit=20, test_id=HYGIENE_TEST_ID, agent_id=agent["id"]):
            if run["status"] in ("queued", "dispatched"):
                return False
            if run["status"] in ("completed", "evaluated"):
                age = (utcnow() - parse_iso(run["created_at"])).total_seconds()  # type: ignore[operator]
                return age >= self.settings.hygiene_interval
        return True

    def tasks_for(self, agent: dict[str, Any]) -> list[dict[str, Any]]:
        """Signed bundles for every run that is due on this agent."""
        scope = self.lab_scope(agent)
        if scope is None:
            return []
        if self._hygiene_due(agent):
            self.store.create_run(HYGIENE_TEST_ID, 1, agent["id"], "hygiene")
        now = utcnow()
        bundles = []
        for run in self.store.due_runs(agent["id"]):
            try:
                if run["test_id"] == HYGIENE_TEST_ID:
                    bundle = build_hygiene_bundle(run, agent, self.signer, scope, now, self.settings.bundle_ttl)
                else:
                    test = self.library.get(run["test_id"])
                    if not test.dispatchable:
                        raise LibraryError(f"{test.id} is {test.status.value}")
                    bundle = build_test_bundle(run, test, agent, self.signer, scope, now, self.settings.bundle_ttl)
            except (LibraryError, CatalogError, ValueError) as exc:
                log.warning("cancelling run %s: %s", run["id"], exc)
                with self.store.tx() as c:
                    c.execute("UPDATE runs SET status = 'cancelled', agent_log = ? WHERE id = ?", (str(exc), run["id"]))
                continue
            self.store.mark_dispatched(run["id"], now + timedelta(seconds=self.settings.bundle_ttl))
            bundles.append(bundle)
        return bundles

    def queue_runs(self, test_id: str, agent_ids: list[str] | None, tags: list[str] | None, actor: str,
                   source: str = "manual") -> list[dict[str, Any]]:
        """Queue a test on explicit agents or on every agent matching all ``tags``."""
        try:
            test = self.library.get(test_id)
        except LibraryError as exc:
            raise PlatformError(str(exc), status=404) from exc
        if not test.dispatchable:
            raise PlatformError(f"{test_id} is a draft: a human must approve it before it can run", status=409)
        agents = self.store.list_agents()
        if agent_ids:
            targets = [a for a in agents if a["id"] in set(agent_ids)]
            if len(targets) != len(set(agent_ids)):
                raise PlatformError("unknown agent id in the request", status=404)
        elif tags:
            targets = [a for a in agents if set(tags) <= set(a["tags"])]
        else:
            raise PlatformError("give agent_ids or tags")
        runs = []
        for agent in targets:
            if agent["status"] != "active" or self.lab_scope(agent) is None:
                continue
            if agent["platform"] not in test.platforms:
                continue
            kind = "verification" if test.status is ReviewStatus.APPROVED else source
            runs.append(self.store.create_run(test.id, test.version, agent["id"], kind))
        if not runs:
            raise PlatformError("no active, lab-scoped agent with a supported platform matched", status=409)
        self.store.audit(actor, "runs.queued", {"test_id": test_id, "runs": [r["id"] for r in runs]})
        return runs

    # --- results -------------------------------------------------------------------------------------

    def submit_results(self, agent: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        """Record what the agent did. Hygiene reports are processed for drift immediately."""
        steps = payload.get("steps") or []
        if not isinstance(steps, list):
            raise PlatformError("steps must be a list")
        try:
            run = self.store.complete_run(payload["run_id"], agent["id"], payload["started_at"],
                                          payload["finished_at"], steps, str(payload.get("log", "")))
        except StoreError as exc:
            raise PlatformError(str(exc), status=409) from exc
        if run["test_id"] == HYGIENE_TEST_ID:
            return self._ingest_hygiene(agent, run, steps)
        return run

    def _ingest_hygiene(self, agent: dict[str, Any], run: dict[str, Any],
                        steps: list[dict[str, Any]]) -> dict[str, Any]:
        report = (steps[0].get("output") if steps else None) or {}
        if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
            return self.store.save_evaluation(run["id"], "error", False,
                                              {"notes": ["hygiene step returned no report"]})
        collected_at = report.get("collected_at") or run["finished_at"]
        previous = self.store.latest_hygiene(agent["id"], before=collected_at)
        self.store.add_hygiene(agent["id"], collected_at, report)
        current = {"collected_at": collected_at, "report": report}
        events = []
        for event in drift_mod.compare_snapshots(agent["id"], previous, current):
            drift_mod.pinpoint(event, agent["hostname"], self.elastic, self.settings.telemetry_index)
            events.append(self.store.add_drift(event))
        summary = {"checks": len(report["checks"]), "failing": sum(1 for c in report["checks"]
                                                                   if c.get("status") == "fail"),
                   "drift_events": [e["id"] for e in events]}
        return self.store.save_evaluation(run["id"], "collected", True, summary)

    def evaluate_run(self, run_id: str, write_evidence: bool = True) -> dict[str, Any]:
        """Score a completed run, record test drift, apply the verification gate, write evidence."""
        run = self.store.get_run(run_id)
        if run["status"] not in ("completed", "evaluated"):
            raise PlatformError(f"run {run_id} is {run['status']}", status=409)
        if run["test_id"] == HYGIENE_TEST_ID:
            return run
        test = self.library.get(run["test_id"])
        evaluation = self.engine.evaluate(run, test)
        run = self.store.save_evaluation(run_id, evaluation["outcome"], evaluation["passed"], evaluation)
        agent = self.store.get_agent(run["agent_id"])
        hygiene = self.store.latest_hygiene(agent["id"])
        previous = self.store.previous_evaluated_run(test.id, agent["id"], run["finished_at"])
        event = drift_mod.detect_test_drift(agent["id"], test, previous, run, hygiene)
        if event:
            self.store.add_drift(event)
        self._maybe_verify(test, run)
        if write_evidence:
            data = build_bundle(run, self.library.get(test.id), agent, hygiene, self.signer)
            write_bundle(data, self.settings.evidence_dir, run_id)
        return run

    def _maybe_verify(self, test: DriftwatchTest, run: dict[str, Any], at: datetime | None = None,
                      audit: bool = True) -> bool:
        """Promote an approved test to verified when this run executed every step cleanly.

        ``at`` defaults to now; the demo exporter passes the run's evaluation time and writes the audit
        entries itself (``audit=False``) so the chain stays in time order.
        """
        if test.status is not ReviewStatus.APPROVED:
            return False
        steps = run.get("step_results") or []
        clean = bool(steps) and all(s.get("status") in CLEAN_STEP and s.get("cleanup", "ok") != "failed"
                                    for s in steps)
        if not clean or run.get("outcome") == "error":
            return False
        verified = verify(test, run["id"], run["agent_id"], all_steps_executed=True, now=at)
        self.library.save(verified)
        if audit:
            self.store.audit("system", "test.verified", {"test_id": test.id, "run_id": run["id"]}, ts=at)
        return True

    def evaluate_due(self) -> list[str]:
        cutoff = utcnow() - timedelta(seconds=self.settings.evaluation_delay)
        done = []
        for run in self.store.runs_awaiting_evaluation(cutoff):
            try:
                self.evaluate_run(run["id"])
                done.append(run["id"])
            except (PlatformError, LibraryError) as exc:
                log.warning("cannot evaluate run %s: %s", run["id"], exc)
        return done

    # --- review gate ---------------------------------------------------------------------------------

    def approve_test(self, test_id: str, reviewer: str, notes: str | None) -> DriftwatchTest:
        try:
            approved = approve(self.library.get(test_id), reviewer, notes)
        except LibraryError as exc:
            raise PlatformError(str(exc), status=409) from exc
        self.library.save(approved)
        self.store.audit(reviewer, "test.approved", {"test_id": test_id})
        return approved

    # --- scheduling ----------------------------------------------------------------------------------

    def plan_schedules(self, now: datetime | None = None, rng: random.Random | None = None) -> list[PlannedRun]:
        """Plan today's runs for every enabled schedule not yet planned today."""
        now = now or utcnow()
        rng = rng or random.SystemRandom()
        tests = {t.id: t for t in self.library.all()}
        agents = [a for a in self.store.list_agents() if self.lab_scope(a)]
        planned: list[PlannedRun] = []
        for sched in self.store.list_schedules():
            if not sched["enabled"]:
                continue
            today = local_today(sched, now)
            if sched.get("last_planned_date") == today.isoformat():
                continue
            for p in plan_day(sched, today, agents, tests, rng, not_before=now):
                test = tests[p.test_id]
                self.store.create_run(p.test_id, test.version, p.agent_id, "schedule", not_before=p.at,
                                      schedule_id=sched["id"])
                planned.append(p)
            self.store.mark_schedule_planned(sched["id"], today.isoformat())
        return planned

    def tick(self) -> dict[str, Any]:
        """One pass of the background loop."""
        expired = self.store.expire_stale_dispatches()
        planned = self.plan_schedules() if self.settings.scheduler_enabled else []
        evaluated = self.evaluate_due()
        return {"expired": expired, "planned": len(planned), "evaluated": len(evaluated)}
