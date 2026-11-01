"""Export a static, read-only snapshot of a seeded Driftwatch for the UI's demo build (GitHub Pages).

    PYTHONPATH=src python scripts/export_demo.py --out web/public/demo

It seeds a throwaway database with ``driftwatch.demo.seed`` (the synthetic week with the ASR drift story),
starts the real FastAPI app in-process, points the EDR connectors at the in-process mock, and saves each
API response the UI reads as JSON. The demo build reads these files instead of calling /api.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from driftwatch.config import load_settings  # noqa: E402
from driftwatch.crypto import CertificateAuthority, Signer  # noqa: E402
from driftwatch.demo import LAB_OPERATOR, append_audit, audit_events, seed  # noqa: E402
from driftwatch.intel.cisa import Advisory, TechniqueMention  # noqa: E402
from driftwatch.intel.drafter import offline_drafts, write_drafts  # noqa: E402
from driftwatch.library import Library, approve  # noqa: E402
from driftwatch.mock_edr.app import create_app as create_mock  # noqa: E402
from driftwatch.results.elastic import ElasticClient  # noqa: E402
from driftwatch.results.engine import ResultsEngine  # noqa: E402
from driftwatch.server.app import create_app  # noqa: E402
from driftwatch.server.service import Platform  # noqa: E402
from driftwatch.server.store import Store, parse_iso  # noqa: E402

KEY = "demo-export-admin-token-0123456789"


DEMO_ADVISORY = Advisory(
    id="DEMO-01A", title="Synthetic advisory used by the Driftwatch demo (not a real CISA publication)",
    url="https://example.invalid/driftwatch/demo-advisory", published=None,
    techniques=[TechniqueMention("T1082", "the actors ran systeminfo on each host to profile it"),
                TechniqueMention("T1053.005", "persistence came from a scheduled task named like a browser updater")],
)


def verify_demo_tests(platform: Platform) -> list[tuple[datetime, str, str, dict]]:
    """Run each approved test through the real approved -> verified gate at the time its first clean run was
    evaluated. Returns the audit entries the server would have written."""
    events = []
    for test in platform.library.all():
        runs = sorted(platform.store.list_runs(limit=5000, test_id=test.id), key=lambda r: r["created_at"])
        for run in runs:
            at = parse_iso(run.get("evaluated_at"))
            if platform._maybe_verify(platform.library.get(test.id), run, at=at, audit=False):
                events.append((at, "system", "test.verified", {"test_id": test.id, "run_id": run["id"]}))
                break
    return events


def draft_and_approve(platform: Platform, drafts_dir: Path,
                      now: datetime) -> list[tuple[datetime, str, str, dict]]:
    """Use the real offline drafter on the synthetic advisory, then have a human approve one of the drafts,
    so the replay shows a draft waiting for review and an approved test waiting for its first lab run."""
    result = offline_drafts(DEMO_ADVISORY)
    written = write_drafts(result, drafts_dir, {t.id for t in platform.library.all()})
    platform.library.reload()
    # Drafting happens offline (CLI), so it writes no audit entry; the approval does.
    events: list[tuple[datetime, str, str, dict]] = []
    if written:
        test_id = written[0].stem
        approved_at = now - timedelta(hours=2)
        platform.library.save(approve(platform.library.get(test_id), LAB_OPERATOR,
                                      "Reviewed against the advisory; safe catalog steps only.", now=approved_at))
        events.append((approved_at, LAB_OPERATOR, "test.approved", {"test_id": test_id}))
    return events


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "web/public/demo"))
    ap.add_argument("--now", help="ISO time to seed up to (default: now)")
    args = ap.parse_args()
    out = Path(args.out)
    work = Path(tempfile.mkdtemp())
    # Verification rewrites test files, so the demo verifies a throwaway copy, never library/tests itself.
    lib_dir = work / "library"
    shutil.copytree(ROOT / "library/tests", lib_dir / "tests")
    (lib_dir / "drafts").mkdir()
    try:
        settings = load_settings({
            "DRIFTWATCH_DATA_DIR": str(work), "DRIFTWATCH_ADMIN_TOKEN": KEY, "DRIFTWATCH_PROXY_SECRET": KEY,
            "DRIFTWATCH_LIBRARY_DIRS": f"{lib_dir / 'tests'},{lib_dir / 'drafts'}",
            "DRIFTWATCH_RULES_DIR": str(ROOT / "rules"),
        })
        now = datetime.fromisoformat(args.now) if args.now else datetime.now(timezone.utc)
        store = Store(settings.db_path)
        library = Library(*settings.library_dirs)
        seed(store, library, now=now, audit=False)
        signer = Signer.load_or_create(settings.signing_key_path)
        ca = CertificateAuthority.create()
        elastic = ElasticClient("http://127.0.0.1:1")
        platform = Platform(settings, store, library, signer, ca, elastic, ResultsEngine(elastic))
        events = audit_events(store, now - timedelta(days=7)) + verify_demo_tests(platform)
        events += draft_and_approve(platform, lib_dir / "drafts", now)
        append_audit(store, events)

        mock = TestClient(create_mock("demo", "demo"), base_url="http://mock")

        def forward(request: httpx.Request) -> httpx.Response:
            r = mock.request(request.method, request.url.raw_path.decode(), content=request.content,
                             headers={k: v for k, v in request.headers.items() if k.lower() != "host"})
            return httpx.Response(r.status_code, headers=r.headers, content=r.content)

        real_init = httpx.Client.__init__

        def patched(self, *a, **kw):
            if kw.get("transport") is None and str(kw.get("base_url", "")).startswith("http://mock"):
                kw["transport"] = httpx.MockTransport(forward)
            real_init(self, *a, **kw)

        httpx.Client.__init__ = patched  # type: ignore[method-assign]
        mock.post("/_mock/scenario", json={"name": "asr_disabled"})
        os.environ.update({
            "DRIFTWATCH_DEFENDER_CLIENT_ID": "demo", "DRIFTWATCH_DEFENDER_CLIENT_SECRET": "demo",
            "DRIFTWATCH_DEFENDER_LOGIN_URL": "http://mock", "DRIFTWATCH_DEFENDER_GRAPH_URL": "http://mock",
            "DRIFTWATCH_CROWDSTRIKE_CLIENT_ID": "demo", "DRIFTWATCH_CROWDSTRIKE_CLIENT_SECRET": "demo",
            "DRIFTWATCH_CROWDSTRIKE_BASE_URL": "http://mock"})

        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        with TestClient(create_app(platform, run_background=False)) as client:
            h = {"X-API-Key": KEY}

            def save(name: str, path: str) -> object:
                resp = client.get(path, headers=h)
                resp.raise_for_status()
                data = resp.json()
                target = out / f"{name}.json"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(data, indent=1), encoding="utf-8")
                return data

            for name in ("summary", "agents", "library", "rules", "catalog", "drift", "schedules", "audit",
                         "correlation"):
                save(name, f"/api/v1/{name}")
            save("audit-verify", "/api/v1/audit/verify")
            save("results-latest", "/api/v1/results/latest")
            save("navigator", "/api/v1/coverage/navigator")
            runs = save("runs", "/api/v1/runs?limit=300")
            for agent in json.loads((out / "agents.json").read_text()):
                save(f"agents/{agent['id']}", f"/api/v1/agents/{agent['id']}")
                save(f"hygiene/{agent['id']}", f"/api/v1/hygiene/{agent['id']}?limit=60")
            for test in json.loads((out / "library.json").read_text()):
                save(f"library/{test['id']}", f"/api/v1/library/{test['id']}")
            (out / "evidence").mkdir()
            for run in runs[:60]:  # type: ignore[index]
                save(f"runs/{run['id']}", f"/api/v1/runs/{run['id']}")
                if run["status"] == "evaluated":
                    resp = client.get(f"/api/v1/runs/{run['id']}/evidence", headers=h)
                    if resp.status_code == 200:
                        (out / "evidence" / f"{run['id']}.zip").write_bytes(resp.content)
        (out / "meta.json").write_text(json.dumps({"exported_at": now.isoformat(), "mode": "replay",
                                                   "signing_key": signer.public_key_b64()}))
        store.close()
        print(f"demo snapshot written to {out}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
