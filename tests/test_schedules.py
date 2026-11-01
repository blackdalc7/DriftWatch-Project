import random
from datetime import date, datetime, timezone

import pytest
from conftest import admin, enroll

from driftwatch.library import approve, verify
from driftwatch.server.scheduler import (
    ScheduleError,
    agent_in_pool,
    parse_hhmm,
    plan_day,
    validate_schedule,
    window_bounds,
)

BASE = {"name": "sweep", "test_ids": ["dw-win-whoami-discovery"], "target_tags": ["lab"], "days": [0, 1, 2, 3, 4],
        "window_start": "09:00", "window_end": "17:00", "timezone": "Europe/London", "randomize": True}


def test_validate_schedule_errors():
    assert validate_schedule(BASE)["window_end"] == "17:00"
    for patch, msg in (({"name": " "}, "name"), ({"test_ids": []}, "test"), ({"target_tags": []}, "tag"),
                       ({"days": [7]}, "weekday"), ({"window_end": "08:00"}, "after"),
                       ({"timezone": "Mars/Base"}, "timezone"), ({"window_start": "9am"}, "HH:MM")):
        with pytest.raises(ScheduleError, match=msg):
            validate_schedule({**BASE, **patch})
    assert parse_hhmm("07:30").hour == 7


def test_window_respects_timezone_and_dst():
    sched = validate_schedule(BASE)
    summer_start, _ = window_bounds(sched, date(2026, 7, 1))
    winter_start, _ = window_bounds(sched, date(2026, 12, 1))
    assert summer_start.hour == 8 and winter_start.hour == 9


def test_plan_day_random_and_spaced(platform):
    tests = {t.id: t for t in platform.library.all()}
    approved = tests["dw-win-whoami-discovery"]
    tests[approved.id] = verify(approved, "0123456789abcdef", "agt", True)
    agents = [{"id": "a1", "platform": "windows", "status": "active", "tags": ["lab"]},
              {"id": "a2", "platform": "windows", "status": "active", "tags": ["lab"]},
              {"id": "a3", "platform": "linux", "status": "active", "tags": ["lab"]},
              {"id": "a4", "platform": "windows", "status": "revoked", "tags": ["lab"]}]
    sched = validate_schedule({**BASE, "timezone": "UTC",
                               "test_ids": ["dw-win-whoami-discovery", "dw-win-local-admin-enum"]})
    plans = plan_day(sched, date(2026, 11, 2), agents, tests, random.Random(1))
    assert {p.agent_id for p in plans} == {"a1", "a2"}
    assert {p.test_id for p in plans} == {"dw-win-whoami-discovery"}  # the other test is not verified
    start, end = window_bounds(sched, date(2026, 11, 2))
    assert all(start <= p.at <= end for p in plans)
    assert plans[0].at != plans[1].at
    assert plan_day(sched, date(2026, 11, 1), agents, tests, random.Random(1)) == []  # Sunday
    spaced = plan_day({**sched, "randomize": False}, date(2026, 11, 2), agents[:1], tests, random.Random(1))
    assert spaced[0].at == datetime(2026, 11, 2, 13, 0, tzinfo=timezone.utc)
    late = datetime(2026, 11, 2, 16, 0, tzinfo=timezone.utc)
    assert all(p.at >= late for p in plan_day(sched, date(2026, 11, 2), agents, tests, random.Random(2), late))
    assert plan_day(sched, date(2026, 11, 2), agents, tests, random.Random(2),
                    datetime(2026, 11, 2, 18, 0, tzinfo=timezone.utc)) == []
    everything = plan_day(sched, date(2026, 11, 2), agents[:1], tests, random.Random(1), verified_only=False)
    assert len(everything) == 2
    assert plans[0].to_dict()["at"].endswith("Z")
    assert not agent_in_pool(agents[0], ["lab", "windows"])


def test_schedule_api_and_planning(client, platform):
    enroll(client)
    test = platform.library.get("dw-win-whoami-discovery")
    platform.library.save(verify(test, "0123456789abcdef", "agt", True))
    created = client.post("/api/v1/schedules", headers=admin(), json={**BASE, "timezone": "UTC",
                                                                       "days": [0, 1, 2, 3, 4, 5, 6]}).json()
    assert created["enabled"] is True and created["days"] == [0, 1, 2, 3, 4, 5, 6]
    assert client.post("/api/v1/schedules", headers=admin(), json={**BASE, "test_ids": ["dw-nope"]}).status_code == 422
    assert client.post("/api/v1/schedules", headers=admin(), json={**BASE, "window_end": "01:00"}).status_code == 422
    preview = client.post("/api/v1/schedules/preview", headers=admin(),
                          json={**BASE, "test_ids": ["dw-win-whoami-discovery", "dw-win-local-admin-enum"],
                                "day": "2026-11-02", "seed": 3}).json()
    assert len(preview["runs"]) == 1 and preview["unverified_tests_skipped"] == ["dw-win-local-admin-enum"]
    morning = datetime(2026, 11, 2, 6, 0, tzinfo=timezone.utc)
    planned = platform.plan_schedules(now=morning, rng=random.Random(5))
    assert len(planned) == 1
    assert platform.plan_schedules(now=morning) == []  # already planned today
    queued = [r for r in platform.store.list_runs() if r["source"] == "schedule"]
    assert queued and queued[0]["schedule_id"] == created["id"]
    off = client.post(f"/api/v1/schedules/{created['id']}/enabled?enabled=false", headers=admin()).json()
    assert off["enabled"] is False
    assert platform.plan_schedules(now=datetime(2026, 11, 3, 6, tzinfo=timezone.utc)) == []
    assert len(client.get("/api/v1/schedules", headers=admin()).json()) == 1
    assert client.delete(f"/api/v1/schedules/{created['id']}", headers=admin()).json()["status"] == "deleted"
    assert client.delete(f"/api/v1/schedules/{created['id']}", headers=admin()).status_code == 404
    result = platform.tick()
    assert set(result) == {"expired", "planned", "evaluated"}


def test_approve_then_verify_flow_helper():
    from pathlib import Path

    from driftwatch.library import Library

    lib = Library(Path(__file__).resolve().parents[1] / "library/tests")
    with pytest.raises(Exception, match="only drafts"):
        approve(lib.get("dw-win-whoami-discovery"), "x")
