"""Randomized test scheduling inside office hours.

A schedule names tests, an agent pool (by tags), weekdays and a local time window. Each day it is
planned once: every (agent, test) pair gets its own time inside the window, either uniformly random
(the default, so tests do not all fire at 09:00 and so attackers or admins cannot predict them) or
evenly spaced. Planning is a pure function so it can be previewed in the UI and unit-tested with a
seeded RNG.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from driftwatch.schema import DriftwatchTest, ReviewStatus


class ScheduleError(ValueError):
    """Raised for invalid schedule definitions."""


@dataclass(frozen=True)
class PlannedRun:
    """One (test, agent, time) slot produced by planning."""

    test_id: str
    agent_id: str
    at: datetime  # UTC

    def to_dict(self) -> dict[str, Any]:
        return {"test_id": self.test_id, "agent_id": self.agent_id, "at": self.at.isoformat().replace("+00:00", "Z")}


def parse_hhmm(text: str) -> time:
    """Parse ``HH:MM``."""
    try:
        hh, mm = text.split(":")
        return time(int(hh), int(mm))
    except (ValueError, TypeError):
        raise ScheduleError(f"{text!r} is not a HH:MM time") from None


def validate_schedule(sched: dict[str, Any]) -> dict[str, Any]:
    """Check and normalize a schedule definition coming from the API."""
    name = str(sched.get("name", "")).strip()
    if not name:
        raise ScheduleError("a schedule needs a name")
    tests = list(sched.get("test_ids") or [])
    if not tests:
        raise ScheduleError("a schedule needs at least one test")
    tags = [str(t) for t in sched.get("target_tags") or []]
    if not tags:
        raise ScheduleError("a schedule needs at least one target tag")
    days = sorted({int(d) for d in sched.get("days", [0, 1, 2, 3, 4])})
    if not days or any(d < 0 or d > 6 for d in days):
        raise ScheduleError("days must be weekday numbers 0 (Monday) to 6 (Sunday)")
    start, end = parse_hhmm(sched.get("window_start", "09:00")), parse_hhmm(sched.get("window_end", "17:00"))
    if end <= start:
        raise ScheduleError("window_end must be after window_start")
    tz = sched.get("timezone", "UTC")
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise ScheduleError(f"unknown timezone {tz!r}") from None
    return {
        "name": name,
        "test_ids": tests,
        "target_tags": tags,
        "days": days,
        "window_start": start.strftime("%H:%M"),
        "window_end": end.strftime("%H:%M"),
        "timezone": tz,
        "randomize": bool(sched.get("randomize", True)),
        "enabled": bool(sched.get("enabled", True)),
    }


def agent_in_pool(agent: dict[str, Any], target_tags: list[str]) -> bool:
    """An agent is in the pool when it is active and carries every target tag."""
    return agent.get("status") == "active" and set(target_tags) <= set(agent.get("tags") or [])


def window_bounds(sched: dict[str, Any], day: date) -> tuple[datetime, datetime]:
    """The schedule's window on ``day`` as UTC datetimes."""
    tz = ZoneInfo(sched["timezone"])
    start = datetime.combine(day, parse_hhmm(sched["window_start"]), tzinfo=tz)
    end = datetime.combine(day, parse_hhmm(sched["window_end"]), tzinfo=tz)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def plan_day(sched: dict[str, Any], day: date, agents: list[dict[str, Any]], tests: dict[str, DriftwatchTest],
             rng: random.Random, not_before: datetime | None = None, verified_only: bool = True) -> list[PlannedRun]:
    """Plan one day of a schedule.

    Only verified tests are scheduled (approved tests run on demand to get verified), and only on agents
    whose platform the test supports. Slots before ``not_before`` are moved into the rest of the window,
    or dropped if the window is over.
    """
    if day.weekday() not in sched["days"]:
        return []
    start, end = window_bounds(sched, day)
    floor = max(start, not_before) if not_before else start
    if floor >= end:
        return []
    span = (end - floor).total_seconds()
    pool = [a for a in agents if agent_in_pool(a, sched["target_tags"])]
    plans: list[PlannedRun] = []
    for agent in sorted(pool, key=lambda a: a["id"]):
        eligible = []
        for test_id in sched["test_ids"]:
            test = tests.get(test_id)
            if test is None or agent["platform"] not in test.platforms:
                continue
            if verified_only and test.status is not ReviewStatus.VERIFIED:
                continue
            eligible.append(test_id)
        for i, test_id in enumerate(eligible):
            # Random by default; evenly spaced slots when randomization is off.
            offset = rng.uniform(0, span) if sched.get("randomize", True) else span * (i + 1) / (len(eligible) + 1)
            plans.append(PlannedRun(test_id, agent["id"], floor + timedelta(seconds=offset)))
    return sorted(plans, key=lambda p: (p.at, p.agent_id, p.test_id))


def local_today(sched: dict[str, Any], now: datetime) -> date:
    """The current date in the schedule's timezone."""
    return now.astimezone(ZoneInfo(sched["timezone"])).date()
