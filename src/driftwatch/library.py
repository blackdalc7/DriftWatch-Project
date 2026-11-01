"""Load, validate and change the state of tests in the on-disk library.

Tests live as YAML in git (``library/tests`` for reviewed tests, ``library/drafts`` for drafts), so every
status change is a reviewable diff. State changes go through :func:`approve` and :func:`verify`, which
enforce the human-review and lab-run gates; nothing else in the platform writes the status field.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import ValidationError

from driftwatch.schema import DriftwatchTest, ReviewStatus


class LibraryError(Exception):
    """Raised for unreadable files, duplicate ids and illegal state changes."""


@dataclass
class LoadedTest:
    """A parsed test plus the file it came from."""

    test: DriftwatchTest
    path: Path


def load_file(path: Path) -> DriftwatchTest:
    """Parse and validate one YAML test file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise LibraryError(f"{path}: cannot read YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise LibraryError(f"{path}: a test file must be a YAML mapping")
    try:
        return DriftwatchTest.model_validate(data)
    except ValidationError as exc:
        raise LibraryError(f"{path}: {exc}") from exc


def dump_test(test: DriftwatchTest) -> str:
    """Serialize a test to stable, human-friendly YAML."""
    data = test.model_dump(mode="json", exclude_none=False)
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=110)


class Library:
    """All tests found under one or more directories, keyed by id."""

    def __init__(self, *roots: Path) -> None:
        self.roots = [Path(r) for r in roots]
        self._tests: dict[str, LoadedTest] = {}
        self.reload()

    def reload(self) -> None:
        """Re-read every ``*.yml`` / ``*.yaml`` file under the roots."""
        tests: dict[str, LoadedTest] = {}
        for root in self.roots:
            if not root.exists():
                continue
            for path in sorted([*root.rglob("*.yml"), *root.rglob("*.yaml")]):
                test = load_file(path)
                if test.id in tests:
                    raise LibraryError(f"duplicate test id {test.id!r} in {path} and {tests[test.id].path}")
                tests[test.id] = LoadedTest(test, path)
        self._tests = tests

    def __len__(self) -> int:
        return len(self._tests)

    def __contains__(self, test_id: object) -> bool:
        return test_id in self._tests

    def get(self, test_id: str) -> DriftwatchTest:
        """Return a test by id or raise :class:`LibraryError`."""
        try:
            return self._tests[test_id].test
        except KeyError:
            raise LibraryError(f"unknown test {test_id!r}") from None

    def path_of(self, test_id: str) -> Path:
        """The file a test was loaded from."""
        self.get(test_id)
        return self._tests[test_id].path

    def all(self) -> list[DriftwatchTest]:
        """Every test, sorted by id."""
        return [self._tests[k].test for k in sorted(self._tests)]

    def save(self, test: DriftwatchTest, path: Path | None = None) -> Path:
        """Write a test back to disk (to its original file unless ``path`` is given)."""
        DriftwatchTest.model_validate(test.model_dump())
        target = path or (self._tests[test.id].path if test.id in self._tests else None)
        if target is None:
            raise LibraryError(f"no file known for new test {test.id!r}; pass a path")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(dump_test(test), encoding="utf-8")
        self._tests[test.id] = LoadedTest(test, target)
        return target


def approve(test: DriftwatchTest, reviewer: str, notes: str | None = None,
            now: datetime | None = None) -> DriftwatchTest:
    """Human review gate: draft -> approved."""
    reviewer = reviewer.strip()
    if not reviewer:
        raise LibraryError("a reviewer name is required to approve a test")
    if test.status is not ReviewStatus.DRAFT:
        raise LibraryError(f"{test.id} is {test.status.value}; only drafts can be approved")
    data = test.model_dump()
    data["status"] = ReviewStatus.APPROVED
    data["review"] = {"approved_by": reviewer, "approved_at": now or datetime.now(timezone.utc), "notes": notes}
    return DriftwatchTest.model_validate(data)


def verify(test: DriftwatchTest, run_id: str, agent_id: str, all_steps_executed: bool,
           now: datetime | None = None) -> DriftwatchTest:
    """Lab-run gate: approved -> verified, only when every step of the run executed and cleaned up."""
    if test.status is not ReviewStatus.APPROVED:
        raise LibraryError(f"{test.id} is {test.status.value}; only approved tests can be verified")
    if not all_steps_executed:
        raise LibraryError(f"run {run_id} did not execute every step of {test.id}; not verifying")
    data = test.model_dump()
    data["status"] = ReviewStatus.VERIFIED
    data["verification"] = {"run_id": run_id, "agent_id": agent_id, "verified_at": now or datetime.now(timezone.utc)}
    return DriftwatchTest.model_validate(data)
