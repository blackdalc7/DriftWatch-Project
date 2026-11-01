"""The shared Driftwatch test format (YAML), as Pydantic models.

One test file describes what to emulate (steps from the Safe Action Catalog), which ATT&CK techniques it
covers, what a defender should see (expected outcome and the Sigma rules that must fire), which baseline
controls should stop it, and where it came from. The same format is consumed by the server, the
regression runner, the intel drafter and the UI; ``schema/driftwatch-test.schema.json`` is generated
from these models so editors and other tools can validate files too.

Lifecycle: ``draft`` (written by a person or the AI drafter) -> ``approved`` (a named human reviewed it)
-> ``verified`` (a lab run of the approved test executed every step cleanly). Only approved and verified
tests can be dispatched to agents, and only verified tests are scheduled.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from driftwatch.catalog import PLATFORMS, CatalogError, techniques_for_step, validate_step

TEST_ID_PATTERN = r"^dw-[a-z0-9][a-z0-9-]{2,62}$"
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTICS = (
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
)


class ReviewStatus(str, Enum):
    """Review state of a test."""

    DRAFT = "draft"
    APPROVED = "approved"
    VERIFIED = "verified"


class Outcome(str, Enum):
    """How a single run scored."""

    PREVENTED = "prevented"
    DETECTED = "detected"
    MISSED = "missed"
    ERROR = "error"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Step(_Strict):
    """One catalog action with its parameters."""

    action: str
    params: dict[str, Any] = Field(default_factory=dict)


class Attack(_Strict):
    """ATT&CK mapping."""

    tactic: str
    techniques: list[str] = Field(min_length=1)

    @field_validator("tactic")
    @classmethod
    def _tactic(cls, value: str) -> str:
        if value not in TACTICS:
            raise ValueError(f"unknown tactic {value!r}")
        return value

    @field_validator("techniques")
    @classmethod
    def _techniques(cls, value: list[str]) -> list[str]:
        for t in value:
            if not TECHNIQUE_PATTERN.match(t):
                raise ValueError(f"{t!r} is not an ATT&CK technique id like T1059 or T1059.001")
        return value


class Expected(_Strict):
    """What a working defense looks like for this test."""

    outcome: Outcome = Outcome.DETECTED
    detections: list[str] = Field(default_factory=list, description="Sigma rule ids that must fire")
    window_seconds: int = Field(default=300, ge=30, le=3600)

    @field_validator("outcome")
    @classmethod
    def _outcome(cls, value: Outcome) -> Outcome:
        if value not in (Outcome.PREVENTED, Outcome.DETECTED):
            raise ValueError("expected.outcome must be 'prevented' or 'detected'")
        return value

    def passes(self, outcome: Outcome) -> bool:
        """Whether an observed outcome meets this expectation (prevention also satisfies detection)."""
        if self.outcome is Outcome.PREVENTED:
            return outcome is Outcome.PREVENTED
        return outcome in (Outcome.PREVENTED, Outcome.DETECTED)


class Provenance(_Strict):
    """Where the test came from."""

    source: str = Field(default="manual", pattern=r"^(manual|cisa|atomic-red-team)$")
    reference: str | None = None
    generated_by: str | None = None
    generated_at: datetime | None = None


class Review(_Strict):
    """The human review that moved a draft to approved."""

    approved_by: str | None = None
    approved_at: datetime | None = None
    notes: str | None = None


class Verification(_Strict):
    """The lab run that moved an approved test to verified."""

    run_id: str | None = None
    agent_id: str | None = None
    verified_at: datetime | None = None


class DriftwatchTest(_Strict):
    """A complete test definition."""

    id: str = Field(pattern=TEST_ID_PATTERN)
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10)
    version: int = Field(default=1, ge=1)
    status: ReviewStatus = ReviewStatus.DRAFT
    platforms: list[str] = Field(min_length=1)
    severity: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    attack: Attack
    steps: list[Step] = Field(min_length=1, max_length=10)
    expected: Expected = Field(default_factory=Expected)
    hygiene_controls: list[str] = Field(default_factory=list)
    provenance: Provenance = Field(default_factory=Provenance)
    review: Review = Field(default_factory=Review)
    verification: Verification = Field(default_factory=Verification)

    @field_validator("platforms")
    @classmethod
    def _platforms(cls, value: list[str]) -> list[str]:
        for p in value:
            if p not in PLATFORMS:
                raise ValueError(f"platform {p!r} must be one of {PLATFORMS}")
        return sorted(set(value))

    @model_validator(mode="after")
    def _steps_in_catalog(self) -> DriftwatchTest:
        for index, step in enumerate(self.steps):
            for platform in self.platforms:
                try:
                    step.params = validate_step(step.action, step.params, platform)
                except CatalogError as exc:
                    raise ValueError(f"steps[{index}]: {exc}") from exc
        if self.status is ReviewStatus.APPROVED and not self.review.approved_by:
            raise ValueError("an approved test must name review.approved_by")
        if self.status is ReviewStatus.VERIFIED and not (self.review.approved_by and self.verification.run_id):
            raise ValueError("a verified test needs review.approved_by and verification.run_id")
        return self

    @property
    def dispatchable(self) -> bool:
        """Approved and verified tests may run on an agent; drafts never do."""
        return self.status in (ReviewStatus.APPROVED, ReviewStatus.VERIFIED)

    def emulated_techniques(self) -> list[str]:
        """Techniques the steps actually emulate, according to the catalog."""
        found: list[str] = []
        for step in self.steps:
            for t in techniques_for_step(step.action, step.params):
                if t not in found:
                    found.append(t)
        return found


def export_json_schema() -> dict[str, Any]:
    """JSON Schema for the test format, for editors and non-Python consumers."""
    schema = DriftwatchTest.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://driftwatch.dev/schema/driftwatch-test.schema.json"
    schema["title"] = "Driftwatch test"
    return schema
