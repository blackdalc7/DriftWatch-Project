"""The Safe Action Catalog: the only things a Driftwatch agent will ever do.

Every test is a list of steps, and every step names one action from this catalog plus parameters that are
validated against the action's typed parameter specs. There is no free-form command field anywhere in the
platform. The Go agent compiles in the same list of action ids (``agent/internal/actions``) and refuses
anything else, so a compromised server still cannot make an agent run arbitrary code.

Design rules for adding an action:

* It must be benign: no exploit, no real credential access, no destructive change, nothing that persists
  past its own cleanup step.
* It must be observable: it emulates the telemetry a defender expects to see, and it must carry the run
  marker (``DW-<run id>``) somewhere a SIEM indexes (command line, file path, registry value, DNS name).
* It must not evade: no obfuscation beyond what the emulated technique literally is, no tampering with
  security tooling, no unhooking, no sleeping to dodge sandboxes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

WINDOWS = "windows"
LINUX = "linux"
PLATFORMS = (WINDOWS, LINUX)

MARKER_PREFIX = "DW-"
RUN_ID_PATTERN = re.compile(r"^[a-f0-9]{16}$")


class CatalogError(ValueError):
    """Raised when a step names an unknown action or carries invalid parameters."""


@dataclass(frozen=True)
class ParamSpec:
    """One typed parameter of a catalog action."""

    name: str
    kind: str  # "enum" | "int" | "bool"
    description: str
    required: bool = False
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    default: Any = None

    def validate(self, value: Any) -> Any:
        """Return the normalized value or raise :class:`CatalogError`."""
        if self.kind == "enum":
            if not isinstance(value, str) or value not in self.choices:
                raise CatalogError(f"parameter {self.name!r} must be one of {list(self.choices)}, got {value!r}")
            return value
        if self.kind == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise CatalogError(f"parameter {self.name!r} must be an integer, got {value!r}")
            if self.minimum is not None and value < self.minimum:
                raise CatalogError(f"parameter {self.name!r} must be >= {self.minimum}")
            if self.maximum is not None and value > self.maximum:
                raise CatalogError(f"parameter {self.name!r} must be <= {self.maximum}")
            return value
        if self.kind == "bool":
            if not isinstance(value, bool):
                raise CatalogError(f"parameter {self.name!r} must be true or false, got {value!r}")
            return value
        raise CatalogError(f"unsupported parameter kind {self.kind!r}")  # pragma: no cover - guarded by tests


@dataclass(frozen=True)
class SafeAction:
    """A benign, typed, reversible action the agent knows how to perform and clean up."""

    id: str
    title: str
    description: str
    platforms: tuple[str, ...]
    techniques: tuple[str, ...]
    observables: tuple[str, ...]
    cleanup: str
    params: tuple[ParamSpec, ...] = field(default_factory=tuple)
    # Techniques for specific enum choices, when one action emulates several techniques.
    technique_by_choice: dict[str, str] = field(default_factory=dict)
    # Choices that only exist on one platform (choice -> platform).
    choice_platform: dict[str, str] = field(default_factory=dict)
    schedulable_as_test: bool = True

    def param(self, name: str) -> ParamSpec | None:
        """Look up a parameter spec by name."""
        return next((p for p in self.params if p.name == name), None)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for the API, the docs generator and the LLM drafter prompt."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "platforms": list(self.platforms),
            "techniques": list(self.techniques),
            "observables": list(self.observables),
            "cleanup": self.cleanup,
            "params": [
                {
                    "name": p.name,
                    "kind": p.kind,
                    "description": p.description,
                    "required": p.required,
                    "choices": list(p.choices),
                    "minimum": p.minimum,
                    "maximum": p.maximum,
                    "default": p.default,
                }
                for p in self.params
            ],
            "technique_by_choice": dict(self.technique_by_choice),
            "choice_platform": dict(self.choice_platform),
            "schedulable_as_test": self.schedulable_as_test,
        }


_DISCOVERY_CHOICES = {
    # choice: (platform, technique)
    "whoami_all": (WINDOWS, "T1033"),
    "systeminfo": (WINDOWS, "T1082"),
    "ipconfig_all": (WINDOWS, "T1016"),
    "net_localgroup_admins": (WINDOWS, "T1069.001"),
    "tasklist": (WINDOWS, "T1057"),
    "id": (LINUX, "T1033"),
    "uname_a": (LINUX, "T1082"),
    "ip_addr": (LINUX, "T1016"),
    "getent_group_sudo": (LINUX, "T1069.001"),
    "ps_aux": (LINUX, "T1057"),
}

_ACTIONS: tuple[SafeAction, ...] = (
    SafeAction(
        id="file.eicar_drop",
        title="Drop the EICAR test file",
        description=(
            "Writes the industry-standard EICAR antivirus test string to the agent workspace as "
            "eicar-DW-<run>.com, waits, then checks whether the file was quarantined. The string is inert."
        ),
        platforms=(WINDOWS, LINUX),
        techniques=("T1105",),
        observables=("file.path",),
        cleanup="Deletes the file if it still exists.",
        params=(
            ParamSpec("wait_seconds", "int", "Seconds to wait for antivirus before checking the file", False,
                      minimum=1, maximum=60, default=10),
        ),
    ),
    SafeAction(
        id="process.discovery",
        title="Run an allow-listed discovery command",
        description=(
            "Runs one fixed, read-only discovery command chosen from an enum, with the run marker appended "
            "as a shell comment so the command line is attributable. No user-supplied text reaches the shell."
        ),
        platforms=(WINDOWS, LINUX),
        techniques=tuple(sorted({t for _, t in _DISCOVERY_CHOICES.values()})),
        observables=("process.command_line",),
        cleanup="Nothing to clean up: the command is read-only.",
        params=(ParamSpec("command", "enum", "Which discovery command to run", True,
                          choices=tuple(_DISCOVERY_CHOICES)),),
        technique_by_choice={c: t for c, (_, t) in _DISCOVERY_CHOICES.items()},
        choice_platform={c: p for c, (p, _) in _DISCOVERY_CHOICES.items()},
    ),
    SafeAction(
        id="registry.run_key_canary",
        title="Write a Run key canary value",
        description=(
            "Creates HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DriftwatchCanary-DW-<run> pointing "
            "at a non-existent .txt path in the workspace, so nothing can ever execute at logon, then removes it."
        ),
        platforms=(WINDOWS,),
        techniques=("T1547.001",),
        observables=("registry.path", "registry.value"),
        cleanup="Deletes the registry value immediately after the hold period.",
        params=(ParamSpec("hold_seconds", "int", "How long the value exists before cleanup", False,
                          minimum=1, maximum=120, default=15),),
    ),
    SafeAction(
        id="scheduled_task.canary",
        title="Register a disabled scheduled task canary",
        description=(
            "Registers a disabled scheduled task named DriftwatchCanary-DW-<run> whose only action is "
            "'cmd.exe /c exit 0', set to a date in 2099, then deletes it."
        ),
        platforms=(WINDOWS,),
        techniques=("T1053.005",),
        observables=("process.command_line",),
        cleanup="Deletes the scheduled task.",
        params=(ParamSpec("hold_seconds", "int", "How long the task exists before cleanup", False,
                          minimum=1, maximum=120, default=15),),
    ),
    SafeAction(
        id="persistence.autostart_canary",
        title="Write an XDG autostart canary",
        description=(
            "Writes ~/.config/autostart/driftwatch-DW-<run>.desktop with Hidden=true and Exec=/bin/true, "
            "then removes it."
        ),
        platforms=(LINUX,),
        techniques=("T1547.013",),
        observables=("file.path",),
        cleanup="Deletes the .desktop file.",
        params=(ParamSpec("hold_seconds", "int", "How long the file exists before cleanup", False,
                          minimum=1, maximum=120, default=15),),
    ),
    SafeAction(
        id="dns.sinkhole_query",
        title="Resolve a reserved .invalid domain",
        description=(
            "Looks up dw-<run>.c2-canary.invalid. The .invalid TLD is reserved by RFC 2606 and never "
            "resolves, so no traffic leaves the resolver, but the query is logged by DNS telemetry."
        ),
        platforms=(WINDOWS, LINUX),
        techniques=("T1071.004",),
        observables=("dns.question.name",),
        cleanup="Nothing to clean up.",
        params=(ParamSpec("count", "int", "Number of lookups (emulates beaconing)", False,
                          minimum=1, maximum=10, default=3),),
    ),
    SafeAction(
        id="file.credential_canary_read",
        title="Read a planted fake credential file",
        description=(
            "Creates workspace/canary/passwords-DW-<run>.txt containing obviously fake credentials, reads it "
            "back the way a credential harvester would, then deletes it. No real secret store is touched."
        ),
        platforms=(WINDOWS, LINUX),
        techniques=("T1552.001",),
        observables=("file.path",),
        cleanup="Deletes the canary file and its folder.",
    ),
    SafeAction(
        id="powershell.encoded_marker",
        title="Run a fixed encoded PowerShell command",
        description=(
            "Runs powershell.exe -NoProfile -EncodedCommand with the Base64 of a fixed statement that only "
            "prints 'Driftwatch DW-<run>'. Emulates the observable shape of T1059.001 with T1027 encoding; "
            "the decoded content is visible in script block logging."
        ),
        platforms=(WINDOWS,),
        techniques=("T1059.001", "T1027"),
        observables=("process.command_line", "powershell.file.script_block_text"),
        cleanup="Nothing to clean up: the command only writes to stdout.",
    ),
    SafeAction(
        id="hygiene.collect",
        title="Collect the baseline hygiene report",
        description=(
            "Runs the baseline script compiled into the agent (PowerShell on Windows, Bash on Linux) and "
            "returns its JSON report. Read-only."
        ),
        platforms=(WINDOWS, LINUX),
        techniques=(),
        observables=(),
        cleanup="Nothing to clean up: the script only reads configuration.",
        schedulable_as_test=False,
    ),
)

CATALOG: dict[str, SafeAction] = {a.id: a for a in _ACTIONS}


def get_action(action_id: str) -> SafeAction:
    """Return the catalog action or raise :class:`CatalogError`."""
    try:
        return CATALOG[action_id]
    except KeyError:
        raise CatalogError(f"unknown action {action_id!r}; not in the Safe Action Catalog") from None


def validate_step(action_id: str, params: dict[str, Any] | None, platform: str | None = None) -> dict[str, Any]:
    """Validate one step and return its parameters with defaults filled in.

    Unknown parameters are rejected rather than ignored, so a drafted test cannot smuggle extra fields
    to the agent.
    """
    action = get_action(action_id)
    params = dict(params or {})
    if platform is not None and platform not in action.platforms:
        raise CatalogError(f"action {action_id!r} does not support platform {platform!r}")
    unknown = set(params) - {p.name for p in action.params}
    if unknown:
        raise CatalogError(f"action {action_id!r} does not accept parameters {sorted(unknown)}")
    normalized: dict[str, Any] = {}
    for spec in action.params:
        if spec.name in params:
            normalized[spec.name] = spec.validate(params[spec.name])
        elif spec.required:
            raise CatalogError(f"action {action_id!r} requires parameter {spec.name!r}")
        elif spec.default is not None:
            normalized[spec.name] = spec.default
    if platform is not None:
        for name, value in normalized.items():
            owner = action.choice_platform.get(value) if isinstance(value, str) else None
            if owner is not None and owner != platform:
                raise CatalogError(f"{name}={value!r} of {action_id!r} is a {owner} choice, not {platform}")
    return normalized


def techniques_for_step(action_id: str, params: dict[str, Any] | None) -> tuple[str, ...]:
    """The ATT&CK techniques one step emulates, narrowed by enum choice where the action defines it."""
    action = get_action(action_id)
    for value in (params or {}).values():
        if isinstance(value, str) and value in action.technique_by_choice:
            return (action.technique_by_choice[value],)
    return action.techniques


def actions_for_technique(technique: str) -> list[tuple[SafeAction, dict[str, Any]]]:
    """Every (action, params) pair that emulates ``technique`` (or its parent technique).

    Used by the intel drafter's offline mode and to constrain the LLM: if this returns nothing,
    Driftwatch cannot safely emulate the technique and the drafter must skip it.
    """
    parent = technique.split(".")[0]
    matches: list[tuple[SafeAction, dict[str, Any]]] = []
    for action in _ACTIONS:
        if not action.schedulable_as_test:
            continue
        if action.technique_by_choice:
            spec = action.params[0]
            for choice, tech in action.technique_by_choice.items():
                if tech == technique or tech.split(".")[0] == parent:
                    matches.append((action, {spec.name: choice}))
        elif any(t == technique or t.split(".")[0] == parent for t in action.techniques):
            matches.append((action, {}))
    return matches


def marker_for(run_id: str) -> str:
    """The searchable marker every action embeds in its telemetry."""
    if not RUN_ID_PATTERN.match(run_id):
        raise CatalogError(f"run id {run_id!r} must be 16 lowercase hex characters")
    return f"{MARKER_PREFIX}{run_id}"


def catalog_as_dicts() -> list[dict[str, Any]]:
    """The whole catalog, serialized."""
    return [a.to_dict() for a in _ACTIONS]
