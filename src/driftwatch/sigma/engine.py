"""Parse Sigma rules and evaluate them against ECS events.

Driftwatch's detection regression gate runs in CI, where there is no SIEM. Instead of converting rules
and querying Elastic, it evaluates each rule directly against recorded ECS telemetry from lab runs. This
module implements the subset of the Sigma specification that host-based rules use:

* selections as maps (AND), lists of maps (OR) and keyword lists
* field modifiers ``contains``, ``startswith``, ``endswith``, ``all``, ``re`` and ``windash``
* ``*`` and ``?`` wildcards, case-insensitive matching, ``null`` for a missing field
* conditions with ``and``, ``or``, ``not``, parentheses, ``1 of x*``, ``all of x*`` and ``them``
* logsource ``product``, ``category`` and ``service``, mapped onto ECS fields

Anything outside that subset raises :class:`SigmaError` instead of silently matching nothing, so an
unsupported rule fails the gate loudly.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Sigma (Sysmon-style) field names -> ECS. Rules may also use ECS names directly.
FIELD_MAP: dict[str, str] = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "OriginalFileName": "process.pe.original_file_name",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "User": "user.name",
    "CurrentDirectory": "process.working_directory",
    "TargetFilename": "file.path",
    "TargetObject": "registry.path",
    "Details": "registry.data.strings",
    "QueryName": "dns.question.name",
    "ScriptBlockText": "powershell.file.script_block_text",
    "EventID": "event.code",
    "Computer": "host.name",
    "exe": "process.executable",
    "comm": "process.name",
}

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "windash"}


class SigmaError(ValueError):
    """Raised for malformed or unsupported rules."""


def get_field(event: dict[str, Any], dotted: str) -> Any:
    """Read ``a.b.c`` from a nested ECS document, also accepting flat dotted keys."""
    if dotted in event:
        return event[dotted]
    node: Any = event
    parts = dotted.split(".")
    for i, part in enumerate(parts):
        if not isinstance(node, dict):
            return None
        if part in node:
            node = node[part]
            continue
        rest = ".".join(parts[i:])
        return node.get(rest)
    return node


def _values(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(v) for v in raw if v is not None]
    return [str(raw)]


# --- condition AST -------------------------------------------------------------------------------


@dataclass
class FieldTest:
    """``field|modifiers: values`` inside a selection."""

    field: str
    modifiers: tuple[str, ...]
    values: tuple[Any, ...]

    @property
    def ecs_field(self) -> str:
        return FIELD_MAP.get(self.field, self.field)

    def _patterns(self) -> list[str]:
        out: list[str] = []
        for v in self.values:
            text = str(v)
            variants = [text]
            if "windash" in self.modifiers:
                slashed = re.sub(r"(^|\s)-", r"\1/", text)
                if slashed != text:
                    variants.append(slashed)
            for t in variants:
                if "contains" in self.modifiers:
                    t = f"*{t}*"
                elif "startswith" in self.modifiers:
                    t = f"{t}*"
                elif "endswith" in self.modifiers:
                    t = f"*{t}"
                out.append(t)
        return out

    def matches(self, event: dict[str, Any]) -> bool:
        """True when the event field satisfies this test and its modifiers (``null`` matches a missing field)."""
        actual = _values(get_field(event, self.ecs_field))
        if self.values == (None,):
            return not actual
        if not actual:
            return False
        if "re" in self.modifiers:
            regexes = [re.compile(str(v)) for v in self.values]
            hits = [any(r.search(a) for a in actual) for r in regexes]
        else:
            hits = [
                any(fnmatch.fnmatchcase(a.lower(), p.lower()) for a in actual)
                for p in self._patterns()
            ]
        if "all" in self.modifiers:
            return all(hits)
        return any(hits)


@dataclass
class Keywords:
    """A keyword list: any value appears anywhere in the event's text fields."""

    values: tuple[str, ...]

    def matches(self, event: dict[str, Any]) -> bool:
        haystack: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
            elif node is not None:
                haystack.append(str(node).lower())

        walk(event)
        return any(fnmatch.fnmatchcase(h, f"*{k.lower()}*") for k in self.values for h in haystack)


@dataclass
class Selection:
    """A named selection: OR over alternatives, each an AND over field tests."""

    name: str
    alternatives: list[list[FieldTest | Keywords]]

    def matches(self, event: dict[str, Any]) -> bool:
        return any(all(t.matches(event) for t in alt) for alt in self.alternatives)


@dataclass
class Node:
    """Condition tree node: op is 'and' | 'or' | 'not' | 'sel'."""

    op: str
    children: list[Node] = field(default_factory=list)
    selection: Selection | None = None

    def matches(self, event: dict[str, Any]) -> bool:
        if self.op == "sel":
            assert self.selection is not None
            return self.selection.matches(event)
        if self.op == "not":
            return not self.children[0].matches(event)
        if self.op == "and":
            return all(c.matches(event) for c in self.children)
        return any(c.matches(event) for c in self.children)


def _parse_selection(name: str, body: Any) -> Selection:
    def parse_map(mapping: dict[str, Any]) -> list[FieldTest | Keywords]:
        tests: list[FieldTest | Keywords] = []
        for key, raw in mapping.items():
            parts = str(key).split("|")
            mods = tuple(parts[1:])
            unknown = set(mods) - SUPPORTED_MODIFIERS
            if unknown:
                raise SigmaError(f"selection {name!r}: unsupported modifiers {sorted(unknown)}")
            values = tuple(raw) if isinstance(raw, list) else (raw,)
            if not values:
                raise SigmaError(f"selection {name!r}: field {parts[0]!r} has an empty value list")
            tests.append(FieldTest(parts[0], mods, values))
        return tests

    if isinstance(body, dict):
        return Selection(name, [parse_map(body)])
    if isinstance(body, list) and body and all(isinstance(b, dict) for b in body):
        return Selection(name, [parse_map(b) for b in body])
    if isinstance(body, list) and body and all(isinstance(b, (str, int)) for b in body):
        return Selection(name, [[Keywords(tuple(str(b) for b in body))]])
    raise SigmaError(f"selection {name!r} must be a map, a list of maps or a keyword list")


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise SigmaError(f"cannot parse condition near {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(condition) and condition[pos].isspace():
            pos += 1
    return tokens


class _ConditionParser:
    def __init__(self, tokens: list[str], selections: dict[str, Selection]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.selections = selections

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaError("condition ended unexpectedly")
        self.pos += 1
        return tok

    def parse(self) -> Node:
        node = self.parse_or()
        if self.peek() is not None:
            raise SigmaError(f"unexpected token {self.peek()!r} in condition")
        return node

    def parse_or(self) -> Node:
        children = [self.parse_and()]
        while self.peek() and self.peek().lower() == "or":  # type: ignore[union-attr]
            self.take()
            children.append(self.parse_and())
        return children[0] if len(children) == 1 else Node("or", children)

    def parse_and(self) -> Node:
        children = [self.parse_not()]
        while self.peek() and self.peek().lower() == "and":  # type: ignore[union-attr]
            self.take()
            children.append(self.parse_not())
        return children[0] if len(children) == 1 else Node("and", children)

    def parse_not(self) -> Node:
        if self.peek() and self.peek().lower() == "not":  # type: ignore[union-attr]
            self.take()
            return Node("not", [self.parse_not()])
        return self.parse_atom()

    def _group(self, pattern: str) -> list[Node]:
        names = [n for n in self.selections if pattern == "them" or fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise SigmaError(f"no selection matches {pattern!r}")
        return [Node("sel", selection=self.selections[n]) for n in names]

    def parse_atom(self) -> Node:
        tok = self.take()
        if tok == "(":
            node = self.parse_or()
            if self.peek() != ")":
                raise SigmaError("missing closing parenthesis")
            self.pos += 1
            return node
        if tok in ("1", "all", "any"):
            if self.take().lower() != "of":
                raise SigmaError(f"expected 'of' after {tok!r}")
            nodes = self._group(self.take())
            return Node("and" if tok == "all" else "or", nodes) if len(nodes) > 1 else nodes[0]
        if tok not in self.selections:
            raise SigmaError(f"condition references unknown selection {tok!r}")
        return Node("sel", selection=self.selections[tok])


@dataclass
class SigmaRule:
    """A parsed rule, ready to match events."""

    id: str
    title: str
    level: str
    status: str
    logsource: dict[str, str]
    tags: list[str]
    condition: Node
    selections: dict[str, Selection]
    source: dict[str, Any]
    path: Path | None = None

    @property
    def techniques(self) -> list[str]:
        """ATT&CK technique ids from ``attack.tXXXX`` tags."""
        out = []
        for tag in self.tags:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag.lower())
            if m:
                out.append(m.group(1).upper())
        return out

    def logsource_matches(self, event: dict[str, Any]) -> bool:
        """Whether the event belongs to the rule's logsource."""
        product = self.logsource.get("product")
        if product and str(get_field(event, "host.os.type") or "").lower() != product.lower():
            return False
        category = self.logsource.get("category")
        if category and not _category_matches(category, event):
            return False
        service = self.logsource.get("service")
        return not (service and not _service_matches(service, event))

    def matches(self, event: dict[str, Any]) -> bool:
        """Full evaluation: logsource first, then the condition."""
        return self.logsource_matches(event) and self.condition.matches(event)


def _has(event: dict[str, Any], dotted: str, value: str) -> bool:
    return value.lower() in [v.lower() for v in _values(get_field(event, dotted))]


CATEGORY_RULES: dict[str, tuple[tuple[str, str], ...]] = {
    "process_creation": (("event.category", "process"), ("event.type", "start")),
    "registry_set": (("event.category", "registry"),),
    "registry_event": (("event.category", "registry"),),
    "registry_add": (("event.category", "registry"),),
    "file_event": (("event.category", "file"), ("event.type", "creation")),
    "file_access": (("event.category", "file"), ("event.type", "access")),
    "dns_query": (("event.category", "network"), ("event.type", "protocol")),
    "ps_script": (("event.category", "process"), ("event.provider", "Microsoft-Windows-PowerShell")),
}

SERVICE_CHANNELS: dict[str, str] = {
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "security": "Security",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "auditd": "auditd",
}


def _category_matches(category: str, event: dict[str, Any]) -> bool:
    try:
        rules = CATEGORY_RULES[category]
    except KeyError:
        raise SigmaError(f"unsupported logsource category {category!r}") from None
    return all(_has(event, f, v) for f, v in rules)


def _service_matches(service: str, event: dict[str, Any]) -> bool:
    try:
        channel = SERVICE_CHANNELS[service]
    except KeyError:
        raise SigmaError(f"unsupported logsource service {service!r}") from None
    if service == "auditd":
        return _has(event, "event.module", "auditd") or _has(event, "event.dataset", "auditd.log")
    return _has(event, "winlog.channel", channel)


def parse_rule(data: dict[str, Any], path: Path | None = None) -> SigmaRule:
    """Build a :class:`SigmaRule` from a parsed YAML document."""
    where = f" ({path})" if path else ""
    for key in ("id", "title", "logsource", "detection"):
        if key not in data:
            raise SigmaError(f"rule is missing {key!r}{where}")
    detection = dict(data["detection"])
    condition = detection.pop("condition", None)
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    if not isinstance(condition, str) or not condition.strip():
        raise SigmaError(f"rule has no condition{where}")
    detection.pop("timeframe", None)
    selections = {name: _parse_selection(name, body) for name, body in detection.items()}
    node = _ConditionParser(_tokenize(condition), selections).parse()
    return SigmaRule(
        id=str(data["id"]),
        title=str(data["title"]),
        level=str(data.get("level", "medium")),
        status=str(data.get("status", "experimental")),
        logsource={k: str(v) for k, v in dict(data["logsource"]).items()},
        tags=[str(t) for t in data.get("tags", [])],
        condition=node,
        selections=selections,
        source=data,
        path=path,
    )


def load_rules(directory: Path) -> dict[str, SigmaRule]:
    """Load every rule under ``directory``, keyed by rule id."""
    rules: dict[str, SigmaRule] = {}
    for path in sorted([*Path(directory).rglob("*.yml"), *Path(directory).rglob("*.yaml")]):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise SigmaError(f"{path}: invalid YAML: {exc}") from exc
        rule = parse_rule(data, path)
        if rule.id in rules:
            raise SigmaError(f"duplicate rule id {rule.id} in {path} and {rules[rule.id].path}")
        rules[rule.id] = rule
    return rules
