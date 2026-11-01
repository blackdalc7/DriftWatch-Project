"""Convert a parsed Sigma rule into a Kibana KQL query against ECS fields.

The output is what you paste into a Kibana custom query rule, or what ``driftwatch rules deploy`` sends
to the Kibana detection engine API. Regular expressions have no KQL form and raise :class:`SigmaError`.
"""

from __future__ import annotations

from driftwatch.sigma.engine import (
    CATEGORY_RULES,
    SERVICE_CHANNELS,
    FieldTest,
    Keywords,
    Node,
    Selection,
    SigmaError,
    SigmaRule,
)

_SPECIAL = set('\\():<>"{} ')


def _escape(text: str, keep_wildcards: bool) -> str:
    out = []
    for ch in text:
        if ch == "*" and keep_wildcards:
            out.append("*")
        elif ch in _SPECIAL or ch == "*":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _field_test(test: FieldTest) -> str:
    if "re" in test.modifiers:
        raise SigmaError(f"field {test.field!r} uses a regular expression, which KQL cannot express")
    if test.values == (None,):
        return f"not {test.ecs_field}:*"
    parts = []
    for pattern in test._patterns():
        wildcard = "*" in pattern or "?" in pattern
        if wildcard:
            parts.append(f"{test.ecs_field}:{_escape(pattern.replace('?', '*'), keep_wildcards=True)}")
        else:
            parts.append(f"{test.ecs_field}:{_quote(pattern)}")
    joiner = " and " if "all" in test.modifiers else " or "
    return parts[0] if len(parts) == 1 else "(" + joiner.join(parts) + ")"


def _selection(sel: Selection) -> str:
    alts = []
    for alt in sel.alternatives:
        pieces = []
        for t in alt:
            if isinstance(t, Keywords):
                pieces.append("(" + " or ".join(_quote(k) for k in t.values) + ")")
            else:
                pieces.append(_field_test(t))
        alts.append(pieces[0] if len(pieces) == 1 else "(" + " and ".join(pieces) + ")")
    return alts[0] if len(alts) == 1 else "(" + " or ".join(alts) + ")"


def _node(node: Node) -> str:
    if node.op == "sel":
        assert node.selection is not None
        return _selection(node.selection)
    if node.op == "not":
        return f"not {_node(node.children[0])}"
    joiner = f" {node.op} "
    return "(" + joiner.join(_node(c) for c in node.children) + ")"


def _logsource(rule: SigmaRule) -> list[str]:
    clauses: list[str] = []
    if "product" in rule.logsource:
        clauses.append(f"host.os.type:{_quote(rule.logsource['product'].lower())}")
    category = rule.logsource.get("category")
    if category:
        if category not in CATEGORY_RULES:
            raise SigmaError(f"unsupported logsource category {category!r}")
        clauses.extend(f"{f}:{_quote(v)}" for f, v in CATEGORY_RULES[category])
    service = rule.logsource.get("service")
    if service:
        if service not in SERVICE_CHANNELS:
            raise SigmaError(f"unsupported logsource service {service!r}")
        if service == "auditd":
            clauses.append('event.module:"auditd"')
        else:
            clauses.append(f"winlog.channel:{_quote(SERVICE_CHANNELS[service])}")
    return clauses


def to_kql(rule: SigmaRule) -> str:
    """The rule's logsource and condition as one KQL expression."""
    return " and ".join([*_logsource(rule), _node(rule.condition)])
