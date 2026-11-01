"""A compact Sigma engine: parse rules, match them against ECS events, and convert them to KQL."""

from driftwatch.sigma.engine import SigmaError, SigmaRule, load_rules, parse_rule
from driftwatch.sigma.kql import to_kql

__all__ = ["SigmaError", "SigmaRule", "load_rules", "parse_rule", "to_kql"]
