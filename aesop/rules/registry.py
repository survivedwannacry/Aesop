"""Rule registry — discovers and runs all threat-detection rules."""

from __future__ import annotations

from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule

# Global rule registry
_RULES: list[BaseRule] = []


def register(rule: BaseRule) -> BaseRule:
    """Register a rule instance in the global registry."""
    _RULES.append(rule)
    return rule


def get_all_rules() -> list[BaseRule]:
    """Return all registered rules."""
    return list(_RULES)


def run_all(system: NormalizedSystem) -> list[Finding]:
    """Run every registered rule against the system and collect findings."""
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule.evaluate(system))
    return findings


def _ensure_rules_loaded() -> None:
    """Import all rule modules to trigger registration."""
    from aesop.rules import (  # noqa: F401
        cross_context,
        dos_cost_abuse,
        excessive_agency,
        insecure_output,
        logging_leakage,
        memory_abuse,
        missing_approval,
        prompt_injection,
        retrieval_exfiltration,
        secret_exposure,
        supply_chain,
        tool_abuse,
    )


_ensure_rules_loaded()
