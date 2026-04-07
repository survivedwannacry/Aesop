"""Deterministic severity scoring for findings.

Adjusts severity based on the overall system risk posture.
The logic is intentionally simple and transparent.
"""

from __future__ import annotations

from aesop.domain.enums import Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem


def score_findings(
    findings: list[Finding],
    system: NormalizedSystem,
) -> list[Finding]:
    """Adjust finding severities based on system-level risk factors."""
    risk_level = _assess_system_risk(system)
    scored: list[Finding] = []

    for finding in findings:
        adjusted = _adjust_severity(finding.severity, risk_level)
        if adjusted != finding.severity:
            scored.append(finding.model_copy(update={"severity": adjusted}))
        else:
            scored.append(finding)

    return scored


def _assess_system_risk(system: NormalizedSystem) -> int:
    """Compute a simple additive risk score from system properties.

    Returns a score from 0 to ~10. Higher means riskier context.
    Each factor contributes 0 or 1 point (sometimes 2).
    """
    score = 0
    if system.internet_facing:
        score += 2
    if system.has_external_users:
        score += 1
    if system.has_retrieval:
        score += 1
    if system.has_memory:
        score += 1
    if system.has_sensitive_data:
        score += 1
    if system.has_pii:
        score += 1
    if system.has_write_tools:
        score += 1
    if system.has_privileged_tools:
        score += 1
    if system.num_trust_boundaries >= 4:
        score += 1
    return score


def _adjust_severity(base: Severity, risk_level: int) -> Severity:
    """Potentially upgrade severity for high-risk systems.

    Only upgrades by at most one level, and only when the overall
    system risk context is elevated.
    """
    if risk_level >= 7 and base == Severity.MEDIUM:
        return Severity.HIGH
    if risk_level >= 8 and base == Severity.HIGH:
        return Severity.CRITICAL
    return base
