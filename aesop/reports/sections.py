"""Shared report section builders used across output formats."""

from __future__ import annotations

from aesop.domain.enums import Severity
from aesop.domain.findings import AnalysisResult, Finding


def severity_badge(severity: Severity) -> str:
    """Return an emoji-style badge for terminal/markdown display."""
    return {
        Severity.CRITICAL: "🔴 CRITICAL",
        Severity.HIGH: "🟠 HIGH",
        Severity.MEDIUM: "🟡 MEDIUM",
        Severity.LOW: "🟢 LOW",
    }[severity]


def sort_findings_by_severity(findings: list[Finding]) -> list[Finding]:
    """Sort findings from most to least severe."""
    return sorted(findings, key=lambda f: f.severity.rank, reverse=True)


def filter_by_min_severity(
    findings: list[Finding],
    min_severity: Severity,
) -> list[Finding]:
    """Keep only findings at or above the minimum severity."""
    return [f for f in findings if f.severity >= min_severity]


def architecture_summary(result: AnalysisResult) -> dict[str, str]:
    """Build a key-value summary of the analyzed architecture."""
    return {
        "System": result.system_name,
        "Type": result.system_type,
        "Description": result.description or "(none)",
        "Total Findings": str(result.severity_summary.total),
        "Critical": str(result.severity_summary.critical),
        "High": str(result.severity_summary.high),
        "Medium": str(result.severity_summary.medium),
        "Low": str(result.severity_summary.low),
    }
