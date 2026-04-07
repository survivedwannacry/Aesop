"""Rich terminal report output."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aesop.domain.enums import Severity
from aesop.domain.findings import AnalysisResult, Finding
from aesop.reports.sections import (
    architecture_summary,
    filter_by_min_severity,
    severity_badge,
    sort_findings_by_severity,
)
from aesop.utils.logging import output_console


_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
}


def render_terminal(
    result: AnalysisResult,
    min_severity: Severity = Severity.LOW,
) -> None:
    """Print a complete threat model report to the terminal."""
    _print_header(result)
    _print_summary_table(result)

    findings = filter_by_min_severity(result.findings, min_severity)
    findings = sort_findings_by_severity(findings)

    if not findings:
        output_console.print("\n[dim]No findings at or above the selected severity.[/dim]")
        return

    _print_findings(findings)
    _print_atlas_section(result)
    _print_recommendations(findings)


def _print_header(result: AnalysisResult) -> None:
    output_console.print()
    output_console.print(
        Panel(
            f"[bold]Aesop Threat Model Report[/bold]\n"
            f"[dim]{result.system_name} ({result.system_type})[/dim]",
            border_style="blue",
        )
    )


def _print_summary_table(result: AnalysisResult) -> None:
    table = Table(title="Architecture Summary", show_header=False, border_style="dim")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    for key, val in architecture_summary(result).items():
        table.add_row(key, val)
    output_console.print(table)


def _print_findings(findings: list[Finding]) -> None:
    output_console.print("\n[bold]Findings[/bold]\n")
    for finding in findings:
        color = _SEVERITY_COLORS[finding.severity]
        output_console.print(
            Panel(
                _finding_body(finding),
                title=f"[{color}]{severity_badge(finding.severity)}[/{color}] {finding.title}",
                subtitle=f"[dim]{finding.id} | {finding.rule_id}[/dim]",
                border_style=color,
            )
        )


def _finding_body(finding: Finding) -> Text:
    text = Text()
    text.append(finding.summary + "\n\n", style="bold")
    text.append(finding.description + "\n\n")

    if finding.affected_components:
        text.append("Affected: ", style="bold")
        text.append(", ".join(finding.affected_components) + "\n")

    if finding.evidence:
        text.append("\nEvidence:\n", style="bold")
        for e in finding.evidence:
            text.append(f"  • {e}\n")

    if finding.attack_path:
        text.append("\nAttack path: ", style="bold")
        text.append(finding.attack_path + "\n")

    if finding.mitigations:
        text.append("\nMitigations:\n", style="bold")
        for m in finding.mitigations:
            text.append(f"  → {m}\n")

    return text


def _print_atlas_section(result: AnalysisResult) -> None:
    if not result.atlas_techniques_used:
        return
    output_console.print("\n[bold]MITRE ATLAS Techniques[/bold]\n")
    table = Table(border_style="dim")
    table.add_column("ID", style="cyan")
    table.add_column("Technique")
    table.add_column("Tactic", style="dim")
    for t in result.atlas_techniques_used:
        table.add_row(t.technique_id, t.technique_name, t.tactic)
    output_console.print(table)


def _print_recommendations(findings: list[Finding]) -> None:
    seen: set[str] = set()
    mitigations: list[str] = []
    for f in findings:
        for m in f.mitigations:
            if m not in seen:
                seen.add(m)
                mitigations.append(m)

    if not mitigations:
        return

    output_console.print("\n[bold]Top Recommendations[/bold]\n")
    for i, m in enumerate(mitigations[:10], 1):
        output_console.print(f"  {i}. {m}")
    output_console.print()
