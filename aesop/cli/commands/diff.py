"""Diff command — compare two architecture specs."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.panel import Panel
from rich.table import Table

from aesop.cli.app import app
from aesop.cli.common import handle_error, success
from aesop.core.diff_engine import DiffResult, diff_specs
from aesop.core.parser import parse_spec
from aesop.domain.findings import Finding
from aesop.reports.json_report import render_json
from aesop.reports.markdown import render_markdown
from aesop.reports.sections import severity_badge
from aesop.utils.errors import AesopError
from aesop.utils.io import write_text
from aesop.utils.logging import output_console


class DiffFormat(str, Enum):
    terminal = "terminal"
    markdown = "markdown"
    json = "json"


@app.command()
def diff(
    old_spec: Annotated[
        Path,
        typer.Argument(help="Path to the baseline (old) architecture spec."),
    ],
    new_spec: Annotated[
        Path,
        typer.Argument(help="Path to the updated (new) architecture spec."),
    ],
    format: Annotated[
        DiffFormat,
        typer.Option("--format", "-f", help="Output format: terminal, markdown, or json."),
    ] = DiffFormat.terminal,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write the diff report to a file instead of stdout."),
    ] = None,
) -> None:
    """Compare two architecture specs and show security posture changes.

    Detects added/removed components, new and resolved findings,
    and severity changes between spec versions.
    """
    try:
        old = parse_spec(old_spec)
        new = parse_spec(new_spec)
        result = diff_specs(old, new)

        if format == DiffFormat.terminal:
            _render_diff_terminal(result)
        elif format == DiffFormat.markdown:
            content = _render_diff_markdown(result)
            if output:
                write_text(output, content)
                success(f"Diff report → [bold]{output}[/bold]")
            else:
                typer.echo(content)
        elif format == DiffFormat.json:
            content = render_json(result.new_result)
            if output:
                write_text(output, content)
                success(f"JSON report → [bold]{output}[/bold]")
            else:
                typer.echo(content)

    except AesopError as err:
        handle_error(err)


def _render_diff_terminal(result: DiffResult) -> None:
    output_console.print()
    output_console.print(Panel(
        f"[bold]Aesop Architecture Diff[/bold]\n"
        f"[dim]{result.old_name} → {result.new_name}[/dim]",
        border_style="blue",
    ))

    changes = result.component_changes
    if changes.has_changes:
        table = Table(title="Component Changes", border_style="dim")
        table.add_column("Change", style="bold")
        table.add_column("Details")
        for label, items in [
            ("Tools added", changes.tools_added),
            ("Tools removed", changes.tools_removed),
            ("Retrieval added", changes.retrieval_added),
            ("Retrieval removed", changes.retrieval_removed),
            ("Memory added", changes.memory_added),
            ("Memory removed", changes.memory_removed),
            ("Secrets added", changes.secrets_added),
            ("Secrets removed", changes.secrets_removed),
            ("Boundaries added", changes.boundaries_added),
            ("Boundaries removed", changes.boundaries_removed),
            ("Exposure changes", changes.exposure_changes),
            ("Model changes", changes.model_changes),
        ]:
            if items:
                table.add_row(label, ", ".join(items))
        output_console.print(table)

    if result.severity_changes:
        output_console.print("\n[bold]Severity Changes[/bold]")
        for sc in result.severity_changes:
            output_console.print(f"  • {sc}")

    _print_finding_list("New Findings", result.new_findings, "red")
    _print_finding_list("Resolved Findings", result.resolved_findings, "green")

    output_console.print()


def _print_finding_list(title: str, findings: list[Finding], color: str) -> None:
    if not findings:
        return
    output_console.print(f"\n[bold {color}]{title}[/bold {color}]")
    for f in findings:
        output_console.print(f"  {severity_badge(f.severity)} {f.title} ({f.id})")


def _render_diff_markdown(result: DiffResult) -> str:
    lines = [
        f"# Aesop Architecture Diff\n",
        f"**Old:** {result.old_name}  ",
        f"**New:** {result.new_name}\n",
    ]

    changes = result.component_changes
    if changes.has_changes:
        lines.append("## Component Changes\n")
        for label, items in [
            ("Tools added", changes.tools_added),
            ("Tools removed", changes.tools_removed),
            ("Retrieval added", changes.retrieval_added),
            ("Retrieval removed", changes.retrieval_removed),
            ("Exposure changes", changes.exposure_changes),
            ("Model changes", changes.model_changes),
        ]:
            if items:
                lines.append(f"- **{label}:** {', '.join(items)}")
        lines.append("")

    if result.severity_changes:
        lines.append("## Severity Changes\n")
        for sc in result.severity_changes:
            lines.append(f"- {sc}")
        lines.append("")

    if result.new_findings:
        lines.append("## New Findings\n")
        for f in result.new_findings:
            lines.append(f"- {severity_badge(f.severity)} **{f.title}** (`{f.id}`)")
        lines.append("")

    if result.resolved_findings:
        lines.append("## Resolved Findings\n")
        for f in result.resolved_findings:
            lines.append(f"- ~~{f.title}~~ (`{f.id}`)")
        lines.append("")

    return "\n".join(lines) + "\n"
