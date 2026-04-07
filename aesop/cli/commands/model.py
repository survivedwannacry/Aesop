"""Model command — generate a threat model from an architecture spec."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from aesop.cli.app import app
from aesop.cli.common import handle_error, success
from aesop.core.analyzer import analyze_spec
from aesop.core.diagrams import generate_mermaid
from aesop.core.parser import parse_spec
from aesop.domain.enums import Severity
from aesop.domain.findings import AnalysisResult
from aesop.reports.json_report import render_json
from aesop.reports.markdown import render_markdown
from aesop.reports.terminal import render_terminal
from aesop.utils.errors import AesopError
from aesop.utils.io import write_text


class OutputFormat(str, Enum):
    terminal = "terminal"
    markdown = "markdown"
    json = "json"


@app.command()
def model(
    spec_file: Annotated[
        Path,
        typer.Argument(help="Path to the architecture spec YAML file."),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: terminal, markdown, or json."),
    ] = OutputFormat.terminal,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Write the report to a file instead of stdout."),
    ] = None,
    diagram: Annotated[
        bool,
        typer.Option("--diagram", help="Include a Mermaid architecture diagram in the report."),
    ] = False,
    min_severity: Annotated[
        Severity,
        typer.Option("--min-severity", help="Only show findings at or above this severity level."),
    ] = Severity.LOW,
) -> None:
    """Analyze an architecture spec and generate a threat model."""
    try:
        spec = parse_spec(spec_file)
        result = analyze_spec(spec)

        if diagram:
            mermaid = generate_mermaid(spec)
            result = AnalysisResult.build(
                system_name=result.system_name,
                system_type=result.system_type,
                description=result.description,
                findings=result.findings,
                diagram=mermaid,
            )

        content = _render(result, format, min_severity)

        if output:
            write_text(output, content)
            success(f"Report written to [bold]{output}[/bold]")
        elif format != OutputFormat.terminal:
            typer.echo(content)

    except AesopError as err:
        handle_error(err)


def _render(
    result: AnalysisResult,
    fmt: OutputFormat,
    min_severity: Severity,
) -> str:
    if fmt == OutputFormat.terminal:
        render_terminal(result, min_severity=min_severity)
        return ""
    elif fmt == OutputFormat.markdown:
        return render_markdown(result)
    elif fmt == OutputFormat.json:
        return render_json(result)
    return ""
