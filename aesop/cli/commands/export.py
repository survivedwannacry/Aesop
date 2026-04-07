"""Export command — export analysis artifacts in multiple formats."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from aesop.cli.app import app
from aesop.cli.common import handle_error, success
from aesop.core.analyzer import analyze_spec
from aesop.core.diagrams import generate_mermaid
from aesop.core.parser import parse_spec
from aesop.domain.findings import AnalysisResult
from aesop.reports.json_report import render_json
from aesop.reports.markdown import render_markdown
from aesop.utils.errors import AesopError
from aesop.utils.io import write_text


@app.command()
def export(
    spec_file: Annotated[
        Path,
        typer.Argument(help="Path to the architecture spec YAML file."),
    ],
    markdown: Annotated[
        Optional[Path],
        typer.Option("--markdown", "--md", help="Write a Markdown report to this path."),
    ] = None,
    json_path: Annotated[
        Optional[Path],
        typer.Option("--json", help="Write a JSON report to this path."),
    ] = None,
    mermaid: Annotated[
        Optional[Path],
        typer.Option("--mermaid", help="Write a Mermaid diagram to this path."),
    ] = None,
) -> None:
    """Export threat model artifacts in one command.

    Analyzes the spec once and writes selected outputs.
    Provide at least one of --markdown, --json, or --mermaid.
    """
    if not any([markdown, json_path, mermaid]):
        typer.echo(
            "Error: No output specified. Use --markdown, --json, or --mermaid.",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        spec = parse_spec(spec_file)
        result = analyze_spec(spec)

        # Generate diagram if needed for markdown or mermaid
        if markdown or mermaid:
            diagram = generate_mermaid(spec)
            result = AnalysisResult.build(
                system_name=result.system_name,
                system_type=result.system_type,
                description=result.description,
                findings=result.findings,
                diagram=diagram,
            )

        if markdown:
            write_text(markdown, render_markdown(result))
            success(f"Markdown report → [bold]{markdown}[/bold]")

        if json_path:
            write_text(json_path, render_json(result))
            success(f"JSON report → [bold]{json_path}[/bold]")

        if mermaid:
            write_text(mermaid, result.diagram_mermaid)
            success(f"Mermaid diagram → [bold]{mermaid}[/bold]")

    except AesopError as err:
        handle_error(err)
