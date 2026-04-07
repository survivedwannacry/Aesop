"""Validate command — validates an architecture spec YAML file."""

from pathlib import Path
from typing import Annotated

import typer

from aesop.cli.app import app
from aesop.cli.common import handle_error, success
from aesop.core.parser import parse_spec
from aesop.utils.errors import AesopError


@app.command()
def validate(
    spec_file: Annotated[
        Path,
        typer.Argument(
            help="Path to the architecture spec YAML file.",
            exists=False,
        ),
    ],
) -> None:
    """Validate an AI system architecture spec.

    Checks YAML syntax, required fields, field types, and enumerated values.
    Returns exit code 0 on success, 1 on validation failure.
    """
    try:
        spec = parse_spec(spec_file)
    except AesopError as err:
        handle_error(err)
        return

    success(
        f"Specification [bold]{spec.system.name}[/bold] "
        f"({spec.system.type.value}) is valid."
    )
