"""Shared CLI utilities for consistent error handling and output."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from rich.panel import Panel

from aesop.utils.logging import console

if TYPE_CHECKING:
    from aesop.utils.errors import AesopError


def handle_error(err: AesopError) -> None:
    """Print a user-friendly error and exit with code 1."""
    console.print(
        Panel(
            f"[bold red]Error:[/bold red] {err.message}",
            subtitle=f"[dim]{err.hint}[/dim]" if err.hint else None,
            border_style="red",
        )
    )
    sys.exit(1)


def success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✓[/bold green] {message}")
