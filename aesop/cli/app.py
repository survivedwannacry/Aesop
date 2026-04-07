"""Aesop CLI application and command registration."""

import typer

app = typer.Typer(
    name="aesop",
    help=(
        "Aesop — Threat modeling for AI agents, LLM apps, and RAG systems.\n\n"
        "Describe your AI system in YAML and get a structured threat model with "
        "deterministic findings, MITRE ATLAS mappings, and actionable mitigations."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _register_commands() -> None:
    """Import and register all CLI commands."""
    from aesop.cli.commands import diff, export, model, validate  # noqa: F401


_register_commands()
