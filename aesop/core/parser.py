"""Parse and validate YAML architecture specifications."""

from pathlib import Path

import yaml
from pydantic import ValidationError

from aesop.domain.models import ArchitectureSpec
from aesop.utils.errors import SchemaValidationError, YAMLParseError
from aesop.utils.io import read_text


def load_yaml(path: Path) -> dict:
    """Load a YAML file and return the raw dictionary."""
    text = read_text(path)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise YAMLParseError(str(path), str(exc)) from exc

    if not isinstance(data, dict):
        raise YAMLParseError(str(path), "Expected a YAML mapping at the top level.")
    return data


def parse_spec(path: Path) -> ArchitectureSpec:
    """Parse and validate a YAML spec file into an ArchitectureSpec."""
    data = load_yaml(path)
    return validate_spec(data, source=str(path))


def validate_spec(data: dict, source: str = "<input>") -> ArchitectureSpec:
    """Validate a raw dictionary against the ArchitectureSpec schema."""
    try:
        return ArchitectureSpec.model_validate(data)
    except ValidationError as exc:
        errors = _format_pydantic_errors(exc)
        raise SchemaValidationError(errors) from exc


def _format_pydantic_errors(exc: ValidationError) -> list[str]:
    """Convert Pydantic validation errors into human-readable strings."""
    messages: list[str] = []
    for err in exc.errors():
        loc = " → ".join(str(part) for part in err["loc"])
        msg = err["msg"]
        messages.append(f"{loc}: {msg}")
    return messages
