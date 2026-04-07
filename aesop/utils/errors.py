"""Custom error types for user-friendly CLI error reporting."""


class AesopError(Exception):
    """Base error for all Aesop-specific exceptions."""

    def __init__(self, message: str, hint: str = "") -> None:
        self.message = message
        self.hint = hint
        super().__init__(message)


class FileNotFoundError_(AesopError):
    """Raised when a spec file does not exist."""

    def __init__(self, path: str) -> None:
        super().__init__(
            message=f"File not found: {path}",
            hint="Check the file path and try again.",
        )


class YAMLParseError(AesopError):
    """Raised when YAML cannot be parsed."""

    def __init__(self, path: str, detail: str = "") -> None:
        msg = f"Invalid YAML in {path}"
        if detail:
            msg += f": {detail}"
        super().__init__(
            message=msg,
            hint="Ensure the file contains valid YAML syntax.",
        )


class SchemaValidationError(AesopError):
    """Raised when the spec fails Pydantic schema validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        bullet_list = "\n".join(f"  • {e}" for e in errors)
        super().__init__(
            message=f"Schema validation failed:\n{bullet_list}",
            hint="Review the spec against the expected schema.",
        )


class OutputPathError(AesopError):
    """Raised when an output path is invalid or not writable."""

    def __init__(self, path: str, reason: str = "") -> None:
        msg = f"Cannot write to {path}"
        if reason:
            msg += f": {reason}"
        super().__init__(
            message=msg,
            hint="Check that the directory exists and is writable.",
        )
