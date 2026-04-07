"""File I/O helpers."""

from pathlib import Path

from aesop.utils.errors import FileNotFoundError_, OutputPathError


def read_text(path: Path) -> str:
    """Read a text file, raising a clean error if missing."""
    if not path.exists():
        raise FileNotFoundError_(str(path))
    if not path.is_file():
        raise FileNotFoundError_(f"{path} (not a regular file)")
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    """Write text to a file, creating parent directories as needed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise OutputPathError(str(path), str(exc)) from exc
