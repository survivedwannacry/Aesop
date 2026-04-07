"""Aesop CLI entrypoint."""

from aesop.cli.app import app


def main() -> None:
    """Run the Aesop CLI."""
    app()


if __name__ == "__main__":
    main()
