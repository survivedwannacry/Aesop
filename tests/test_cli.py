"""CLI integration tests using Typer's test runner."""

from pathlib import Path

from typer.testing import CliRunner

from aesop.cli.app import app

runner = CliRunner()
FIXTURES = Path(__file__).parent.parent / "examples"


class TestValidateCommand:
    def test_valid_spec(self) -> None:
        result = runner.invoke(app, ["validate", str(FIXTURES / "simple_agent.yaml")])
        assert result.exit_code == 0
        assert "valid" in result.output.lower() or "✓" in result.output

    def test_missing_file(self) -> None:
        result = runner.invoke(app, ["validate", "nonexistent.yaml"])
        assert result.exit_code != 0

    def test_invalid_spec(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("system:\n  name: test\n  type: invalid-type\n", encoding="utf-8")
        result = runner.invoke(app, ["validate", str(bad)])
        assert result.exit_code != 0


class TestModelCommand:
    def test_terminal_output(self) -> None:
        result = runner.invoke(app, ["model", str(FIXTURES / "simple_agent.yaml")])
        assert result.exit_code == 0

    def test_json_output(self) -> None:
        result = runner.invoke(app, [
            "model", str(FIXTURES / "simple_agent.yaml"),
            "--format", "json",
        ])
        assert result.exit_code == 0
        assert '"findings"' in result.output

    def test_markdown_output(self) -> None:
        result = runner.invoke(app, [
            "model", str(FIXTURES / "simple_agent.yaml"),
            "--format", "markdown",
        ])
        assert result.exit_code == 0
        assert "# Aesop Threat Model Report" in result.output

    def test_write_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(app, [
            "model", str(FIXTURES / "simple_agent.yaml"),
            "--format", "json",
            "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()

    def test_with_diagram(self) -> None:
        result = runner.invoke(app, [
            "model", str(FIXTURES / "simple_agent.yaml"),
            "--format", "markdown",
            "--diagram",
        ])
        assert result.exit_code == 0
        assert "mermaid" in result.output.lower()

    def test_min_severity_filter(self) -> None:
        result = runner.invoke(app, [
            "model", str(FIXTURES / "simple_agent.yaml"),
            "--min-severity", "critical",
        ])
        assert result.exit_code == 0


class TestExportCommand:
    def test_export_markdown(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        result = runner.invoke(app, [
            "export", str(FIXTURES / "simple_agent.yaml"),
            "--markdown", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        assert "# Aesop" in out.read_text(encoding="utf-8")

    def test_export_json(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(app, [
            "export", str(FIXTURES / "simple_agent.yaml"),
            "--json", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()

    def test_export_mermaid(self, tmp_path: Path) -> None:
        out = tmp_path / "diagram.mmd"
        result = runner.invoke(app, [
            "export", str(FIXTURES / "simple_agent.yaml"),
            "--mermaid", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        assert "graph TD" in out.read_text(encoding="utf-8")

    def test_export_no_flags_fails(self) -> None:
        result = runner.invoke(app, [
            "export", str(FIXTURES / "simple_agent.yaml"),
        ])
        assert result.exit_code != 0

    def test_export_all_formats(self, tmp_path: Path) -> None:
        result = runner.invoke(app, [
            "export", str(FIXTURES / "simple_agent.yaml"),
            "--markdown", str(tmp_path / "r.md"),
            "--json", str(tmp_path / "r.json"),
            "--mermaid", str(tmp_path / "d.mmd"),
        ])
        assert result.exit_code == 0
        assert (tmp_path / "r.md").exists()
        assert (tmp_path / "r.json").exists()
        assert (tmp_path / "d.mmd").exists()


class TestDiffCommand:
    def test_diff_terminal(self) -> None:
        result = runner.invoke(app, [
            "diff",
            str(FIXTURES / "diff_old.yaml"),
            str(FIXTURES / "diff_new.yaml"),
        ])
        assert result.exit_code == 0

    def test_diff_markdown(self) -> None:
        result = runner.invoke(app, [
            "diff",
            str(FIXTURES / "diff_old.yaml"),
            str(FIXTURES / "diff_new.yaml"),
            "--format", "markdown",
        ])
        assert result.exit_code == 0
        assert "Diff" in result.output

    def test_diff_missing_file(self) -> None:
        result = runner.invoke(app, [
            "diff",
            "nonexistent.yaml",
            str(FIXTURES / "diff_new.yaml"),
        ])
        assert result.exit_code != 0


class TestHelpText:
    def test_main_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "aesop" in result.output.lower()

    def test_validate_help(self) -> None:
        result = runner.invoke(app, ["validate", "--help"])
        assert result.exit_code == 0

    def test_model_help(self) -> None:
        result = runner.invoke(app, ["model", "--help"])
        assert result.exit_code == 0

    def test_diff_help(self) -> None:
        result = runner.invoke(app, ["diff", "--help"])
        assert result.exit_code == 0

    def test_export_help(self) -> None:
        result = runner.invoke(app, ["export", "--help"])
        assert result.exit_code == 0
