"""Tests for the diff engine."""

from pathlib import Path

from aesop.core.diff_engine import diff_specs
from aesop.core.parser import parse_spec, validate_spec


FIXTURES = Path(__file__).parent.parent / "examples"


def _make_spec(**overrides: object) -> dict:
    base: dict = {
        "system": {"name": "test", "type": "llm-agent"},
        "model": {"provider": "openai", "hosted": "external_api"},
    }
    base.update(overrides)
    return base


class TestDiffEngine:
    def test_identical_specs_no_changes(self) -> None:
        spec = validate_spec(_make_spec())
        result = diff_specs(spec, spec)
        assert not result.component_changes.has_changes
        assert result.new_findings == []
        assert result.resolved_findings == []

    def test_tool_added_detected(self) -> None:
        old = validate_spec(_make_spec())
        new = validate_spec(_make_spec(
            tools=[{"name": "jira", "permissions": ["read"]}]
        ))
        result = diff_specs(old, new)
        assert "jira" in result.component_changes.tools_added

    def test_tool_removed_detected(self) -> None:
        old = validate_spec(_make_spec(
            tools=[{"name": "jira", "permissions": ["read"]}]
        ))
        new = validate_spec(_make_spec())
        result = diff_specs(old, new)
        assert "jira" in result.component_changes.tools_removed

    def test_exposure_change_detected(self) -> None:
        old = validate_spec(_make_spec(
            exposure={"internet_facing": False}
        ))
        new = validate_spec(_make_spec(
            exposure={"internet_facing": True}
        ))
        result = diff_specs(old, new)
        assert any("enabled" in c for c in result.component_changes.exposure_changes)

    def test_new_findings_on_added_capabilities(self) -> None:
        old = validate_spec(_make_spec(
            exposure={"internet_facing": False, "users": ["ops"]},
        ))
        new = validate_spec(_make_spec(
            exposure={"internet_facing": True, "users": ["external_customers"]},
            tools=[{"name": "jira", "permissions": ["write_comments"],
                    "trust_boundary": "external_service"}],
            retrieval={"enabled": True,
                       "sources": [{"name": "kb", "sensitivity": "confidential"}]},
        ))
        result = diff_specs(old, new)
        assert len(result.new_findings) > 0

    def test_severity_changes_tracked(self) -> None:
        old = validate_spec(_make_spec())
        new = validate_spec(_make_spec(
            exposure={"internet_facing": True, "users": ["external_customers"]},
            tools=[{"name": "admin", "permissions": ["admin"],
                    "trust_boundary": "external_service"}],
        ))
        result = diff_specs(old, new)
        # New findings increase severity counts
        assert (
            result.new_result.severity_summary.total
            >= result.old_result.severity_summary.total
        )

    def test_example_diff_files(self) -> None:
        old = parse_spec(FIXTURES / "diff_old.yaml")
        new = parse_spec(FIXTURES / "diff_new.yaml")
        result = diff_specs(old, new)
        assert result.component_changes.has_changes
        assert "slack" in result.component_changes.tools_added
        assert len(result.new_findings) > 0
