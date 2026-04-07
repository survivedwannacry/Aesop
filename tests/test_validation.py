"""Tests for schema validation details."""

import pytest

from aesop.core.parser import validate_spec
from aesop.domain.enums import DataSensitivity, SystemType
from aesop.utils.errors import SchemaValidationError


def _minimal(**overrides: object) -> dict:
    """Build a minimal valid spec dict with optional overrides."""
    base: dict = {
        "system": {"name": "test-sys", "type": "llm-agent"},
        "model": {"provider": "openai"},
    }
    base.update(overrides)
    return base


class TestSystemValidation:
    def test_all_valid_system_types(self) -> None:
        for st in SystemType:
            spec = validate_spec(_minimal(system={"name": "x", "type": st.value}))
            assert spec.system.type == st

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(SchemaValidationError):
            validate_spec(_minimal(system={"name": "", "type": "llm-agent"}))


class TestToolValidation:
    def test_tool_with_all_fields(self) -> None:
        spec = validate_spec(
            _minimal(
                tools=[
                    {
                        "name": "slack",
                        "permissions": ["send_message", "read_channels"],
                        "trust_boundary": "external_service",
                    }
                ]
            )
        )
        assert len(spec.tools) == 1
        assert spec.tools[0].name == "slack"

    def test_tool_minimal(self) -> None:
        spec = validate_spec(_minimal(tools=[{"name": "calc"}]))
        assert spec.tools[0].permissions == []
        assert spec.tools[0].trust_boundary == "unknown"


class TestRetrievalValidation:
    def test_retrieval_with_sources(self) -> None:
        spec = validate_spec(
            _minimal(
                retrieval={
                    "enabled": True,
                    "sources": [{"name": "docs", "sensitivity": "pii"}],
                }
            )
        )
        assert spec.retrieval.enabled is True
        assert spec.retrieval.sources[0].sensitivity == DataSensitivity.PII


class TestDataSensitivity:
    def test_multiple_sensitivities(self) -> None:
        spec = validate_spec(
            _minimal(data={"sensitivity": ["internal", "confidential", "pii"]})
        )
        assert DataSensitivity.PII in spec.data.sensitivity
        assert len(spec.data.sensitivity) == 3
