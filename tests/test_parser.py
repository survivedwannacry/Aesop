"""Tests for YAML parsing and spec loading."""

from pathlib import Path

import pytest

from aesop.core.parser import load_yaml, parse_spec, validate_spec
from aesop.utils.errors import FileNotFoundError_, SchemaValidationError, YAMLParseError


FIXTURES = Path(__file__).parent.parent / "examples"


class TestLoadYaml:
    def test_loads_valid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "test.yaml"
        f.write_text("system:\n  name: test\n  type: llm-agent\n", encoding="utf-8")
        data = load_yaml(f)
        assert data["system"]["name"] == "test"

    def test_raises_on_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError_):
            load_yaml(tmp_path / "nonexistent.yaml")

    def test_raises_on_invalid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("{{invalid: yaml: [", encoding="utf-8")
        with pytest.raises(YAMLParseError):
            load_yaml(f)

    def test_raises_on_non_mapping(self, tmp_path: Path) -> None:
        f = tmp_path / "list.yaml"
        f.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(YAMLParseError, match="mapping"):
            load_yaml(f)


class TestValidateSpec:
    def test_valid_minimal_spec(self) -> None:
        data = {
            "system": {"name": "test", "type": "llm-agent"},
            "model": {"provider": "openai"},
        }
        spec = validate_spec(data)
        assert spec.system.name == "test"
        assert spec.exposure.internet_facing is False
        assert spec.tools == []

    def test_invalid_system_type(self) -> None:
        data = {
            "system": {"name": "test", "type": "invalid-type"},
            "model": {"provider": "openai"},
        }
        with pytest.raises(SchemaValidationError):
            validate_spec(data)

    def test_missing_required_system(self) -> None:
        data = {"model": {"provider": "openai"}}
        with pytest.raises(SchemaValidationError):
            validate_spec(data)

    def test_missing_required_model(self) -> None:
        data = {"system": {"name": "test", "type": "llm-agent"}}
        with pytest.raises(SchemaValidationError):
            validate_spec(data)

    def test_invalid_sensitivity(self) -> None:
        data = {
            "system": {"name": "test", "type": "llm-agent"},
            "model": {"provider": "openai"},
            "data": {"sensitivity": ["top_secret"]},
        }
        with pytest.raises(SchemaValidationError):
            validate_spec(data)


class TestParseSpec:
    def test_parses_simple_agent_example(self) -> None:
        spec = parse_spec(FIXTURES / "simple_agent.yaml")
        assert spec.system.name == "customer-support-agent"
        assert spec.exposure.internet_facing is True
        assert len(spec.tools) == 2
        assert spec.retrieval.enabled is True
        assert spec.memory.enabled is True
        assert len(spec.secrets) == 2
