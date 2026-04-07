"""Tests for the normalization layer."""

from aesop.core.normalizer import normalize
from aesop.core.parser import validate_spec
from aesop.domain.enums import DataSensitivity


def _make_spec(**overrides: object) -> dict:
    base: dict = {
        "system": {"name": "test-sys", "type": "llm-agent"},
        "model": {"provider": "openai"},
    }
    base.update(overrides)
    return base


class TestNormalization:
    def test_basic_fields(self) -> None:
        spec = validate_spec(_make_spec())
        ns = normalize(spec)
        assert ns.name == "test-sys"
        assert ns.system_type == "llm-agent"
        assert ns.internet_facing is False
        assert ns.has_tools is False
        assert ns.has_retrieval is False
        assert ns.has_memory is False

    def test_internet_facing_implies_external_users(self) -> None:
        spec = validate_spec(
            _make_spec(exposure={"internet_facing": True, "users": []})
        )
        ns = normalize(spec)
        assert ns.internet_facing is True
        assert ns.has_external_users is True

    def test_external_user_detection(self) -> None:
        spec = validate_spec(
            _make_spec(
                exposure={
                    "internet_facing": False,
                    "users": ["external_customers"],
                }
            )
        )
        ns = normalize(spec)
        assert ns.has_external_users is True

    def test_internal_only_users(self) -> None:
        spec = validate_spec(
            _make_spec(
                exposure={
                    "internet_facing": False,
                    "users": ["internal_admin", "ops_team"],
                }
            )
        )
        ns = normalize(spec)
        assert ns.has_external_users is False

    def test_tool_normalization(self) -> None:
        spec = validate_spec(
            _make_spec(
                tools=[
                    {
                        "name": "jira",
                        "permissions": ["write_comments", "read_tickets"],
                        "trust_boundary": "external_service",
                    }
                ]
            )
        )
        ns = normalize(spec)
        assert ns.has_tools is True
        assert ns.has_write_tools is True
        assert ns.has_cross_boundary_tools is True
        assert ns.tools[0].has_write is True

    def test_read_only_tool(self) -> None:
        spec = validate_spec(
            _make_spec(
                tools=[{"name": "search", "permissions": ["read_docs"]}]
            )
        )
        ns = normalize(spec)
        assert ns.has_write_tools is False

    def test_retrieval_sensitivity(self) -> None:
        spec = validate_spec(
            _make_spec(
                retrieval={
                    "enabled": True,
                    "sources": [{"name": "kb", "sensitivity": "confidential"}],
                }
            )
        )
        ns = normalize(spec)
        assert ns.has_retrieval is True
        assert ns.has_confidential_retrieval is True

    def test_model_hosted_externally(self) -> None:
        spec = validate_spec(
            _make_spec(model={"provider": "openai", "hosted": "external_api"})
        )
        ns = normalize(spec)
        assert ns.model_hosted_externally is True
        assert ns.has_external_providers is True

    def test_model_hosted_internally(self) -> None:
        spec = validate_spec(
            _make_spec(model={"provider": "local", "hosted": "on_premise"})
        )
        ns = normalize(spec)
        assert ns.model_hosted_externally is False

    def test_data_sensitivity_flags(self) -> None:
        spec = validate_spec(
            _make_spec(data={"sensitivity": ["pii", "confidential"]})
        )
        ns = normalize(spec)
        assert ns.has_sensitive_data is True
        assert ns.has_pii is True

    def test_secrets_normalization(self) -> None:
        spec = validate_spec(
            _make_spec(
                secrets=[
                    {"name": "api_key", "scope": "backend"},
                    {"name": "db_pass", "scope": "tool_connector"},
                ]
            )
        )
        ns = normalize(spec)
        assert ns.has_secrets is True
        assert len(ns.secrets) == 2
