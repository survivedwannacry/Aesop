"""Tests for the threat analysis engine and individual rules."""

from pathlib import Path

from aesop.core.analyzer import analyze_file, analyze_spec
from aesop.core.parser import validate_spec
from aesop.domain.enums import FindingCategory, Severity


FIXTURES = Path(__file__).parent.parent / "examples"


def _make_spec(**overrides: object) -> dict:
    base: dict = {
        "system": {"name": "test-sys", "type": "llm-agent"},
        "model": {"provider": "openai", "hosted": "external_api"},
    }
    base.update(overrides)
    return base


def _analyze(overrides: dict) -> list:
    spec = validate_spec(_make_spec(**overrides))
    result = analyze_spec(spec)
    return result.findings


def _findings_by_category(findings: list, category: FindingCategory) -> list:
    return [f for f in findings if f.category == category]


# ── Prompt Injection ──────────────────────────────────────────────


class TestPromptInjection:
    def test_triggers_on_internet_facing(self) -> None:
        findings = _analyze({"exposure": {"internet_facing": True}})
        pi = _findings_by_category(findings, FindingCategory.PROMPT_INJECTION)
        assert len(pi) >= 1

    def test_critical_with_tools_and_retrieval(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": True},
            "tools": [{"name": "jira", "permissions": ["write_comments"]}],
            "retrieval": {"enabled": True, "sources": [{"name": "kb"}]},
        })
        pi = _findings_by_category(findings, FindingCategory.PROMPT_INJECTION)
        critical = [f for f in pi if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_no_trigger_internal_only(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": False, "users": ["ops_team"]},
        })
        pi = _findings_by_category(findings, FindingCategory.PROMPT_INJECTION)
        assert len(pi) == 0


# ── Tool Abuse ────────────────────────────────────────────────────


class TestToolAbuse:
    def test_triggers_on_write_tools(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "jira", "permissions": ["write_comments"],
                 "trust_boundary": "external_service"},
            ],
        })
        ta = _findings_by_category(findings, FindingCategory.TOOL_ABUSE)
        assert len(ta) >= 1

    def test_no_trigger_without_tools(self) -> None:
        findings = _analyze({})
        ta = _findings_by_category(findings, FindingCategory.TOOL_ABUSE)
        assert len(ta) == 0

    def test_privileged_tool_is_critical(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "infra", "permissions": ["admin", "execute"],
                 "trust_boundary": "external_service"},
            ],
        })
        ta = _findings_by_category(findings, FindingCategory.TOOL_ABUSE)
        critical = [f for f in ta if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


# ── Retrieval Exfiltration ────────────────────────────────────────


class TestRetrievalExfiltration:
    def test_triggers_on_confidential_retrieval(self) -> None:
        findings = _analyze({
            "retrieval": {
                "enabled": True,
                "sources": [{"name": "docs", "sensitivity": "confidential"}],
            },
        })
        re_ = _findings_by_category(findings, FindingCategory.RETRIEVAL_EXFILTRATION)
        assert len(re_) >= 1

    def test_no_trigger_retrieval_disabled(self) -> None:
        findings = _analyze({
            "retrieval": {"enabled": False},
        })
        re_ = _findings_by_category(findings, FindingCategory.RETRIEVAL_EXFILTRATION)
        assert len(re_) == 0

    def test_pii_retrieval_is_critical(self) -> None:
        findings = _analyze({
            "retrieval": {
                "enabled": True,
                "sources": [{"name": "users", "sensitivity": "pii"}],
            },
        })
        re_ = _findings_by_category(findings, FindingCategory.RETRIEVAL_EXFILTRATION)
        critical = [f for f in re_ if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


# ── Secret Exposure ───────────────────────────────────────────────


class TestSecretExposure:
    def test_triggers_with_secrets(self) -> None:
        findings = _analyze({
            "secrets": [{"name": "api_key", "scope": "backend"}],
        })
        se = _findings_by_category(findings, FindingCategory.SECRET_EXPOSURE)
        assert len(se) >= 1

    def test_tool_connector_secret_finding(self) -> None:
        findings = _analyze({
            "secrets": [{"name": "gh_token", "scope": "tool_connector"}],
            "tools": [{"name": "github", "permissions": ["read"]}],
        })
        se = _findings_by_category(findings, FindingCategory.SECRET_EXPOSURE)
        assert len(se) >= 2  # General + tool connector


# ── Memory Abuse ──────────────────────────────────────────────────


class TestMemoryAbuse:
    def test_triggers_with_memory_enabled(self) -> None:
        findings = _analyze({
            "memory": {
                "enabled": True,
                "stores": [{"type": "conversation_memory"}],
            },
        })
        ma = _findings_by_category(findings, FindingCategory.MEMORY_ABUSE)
        assert len(ma) >= 1

    def test_no_trigger_without_memory(self) -> None:
        findings = _analyze({})
        ma = _findings_by_category(findings, FindingCategory.MEMORY_ABUSE)
        assert len(ma) == 0

    def test_external_users_increases_findings(self) -> None:
        internal = _analyze({
            "exposure": {"internet_facing": False, "users": ["ops"]},
            "memory": {"enabled": True, "stores": [{"type": "ctx"}]},
        })
        external = _analyze({
            "exposure": {"internet_facing": True, "users": ["external_customers"]},
            "memory": {"enabled": True, "stores": [{"type": "ctx"}]},
        })
        ma_int = _findings_by_category(internal, FindingCategory.MEMORY_ABUSE)
        ma_ext = _findings_by_category(external, FindingCategory.MEMORY_ABUSE)
        assert len(ma_ext) >= len(ma_int)


# ── Supply Chain ──────────────────────────────────────────────────


class TestSupplyChain:
    def test_triggers_on_external_provider(self) -> None:
        findings = _analyze({})
        sc = _findings_by_category(findings, FindingCategory.SUPPLY_CHAIN)
        assert len(sc) >= 1  # External model provider

    def test_trust_boundary_complexity(self) -> None:
        findings = _analyze({
            "trust_boundaries": ["a", "b", "c", "d", "e"],
        })
        sc = _findings_by_category(findings, FindingCategory.SUPPLY_CHAIN)
        complexity = [f for f in sc if "Complex" in f.title]
        assert len(complexity) == 1


# ── Integration ───────────────────────────────────────────────────


class TestFullAnalysis:
    def test_simple_agent_example(self) -> None:
        result = analyze_file(FIXTURES / "simple_agent.yaml")
        assert result.system_name == "customer-support-agent"
        assert result.severity_summary.total > 0
        # Should trigger multiple categories
        categories = {f.category for f in result.findings}
        assert FindingCategory.PROMPT_INJECTION in categories
        assert FindingCategory.TOOL_ABUSE in categories
        assert FindingCategory.RETRIEVAL_EXFILTRATION in categories

    def test_severity_summary_correct(self) -> None:
        result = analyze_file(FIXTURES / "simple_agent.yaml")
        total = result.severity_summary.total
        assert total == len(result.findings)
