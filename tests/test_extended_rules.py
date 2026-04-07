"""Tests for the extended rule set (rules 7-12)."""

from aesop.core.analyzer import analyze_spec
from aesop.core.parser import validate_spec
from aesop.domain.enums import FindingCategory, Severity


def _make_spec(**overrides: object) -> dict:
    base: dict = {
        "system": {"name": "test-sys", "type": "llm-agent"},
        "model": {"provider": "openai", "hosted": "external_api"},
    }
    base.update(overrides)
    return base


def _analyze(overrides: dict) -> list:
    spec = validate_spec(_make_spec(**overrides))
    return analyze_spec(spec).findings


def _by_cat(findings: list, cat: FindingCategory) -> list:
    return [f for f in findings if f.category == cat]


# ── Insecure Output Handling ──────────────────────────────────────


class TestInsecureOutput:
    def test_triggers_on_write_tools(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "jira", "permissions": ["write_comments"],
                 "trust_boundary": "external_service"},
            ],
        })
        io = _by_cat(findings, FindingCategory.INSECURE_OUTPUT)
        assert len(io) >= 1

    def test_no_trigger_without_tools(self) -> None:
        findings = _analyze({})
        io = _by_cat(findings, FindingCategory.INSECURE_OUTPUT)
        assert len(io) == 0

    def test_cross_boundary_finding(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "api", "permissions": ["read"],
                 "trust_boundary": "external_service"},
            ],
        })
        io = _by_cat(findings, FindingCategory.INSECURE_OUTPUT)
        cross = [f for f in io if "Boundary" in f.title]
        assert len(cross) >= 1


# ── Excessive Agency ──────────────────────────────────────────────


class TestExcessiveAgency:
    def test_triggers_on_multiple_write_tools(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "jira", "permissions": ["write_comments"],
                 "trust_boundary": "external_service"},
                {"name": "github", "permissions": ["write_repo"],
                 "trust_boundary": "external_service"},
            ],
        })
        ea = _by_cat(findings, FindingCategory.EXCESSIVE_AGENCY)
        assert len(ea) >= 1

    def test_critical_with_three_plus_write_tools(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "jira", "permissions": ["write"], "trust_boundary": "ext"},
                {"name": "github", "permissions": ["create_pr"], "trust_boundary": "ext"},
                {"name": "slack", "permissions": ["write_message"], "trust_boundary": "ext"},
            ],
        })
        ea = _by_cat(findings, FindingCategory.EXCESSIVE_AGENCY)
        critical = [f for f in ea if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_no_trigger_single_write_tool(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "jira", "permissions": ["write_comments"]},
            ],
        })
        ea = _by_cat(findings, FindingCategory.EXCESSIVE_AGENCY)
        autonomy = [f for f in ea if "Autonomy" in f.title]
        assert len(autonomy) == 0

    def test_no_trigger_read_only(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "search", "permissions": ["read"]},
                {"name": "docs", "permissions": ["read"]},
            ],
        })
        ea = _by_cat(findings, FindingCategory.EXCESSIVE_AGENCY)
        assert len(ea) == 0


# ── Cross-Context Isolation ───────────────────────────────────────


class TestCrossContext:
    def test_triggers_shared_memory_external_users(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": True, "users": ["external_customers"]},
            "memory": {"enabled": True, "stores": [{"type": "conversation_memory"}]},
        })
        cc = _by_cat(findings, FindingCategory.CROSS_CONTEXT)
        assert len(cc) >= 1

    def test_triggers_shared_retrieval_external_users(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": True, "users": ["external_customers"]},
            "retrieval": {
                "enabled": True,
                "sources": [{"name": "kb", "sensitivity": "pii"}],
            },
        })
        cc = _by_cat(findings, FindingCategory.CROSS_CONTEXT)
        assert len(cc) >= 1

    def test_no_trigger_internal_only(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": False, "users": ["ops_team"]},
            "memory": {"enabled": True, "stores": [{"type": "ctx"}]},
        })
        cc = _by_cat(findings, FindingCategory.CROSS_CONTEXT)
        assert len(cc) == 0


# ── Logging Leakage ──────────────────────────────────────────────


class TestLoggingLeakage:
    def test_triggers_with_secrets(self) -> None:
        findings = _analyze({
            "secrets": [{"name": "api_key", "scope": "backend"}],
        })
        ll = _by_cat(findings, FindingCategory.LOGGING_LEAKAGE)
        assert len(ll) >= 1

    def test_triggers_with_confidential_retrieval(self) -> None:
        findings = _analyze({
            "retrieval": {
                "enabled": True,
                "sources": [{"name": "docs", "sensitivity": "confidential"}],
            },
        })
        ll = _by_cat(findings, FindingCategory.LOGGING_LEAKAGE)
        assert len(ll) >= 1

    def test_no_trigger_no_secrets_no_retrieval(self) -> None:
        findings = _analyze({})
        ll = _by_cat(findings, FindingCategory.LOGGING_LEAKAGE)
        assert len(ll) == 0


# ── DoS / Cost Abuse ─────────────────────────────────────────────


class TestDosCostAbuse:
    def test_triggers_public_with_external_model(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": True},
        })
        dc = _by_cat(findings, FindingCategory.DOS_COST_ABUSE)
        assert len(dc) >= 1

    def test_higher_severity_with_tools_and_retrieval(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": True},
            "tools": [{"name": "jira", "permissions": ["read"]}],
            "retrieval": {"enabled": True, "sources": [{"name": "kb"}]},
        })
        dc = _by_cat(findings, FindingCategory.DOS_COST_ABUSE)
        high = [f for f in dc if f.severity >= Severity.HIGH]
        assert len(high) >= 1

    def test_no_trigger_internal(self) -> None:
        findings = _analyze({
            "exposure": {"internet_facing": False, "users": ["ops"]},
        })
        dc = _by_cat(findings, FindingCategory.DOS_COST_ABUSE)
        assert len(dc) == 0


# ── Missing Approval ─────────────────────────────────────────────


class TestMissingApproval:
    def test_triggers_on_write_tools(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "jira", "permissions": ["write_comments"]},
            ],
        })
        mg = _by_cat(findings, FindingCategory.MISSING_APPROVAL)
        assert len(mg) >= 1

    def test_privileged_with_secrets(self) -> None:
        findings = _analyze({
            "tools": [
                {"name": "admin", "permissions": ["admin", "execute"],
                 "trust_boundary": "external_service"},
            ],
            "secrets": [{"name": "admin_key", "scope": "tool_connector"}],
        })
        mg = _by_cat(findings, FindingCategory.MISSING_APPROVAL)
        assert len(mg) >= 2  # write tool + privileged integration

    def test_no_trigger_read_only(self) -> None:
        findings = _analyze({
            "tools": [{"name": "search", "permissions": ["read"]}],
        })
        mg = _by_cat(findings, FindingCategory.MISSING_APPROVAL)
        assert len(mg) == 0
