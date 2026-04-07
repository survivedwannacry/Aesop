"""Tests for severity scoring."""

from aesop.core.scoring import _assess_system_risk, _adjust_severity, score_findings
from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import (
    NormalizedSystem,
    NormalizedTool,
    NormalizedRetrievalSource,
    NormalizedMemoryStore,
)
from aesop.domain.enums import DataSensitivity


def _minimal_system(**kwargs: object) -> NormalizedSystem:
    defaults = dict(
        name="test",
        system_type="llm-agent",
        description="",
        internet_facing=False,
        has_external_users=False,
    )
    defaults.update(kwargs)
    return NormalizedSystem(**defaults)  # type: ignore[arg-type]


def _dummy_finding(severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        id="TEST-001",
        rule_id="TEST",
        title="Test Finding",
        summary="A test",
        description="A test finding",
        severity=severity,
        confidence=Confidence.MEDIUM,
        category=FindingCategory.PROMPT_INJECTION,
    )


class TestSystemRisk:
    def test_minimal_system_low_risk(self) -> None:
        system = _minimal_system()
        assert _assess_system_risk(system) == 0

    def test_internet_facing_adds_two(self) -> None:
        system = _minimal_system(internet_facing=True)
        assert _assess_system_risk(system) >= 2

    def test_high_risk_system(self) -> None:
        system = _minimal_system(
            internet_facing=True,
            has_external_users=True,
            has_retrieval=True,
            has_memory=True,
            data_sensitivities=(DataSensitivity.PII, DataSensitivity.CONFIDENTIAL),
            tools=(
                NormalizedTool(
                    name="admin",
                    permissions=("admin", "execute"),
                    trust_boundary="external",
                ),
            ),
            trust_boundaries=("a", "b", "c", "d"),
        )
        score = _assess_system_risk(system)
        assert score >= 7


class TestSeverityAdjustment:
    def test_no_upgrade_low_risk(self) -> None:
        assert _adjust_severity(Severity.MEDIUM, risk_level=3) == Severity.MEDIUM

    def test_medium_to_high_at_risk_7(self) -> None:
        assert _adjust_severity(Severity.MEDIUM, risk_level=7) == Severity.HIGH

    def test_high_to_critical_at_risk_8(self) -> None:
        assert _adjust_severity(Severity.HIGH, risk_level=8) == Severity.CRITICAL

    def test_low_not_upgraded(self) -> None:
        assert _adjust_severity(Severity.LOW, risk_level=10) == Severity.LOW


class TestScoreFindings:
    def test_scoring_preserves_finding_count(self) -> None:
        findings = [_dummy_finding(), _dummy_finding(Severity.LOW)]
        system = _minimal_system()
        scored = score_findings(findings, system)
        assert len(scored) == 2

    def test_scoring_upgrades_in_high_risk(self) -> None:
        findings = [_dummy_finding(Severity.MEDIUM)]
        system = _minimal_system(
            internet_facing=True,
            has_external_users=True,
            has_retrieval=True,
            has_memory=True,
            data_sensitivities=(DataSensitivity.PII,),
            tools=(
                NormalizedTool(name="x", permissions=("write",), trust_boundary="ext"),
            ),
            trust_boundaries=("a", "b", "c", "d"),
        )
        scored = score_findings(findings, system)
        assert scored[0].severity == Severity.HIGH
