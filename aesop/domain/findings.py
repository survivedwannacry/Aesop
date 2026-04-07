"""Domain models for threat findings and analysis results."""

from __future__ import annotations

from pydantic import BaseModel, Field

from aesop.domain.enums import Confidence, FindingCategory, Severity


class AtlasTechniqueRef(BaseModel):
    """Reference to a MITRE ATLAS technique."""

    technique_id: str
    technique_name: str
    tactic: str = ""


class Finding(BaseModel):
    """A single threat-model finding."""

    id: str = Field(..., description="Unique finding identifier")
    rule_id: str = Field(..., description="Rule that produced this finding")
    title: str
    summary: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    affected_components: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    attack_path: str = ""
    atlas_techniques: list[AtlasTechniqueRef] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


class SeveritySummary(BaseModel):
    """Aggregate severity counts."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class AnalysisResult(BaseModel):
    """Complete output of a threat-model analysis run."""

    system_name: str
    system_type: str
    description: str = ""
    findings: list[Finding] = Field(default_factory=list)
    severity_summary: SeveritySummary = Field(default_factory=SeveritySummary)
    atlas_techniques_used: list[AtlasTechniqueRef] = Field(default_factory=list)
    diagram_mermaid: str = ""

    @classmethod
    def build(
        cls,
        system_name: str,
        system_type: str,
        description: str,
        findings: list[Finding],
        diagram: str = "",
    ) -> "AnalysisResult":
        """Construct an AnalysisResult with computed summaries."""
        summary = SeveritySummary(
            critical=sum(1 for f in findings if f.severity == Severity.CRITICAL),
            high=sum(1 for f in findings if f.severity == Severity.HIGH),
            medium=sum(1 for f in findings if f.severity == Severity.MEDIUM),
            low=sum(1 for f in findings if f.severity == Severity.LOW),
        )
        # Deduplicate ATLAS techniques across findings
        seen: set[str] = set()
        techniques: list[AtlasTechniqueRef] = []
        for f in findings:
            for t in f.atlas_techniques:
                if t.technique_id not in seen:
                    seen.add(t.technique_id)
                    techniques.append(t)

        return cls(
            system_name=system_name,
            system_type=system_type,
            description=description,
            findings=findings,
            severity_summary=summary,
            atlas_techniques_used=techniques,
            diagram_mermaid=diagram,
        )
