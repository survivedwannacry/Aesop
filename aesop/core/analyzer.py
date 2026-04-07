"""Threat analysis orchestrator.

Coordinates parsing, normalization, rule execution, scoring,
and ATLAS mapping into a complete AnalysisResult.
"""

from __future__ import annotations

from pathlib import Path

from aesop.atlas.mapper import enrich_findings
from aesop.core.normalizer import normalize
from aesop.core.parser import parse_spec
from aesop.core.scoring import score_findings
from aesop.domain.findings import AnalysisResult, Finding
from aesop.domain.models import ArchitectureSpec
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.registry import run_all


def analyze_spec(spec: ArchitectureSpec) -> AnalysisResult:
    """Run full threat analysis on a validated architecture spec."""
    normalized = normalize(spec)
    findings = run_all(normalized)
    findings = score_findings(findings, normalized)
    findings = enrich_findings(findings)
    return AnalysisResult.build(
        system_name=spec.system.name,
        system_type=spec.system.type.value,
        description=spec.system.description,
        findings=findings,
    )


def analyze_file(path: Path) -> AnalysisResult:
    """Parse a YAML file and run full threat analysis."""
    spec = parse_spec(path)
    return analyze_spec(spec)


def get_normalized(spec: ArchitectureSpec) -> NormalizedSystem:
    """Normalize a spec (exposed for testing and reporting)."""
    return normalize(spec)
