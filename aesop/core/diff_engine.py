"""Architecture diff engine.

Compares two architecture specs, re-runs analysis on both,
and produces a structured summary of security posture changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aesop.core.analyzer import analyze_spec
from aesop.domain.findings import AnalysisResult, Finding
from aesop.domain.models import ArchitectureSpec


@dataclass
class ComponentChanges:
    """Tracks added/removed items across spec sections."""

    tools_added: list[str] = field(default_factory=list)
    tools_removed: list[str] = field(default_factory=list)
    retrieval_added: list[str] = field(default_factory=list)
    retrieval_removed: list[str] = field(default_factory=list)
    memory_added: list[str] = field(default_factory=list)
    memory_removed: list[str] = field(default_factory=list)
    secrets_added: list[str] = field(default_factory=list)
    secrets_removed: list[str] = field(default_factory=list)
    boundaries_added: list[str] = field(default_factory=list)
    boundaries_removed: list[str] = field(default_factory=list)
    exposure_changes: list[str] = field(default_factory=list)
    model_changes: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(
            getattr(self, f.name)
            for f in self.__dataclass_fields__.values()
        )


@dataclass
class DiffResult:
    """Complete diff output between two spec versions."""

    old_name: str
    new_name: str
    component_changes: ComponentChanges
    old_result: AnalysisResult
    new_result: AnalysisResult
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    severity_changes: list[str] = field(default_factory=list)


def diff_specs(old: ArchitectureSpec, new: ArchitectureSpec) -> DiffResult:
    """Compare two architecture specs and their threat analysis results."""
    changes = _compare_components(old, new)
    old_result = analyze_spec(old)
    new_result = analyze_spec(new)

    old_ids = {f.id for f in old_result.findings}
    new_ids = {f.id for f in new_result.findings}

    new_findings = [f for f in new_result.findings if f.id not in old_ids]
    resolved_findings = [f for f in old_result.findings if f.id not in new_ids]

    severity_changes = _detect_severity_changes(old_result, new_result)

    return DiffResult(
        old_name=old.system.name,
        new_name=new.system.name,
        component_changes=changes,
        old_result=old_result,
        new_result=new_result,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        severity_changes=severity_changes,
    )


def _compare_components(old: ArchitectureSpec, new: ArchitectureSpec) -> ComponentChanges:
    changes = ComponentChanges()

    # Tools
    old_tools = {t.name for t in old.tools}
    new_tools = {t.name for t in new.tools}
    changes.tools_added = sorted(new_tools - old_tools)
    changes.tools_removed = sorted(old_tools - new_tools)

    # Retrieval sources
    old_ret = {s.name for s in old.retrieval.sources}
    new_ret = {s.name for s in new.retrieval.sources}
    changes.retrieval_added = sorted(new_ret - old_ret)
    changes.retrieval_removed = sorted(old_ret - new_ret)

    # Memory stores
    old_mem = {m.type for m in old.memory.stores}
    new_mem = {m.type for m in new.memory.stores}
    changes.memory_added = sorted(new_mem - old_mem)
    changes.memory_removed = sorted(old_mem - new_mem)

    # Secrets
    old_sec = {s.name for s in old.secrets}
    new_sec = {s.name for s in new.secrets}
    changes.secrets_added = sorted(new_sec - old_sec)
    changes.secrets_removed = sorted(old_sec - new_sec)

    # Trust boundaries
    old_bounds = set(old.trust_boundaries)
    new_bounds = set(new.trust_boundaries)
    changes.boundaries_added = sorted(new_bounds - old_bounds)
    changes.boundaries_removed = sorted(old_bounds - new_bounds)

    # Exposure
    if old.exposure.internet_facing != new.exposure.internet_facing:
        direction = "enabled" if new.exposure.internet_facing else "disabled"
        changes.exposure_changes.append(f"Internet exposure {direction}")

    old_users = set(old.exposure.users)
    new_users = set(new.exposure.users)
    for u in sorted(new_users - old_users):
        changes.exposure_changes.append(f"User group added: {u}")
    for u in sorted(old_users - new_users):
        changes.exposure_changes.append(f"User group removed: {u}")

    # Model
    if old.model.provider != new.model.provider:
        changes.model_changes.append(
            f"Provider changed: {old.model.provider} → {new.model.provider}"
        )
    if old.model.hosted != new.model.hosted:
        changes.model_changes.append(
            f"Hosting changed: {old.model.hosted} → {new.model.hosted}"
        )

    return changes


def _detect_severity_changes(
    old_result: AnalysisResult,
    new_result: AnalysisResult,
) -> list[str]:
    changes: list[str] = []
    old_summary = old_result.severity_summary
    new_summary = new_result.severity_summary

    for level in ("critical", "high", "medium", "low"):
        old_val = getattr(old_summary, level)
        new_val = getattr(new_summary, level)
        if new_val > old_val:
            changes.append(f"{level.upper()} findings increased: {old_val} → {new_val}")
        elif new_val < old_val:
            changes.append(f"{level.upper()} findings decreased: {old_val} → {new_val}")

    return changes
