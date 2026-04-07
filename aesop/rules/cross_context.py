"""Rule: Cross-context and cross-tenant isolation risk."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class CrossContextRule(BaseRule):
    rule_id = "AESOP-CC"
    name = "Cross-Context / Cross-Tenant Isolation Risk"
    description = (
        "Detects when shared memory, retrieval, or context could allow "
        "one user or session to influence or access another's data."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        if not system.has_external_users:
            return []

        findings: list[Finding] = []

        # Shared memory without isolation
        if system.has_memory and system.has_external_users:
            store_types = [m.store_type for m in system.memory_stores]
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Cross-Session Memory Contamination Risk",
                summary=(
                    "Multiple users share memory stores with no declared "
                    "isolation, risking cross-session data bleed."
                ),
                description=(
                    "When external users share the system and memory is "
                    "enabled without per-user or per-session namespacing, "
                    "data written by one user may influence or be visible "
                    "to another user's session."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.CROSS_CONTEXT,
                affected_components=store_types,
                evidence=[
                    f"Memory stores: {', '.join(store_types)}",
                    "External users share the system",
                    "No per-user memory isolation declared",
                ],
                attack_path=(
                    "User A → writes to shared memory → User B session "
                    "loads contaminated context → data bleed or manipulation"
                ),
                mitigations=[
                    "Implement per-user or per-session memory namespaces",
                    "Enforce tenant isolation at the memory layer",
                    "Audit cross-user memory access patterns",
                ],
            ))

        # Shared retrieval with sensitive sources
        if system.has_retrieval and system.has_confidential_retrieval:
            names = system.retrieval_source_names
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Cross-Tenant Retrieval Exposure",
                summary=(
                    "Sensitive retrieval sources are shared across user "
                    "sessions without declared access segmentation."
                ),
                description=(
                    "When multiple users query the same retrieval sources "
                    "that contain confidential or PII data, results intended "
                    "for one user's context can surface in another's response."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.CROSS_CONTEXT,
                affected_components=names,
                evidence=[
                    f"Shared retrieval sources: {', '.join(names)}",
                    "Sources contain confidential or PII data",
                    "Multiple external users access the system",
                ],
                attack_path=(
                    "User A's query → retrieves User B's sensitive data → "
                    "LLM includes in response → cross-tenant disclosure"
                ),
                mitigations=[
                    "Implement per-user retrieval access controls",
                    "Segment retrieval indices by tenant or role",
                    "Filter retrieval results based on user permissions",
                ],
            ))

        return findings


register(CrossContextRule())
