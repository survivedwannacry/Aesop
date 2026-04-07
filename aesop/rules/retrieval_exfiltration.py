"""Rule: Retrieval exfiltration risk detection."""

from __future__ import annotations

from aesop.domain.enums import Confidence, DataSensitivity, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class RetrievalExfiltrationRule(BaseRule):
    rule_id = "AESOP-RE"
    name = "Retrieval Exfiltration Risk"
    description = (
        "Detects risks of sensitive data leakage through "
        "retrieval-augmented generation pathways."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        if not system.has_retrieval:
            return []

        findings: list[Finding] = []
        sensitive_sources = [
            s for s in system.retrieval_sources
            if s.sensitivity in (
                DataSensitivity.CONFIDENTIAL,
                DataSensitivity.PII,
                DataSensitivity.RESTRICTED,
            )
        ]

        # Sensitive knowledge disclosure
        if sensitive_sources:
            names = [s.name for s in sensitive_sources]
            has_pii_source = any(
                s.sensitivity == DataSensitivity.PII for s in sensitive_sources
            )
            severity = Severity.CRITICAL if has_pii_source else Severity.HIGH

            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Sensitive Knowledge Disclosure via Retrieval",
                summary=(
                    "Retrieval sources contain sensitive data that could be "
                    "disclosed through LLM-generated responses."
                ),
                description=(
                    "The system retrieves from sources marked as confidential, "
                    "PII-bearing, or restricted. Retrieved content is injected "
                    "into the LLM context and may appear in responses to users "
                    "who should not have access to that data."
                ),
                severity=severity,
                confidence=Confidence.HIGH,
                category=FindingCategory.RETRIEVAL_EXFILTRATION,
                affected_components=names,
                evidence=[
                    f"Sensitive retrieval sources: {', '.join(names)}",
                    *[f"{s.name}: sensitivity={s.sensitivity.value}" for s in sensitive_sources],
                ],
                attack_path=(
                    "User query → retrieval of sensitive documents → "
                    "LLM incorporates content → sensitive data in response"
                ),
                mitigations=[
                    "Implement document-level access controls in retrieval",
                    "Filter retrieved content based on user permissions",
                    "Redact PII before injecting into LLM context",
                    "Apply output filters to detect sensitive data leakage",
                ],
            ))

        # Exfiltration via crafted prompts (requires external users)
        if sensitive_sources and (system.internet_facing or system.has_external_users):
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Data Exfiltration Through Crafted Prompts",
                summary=(
                    "External users could craft prompts designed to extract "
                    "sensitive data from retrieval sources."
                ),
                description=(
                    "When the system is accessible to external or untrusted "
                    "users and retrieves from sensitive sources, attackers can "
                    "systematically extract knowledge base contents through "
                    "carefully crafted queries."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.RETRIEVAL_EXFILTRATION,
                affected_components=system.retrieval_source_names,
                evidence=[
                    "System has external/untrusted users",
                    f"Sensitive sources: {', '.join(s.name for s in sensitive_sources)}",
                ],
                attack_path=(
                    "Attacker → targeted queries → retrieval returns sensitive "
                    "docs → LLM summarizes → data exfiltrated"
                ),
                mitigations=[
                    "Rate-limit retrieval queries per user",
                    "Detect and block systematic extraction patterns",
                    "Limit retrieved context size per query",
                    "Log and audit retrieval access patterns",
                ],
            ))

        # Cross-context leakage (multiple sources)
        if len(system.retrieval_sources) > 1:
            findings.append(Finding(
                id=self._make_id("003"),
                rule_id=self.rule_id,
                title="Cross-Context Knowledge Leakage",
                summary=(
                    "Multiple retrieval sources may allow information from "
                    "one context to leak into another."
                ),
                description=(
                    "When the system retrieves from multiple sources with "
                    "different sensitivity levels, content from a higher-"
                    "sensitivity source could be mixed with responses that "
                    "reference lower-sensitivity data."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.RETRIEVAL_EXFILTRATION,
                affected_components=system.retrieval_source_names,
                evidence=[
                    f"Multiple retrieval sources: {', '.join(system.retrieval_source_names)}",
                ],
                attack_path=(
                    "Query spans multiple sources → mixed-sensitivity content "
                    "in LLM context → unintended disclosure"
                ),
                mitigations=[
                    "Isolate retrieval pipelines per sensitivity level",
                    "Label retrieved content with source metadata",
                    "Apply per-source access controls",
                ],
            ))

        return findings


register(RetrievalExfiltrationRule())
