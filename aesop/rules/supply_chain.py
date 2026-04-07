"""Rule: Supply chain and external dependency risk detection."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class SupplyChainRule(BaseRule):
    rule_id = "AESOP-SC"
    name = "Supply Chain / External Dependency Risk"
    description = (
        "Detects risks from reliance on external model providers, "
        "third-party tools, and service boundaries."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        findings: list[Finding] = []

        # External model provider dependency
        if system.has_external_providers:
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="External Model Provider Dependency",
                summary=(
                    "The system depends on an external LLM provider, "
                    "introducing supply chain risk."
                ),
                description=(
                    "The LLM is hosted by an external provider. A compromise, "
                    "outage, or policy change at the provider could affect "
                    "system availability, data confidentiality, or behavior. "
                    "Data sent to the provider leaves the trust boundary."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=FindingCategory.SUPPLY_CHAIN,
                affected_components=[f"model:{system.model_provider}"],
                evidence=[
                    f"Model provider: {system.model_provider}",
                    f"Model family: {system.model_family}",
                    f"Hosted: externally",
                ],
                attack_path=(
                    "User data → sent to external provider → provider "
                    "compromise or policy change → data exposure or "
                    "behavior alteration"
                ),
                mitigations=[
                    "Review provider data handling and retention policies",
                    "Implement fallback model providers where feasible",
                    "Minimize sensitive data sent to the provider",
                    "Monitor provider status and incident reports",
                ],
            ))

        # Trust boundary expansion via external tools
        external_tools = [t for t in system.tools if t.crosses_boundary]
        if external_tools:
            names = [t.name for t in external_tools]
            severity = Severity.HIGH if system.has_write_tools else Severity.MEDIUM

            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Trust Boundary Expansion via External Tools",
                summary=(
                    "Each external tool integration extends the system's "
                    "trust boundary and attack surface."
                ),
                description=(
                    "External tool integrations create transitive trust "
                    "relationships. A compromise of any connected service "
                    "could propagate to the agent and vice versa. Each "
                    "integration adds credential management burden and "
                    "potential lateral movement paths."
                ),
                severity=severity,
                confidence=Confidence.HIGH,
                category=FindingCategory.SUPPLY_CHAIN,
                affected_components=names,
                evidence=[
                    f"External tools: {', '.join(names)}",
                    f"Trust boundaries crossed: {len(external_tools)}",
                    f"Total trust boundaries: {system.num_trust_boundaries}",
                ],
                attack_path=(
                    f"External service compromise ({', '.join(names)}) → "
                    "transitive trust → agent compromise or data leak"
                ),
                mitigations=[
                    "Audit third-party tool security posture",
                    "Use scoped and rotatable credentials per tool",
                    "Implement network segmentation between tools",
                    "Monitor for anomalous third-party behavior",
                ],
            ))

        # Many trust boundaries = increased complexity
        if system.num_trust_boundaries >= 4:
            findings.append(Finding(
                id=self._make_id("003"),
                rule_id=self.rule_id,
                title="Complex Trust Boundary Topology",
                summary=(
                    "The system spans many trust boundaries, increasing "
                    "architectural complexity and risk."
                ),
                description=(
                    "Systems with many distinct trust boundaries are harder "
                    "to secure and audit. Each boundary transition is a "
                    "potential point of misconfiguration or compromise."
                ),
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.SUPPLY_CHAIN,
                affected_components=list(system.trust_boundaries),
                evidence=[
                    f"Trust boundaries ({system.num_trust_boundaries}): "
                    f"{', '.join(system.trust_boundaries)}",
                ],
                attack_path=(
                    "Misconfigured boundary → lateral movement across "
                    "trust domains"
                ),
                mitigations=[
                    "Document all trust boundary transitions",
                    "Apply defense-in-depth at each boundary",
                    "Regularly audit boundary configurations",
                    "Simplify architecture where feasible",
                ],
            ))

        return findings


register(SupplyChainRule())
