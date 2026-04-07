"""Rule: Model denial-of-service and cost abuse risk."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class DosCostAbuseRule(BaseRule):
    rule_id = "AESOP-DC"
    name = "Model Denial-of-Service / Cost Abuse Risk"
    description = (
        "Detects when public-facing systems could be abused to create "
        "excessive cost, latency, or service degradation."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        if not (system.internet_facing or system.has_external_users):
            return []

        findings: list[Finding] = []

        # Cost explosion via external model
        if system.has_external_providers:
            has_amplifiers = system.has_tools or system.has_retrieval
            severity = Severity.HIGH if has_amplifiers else Severity.MEDIUM
            evidence = [
                "System is publicly accessible",
                f"External model provider: {system.model_provider}",
            ]
            if system.has_tools:
                evidence.append(f"Tools that amplify cost: {', '.join(system.tool_names)}")
            if system.has_retrieval:
                evidence.append("Retrieval adds per-query cost")

            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Cost Explosion via Abusive Query Volume",
                summary=(
                    "Public-facing system with external model provider is "
                    "vulnerable to cost abuse through high query volume."
                ),
                description=(
                    "An attacker or abusive user can send a large volume of "
                    "queries to a public-facing AI system, driving up costs "
                    "for the external model provider. When tools or retrieval "
                    "are involved, each query can trigger multiple downstream "
                    "API calls, amplifying the cost."
                ),
                severity=severity,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.DOS_COST_ABUSE,
                affected_components=[f"model:{system.model_provider}"] + system.tool_names,
                evidence=evidence,
                attack_path=(
                    "Attacker → high-volume queries → external model API → "
                    "cost escalation (amplified by tool/retrieval calls)"
                ),
                mitigations=[
                    "Implement per-user and per-session rate limiting",
                    "Set cost ceilings and usage budgets",
                    "Monitor for anomalous query volume spikes",
                    "Add CAPTCHAs or proof-of-work for unauthenticated access",
                ],
            ))

        # Resource exhaustion through multi-step workflows
        if system.has_tools and system.has_retrieval:
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Resource Exhaustion via Complex Query Workflows",
                summary=(
                    "Multi-step tool and retrieval workflows can be abused "
                    "to exhaust system resources."
                ),
                description=(
                    "Queries that trigger both retrieval and tool calls "
                    "create multi-step workflows. An attacker can craft "
                    "inputs that maximize the number of downstream calls "
                    "per query, causing latency spikes and resource exhaustion."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.DOS_COST_ABUSE,
                affected_components=system.tool_names + system.retrieval_source_names,
                evidence=[
                    f"Tools: {', '.join(system.tool_names)}",
                    f"Retrieval sources: {', '.join(system.retrieval_source_names)}",
                    "Multi-step workflows amplify resource usage",
                ],
                attack_path=(
                    "Crafted query → retrieval + tool calls → "
                    "multiple downstream requests → resource exhaustion"
                ),
                mitigations=[
                    "Limit tool call depth and count per query",
                    "Set timeouts on multi-step workflows",
                    "Implement circuit breakers for downstream services",
                ],
            ))

        return findings


register(DosCostAbuseRule())
