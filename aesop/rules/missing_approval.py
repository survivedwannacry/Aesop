"""Rule: Missing approval gates and guardrail risk."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class MissingApprovalRule(BaseRule):
    rule_id = "AESOP-MG"
    name = "Missing Approval / Guardrail Risk"
    description = (
        "Detects when the architecture enables sensitive actions "
        "without explicit approval, review, or policy checkpoints."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        findings: list[Finding] = []

        # Write-capable tools without approval signal
        write_tools = [t for t in system.tools if t.has_write]
        if write_tools:
            names = [t.name for t in write_tools]
            severity = Severity.HIGH if system.internet_facing else Severity.MEDIUM
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Sensitive Actions Without Declared Approval Gate",
                summary=(
                    "Write-capable tool actions can execute without any "
                    "declared human approval or policy checkpoint."
                ),
                description=(
                    "The architecture includes tools that can modify external "
                    "systems but does not declare any approval mechanism, "
                    "confirmation gate, or policy enforcement layer. This "
                    "means the agent can autonomously perform destructive "
                    "or irreversible actions."
                ),
                severity=severity,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.MISSING_APPROVAL,
                affected_components=names,
                evidence=[
                    f"Write-capable tools: {', '.join(names)}",
                    "No approval gates declared in spec",
                    f"Internet-facing: {system.internet_facing}",
                ],
                attack_path=(
                    "User input → agent decides to act → write tool "
                    f"({', '.join(names)}) → external modification "
                    "without human review"
                ),
                mitigations=[
                    "Add human-in-the-loop approval for write operations",
                    "Implement policy-as-code checks before tool execution",
                    "Require explicit user confirmation for destructive actions",
                    "Log all approval decisions for audit",
                ],
            ))

        # Secrets and privileged integrations without guardrails
        if system.has_secrets and system.has_privileged_tools:
            priv_names = [t.name for t in system.tools if t.is_privileged]
            secret_names = [s.name for s in system.secrets]
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Privileged Integrations Without Policy Enforcement",
                summary=(
                    "Privileged tools backed by secrets operate without "
                    "declared policy boundaries or approval constraints."
                ),
                description=(
                    "The agent has access to privileged tool integrations "
                    "authenticated by secrets, but the architecture does "
                    "not declare any policy enforcement or guardrail layer. "
                    "This creates a path from user input to privileged "
                    "external action with no checkpoint."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.MISSING_APPROVAL,
                affected_components=priv_names + secret_names,
                evidence=[
                    f"Privileged tools: {', '.join(priv_names)}",
                    f"Secrets: {', '.join(secret_names)}",
                    "No policy enforcement layer declared",
                ],
                attack_path=(
                    "User input → agent → privileged tool authenticated "
                    "by secret → admin-level action without policy check"
                ),
                mitigations=[
                    "Implement a policy enforcement layer before tool dispatch",
                    "Require multi-factor approval for privileged actions",
                    "Separate privileged credentials behind an approval gate",
                    "Audit all privileged tool invocations",
                ],
            ))

        return findings


register(MissingApprovalRule())
