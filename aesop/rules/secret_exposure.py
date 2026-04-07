"""Rule: Secret exposure risk detection."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class SecretExposureRule(BaseRule):
    rule_id = "AESOP-SE"
    name = "Secret Exposure Risk"
    description = (
        "Detects risks of credential and secret leakage through "
        "prompts, logs, tools, or LLM responses."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        if not system.has_secrets:
            return []

        findings: list[Finding] = []
        secret_names = [s.name for s in system.secrets]

        # Credential leakage through LLM context
        findings.append(Finding(
            id=self._make_id("001"),
            rule_id=self.rule_id,
            title="Credential Leakage Through LLM Context",
            summary=(
                "Secrets used by the system may be exposed through "
                "LLM prompts, logs, or error messages."
            ),
            description=(
                "If secrets are included in prompts, system instructions, "
                "or error handling paths, they could appear in LLM responses, "
                "logs, or debug output. This is especially dangerous when "
                "the system is internet-facing."
            ),
            severity=(
                Severity.HIGH if system.internet_facing else Severity.MEDIUM
            ),
            confidence=Confidence.MEDIUM,
            category=FindingCategory.SECRET_EXPOSURE,
            affected_components=secret_names,
            evidence=[
                f"Secrets declared: {', '.join(secret_names)}",
                f"Internet-facing: {system.internet_facing}",
            ],
            attack_path=(
                "Secret in system context → LLM includes in response "
                "or error → credential exposed to user"
            ),
            mitigations=[
                "Never include raw secrets in LLM prompts",
                "Use secret references, not values, in configuration",
                "Scrub secrets from all log output",
                "Implement output scanning for credential patterns",
            ],
        ))

        # Tool connector secrets at risk
        tool_secrets = [s for s in system.secrets if s.scope == "tool_connector"]
        if tool_secrets and system.has_tools:
            names = [s.name for s in tool_secrets]
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Tool Connector Secret Misuse",
                summary=(
                    "Secrets scoped to tool connectors could be exposed or "
                    "abused through tool integration pathways."
                ),
                description=(
                    "Tool connector credentials bridge the agent to external "
                    "services. If an attacker manipulates tool calls, these "
                    "credentials could be used to access the external service "
                    "directly or leaked through error messages."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.SECRET_EXPOSURE,
                affected_components=names + system.tool_names,
                evidence=[
                    f"Tool connector secrets: {', '.join(names)}",
                    f"Tools: {', '.join(system.tool_names)}",
                ],
                attack_path=(
                    "Agent manipulation → tool call with connector secret → "
                    "secret exposed in error or response"
                ),
                mitigations=[
                    "Use short-lived tokens for tool authentication",
                    "Rotate tool connector secrets regularly",
                    "Scope tool credentials to minimum permissions",
                    "Never surface raw tool errors to users",
                ],
            ))

        return findings


register(SecretExposureRule())
