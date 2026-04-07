"""Rule: Prompt injection risk detection."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class PromptInjectionRule(BaseRule):
    rule_id = "AESOP-PI"
    name = "Prompt Injection Risk"
    description = (
        "Detects conditions where untrusted user input could manipulate "
        "LLM behavior through prompt injection attacks."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        findings: list[Finding] = []

        # Core prompt injection — internet-facing with untrusted input
        if system.internet_facing or system.has_external_users:
            evidence = self._base_evidence(system)
            severity = Severity.HIGH
            if system.has_tools or system.has_retrieval:
                severity = Severity.CRITICAL

            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Prompt Injection via Untrusted Input",
                summary=(
                    "The system accepts input from untrusted users and processes "
                    "it through an LLM, creating prompt injection risk."
                ),
                description=(
                    "An attacker can craft input that overrides system instructions, "
                    "extracts sensitive context, or triggers unintended actions. "
                    "This risk increases when the LLM has access to tools or "
                    "retrieval sources that can act on injected instructions."
                ),
                severity=severity,
                confidence=Confidence.HIGH,
                category=FindingCategory.PROMPT_INJECTION,
                affected_components=["user_input", "llm_orchestrator"],
                evidence=evidence,
                attack_path=(
                    "Untrusted user → web interface → LLM prompt → "
                    "instruction override → unauthorized action"
                ),
                mitigations=[
                    "Implement input validation and sanitization",
                    "Use system prompt hardening techniques",
                    "Apply output filtering before tool execution",
                    "Enforce least-privilege on tool permissions",
                    "Monitor for anomalous prompt patterns",
                ],
            ))

        # Tool-triggered unsafe action chain
        if (system.internet_facing or system.has_external_users) and system.has_tools:
            tool_names = system.tool_names
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Tool-Triggered Unsafe Action Chain",
                summary=(
                    "Injected prompts could trigger tool calls that perform "
                    "unauthorized actions on integrated services."
                ),
                description=(
                    "When an LLM processes untrusted input and has tool access, "
                    "a prompt injection attack could chain tool calls to perform "
                    "actions the user is not authorized to take."
                ),
                severity=Severity.HIGH if system.has_write_tools else Severity.MEDIUM,
                confidence=Confidence.HIGH if system.has_write_tools else Confidence.MEDIUM,
                category=FindingCategory.PROMPT_INJECTION,
                affected_components=["llm_orchestrator"] + tool_names,
                evidence=[
                    f"Tools available: {', '.join(tool_names)}",
                    f"Write-capable tools: {system.has_write_tools}",
                    "System accepts untrusted user input",
                ],
                attack_path=(
                    "Untrusted user → crafted prompt → LLM → "
                    f"tool calls ({', '.join(tool_names)}) → unauthorized actions"
                ),
                mitigations=[
                    "Require user confirmation for destructive tool actions",
                    "Implement tool-call allowlists per user role",
                    "Add output validation between LLM and tool execution",
                    "Log all tool invocations for audit",
                ],
            ))

        # Retrieval steering
        if (system.internet_facing or system.has_external_users) and system.has_retrieval:
            findings.append(Finding(
                id=self._make_id("003"),
                rule_id=self.rule_id,
                title="Unsafe Retrieval Steering via Prompt Injection",
                summary=(
                    "Injected prompts could steer retrieval queries to "
                    "extract unintended knowledge base content."
                ),
                description=(
                    "An attacker could craft prompts that manipulate the "
                    "retrieval query to access sensitive documents or knowledge "
                    "base entries not intended for the current user."
                ),
                severity=Severity.HIGH if system.has_confidential_retrieval else Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.PROMPT_INJECTION,
                affected_components=["llm_orchestrator"] + system.retrieval_source_names,
                evidence=[
                    "Retrieval is enabled",
                    f"Sources: {', '.join(system.retrieval_source_names)}",
                    f"Confidential retrieval: {system.has_confidential_retrieval}",
                ],
                attack_path=(
                    "Untrusted user → crafted prompt → manipulated retrieval "
                    "query → sensitive document extraction"
                ),
                mitigations=[
                    "Implement retrieval access controls per user role",
                    "Filter retrieval results before LLM context injection",
                    "Limit retrieval scope based on conversation context",
                    "Log retrieval queries for anomaly detection",
                ],
            ))

        return findings

    def _base_evidence(self, system: NormalizedSystem) -> list[str]:
        evidence = []
        if system.internet_facing:
            evidence.append("System is internet-facing")
        if system.has_external_users:
            evidence.append(f"External users: {', '.join(system.user_types)}")
        if system.has_tools:
            evidence.append(f"Tools available: {', '.join(system.tool_names)}")
        if system.has_retrieval:
            evidence.append(f"Retrieval sources: {', '.join(system.retrieval_source_names)}")
        return evidence


register(PromptInjectionRule())
