"""Rule: Insecure output handling risk detection."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class InsecureOutputRule(BaseRule):
    rule_id = "AESOP-IO"
    name = "Insecure Output Handling"
    description = (
        "Detects when model outputs may directly influence external "
        "systems, tools, or downstream logic without sufficient validation."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        if not system.has_tools:
            return []

        findings: list[Finding] = []

        # Output-to-tool execution path
        if system.has_write_tools:
            write_tools = [t.name for t in system.tools if t.has_write]
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Unsafe Downstream Execution of Model Output",
                summary=(
                    "Model output is used to drive write operations on "
                    "external tools without declared output validation."
                ),
                description=(
                    "When LLM output directly triggers tool calls that modify "
                    "external systems, a compromised or manipulated output "
                    "can cause unintended writes, deletions, or state changes "
                    "in connected services."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=FindingCategory.INSECURE_OUTPUT,
                affected_components=["llm_orchestrator"] + write_tools,
                evidence=[
                    f"Write-capable tools: {', '.join(write_tools)}",
                    "Model output drives tool execution",
                ],
                attack_path=(
                    "LLM generates output → output parsed as tool call → "
                    f"write action on {', '.join(write_tools)} → unvalidated change"
                ),
                mitigations=[
                    "Validate and sanitize all model outputs before tool execution",
                    "Treat model output as untrusted data",
                    "Implement output schema enforcement",
                    "Add confirmation step before destructive actions",
                ],
            ))

        # Output-to-action escalation with cross-boundary tools
        cross_tools = [t for t in system.tools if t.crosses_boundary]
        if cross_tools:
            names = [t.name for t in cross_tools]
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Cross-Boundary Insecure Output Handling",
                summary=(
                    "Model-generated actions reach external services "
                    "across trust boundaries without output validation."
                ),
                description=(
                    "The LLM's output is consumed as actionable instructions "
                    "by tools that operate across trust boundaries. A "
                    "malformed or manipulated output can escalate into "
                    "actions on external systems the user does not control."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.INSECURE_OUTPUT,
                affected_components=names,
                evidence=[
                    f"Cross-boundary tools: {', '.join(names)}",
                    "Model output consumed by external tools",
                ],
                attack_path=(
                    "LLM output → tool interprets as command → "
                    "cross-boundary action on external service"
                ),
                mitigations=[
                    "Apply output validation at the tool invocation layer",
                    "Enforce strict schemas for tool call parameters",
                    "Log all cross-boundary actions for audit",
                ],
            ))

        return findings


register(InsecureOutputRule())
