"""Rule: Excessive agency and over-privileged agent design."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register

_WRITE_TOOL_THRESHOLD = 2


class ExcessiveAgencyRule(BaseRule):
    rule_id = "AESOP-EA"
    name = "Excessive Agency / Over-Privileged Agent Design"
    description = (
        "Detects when the architecture grants the agent overly broad "
        "capabilities, multiple write-capable tools, or insufficient constraints."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        findings: list[Finding] = []

        write_tools = [t for t in system.tools if t.has_write]
        privileged_tools = [t for t in system.tools if t.is_privileged]

        # Multiple write-capable tools
        if len(write_tools) >= _WRITE_TOOL_THRESHOLD:
            names = [t.name for t in write_tools]
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Excessive Autonomy — Multiple Write-Capable Tools",
                summary=(
                    "The agent has write access to multiple external tools, "
                    "granting broad autonomous modification capability."
                ),
                description=(
                    "An agent with write permissions across multiple tools "
                    "can chain modifications that compound into significant "
                    "unintended outcomes. The blast radius of a single "
                    "prompt injection or logic error expands with each "
                    "additional write-capable integration."
                ),
                severity=(
                    Severity.CRITICAL if len(write_tools) >= 3
                    else Severity.HIGH
                ),
                confidence=Confidence.HIGH,
                category=FindingCategory.EXCESSIVE_AGENCY,
                affected_components=names,
                evidence=[
                    f"Write-capable tools ({len(write_tools)}): {', '.join(names)}",
                    *[
                        f"{t.name}: permissions={list(t.permissions)}"
                        for t in write_tools
                    ],
                ],
                attack_path=(
                    "Agent manipulation → compound writes across "
                    f"{', '.join(names)} → broad unintended state change"
                ),
                mitigations=[
                    "Reduce write-capable tool count to the minimum necessary",
                    "Separate read and write tool credentials",
                    "Require human approval for multi-tool write operations",
                    "Implement per-tool action budgets",
                ],
            ))

        # Privileged cross-boundary tools without constraints
        priv_cross = [t for t in privileged_tools if t.crosses_boundary]
        if priv_cross:
            names = [t.name for t in priv_cross]
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Over-Broad Capability — Privileged Cross-Boundary Access",
                summary=(
                    "Privileged tools operate across trust boundaries, "
                    "creating disproportionate agent authority."
                ),
                description=(
                    "The agent holds admin or execute-level permissions on "
                    "external services. This is a design-level concern: "
                    "the agent's capabilities exceed what is typically "
                    "needed for its stated purpose."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=FindingCategory.EXCESSIVE_AGENCY,
                affected_components=names,
                evidence=[
                    f"Privileged cross-boundary tools: {', '.join(names)}",
                    *[
                        f"{t.name}: boundary={t.trust_boundary}, "
                        f"permissions={list(t.permissions)}"
                        for t in priv_cross
                    ],
                ],
                attack_path=(
                    "Compromised agent → privileged action on external "
                    f"service ({', '.join(names)}) → significant damage"
                ),
                mitigations=[
                    "Apply least-privilege to agent tool permissions",
                    "Replace admin-level access with scoped service accounts",
                    "Add human-in-the-loop gates for privileged operations",
                ],
            ))

        return findings


register(ExcessiveAgencyRule())
