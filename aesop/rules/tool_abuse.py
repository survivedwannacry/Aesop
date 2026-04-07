"""Rule: Tool abuse risk detection."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class ToolAbuseRule(BaseRule):
    rule_id = "AESOP-TA"
    name = "Tool Abuse Risk"
    description = (
        "Detects risks arising from agent tool integrations, "
        "especially those with write or privileged permissions."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        if not system.has_tools:
            return []

        findings: list[Finding] = []

        # Write-capable tools crossing trust boundaries
        write_boundary_tools = [
            t for t in system.tools if t.has_write and t.crosses_boundary
        ]
        if write_boundary_tools:
            names = [t.name for t in write_boundary_tools]
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Write-Capable Tools Crossing Trust Boundaries",
                summary=(
                    "Tools with write permissions operate across trust "
                    "boundaries, enabling unauthorized external actions."
                ),
                description=(
                    "The agent can invoke tools that modify data in external "
                    "services. If the agent is compromised or manipulated, "
                    "these tools could be used to alter tickets, push code, "
                    "send messages, or modify records in connected systems."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=FindingCategory.TOOL_ABUSE,
                affected_components=names,
                evidence=[
                    f"Write-capable cross-boundary tools: {', '.join(names)}",
                    *[
                        f"{t.name}: permissions={list(t.permissions)}, boundary={t.trust_boundary}"
                        for t in write_boundary_tools
                    ],
                ],
                attack_path=(
                    f"Compromised agent → tool call ({', '.join(names)}) → "
                    "unauthorized write to external service"
                ),
                mitigations=[
                    "Apply least-privilege to tool permissions",
                    "Require human approval for write operations",
                    "Implement per-tool rate limiting",
                    "Audit all tool invocations",
                ],
            ))

        # Excessive tool privileges
        privileged = [t for t in system.tools if t.is_privileged]
        if privileged:
            names = [t.name for t in privileged]
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Excessive Tool Privileges",
                summary=(
                    "One or more tools have administrative or execution-level "
                    "permissions beyond what may be necessary."
                ),
                description=(
                    "Tools with admin, execute, or sudo-level permissions "
                    "present an elevated risk if the agent is manipulated. "
                    "An attacker could escalate through these tools."
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=FindingCategory.TOOL_ABUSE,
                affected_components=names,
                evidence=[
                    f"Privileged tools: {', '.join(names)}",
                    *[f"{t.name}: permissions={list(t.permissions)}" for t in privileged],
                ],
                attack_path=(
                    f"Agent manipulation → privileged tool ({', '.join(names)}) → "
                    "admin-level action on external system"
                ),
                mitigations=[
                    "Reduce tool permissions to minimum required",
                    "Separate read and write tool credentials",
                    "Implement mandatory human-in-the-loop for privileged actions",
                ],
            ))

        # General cross-boundary tools (even read-only)
        cross_tools = [t for t in system.tools if t.crosses_boundary and not t.has_write]
        if cross_tools:
            names = [t.name for t in cross_tools]
            findings.append(Finding(
                id=self._make_id("003"),
                rule_id=self.rule_id,
                title="Cross-Boundary Tool Access",
                summary=(
                    "Read-only tools access external services across trust "
                    "boundaries, expanding the attack surface."
                ),
                description=(
                    "Even read-only tools that cross trust boundaries can "
                    "leak information or be used for reconnaissance if the "
                    "agent is manipulated."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.TOOL_ABUSE,
                affected_components=names,
                evidence=[
                    f"Cross-boundary read tools: {', '.join(names)}",
                ],
                attack_path=(
                    f"Agent manipulation → read tool ({', '.join(names)}) → "
                    "information disclosure from external service"
                ),
                mitigations=[
                    "Scope read access to minimum necessary data",
                    "Use separate service accounts for each tool",
                    "Monitor tool access patterns",
                ],
            ))

        return findings


register(ToolAbuseRule())
