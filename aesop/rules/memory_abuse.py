"""Rule: Memory abuse risk detection."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class MemoryAbuseRule(BaseRule):
    rule_id = "AESOP-MA"
    name = "Memory Abuse Risk"
    description = (
        "Detects risks from persistent memory that could be "
        "poisoned or abused across interactions."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        if not system.has_memory:
            return []

        findings: list[Finding] = []
        store_types = [m.store_type for m in system.memory_stores]

        # Memory poisoning
        if system.internet_facing or system.has_external_users:
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Memory Poisoning via Untrusted Input",
                summary=(
                    "Persistent memory can be poisoned by untrusted users, "
                    "affecting future interactions."
                ),
                description=(
                    "An attacker could craft interactions that inject malicious "
                    "instructions or data into the agent's memory. Future "
                    "sessions would then operate under the influence of the "
                    "poisoned memory, potentially affecting all users."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=FindingCategory.MEMORY_ABUSE,
                affected_components=store_types,
                evidence=[
                    f"Memory stores: {', '.join(store_types)}",
                    "System accepts untrusted user input",
                    f"Internet-facing: {system.internet_facing}",
                ],
                attack_path=(
                    "Attacker → crafted interaction → malicious data stored "
                    "in memory → future sessions poisoned"
                ),
                mitigations=[
                    "Validate and sanitize data before writing to memory",
                    "Implement memory expiration policies",
                    "Separate memory scopes per user or session",
                    "Provide admin tools to inspect and clear memory",
                ],
            ))

        # Persistent malicious instructions
        findings.append(Finding(
            id=self._make_id("002"),
            rule_id=self.rule_id,
            title="Persistent Malicious Instructions in Memory",
            summary=(
                "Long-lived memory could retain injected instructions "
                "that persistently alter agent behavior."
            ),
            description=(
                "If the agent stores conversation context or instructions "
                "in memory without validation, an attacker could embed "
                "instructions that persist across sessions and override "
                "intended system behavior."
            ),
            severity=Severity.MEDIUM if not system.has_external_users else Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.MEMORY_ABUSE,
            affected_components=store_types,
            evidence=[
                f"Memory stores: {', '.join(store_types)}",
                "No memory isolation metadata declared",
            ],
            attack_path=(
                "Injected instruction → stored in memory → loaded in "
                "future context → persistent behavior override"
            ),
            mitigations=[
                "Separate instruction context from user data in memory",
                "Apply memory integrity checks",
                "Implement memory content review mechanisms",
                "Set maximum memory retention periods",
            ],
        ))

        # User-to-user contamination
        if system.has_external_users and len(system.memory_stores) > 0:
            findings.append(Finding(
                id=self._make_id("003"),
                rule_id=self.rule_id,
                title="User-to-User Memory Contamination",
                summary=(
                    "Shared memory stores could allow one user's data to "
                    "influence another user's experience."
                ),
                description=(
                    "Without proper memory isolation, data or instructions "
                    "from one user session could persist and affect a "
                    "different user's session, leading to data leakage "
                    "or behavior manipulation across users."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.MEMORY_ABUSE,
                affected_components=store_types,
                evidence=[
                    "Multiple external users share the system",
                    f"Memory stores: {', '.join(store_types)}",
                    "No per-user memory isolation declared",
                ],
                attack_path=(
                    "User A → data stored in shared memory → "
                    "User B session loads contaminated context"
                ),
                mitigations=[
                    "Enforce per-user memory isolation",
                    "Use user-scoped memory namespaces",
                    "Audit memory access patterns across users",
                ],
            ))

        return findings


register(MemoryAbuseRule())
