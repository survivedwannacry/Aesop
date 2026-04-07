"""Rule: Logging and telemetry leakage risk."""

from __future__ import annotations

from aesop.domain.enums import Confidence, FindingCategory, Severity
from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem
from aesop.rules.base import BaseRule
from aesop.rules.registry import register


class LoggingLeakageRule(BaseRule):
    rule_id = "AESOP-LL"
    name = "Logging / Telemetry Leakage Risk"
    description = (
        "Detects when prompts, responses, secrets, or sensitive "
        "retrieved content may be exposed through logs or telemetry."
    )

    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        findings: list[Finding] = []

        # Secret leakage through logs
        if system.has_secrets:
            secret_names = [s.name for s in system.secrets]
            severity = Severity.HIGH if system.has_external_providers else Severity.MEDIUM
            findings.append(Finding(
                id=self._make_id("001"),
                rule_id=self.rule_id,
                title="Secret Leakage via Logging or Telemetry",
                summary=(
                    "Secrets present in the system may be captured in "
                    "logs, traces, or telemetry pipelines."
                ),
                description=(
                    "When secrets are used for model providers, tool "
                    "connectors, or backend services, they can appear in "
                    "request logs, error traces, or observability pipelines "
                    "unless explicitly redacted."
                ),
                severity=severity,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.LOGGING_LEAKAGE,
                affected_components=secret_names,
                evidence=[
                    f"Secrets: {', '.join(secret_names)}",
                    f"External providers: {system.has_external_providers}",
                    "No explicit logging constraints in spec",
                ],
                attack_path=(
                    "Secret used in API call → request logged → "
                    "secret exposed in log storage or telemetry sink"
                ),
                mitigations=[
                    "Implement structured logging with automatic secret redaction",
                    "Scrub sensitive patterns from all log pipelines",
                    "Use secret references instead of raw values in config",
                    "Audit telemetry exports for credential exposure",
                ],
            ))

        # Sensitive retrieval content in logs
        if system.has_retrieval and system.has_confidential_retrieval:
            sources = system.retrieval_source_names
            findings.append(Finding(
                id=self._make_id("002"),
                rule_id=self.rule_id,
                title="Confidential Data Leakage via Prompt Logging",
                summary=(
                    "Retrieved confidential content injected into prompts "
                    "may be captured in request logs."
                ),
                description=(
                    "When retrieval sources contain confidential or PII data, "
                    "that data is typically injected into the LLM prompt. "
                    "If prompts are logged for debugging or monitoring, "
                    "the sensitive content persists in log storage."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.LOGGING_LEAKAGE,
                affected_components=sources,
                evidence=[
                    f"Confidential retrieval sources: {', '.join(sources)}",
                    "Retrieved content injected into prompts",
                    "Prompt logging may capture sensitive data",
                ],
                attack_path=(
                    "Retrieval returns confidential doc → injected into "
                    "prompt → prompt logged → PII/confidential data in logs"
                ),
                mitigations=[
                    "Redact sensitive content from logged prompts",
                    "Implement per-sensitivity-level logging policies",
                    "Avoid logging full prompt context in production",
                    "Apply data classification labels to log entries",
                ],
            ))

        return findings


register(LoggingLeakageRule())
