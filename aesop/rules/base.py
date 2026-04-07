"""Base rule abstraction for the threat analysis engine."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aesop.domain.findings import Finding
from aesop.domain.normalized import NormalizedSystem


class BaseRule(ABC):
    """Abstract base for all threat-detection rules.

    Subclasses must set ``rule_id``, ``name``, and ``description``
    and implement ``evaluate()``.
    """

    rule_id: str
    name: str
    description: str

    @abstractmethod
    def evaluate(self, system: NormalizedSystem) -> list[Finding]:
        """Evaluate the rule against a normalized system model.

        Returns zero or more findings. An empty list means the rule
        did not trigger.
        """

    def _make_id(self, suffix: str) -> str:
        """Generate a deterministic finding ID from the rule ID."""
        return f"{self.rule_id}-{suffix}"
