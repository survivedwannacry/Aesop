"""Domain enumerations for Aesop threat models."""

from enum import Enum


class Severity(str, Enum):
    """Finding severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison (higher = more severe)."""
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank


class Confidence(str, Enum):
    """Finding confidence levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SystemType(str, Enum):
    """Supported AI system types."""

    LLM_AGENT = "llm-agent"
    RAG_SYSTEM = "rag-system"
    MULTI_AGENT = "multi-agent"
    CHAT_ASSISTANT = "chat-assistant"
    TOOL_AGENT = "tool-agent"
    CUSTOM = "custom"


class DataSensitivity(str, Enum):
    """Data sensitivity classifications."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    RESTRICTED = "restricted"


class FindingCategory(str, Enum):
    """Threat finding categories."""

    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    RETRIEVAL_EXFILTRATION = "retrieval_exfiltration"
    SECRET_EXPOSURE = "secret_exposure"
    MEMORY_ABUSE = "memory_abuse"
    SUPPLY_CHAIN = "supply_chain"
    INSECURE_OUTPUT = "insecure_output"
    EXCESSIVE_AGENCY = "excessive_agency"
    CROSS_CONTEXT = "cross_context"
    LOGGING_LEAKAGE = "logging_leakage"
    DOS_COST_ABUSE = "dos_cost_abuse"
    MISSING_APPROVAL = "missing_approval"
