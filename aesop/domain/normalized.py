"""Normalized system model for simplified rule evaluation.

The normalized model flattens the raw ArchitectureSpec into a set of
booleans, lists, and derived properties that make rule conditions
trivial to express.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aesop.domain.enums import DataSensitivity


@dataclass(frozen=True)
class NormalizedTool:
    """Flattened representation of an integrated tool."""

    name: str
    permissions: tuple[str, ...]
    trust_boundary: str

    @property
    def has_write(self) -> bool:
        return any(
            kw in p
            for p in self.permissions
            for kw in ("write", "create", "delete", "update", "admin", "execute")
        )

    @property
    def is_privileged(self) -> bool:
        return any(
            kw in p for p in self.permissions for kw in ("admin", "execute", "sudo")
        )

    @property
    def crosses_boundary(self) -> bool:
        return self.trust_boundary not in ("", "internal", "backend", "unknown")


@dataclass(frozen=True)
class NormalizedRetrievalSource:
    """Flattened retrieval source."""

    name: str
    sensitivity: DataSensitivity


@dataclass(frozen=True)
class NormalizedMemoryStore:
    """Flattened memory store."""

    store_type: str
    sensitivity: DataSensitivity


@dataclass(frozen=True)
class NormalizedSecret:
    """Flattened secret reference."""

    name: str
    scope: str


@dataclass(frozen=True)
class NormalizedSystem:
    """Fully normalized AI system model for rule evaluation.

    All complex nesting is resolved into flat booleans and lists
    so that rules can express conditions as simple attribute checks.
    """

    # Identity
    name: str
    system_type: str
    description: str

    # Exposure
    internet_facing: bool
    has_external_users: bool
    user_types: tuple[str, ...] = ()

    # Model
    model_provider: str = ""
    model_family: str = ""
    model_hosted_externally: bool = False

    # Interfaces
    interface_types: tuple[str, ...] = ()

    # Tools
    tools: tuple[NormalizedTool, ...] = ()

    # Retrieval
    has_retrieval: bool = False
    retrieval_sources: tuple[NormalizedRetrievalSource, ...] = ()

    # Memory
    has_memory: bool = False
    memory_stores: tuple[NormalizedMemoryStore, ...] = ()

    # Secrets
    secrets: tuple[NormalizedSecret, ...] = ()

    # Data sensitivity
    data_sensitivities: tuple[DataSensitivity, ...] = ()

    # Trust boundaries
    trust_boundaries: tuple[str, ...] = ()

    # ── Derived convenience properties ───────────────────────────

    @property
    def has_tools(self) -> bool:
        return len(self.tools) > 0

    @property
    def has_write_tools(self) -> bool:
        return any(t.has_write for t in self.tools)

    @property
    def has_privileged_tools(self) -> bool:
        return any(t.is_privileged for t in self.tools)

    @property
    def has_cross_boundary_tools(self) -> bool:
        return any(t.crosses_boundary for t in self.tools)

    @property
    def has_secrets(self) -> bool:
        return len(self.secrets) > 0

    @property
    def has_sensitive_data(self) -> bool:
        return any(
            s in (DataSensitivity.CONFIDENTIAL, DataSensitivity.PII, DataSensitivity.RESTRICTED)
            for s in self.data_sensitivities
        )

    @property
    def has_pii(self) -> bool:
        return DataSensitivity.PII in self.data_sensitivities

    @property
    def has_confidential_retrieval(self) -> bool:
        return any(
            s.sensitivity in (DataSensitivity.CONFIDENTIAL, DataSensitivity.PII, DataSensitivity.RESTRICTED)
            for s in self.retrieval_sources
        )

    @property
    def has_external_providers(self) -> bool:
        return self.model_hosted_externally

    @property
    def num_trust_boundaries(self) -> int:
        return len(self.trust_boundaries)

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.tools]

    @property
    def retrieval_source_names(self) -> list[str]:
        return [s.name for s in self.retrieval_sources]
