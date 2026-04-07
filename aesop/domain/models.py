"""Pydantic models for validating YAML architecture specifications."""

from __future__ import annotations

from pydantic import BaseModel, Field

from aesop.domain.enums import DataSensitivity, SystemType


# ── System metadata ──────────────────────────────────────────────


class SystemSpec(BaseModel):
    """Top-level system identification."""

    name: str = Field(..., min_length=1, description="System name")
    type: SystemType = Field(..., description="AI system type")
    description: str = Field(default="", description="Human-readable description")


# ── Exposure ─────────────────────────────────────────────────────


class ExposureSpec(BaseModel):
    """How the system is exposed to users and networks."""

    internet_facing: bool = Field(default=False)
    users: list[str] = Field(default_factory=list)


# ── Model provider ──────────────────────────────────────────────


class ModelSpec(BaseModel):
    """LLM provider configuration."""

    provider: str = Field(..., min_length=1)
    model_family: str = Field(default="unknown")
    hosted: str = Field(default="external_api")


# ── Interface ────────────────────────────────────────────────────


class InterfaceSpec(BaseModel):
    """An entry-point interface to the system."""

    type: str = Field(..., min_length=1)
    auth: str = Field(default="none")


# ── Tool ─────────────────────────────────────────────────────────


class ToolSpec(BaseModel):
    """An integrated tool or service the agent can invoke."""

    name: str = Field(..., min_length=1)
    permissions: list[str] = Field(default_factory=list)
    trust_boundary: str = Field(default="unknown")


# ── Retrieval ────────────────────────────────────────────────────


class RetrievalSourceSpec(BaseModel):
    """A retrieval/knowledge source."""

    name: str = Field(..., min_length=1)
    sensitivity: DataSensitivity = Field(default=DataSensitivity.INTERNAL)


class RetrievalSpec(BaseModel):
    """Retrieval-augmented generation configuration."""

    enabled: bool = Field(default=False)
    sources: list[RetrievalSourceSpec] = Field(default_factory=list)


# ── Memory ───────────────────────────────────────────────────────


class MemoryStoreSpec(BaseModel):
    """A memory store used by the system."""

    type: str = Field(default="conversation_memory")
    sensitivity: DataSensitivity = Field(default=DataSensitivity.INTERNAL)


class MemorySpec(BaseModel):
    """Memory configuration."""

    enabled: bool = Field(default=False)
    stores: list[MemoryStoreSpec] = Field(default_factory=list)


# ── Secrets ──────────────────────────────────────────────────────


class SecretSpec(BaseModel):
    """A secret or credential used by the system."""

    name: str = Field(..., min_length=1)
    scope: str = Field(default="backend")


# ── Data sensitivity ────────────────────────────────────────────


class DataSpec(BaseModel):
    """Data sensitivity declarations."""

    sensitivity: list[DataSensitivity] = Field(default_factory=list)


# ── Root spec ────────────────────────────────────────────────────


class ArchitectureSpec(BaseModel):
    """Complete architecture specification for an AI system."""

    system: SystemSpec
    exposure: ExposureSpec = Field(default_factory=ExposureSpec)
    model: ModelSpec
    interfaces: list[InterfaceSpec] = Field(default_factory=list)
    tools: list[ToolSpec] = Field(default_factory=list)
    retrieval: RetrievalSpec = Field(default_factory=RetrievalSpec)
    memory: MemorySpec = Field(default_factory=MemorySpec)
    secrets: list[SecretSpec] = Field(default_factory=list)
    data: DataSpec = Field(default_factory=DataSpec)
    trust_boundaries: list[str] = Field(default_factory=list)
