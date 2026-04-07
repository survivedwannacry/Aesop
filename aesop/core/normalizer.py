"""Transform a validated ArchitectureSpec into a NormalizedSystem."""

from aesop.domain.models import ArchitectureSpec
from aesop.domain.normalized import (
    NormalizedMemoryStore,
    NormalizedRetrievalSource,
    NormalizedSecret,
    NormalizedSystem,
    NormalizedTool,
)

_EXTERNAL_USER_KEYWORDS = frozenset({
    "external",
    "public",
    "customer",
    "user",
    "anonymous",
    "guest",
})

_EXTERNAL_HOST_VALUES = frozenset({
    "external_api",
    "external",
    "saas",
    "cloud",
    "third_party",
})


def normalize(spec: ArchitectureSpec) -> NormalizedSystem:
    """Convert a raw architecture spec into a normalized analysis model."""
    has_external_users = _detect_external_users(spec)

    tools = tuple(
        NormalizedTool(
            name=t.name,
            permissions=tuple(t.permissions),
            trust_boundary=t.trust_boundary,
        )
        for t in spec.tools
    )

    retrieval_sources = tuple(
        NormalizedRetrievalSource(name=s.name, sensitivity=s.sensitivity)
        for s in spec.retrieval.sources
    )

    memory_stores = tuple(
        NormalizedMemoryStore(store_type=m.type, sensitivity=m.sensitivity)
        for m in spec.memory.stores
    )

    secrets = tuple(
        NormalizedSecret(name=s.name, scope=s.scope)
        for s in spec.secrets
    )

    return NormalizedSystem(
        name=spec.system.name,
        system_type=spec.system.type.value,
        description=spec.system.description,
        internet_facing=spec.exposure.internet_facing,
        has_external_users=has_external_users,
        user_types=tuple(spec.exposure.users),
        model_provider=spec.model.provider,
        model_family=spec.model.model_family,
        model_hosted_externally=spec.model.hosted in _EXTERNAL_HOST_VALUES,
        interface_types=tuple(i.type for i in spec.interfaces),
        tools=tools,
        has_retrieval=spec.retrieval.enabled,
        retrieval_sources=retrieval_sources,
        has_memory=spec.memory.enabled,
        memory_stores=memory_stores,
        secrets=secrets,
        data_sensitivities=tuple(spec.data.sensitivity),
        trust_boundaries=tuple(spec.trust_boundaries),
    )


def _detect_external_users(spec: ArchitectureSpec) -> bool:
    """Heuristically detect whether the system has external users."""
    for user in spec.exposure.users:
        lower = user.lower().replace("-", "_").replace(" ", "_")
        if any(kw in lower for kw in _EXTERNAL_USER_KEYWORDS):
            return True
    return spec.exposure.internet_facing
