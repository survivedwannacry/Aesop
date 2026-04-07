"""Mermaid diagram generation for architecture visualization."""

from __future__ import annotations

from aesop.domain.models import ArchitectureSpec


def generate_mermaid(spec: ArchitectureSpec) -> str:
    """Generate a Mermaid flowchart showing the system architecture."""
    lines = ["graph TD"]

    # User node
    lines.append('    User["👤 User"]')

    # Interfaces
    for i, iface in enumerate(spec.interfaces):
        iid = f"IF{i}"
        label = f"🌐 {iface.type}"
        if iface.auth != "none":
            label += f"\\n(auth: {iface.auth})"
        lines.append(f'    {iid}["{label}"]')
        lines.append(f"    User --> {iid}")

    # If no interfaces, connect user directly to orchestrator
    if not spec.interfaces:
        lines.append("    User --> Orch")

    # Orchestrator
    lines.append(f'    Orch[/"🤖 {spec.system.name}\\nOrchestrator"/]')
    for i in range(len(spec.interfaces)):
        lines.append(f"    IF{i} --> Orch")

    # Model provider
    hosted = spec.model.hosted
    model_label = f"🧠 {spec.model.provider}\\n({spec.model.model_family})"
    lines.append(f'    Model["{model_label}"]')
    lines.append("    Orch <--> Model")

    # Tools
    for i, tool in enumerate(spec.tools):
        tid = f"Tool{i}"
        perms = ", ".join(tool.permissions[:3]) if tool.permissions else "no perms"
        lines.append(f'    {tid}["🔧 {tool.name}\\n({perms})"]')
        lines.append(f"    Orch --> {tid}")

    # Retrieval sources
    if spec.retrieval.enabled:
        for i, src in enumerate(spec.retrieval.sources):
            rid = f"Ret{i}"
            lines.append(f'    {rid}[("📚 {src.name}\\n[{src.sensitivity.value}]")]')
            lines.append(f"    Orch <-.-> {rid}")

    # Memory stores
    if spec.memory.enabled:
        for i, store in enumerate(spec.memory.stores):
            mid = f"Mem{i}"
            lines.append(f'    {mid}[("💾 {store.type}\\n[{store.sensitivity.value}]")]')
            lines.append(f"    Orch <-.-> {mid}")

    # Trust boundary subgraphs
    _add_trust_boundaries(lines, spec)

    # Style classes for risk highlighting
    lines.append("")
    lines.append("    classDef external fill:#ffe0e0,stroke:#cc0000")
    lines.append("    classDef internal fill:#e0f0e0,stroke:#009900")
    if spec.model.hosted in ("external_api", "external", "saas", "cloud"):
        lines.append("    class Model external")
    for i, tool in enumerate(spec.tools):
        if tool.trust_boundary not in ("", "internal", "backend"):
            lines.append(f"    class Tool{i} external")

    return "\n".join(lines)


def _add_trust_boundaries(lines: list[str], spec: ArchitectureSpec) -> None:
    """Add subgraph boxes for trust boundaries when meaningful."""
    if not spec.trust_boundaries or len(spec.trust_boundaries) < 2:
        return

    # Only add a simple external boundary subgraph if tools exist
    external_tools = [
        f"Tool{i}" for i, t in enumerate(spec.tools)
        if t.trust_boundary not in ("", "internal", "backend", "unknown")
    ]
    if external_tools:
        lines.append("")
        lines.append('    subgraph ext["External Services"]')
        for tid in external_tools:
            lines.append(f"        {tid}")
        lines.append("    end")
