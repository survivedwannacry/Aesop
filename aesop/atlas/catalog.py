"""Load and query the local MITRE ATLAS technique catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "atlas_minimal.json"


@dataclass(frozen=True)
class AtlasTechnique:
    """A single ATLAS technique entry."""

    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    description: str
    mitigations: tuple[str, ...] = ()


@dataclass
class AtlasCatalog:
    """In-memory catalog of ATLAS techniques and category mappings."""

    techniques: dict[str, AtlasTechnique] = field(default_factory=dict)
    category_mappings: dict[str, list[str]] = field(default_factory=dict)

    def get(self, technique_id: str) -> AtlasTechnique | None:
        return self.techniques.get(technique_id)

    def techniques_for_category(self, category: str) -> list[AtlasTechnique]:
        """Return all techniques mapped to a finding category."""
        ids = self.category_mappings.get(category, [])
        return [self.techniques[tid] for tid in ids if tid in self.techniques]


# Module-level singleton
_catalog: AtlasCatalog | None = None


def load_catalog(path: Path | None = None) -> AtlasCatalog:
    """Load the ATLAS catalog from the JSON data file."""
    global _catalog
    if _catalog is not None and path is None:
        return _catalog

    data_path = path or _DATA_FILE
    raw = json.loads(data_path.read_text(encoding="utf-8"))

    techniques: dict[str, AtlasTechnique] = {}
    for entry in raw.get("techniques", []):
        t = AtlasTechnique(
            tactic_id=entry["tactic_id"],
            tactic_name=entry["tactic_name"],
            technique_id=entry["technique_id"],
            technique_name=entry["technique_name"],
            description=entry["description"],
            mitigations=tuple(entry.get("mitigations", [])),
        )
        techniques[t.technique_id] = t

    catalog = AtlasCatalog(
        techniques=techniques,
        category_mappings=raw.get("category_mappings", {}),
    )

    if path is None:
        _catalog = catalog
    return catalog
