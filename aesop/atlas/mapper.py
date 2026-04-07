"""Map findings to MITRE ATLAS techniques."""

from __future__ import annotations

from aesop.atlas.catalog import load_catalog
from aesop.domain.findings import AtlasTechniqueRef, Finding


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Attach ATLAS technique references to each finding based on its category."""
    catalog = load_catalog()
    enriched: list[Finding] = []

    for finding in findings:
        techniques = catalog.techniques_for_category(finding.category.value)
        refs = [
            AtlasTechniqueRef(
                technique_id=t.technique_id,
                technique_name=t.technique_name,
                tactic=t.tactic_name,
            )
            for t in techniques
        ]
        # Merge with any already-attached techniques (deduplicate)
        existing_ids = {r.technique_id for r in finding.atlas_techniques}
        merged = list(finding.atlas_techniques) + [
            r for r in refs if r.technique_id not in existing_ids
        ]
        enriched.append(finding.model_copy(update={"atlas_techniques": merged}))

    return enriched
