"""JSON report generation for machine-readable output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from aesop.domain.findings import AnalysisResult


def render_json(result: AnalysisResult) -> str:
    """Generate a stable JSON threat model report."""
    report = {
        "schema_version": "1.0.0",
        "generator": "aesop",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system": {
            "name": result.system_name,
            "type": result.system_type,
            "description": result.description,
        },
        "severity_summary": {
            "critical": result.severity_summary.critical,
            "high": result.severity_summary.high,
            "medium": result.severity_summary.medium,
            "low": result.severity_summary.low,
            "total": result.severity_summary.total,
        },
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "summary": f.summary,
                "description": f.description,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category.value,
                "affected_components": f.affected_components,
                "evidence": f.evidence,
                "attack_path": f.attack_path,
                "atlas_techniques": [
                    {
                        "technique_id": t.technique_id,
                        "technique_name": t.technique_name,
                        "tactic": t.tactic,
                    }
                    for t in f.atlas_techniques
                ],
                "mitigations": f.mitigations,
            }
            for f in result.findings
        ],
        "atlas_techniques_used": [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic": t.tactic,
            }
            for t in result.atlas_techniques_used
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)
