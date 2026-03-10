from __future__ import annotations

from typing import Any, Dict


def recalc_final_severity(
    validation_status: str,
    confidence_score: float,
    correlation_tool_count: int,
) -> str:
    """
    Feature 2 (MANDATORY): Severity recalculation (post-validation).

    Constraints:
    - Does NOT implement CVSS (rule-based + viva-friendly)
    - Keeps original scanner severity intact (engine will store it as-is)
    - Outputs only: low | medium | high

    Simple rules (explainable):
    - confirmed + high confidence OR multi-tool confirmation => high
    - confirmed + medium confidence => medium
    - needs_manual_review => low/medium depending on confidence + correlation
    - false_positive => low
    """
    status = (validation_status or "").strip().lower()
    c = max(0.0, min(1.0, float(confidence_score or 0.0)))
    t = int(correlation_tool_count or 1)

    if status == "false_positive":
        return "low"

    # Cross-tool confirmation increases severity confidence
    if status == "confirmed":
        if c >= 0.85 or t >= 2:
            return "high"
        if c >= 0.60:
            return "medium"
        return "low"

    # Manual review findings should stay conservative
    if status == "needs_manual_review":
        if t >= 2 and c >= 0.60:
            return "medium"
        return "low"

    # Fallback
    if c >= 0.75:
        return "medium"
    return "low"


