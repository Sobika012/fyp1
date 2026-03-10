from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse


def _extract_base_path(url: str) -> str:
    """
    Extract first-level path for contextual correlation.

    Example:
        /admin/login.php  -> /admin
        /admin/config     -> /admin
        /                  -> /
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "/"
    return "/" + parts[0]


def build_correlation_index(normalized_findings: List[Any]) -> Dict[str, Dict[str, Any]]:
    """
    Build improved correlation index grouped by BASE PATH.

    Instead of:
        (vuln_class, exact_url)

    We now group by:
        base_path

    This allows different tools reporting different vuln_classes
    on same area (e.g., /admin) to correlate.
    """

    idx: Dict[str, Dict[str, Any]] = {}

    for nf in normalized_findings:
        url = (getattr(nf, "url", "") or "").strip().lower()
        base_path = _extract_base_path(url) if url else "unknown"

        if base_path not in idx:
            idx[base_path] = {"tools": set()}

        idx[base_path]["tools"].add(
            getattr(nf, "original_tool", "unknown") or "unknown"
        )

    for key in idx:
        idx[key]["tool_count"] = len(idx[key]["tools"])

    return idx


def apply_evidence_correlation(
    validated_findings: List[Dict[str, Any]],
    normalized_findings: List[Any],
) -> List[Dict[str, Any]]:
    """
    Improved multi-tool correlation (FYP-Advanced Level).

    Now:
      - Correlates findings on same base path
      - Boosts confidence if multiple tools reported activity
      - Updates correlation metadata
      - Keeps logic simple and viva-defendable
    """

    idx = build_correlation_index(normalized_findings)

    for i, vf in enumerate(validated_findings):
        try:
            nf = normalized_findings[i]
        except Exception:
            continue

        url = (getattr(nf, "url", "") or "").strip().lower()
        base_path = _extract_base_path(url) if url else "unknown"

        group = idx.get(base_path) or {"tool_count": 1, "tools": set()}

        tool_count = int(group.get("tool_count") or 1)
        tools = sorted(list(group.get("tools") or []))

        # -----------------------------
        # Confidence Boost Logic
        # -----------------------------
        base_conf = float(vf.get("confidence_score") or 0.0)
        boost = 0.0

        if tool_count == 2:
            boost = 0.10
        elif tool_count == 3:
            boost = 0.18
        elif tool_count >= 4:
            boost = 0.25

        new_conf = min(1.0, max(0.0, base_conf + boost))
        vf["confidence_score"] = new_conf

        # -----------------------------
        # Correlation Explanation
        # -----------------------------
        if tool_count > 1:
            reason = vf.get("validation_reason") or ""

            corr_note = (
                f" Evidence correlation: {tool_count} independent tools reported findings "
                f"within the same application area ({base_path}) "
                f"({', '.join(tools)})."
            )

            vf["validation_reason"] = (reason + corr_note).strip()
            vf["correlation"] = {
                "tool_count": tool_count,
                "tools": tools,
                "correlated_area": base_path,
            }
        else:
            vf["correlation"] = {
                "tool_count": 1,
                "tools": tools or [vf.get("original_tool", "unknown")],
                "correlated_area": base_path,
            }

    return validated_findings
