from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

# Keys that commonly hold lists of findings in tool outputs
LIST_KEYS = {"findings", "vulnerabilities", "alerts", "issues", "results", "paths", "items"}


def _is_skipped(tool_result: Any) -> bool:
    if isinstance(tool_result, dict):
        status = str(tool_result.get("status", "")).strip().lower()
        return status == "skipped"
    return False


def _walk_tool_result(obj: Any, path: str = "") -> Iterable[Tuple[Any, str]]:
    """
    Recursively walk a tool result and emit (item, path) for list entries we consider "findings".
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_str = str(k)
            next_path = f"{path}.{k_str}" if path else k_str

            if k_str in LIST_KEYS and isinstance(v, list):
                for i, entry in enumerate(v):
                    yield entry, f"{next_path}[{i}]"
            else:
                yield from _walk_tool_result(v, next_path)

    elif isinstance(obj, list):
        for i, entry in enumerate(obj):
            yield from _walk_tool_result(entry, f"{path}[{i}]")

    else:
        return


def extract_raw_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract raw findings from BOTH possible report shapes:

    A) Combined report:
       {
         "scan_info": {...},
         "findings": [ ... ]
       }

    B) Phase-based report:
       {
         "phase_basic": { "whatweb": {...}, "ffuf": {...}, ... },
         "phase_deep":  { ... }
       }
    """
    out: List[Dict[str, Any]] = []

    # ✅ Case A: combined report format (top-level "findings")
    if isinstance(report, dict) and isinstance(report.get("findings"), list):
        for i, item in enumerate(report["findings"]):
            tool = "unknown"
            if isinstance(item, dict):
                tool = str(item.get("tool", "unknown"))

            out.append(
                {
                    "phase": "combined",
                    "tool": tool,
                    "path": f"findings[{i}]",
                    "item": item,
                }
            )
        return out

    # ✅ Case B: phase-based format (keys that start with "phase")
    for phase_name, phase_data in (report or {}).items():
        if not isinstance(phase_name, str) or not phase_name.lower().startswith("phase"):
            continue
        if not isinstance(phase_data, dict):
            continue

        for tool_name, tool_result in phase_data.items():
            if _is_skipped(tool_result):
                continue
            if not isinstance(tool_name, str):
                continue

            for item, path in _walk_tool_result(tool_result):
                out.append(
                    {
                        "phase": phase_name,
                        "tool": tool_name,
                        "path": path,
                        "item": item,
                    }
                )

    return out

