from __future__ import annotations

import json
from typing import Any, Dict, List

from .classifier import classify_vuln, extract_first_url, normalize_severity
from .models import NormalizedFinding


def _ensure_scheme(url: str) -> str:
    """
    Ensure URL has a scheme so urllib can request it.
    Examples:
      testphp.vulnweb.com -> http://testphp.vulnweb.com
      http://x.com -> unchanged
    """
    url = (url or "").strip()
    if not url:
        return ""
    if "://" in url:
        return url
    return "http://" + url


def _to_text_blob(item: Any) -> str:
    """
    Convert unknown finding shapes (dict/str/etc.) into a searchable text blob.
    """
    if item is None:
        return ""
    if isinstance(item, str):
        return item
    if isinstance(item, (int, float, bool)):
        return str(item)

    if isinstance(item, dict):
        parts: List[str] = []
        for k in (
            "finding_name", "title", "name",
            "type", "category",
            "template", "template-id", "templateID",
            "matcher", "matched-at",
            "risk", "severity", "level",
            "url", "endpoint", "target", "host", "path",
            "description", "detail", "message",
            "raw_output", "evidence", "output",
        ):
            v = item.get(k)
            if v:
                parts.append(f"{k}={v}")

        if not parts:
            try:
                return json.dumps(item, ensure_ascii=False)
            except Exception:
                return str(item)

        return " | ".join(parts)

    try:
        return str(item)
    except Exception:
        return ""


def normalize_findings(raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
    """
    Convert extracted raw findings into NormalizedFinding objects.
    """
    normalized: List[NormalizedFinding] = []

    for rf in raw_findings:
        tool = str(rf.get("tool", "unknown"))
        phase = str(rf.get("phase", ""))
        item = rf.get("item")

        text_blob = _to_text_blob(item)

        # ---------------------------
        # ✅ NEW: extract method + post details (safe defaults)
        # ---------------------------
        method = "GET"
        post_data = ""
        content_type = "application/x-www-form-urlencoded"

        if isinstance(item, dict):
            method = str(item.get("method") or item.get("http_method") or "GET").upper()
            post_data = str(item.get("post_data") or item.get("data") or item.get("body") or "")
            content_type = str(item.get("content_type") or content_type)

        # URL extraction (support different key names from different tools)
        url = ""
        if isinstance(item, dict):
            url = str(
                item.get("url")
                or item.get("target")
                or item.get("endpoint")
                or item.get("matched-at")
                or item.get("host")
                or item.get("path")
                or ""
            )

        # Fallback: extract from text evidence
        if not url:
            url = extract_first_url(text_blob)

        # ✅ Always ensure scheme so validators won't crash
        url = _ensure_scheme(url)

        # Severity normalization (best-effort)
        sev = ""
        if isinstance(item, dict):
            sev = str(item.get("severity") or item.get("risk") or item.get("level") or "")
        severity = normalize_severity(sev)

        vuln_class = classify_vuln(text_blob)

        evidence = text_blob[:240] if text_blob else ""
        normalized.append(
            NormalizedFinding(
                vuln_class=vuln_class,
                original_tool=tool,
                severity=severity,
                url=url,
                evidence=evidence,
                phase=phase,
                raw=item,
                meta={"source_path": rf.get("path", "")},

                # ✅ NEW
                method=method,
                post_data=post_data,
                content_type=content_type,
            )
        )

    return normalized

