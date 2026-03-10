"""
Generic risk-based URL scoring and FFUF result filtering.
Structure-independent; no hardcoded paths.
"""

from urllib.parse import urlparse

from config import (
    SENSITIVE_KEYWORDS,
    STATIC_EXTENSIONS,
    SCORE_PARAMETERIZED,
    SCORE_SENSITIVE_KEYWORD,
    SCORE_STATIC_FILE,
    FFUF_VALID_STATUS_CODES,
)


def score_url(url: str) -> int:
    """
    Score a URL for prioritization. Higher = higher risk priority.
    - Parameterized URL: +60
    - Sensitive keyword in path/lower URL: +40 each (capped by logic: once)
    - Static file extension: -50
    """
    if not url or not isinstance(url, str):
        return 0

    score = 0
    lower = url.lower().strip()
    parsed = urlparse(lower)
    path = parsed.path or "/"

    if "?" in url:
        score += SCORE_PARAMETERIZED

    for kw in SENSITIVE_KEYWORDS:
        if kw in path or kw in parsed.query:
            score += SCORE_SENSITIVE_KEYWORD
            break

    for ext in STATIC_EXTENSIONS:
        if path.endswith(ext) or path.rstrip("/").endswith(ext):
            score += SCORE_STATIC_FILE
            break

    return score


def is_static_url(url: str) -> bool:
    """True if URL path ends with a static file extension."""
    if not url:
        return True
    parsed = urlparse(url)
    path = (parsed.path or "/").lower()
    return any(path.endswith(ext) or path.rstrip("/").endswith(ext) for ext in STATIC_EXTENSIONS)


def _status_from_finding(f: dict) -> int | None:
    s = f.get("status")
    if s is not None:
        return int(s)
    raw = f.get("raw") or f.get("raw_output") or {}
    return raw.get("status") or raw.get("status_code")


def filter_ffuf_results(findings: list, valid_status_codes: tuple = FFUF_VALID_STATUS_CODES) -> list:
    """
    Include only findings with allowed status codes; exclude static files and duplicate paths.
    findings: list of dicts with 'url', and 'status' or raw.status.
    """
    if not findings:
        return []

    seen_paths = set()
    filtered = []

    for f in findings:
        url = f.get("url") or ""
        status = _status_from_finding(f)

        if status is None or status not in valid_status_codes:
            continue
        if is_static_url(url):
            continue

        parsed = urlparse(url)
        path_key = (parsed.netloc or "", parsed.path or "/", parsed.query or "")
        if path_key in seen_paths:
            continue
        seen_paths.add(path_key)
        filtered.append(f)

    return filtered


def get_urls_from_ffuf_findings(findings: list) -> list:
    """Extract unique URLs from FFUF finding dicts (e.g. from normalizer)."""
    urls = []
    seen = set()
    for f in findings:
        u = f.get("url") or ""
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def select_nuclei_urls_basic(root_url: str, ffuf_urls: list, top_n: int = 3) -> list:
    """
    For Basic mode: root URL (always) + all parameterized URLs + top N by risk score.
    Returns deduplicated list with root first, then param URLs, then top N by score.
    """
    always = [root_url] if root_url else []
    param_urls = [u for u in (ffuf_urls or []) if "?" in u]
    scored = [(score_url(u), u) for u in (ffuf_urls or []) if u not in always]
    scored.sort(key=lambda x: (-x[0], x[1]))
    top_urls = [u for _, u in scored[:top_n] if u not in always and u not in param_urls]

    seen = set()
    out = []
    for u in always + param_urls + top_urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def select_nuclei_urls_basic_simple(root_url: str, ffuf_urls: list, max_targets: int = 3) -> list:
    """
    For Basic mode: root URL (always) + parameterized URLs only.
    No risk scoring. Max targets limit enforced.
    Returns deduplicated list with root first, then param URLs.
    """
    always = [root_url] if root_url else []
    param_urls = [u for u in (ffuf_urls or []) if "?" in u and u != root_url]
    
    seen = set()
    out = []
    for u in always:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    
    for u in param_urls:
        if len(out) >= max_targets:
            break
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    
    return out
