from __future__ import annotations

import re
from typing import Dict, List


# Vulnerability classes required by the project brief
VULN_CLASSES = {
    "TLS / SSL Issues",
    "Injection (SQLi, Command Injection)",
    "XSS",
    "Authentication & Session Issues",
    "Security Misconfigurations",
    "Exposure / Enumeration Issues",
    "Information Disclosure",
    "Other",
}


def _compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# ✅ IMPORTANT:
# Order matters (first match wins). We intentionally place
# "Security Misconfigurations" BEFORE "Injection" so that
# "missing security headers" doesn't get misclassified.
_CLASS_PATTERNS: Dict[str, List[re.Pattern]] = {
    "TLS / SSL Issues": _compile_patterns(
        [
            r"\bssl\b",
            r"\btls\b",
            r"certificate",
            r"hsts",
            r"weak cipher",
            r"expired cert",
            r"self[- ]signed",
            r"hostname mismatch",
        ]
    ),

    # ✅ Misconfig BEFORE Injection (fixes missing headers misclassification)
    "Security Misconfigurations": _compile_patterns(
        [
            r"misconfig",
            r"missing.*header",
            r"missing security header",
            r"http missing security headers",
            r"clickjacking",
            r"\bx-frame-options\b",
            r"\bcontent-security-policy\b",
            r"\bx-content-type-options\b",
            r"\bstrict-transport-security\b",
            r"trace method",
            r"server banner",
        ]
    ),

    # ✅ Removed generic r"\binjection\b" (this was the core bug)
    "Injection (SQLi, Command Injection)": _compile_patterns(
        [
            r"\bsqli\b",
            r"sql injection",
            r"database error",
            r"syntax error.*sql",
            r"union select",
            r"command injection",
            r"os command",
            r"\bxp_cmdshell\b",
            r"\brce\b",
            r"\bremote code execution\b",
            r"\bexec\b",
        ]
    ),

    "XSS": _compile_patterns(
        [
            r"\bxss\b",
            r"cross[- ]site scripting",
            r"<script",
            r"onerror=",
            r"onload=",
        ]
    ),

    "Authentication & Session Issues": _compile_patterns(
        [
            r"\bauth\b",
            r"authentication",
            r"authorization",
            r"\bsession\b",
            r"set-cookie",
            r"httponly",
            r"\bsecure\b.*cookie",
            r"samesite",
            r"csrf",
            r"jwt",
        ]
    ),

    # ✅ Exposure should be about exposed sensitive resources / enumeration artifacts
    # ❌ Removed FFUF "status/size/words/lines/ffuf" patterns (those are discovery signals, not exposure)
    "Exposure / Enumeration Issues": _compile_patterns(
        [
            r"exposure",
            r"backup",
            r"leak",
            r"debug",
            r"\.git\b",
            r"\.env\b",
            r"phpinfo",
            r"swagger",
            r"openapi",
            r"robots\.txt",
            r"sitemap",
            r"admin panel",
            r"directory listing",
            r"\.idea\b",
            r"workspace\.xml",
        ]
    ),

    "Information Disclosure": _compile_patterns(
        [
            r"x-powered-by",
            r"server:",
            r"framework",
            r"version",
            r"asp\.net",
            r"php/",
            r"express",
            r"django",
            r"rails",
            r"technology",
            r"banner",
            r"fingerprint",
        ]
    ),
}


def classify_vuln(text_blob: str) -> str:
    """
    Best-effort classification using simple keyword patterns.

    This is NOT tool-specific: it only uses text evidence present in findings.
    """
    if not text_blob:
        return "Other"

    for vuln_class, patterns in _CLASS_PATTERNS.items():
        for p in patterns:
            if p.search(text_blob):
                return vuln_class

    return "Other"


def normalize_severity(raw: str) -> str:
    """
    Normalize severity/risk strings to: high | medium | low | info | unknown.
    """
    if not raw:
        return "unknown"

    v = str(raw).strip().lower()

    # Treat critical as high
    if v == "critical":
        return "high"

    if v == "high":
        return "high"

    if v in ("medium", "med"):
        return "medium"

    if v == "low":
        return "low"

    if v in ("info", "informational"):
        return "info"

    if "high" in v:
        return "high"
    if "medium" in v:
        return "medium"
    if "low" in v:
        return "low"

    return "unknown"


URL_RE = re.compile(r"(https?://[^\s)\"']+)", re.IGNORECASE)


def extract_first_url(text_blob: str) -> str:
    if not text_blob:
        return ""
    m = URL_RE.search(text_blob)
    return m.group(1) if m else ""
