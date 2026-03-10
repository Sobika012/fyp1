from __future__ import annotations

import re
from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult
from .base import BaseValidator


class ExposureValidator(BaseValidator):
    """
    Exposure / enumeration validation via safe re-request.

    Confirm ONLY when the resource is actually accessible (HTTP 200/206) AND looks like
    a real sensitive file/directory listing — not just "it exists".

    - 200/206 with strong indicators => confirmed
    - 301/302/307/308 => needs_manual_review (redirect; follow to verify)
    - 401/403/405 => needs_manual_review (exists but restricted / method issues)
    - 404/410 => false_positive
    - 0/429/5xx => needs_manual_review (unreliable)
    """

    vuln_class = "Exposure / Enumeration Issues"

    # Simple patterns for sensitive exposure (FYP-friendly)
    SENSITIVE_URL_HINTS = [
        r"\.git", r"\.env", r"\.idea", r"workspace\.xml",
        r"config", r"backup", r"dump", r"db", r"sql",
        r"phpinfo\.php", r"\.log", r"\.bak", r"\.old", r"\.zip", r"\.tar", r"\.gz"
    ]

    SENSITIVE_BODY_HINTS = [
        r"Index of /", r"Parent Directory",
        r"(?i)database[_-]?url", r"(?i)db[_-]?pass", r"(?i)password\s*=",
        r"(?i)aws_access_key_id", r"(?i)aws_secret_access_key",
        r"<\?xml", r"<project", r"<workspace"
    ]

    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        if not finding.url:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No URL present; cannot validate exposed resource reachability.",
                confidence_score=0.35,
            )

        resp = client.get(finding.url)
        if resp is None:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Request failed (network/timeout). Cannot validate exposure reachability.",
                confidence_score=0.30,
            )

        status = int(resp.status or 0)
        body = (resp.body_text or "")
        body_len = len(body)

        if status == 0:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No HTTP status received (possible network/proxy issue).",
                confidence_score=0.30,
                details={"http_status": status, "body_len": body_len},
            )

        # Hard false positive
        if status in (404, 410):
            return ValidationResult(
                validation_status="false_positive",
                validation_reason=f"Resource not present (HTTP {status}) on validation request.",
                confidence_score=0.90,
                details={"http_status": status, "body_len": body_len},
            )

        # Unreliable / blocked
        if status == 429:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Rate limited (HTTP 429). Validation unreliable.",
                confidence_score=0.25,
                details={"http_status": status, "body_len": body_len},
            )

        if status >= 500:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason=f"Server error (HTTP {status}). Validation unreliable.",
                confidence_score=0.25,
                details={"http_status": status, "body_len": body_len},
            )

        # Redirects: existence signal, not exposure proof
        if status in (301, 302, 307, 308):
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason=f"Resource redirects (HTTP {status}). Follow redirect to validate exposure.",
                confidence_score=0.45,
                details={"http_status": status, "body_len": body_len},
            )

        # Restricted / method issue: might still be sensitive
        if status in (401, 403, 405):
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason=f"Resource exists but access is restricted or method blocked (HTTP {status}).",
                confidence_score=0.50,
                details={"http_status": status, "body_len": body_len},
            )

        # Confirm exposure ONLY if accessible
        if status in (200, 206):
            url_lower = finding.url.lower()

            url_hint = any(re.search(pat, url_lower) for pat in self.SENSITIVE_URL_HINTS)
            body_hint = any(re.search(pat, body) for pat in self.SENSITIVE_BODY_HINTS)

            # Base confidence for accessible content
            confidence = 0.60

            # Strong signals -> higher confidence
            if url_hint and body_len >= 20:
                confidence = 0.80
            if body_hint:
                confidence = max(confidence, 0.85)

            # If content is super tiny with no hints, don't over-confirm
            if body_len < 20 and not (url_hint or body_hint):
                return ValidationResult(
                    validation_status="needs_manual_review",
                    validation_reason=f"Accessible (HTTP {status}) but response too small and no exposure indicators; review manually.",
                    confidence_score=0.50,
                    details={"http_status": status, "body_len": body_len},
                )

            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Accessible sensitive resource (HTTP {status}) with exposure indicators.",
                confidence_score=confidence,
                details={"http_status": status, "body_len": body_len, "url_hint": url_hint, "body_hint": body_hint},
            )

        # Everything else
        return ValidationResult(
            validation_status="needs_manual_review",
            validation_reason=f"Unexpected HTTP status (HTTP {status}). Needs manual review.",
            confidence_score=0.35,
            details={"http_status": status, "body_len": body_len},
        )
