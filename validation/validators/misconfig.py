from __future__ import annotations

from urllib.parse import urlparse

from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult
from .base import BaseValidator


class MisconfigurationValidator(BaseValidator):
    """
    Security misconfiguration validation via security header inspection.

    Checks (generic, OWASP-aligned):
    - Strict-Transport-Security (HSTS)  [HTTPS only]
    - X-Frame-Options
    - Content-Security-Policy
    - X-Content-Type-Options
    """

    vuln_class = "Security Misconfigurations"

    REQUIRED = [
        "strict-transport-security",
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
    ]

    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        if not finding.url:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No URL present; cannot validate headers automatically.",
                confidence_score=0.35,
            )

        resp = client.get(finding.url)
        if resp is None:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Request failed (network/timeout). Cannot validate misconfiguration headers.",
                confidence_score=0.30,
            )

        status = int(resp.status or 0)
        if status == 0:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No HTTP status received (possible network/proxy issue).",
                confidence_score=0.30,
                details={"http_status": status},
            )

        if status == 429:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Rate limited (HTTP 429). Validation unreliable.",
                confidence_score=0.25,
                details={"http_status": status},
            )

        if status >= 500:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason=f"Server error (HTTP {status}). Validation unreliable.",
                confidence_score=0.25,
                details={"http_status": status},
            )

        # Make header lookup case-insensitive
        headers = resp.headers or {}
        headers_lower = {str(k).lower(): v for k, v in headers.items()}

        # HSTS only makes sense for HTTPS
        scheme = urlparse(finding.url).scheme.lower()
        required = list(self.REQUIRED)
        if scheme != "https":
            required = [h for h in required if h != "strict-transport-security"]

        missing = [h for h in required if h not in headers_lower]

        # Evidence-driven (if finding mentions specific headers)
        ev = (finding.evidence or "").lower()
        mentioned = [h for h in required if h in ev]

        if mentioned:
            missing_mentioned = [h for h in mentioned if h not in headers_lower]
            if missing_mentioned:
                return ValidationResult(
                    validation_status="confirmed",
                    validation_reason=f"Missing security header(s) mentioned in finding: {', '.join(missing_mentioned)}.",
                    confidence_score=0.85,
                    details={"http_status": status, "missing_headers": missing_mentioned},
                )
            return ValidationResult(
                validation_status="false_positive",
                validation_reason="Security header(s) mentioned in finding were present on validation request.",
                confidence_score=0.75,
                details={"http_status": status, "present_headers": mentioned},
            )

        # Generic missing headers check (still deterministic)
        if missing:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Missing common security header(s): {', '.join(missing)}.",
                confidence_score=0.75,
                details={"http_status": status, "missing_headers": missing, "checked_https_only_hsts": (scheme == 'https')},
            )

        return ValidationResult(
            validation_status="false_positive",
            validation_reason="Common security headers were present on validation request.",
            confidence_score=0.75,
            details={"http_status": status},
        )
