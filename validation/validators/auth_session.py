from __future__ import annotations

from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult
from .base import BaseValidator


class AuthSessionValidator(BaseValidator):
    """
    Authentication & session validation using header inspection.

    Generic checks:
    - Presence of Set-Cookie flags (Secure / HttpOnly / SameSite)
    - These are safe, automated, and apply to any web target.
    """

    vuln_class = "Authentication & Session Issues"

    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        if not finding.url:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No URL provided; cannot inspect cookie/session headers automatically.",
                confidence_score=0.35,
            )

        resp = client.get(finding.url)
        if resp is None:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Request failed (network/timeout). Cannot inspect session headers.",
                confidence_score=0.4,
            )

        set_cookie = resp.headers.get("set-cookie", "")
        if not set_cookie:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No Set-Cookie header observed on this request; session issues may still exist but were not observable here.",
                confidence_score=0.45,
                details={"http_status": resp.status},
            )

        flags = {
            "secure": "secure" in set_cookie.lower(),
            "httponly": "httponly" in set_cookie.lower(),
            "samesite": "samesite" in set_cookie.lower(),
        }

        missing = [k for k, v in flags.items() if not v]
        if missing:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Set-Cookie is missing recommended flag(s): {', '.join(missing)}.",
                confidence_score=0.75,
                details={"http_status": resp.status, "missing_flags": missing},
            )

        return ValidationResult(
            validation_status="false_positive",
            validation_reason="Set-Cookie flags Secure/HttpOnly/SameSite were observed on this request.",
            confidence_score=0.65,
            details={"http_status": resp.status},
        )


