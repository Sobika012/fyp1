from __future__ import annotations

from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult
from .base import BaseValidator


class InformationDisclosureValidator(BaseValidator):
    """
    Information Disclosure validation via HTTP header inspection.

    Covers:
    - Server banners
    - Framework/version leaks
    - Technology fingerprints

    This is SAFE and automated.
    """

    vuln_class = "Information Disclosure"

    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        if not finding.url:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No URL available to validate information disclosure.",
                confidence_score=0.4,
            )

        resp = client.get(finding.url)
        if resp is None:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Request failed; cannot inspect headers.",
                confidence_score=0.4,
            )

        headers = resp.headers or {}
        leaks = []

        for h in ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]:
            if h in headers:
                leaks.append(h)

        if leaks:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Information disclosure via HTTP headers: {', '.join(leaks)}.",
                confidence_score=0.75,
                details={"leaked_headers": leaks},
            )

        return ValidationResult(
            validation_status="false_positive",
            validation_reason="No sensitive technology or server headers observed.",
            confidence_score=0.65,
        )
