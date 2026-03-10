from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult
from .base import BaseValidator


class XssValidator(BaseValidator):
    """
    XSS validation using reflection checks (safe and automated).

    Technique:
    - If URL has parameters, inject a unique marker value into one parameter
    - Re-request the page
    - If the marker is reflected unencoded in the response body -> strong signal

    This is not exploitation, but reduces false positives for "reflected XSS" style findings.
    """

    vuln_class = "XSS"

    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        if not finding.url:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No URL present in finding; cannot test reflection safely.",
                confidence_score=0.35,
            )

        parsed = urlparse(finding.url)
        qs = parse_qs(parsed.query or "")
        if not qs:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="URL has no query parameters; reflection test requires a parameterized endpoint.",
                confidence_score=0.35,
            )

        key = sorted(qs.keys())[0]
        marker = "AVDVP_XSS_MARKER_12345"
        test_url = self._with_param(finding.url, key, marker)

        resp = client.get(test_url)
        if resp is None:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Request failed (network/timeout). Cannot validate reflection behavior.",
                confidence_score=0.4,
            )

        body = resp.body_text or ""
        if marker in body:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason="Unique marker was reflected in response body. Potential reflected XSS; confirm encoding/context manually.",
                confidence_score=0.8,
                details={"tested_param": key, "test_url": test_url, "http_status": resp.status},
            )

        # Also check URL-encoded marker
        if re.search(r"AVDVP[_%]XSS[_%]MARKER", body, re.IGNORECASE):
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Marker appears partially encoded/modified in response. Needs manual context check.",
                confidence_score=0.55,
                details={"tested_param": key, "test_url": test_url, "http_status": resp.status},
            )

        return ValidationResult(
            validation_status="false_positive",
            validation_reason="No reflection detected with a simple marker injection; likely false positive (not definitive).",
            confidence_score=0.65,
            details={"tested_param": key, "test_url": test_url, "http_status": resp.status},
        )

    @staticmethod
    def _with_param(url: str, key: str, value: str) -> str:
        p = urlparse(url)
        qs = parse_qs(p.query or "")
        qs[key] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


