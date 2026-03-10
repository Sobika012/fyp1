from __future__ import annotations

import random
import string
from urllib.parse import urlparse, urlunparse

from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult
from .base import BaseValidator


class OtherValidator(BaseValidator):
    """
    Fallback validator (mainly for FFUF discovery-style findings).

    Goal: reduce false positives.
    - Redirects / restricted => endpoint likely exists (confirmed)
    - 200 responses need content check + wildcard detection
    - 404/410 => strong false positive
    """

    vuln_class = "Other"

    def _random_path(self, base_url: str) -> str:
        """
        Generate a random non-existing path under the same host to test wildcard 200 pages.
        """
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        parsed = urlparse(base_url)
        return urlunparse((parsed.scheme, parsed.netloc, f"/__not_real_{token}__", "", "", ""))

    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        if not finding.url:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No URL present; cannot validate reachability.",
                confidence_score=0.35,
            )

        resp = client.get(finding.url)
        if resp is None:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Request failed (network/timeout). Cannot validate reachability.",
                confidence_score=0.30,
            )

        status = int(resp.status or 0)
        body_len = len(resp.body_text or "")

        if status == 0:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No HTTP status received (possible network/proxy issue).",
                confidence_score=0.30,
                details={"http_status": status, "body_len": body_len},
            )

        # ❌ Strong false positives
        if status in (404, 410):
            return ValidationResult(
                validation_status="false_positive",
                validation_reason=f"Endpoint not found (HTTP {status}) on validation request.",
                confidence_score=0.90,
                details={"http_status": status, "body_len": body_len},
            )

        # ⚠ Rate limit / server errors => can't validate reliably
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

        # ✅ Strong "endpoint exists" signals
        if status in (301, 302, 307, 308):
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Endpoint exists and redirects (HTTP {status}).",
                confidence_score=0.60,
                details={"http_status": status, "body_len": body_len},
            )

        if status in (401, 403):
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Endpoint exists but is restricted (HTTP {status}).",
                confidence_score=0.55,
                details={"http_status": status, "body_len": body_len},
            )

        if status == 405:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason="Endpoint exists (HTTP 405 Method Not Allowed).",
                confidence_score=0.60,
                details={"http_status": status, "body_len": body_len},
            )

        # ✅ HTTP 200 handling
        if status == 200:
            # If large content => confirmed
            if body_len >= 80:
                return ValidationResult(
                    validation_status="confirmed",
                    validation_reason=f"Endpoint reachable (HTTP 200) with meaningful content (body_len={body_len}).",
                    confidence_score=0.75,
                    details={"http_status": status, "body_len": body_len},
                )

            # Wildcard test for small content
            bogus_url = self._random_path(finding.url)
            bogus_resp = client.get(bogus_url)

            if bogus_resp is not None:
                bogus_status = int(bogus_resp.status or 0)
                bogus_len = len(bogus_resp.body_text or "")

                # If bogus random path ALSO returns 200 with similar body => wildcard => false positive
                if bogus_status == 200 and abs(bogus_len - body_len) <= 20:
                    return ValidationResult(
                        validation_status="false_positive",
                        validation_reason=f"Possible wildcard/soft-404: random path returned HTTP 200 with similar body (len={bogus_len}).",
                        confidence_score=0.85,
                        details={
                            "http_status": status,
                            "body_len": body_len,
                            "wildcard_test_url": bogus_url,
                            "wildcard_status": bogus_status,
                            "wildcard_body_len": bogus_len,
                        },
                    )

            # If wildcard not confirmed → confirmed-low (tiny file/empty response)
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Endpoint reachable (HTTP 200) but small body (body_len={body_len}); likely real file/empty response.",
                confidence_score=0.55,
                details={"http_status": status, "body_len": body_len},
            )

        # Anything else
        return ValidationResult(
            validation_status="needs_manual_review",
            validation_reason=f"Unexpected HTTP status (HTTP {status}). Needs manual review.",
            confidence_score=0.35,
            details={"http_status": status, "body_len": body_len},
        )
