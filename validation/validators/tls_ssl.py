from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Dict, Optional

from ..models import NormalizedFinding, ValidationResult, clamp_score
from .base import BaseValidator


class TlsSslValidator(BaseValidator):
    """
    TLS/SSL validation (class-based).

    Technique (automated, no exploitation):
    - Perform a TLS handshake to host:443
    - Pull certificate metadata
    - Check basic conditions (expired, not-yet-valid, self-signed)

    This is explainable and generic across websites.
    """

    vuln_class = "TLS / SSL Issues"

    def validate(self, finding: NormalizedFinding, client) -> ValidationResult:
        host = self._extract_host(finding.url)
        if not host:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="No hostname available in finding evidence; cannot perform TLS handshake validation.",
                confidence_score=0.3,
            )

        info = self._get_cert_info(host)
        if info is None:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason="TLS handshake failed (connection or certificate validation failed).",
                confidence_score=0.85,
            )

        now = datetime.utcnow()
        not_before = info.get("not_before")
        not_after = info.get("not_after")
        self_signed = info.get("self_signed", False)

        if isinstance(not_after, datetime) and not_after < now:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Certificate is expired (notAfter={not_after.isoformat()}Z).",
                confidence_score=0.95,
                details={"host": host, **info},
            )
        if isinstance(not_before, datetime) and not_before > now:
            return ValidationResult(
                validation_status="confirmed",
                validation_reason=f"Certificate is not yet valid (notBefore={not_before.isoformat()}Z).",
                confidence_score=0.95,
                details={"host": host, **info},
            )
        if self_signed:
            return ValidationResult(
                validation_status="needs_manual_review",
                validation_reason="Certificate appears self-signed. This may be acceptable in labs/intranets; review context.",
                confidence_score=0.70,
                details={"host": host, **info},
            )

        # If certificate looks normal, many TLS findings become likely false positives.
        return ValidationResult(
            validation_status="false_positive",
            validation_reason="TLS handshake succeeded and certificate appears valid (basic checks passed).",
            confidence_score=0.75,
            details={"host": host, **info},
        )

    @staticmethod
    def _extract_host(url: str) -> str:
        if not url:
            return ""
        try:
            # very small parser to avoid adding dependencies
            if "://" in url:
                url = url.split("://", 1)[1]
            host_port = url.split("/", 1)[0]
            host = host_port.split("@")[-1].split(":")[0]
            return host.strip()
        except Exception:
            return ""

    def _get_cert_info(self, host: str) -> Optional[Dict]:
        """
        Returns cert info dict on success, None on failure.
        """
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=7) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            if not cert:
                return None

            subject = cert.get("subject", ())
            issuer = cert.get("issuer", ())
            nb = cert.get("notBefore")
            na = cert.get("notAfter")
            not_before = self._parse_cert_time(nb)
            not_after = self._parse_cert_time(na)

            # crude self-signed check: subject == issuer
            self_signed = bool(subject and issuer and subject == issuer)

            return {
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "self_signed": self_signed,
            }
        except Exception:
            return None

    @staticmethod
    def _parse_cert_time(s: str):
        if not s:
            return None
        # Typical format: 'Jun  1 12:00:00 2026 GMT'
        try:
            return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            try:
                # some certs include double-space before day
                return datetime.strptime(s, "%b  %d %H:%M:%S %Y %Z")
            except Exception:
                return None



