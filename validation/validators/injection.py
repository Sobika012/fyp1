from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, parse_qsl

from ..http_client import SimpleHttpClient
from ..models import NormalizedFinding, ValidationResult
from .base import BaseValidator


SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning: mysqli?_",
    r"SQLite\/JDBCException",
    r"PostgreSQL.*ERROR",
    r"ODBC SQL Server Driver",
    r"Unclosed quotation mark after the character string",
]


class InjectionValidator(BaseValidator):
    vuln_class = "Injection (SQLi, Command Injection)"

    def validate(self, finding: NormalizedFinding, client: SimpleHttpClient) -> ValidationResult:
        if not finding.url:
            return ValidationResult(
                "needs_manual_review",
                "No URL present in finding; cannot validate safely.",
                0.35,
            )

        method = (finding.method or "GET").upper()

        # ---------------------------
        # ✅ POST VALIDATION
        # ---------------------------
        if method == "POST":
            if not finding.post_data:
                return ValidationResult(
                    "needs_manual_review",
                    "Finding is POST-based but no post_data was provided by scanner; cannot replay safely.",
                    0.40,
                )

            # baseline POST
            baseline = client.post(finding.url, finding.post_data, finding.content_type)

            # mutate first POST param
            params = dict(parse_qsl(finding.post_data, keep_blank_values=True))
            if not params:
                return ValidationResult(
                    "needs_manual_review",
                    "POST data exists but no form parameters could be parsed; cannot mutate safely.",
                    0.40,
                )

            key = sorted(params.keys())[0]
            params[key] = (params.get(key, "") + "'")
            mutated_body = urlencode(params, doseq=True)
            mutated = client.post(finding.url, mutated_body, finding.content_type)

            if baseline is None or mutated is None:
                return ValidationResult(
                    "needs_manual_review",
                    "POST replay failed (network/timeout). Cannot validate injection behavior.",
                    0.45,
                )

            btxt = baseline.body_text or ""
            mtxt = mutated.body_text or ""

            if self._find_sql_error(mtxt) and not self._find_sql_error(btxt):
                return ValidationResult(
                    "confirmed",
                    "POST response shows database error patterns after minimal perturbation.",
                    0.85,
                    details={"tested_param": key, "method": "POST"},
                )

            diff = self._simple_diff_score(btxt, mtxt)
            if diff >= 0.55:
                return ValidationResult(
                    "needs_manual_review",
                    "POST response changed significantly after perturbation but no clear SQL error detected.",
                    0.55,
                    details={"tested_param": key, "diff_score": diff, "method": "POST"},
                )

            return ValidationResult(
                "false_positive",
                "No injection error behavior detected in POST replay; likely false positive (not definitive).",
                0.65,
                details={"tested_param": key, "diff_score": diff, "method": "POST"},
            )

        # ---------------------------
        # ✅ GET VALIDATION
        # ---------------------------
        parsed = urlparse(finding.url)
        qs = parse_qs(parsed.query or "")
        if not qs:
            return ValidationResult(
                "needs_manual_review",
                "URL has no query parameters; GET-based injection verification requires a parameterized endpoint.",
                0.35,
            )

        key = sorted(qs.keys())[0]
        original_val = (qs.get(key) or [""])[0]
        test_val = f"{original_val}'"

        baseline = client.get(finding.url)
        mutated_url = self._with_param(finding.url, key, test_val)
        mutated = client.get(mutated_url)

        if baseline is None or mutated is None:
            return ValidationResult(
                "needs_manual_review",
                "Request failed (network/timeout). Cannot reliably validate injection behavior.",
                0.40,
            )

        btxt = baseline.body_text or ""
        mtxt = mutated.body_text or ""

        if self._find_sql_error(mtxt) and not self._find_sql_error(btxt):
            return ValidationResult(
                "confirmed",
                "Response shows database error patterns after a minimal quote perturbation.",
                0.85,
                details={"tested_param": key, "mutated_url": mutated_url, "method": "GET"},
            )

        diff_score = self._simple_diff_score(btxt, mtxt)
        if diff_score >= 0.55:
            return ValidationResult(
                "needs_manual_review",
                "Response changed significantly after parameter perturbation but no clear SQL error was detected.",
                0.55,
                details={
                    "tested_param": key,
                    "mutated_url": mutated_url,
                    "diff_score": diff_score,
                    "method": "GET",
                },
            )

        return ValidationResult(
            "false_positive",
            "No SQL error behavior detected with a minimal perturbation; likely false positive (not definitive).",
            0.65,
            details={
                "tested_param": key,
                "mutated_url": mutated_url,
                "diff_score": diff_score,
                "method": "GET",
            },
        )

    @staticmethod
    def _with_param(url: str, key: str, value: str) -> str:
        p = urlparse(url)
        qs = parse_qs(p.query or "")
        qs[key] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))

    @staticmethod
    def _find_sql_error(text: str) -> bool:
        for pat in SQL_ERROR_PATTERNS:
            if re.search(pat, text or "", re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _simple_diff_score(a: str, b: str) -> float:
        la = len(a or "")
        lb = len(b or "")
        if la == 0 and lb == 0:
            return 0.0
        return abs(la - lb) / max(la, lb, 1)

