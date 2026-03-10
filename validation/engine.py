from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List

from .extractor import extract_raw_findings
from .http_client import SimpleHttpClient
from .normalizer import normalize_findings
from .correlation import apply_evidence_correlation
from .severity import recalc_final_severity

from .validators.auth_session import AuthSessionValidator
from .validators.exposure import ExposureValidator
from .validators.injection import InjectionValidator
from .validators.misconfig import MisconfigurationValidator
from .validators.other import OtherValidator
from .validators.tls_ssl import TlsSslValidator
from .validators.xss import XssValidator
from .validators.info_disclosure import InformationDisclosureValidator


class ValidationEngine:
    """
    Main orchestration engine.
    - Tool-agnostic
    - Works on .json and .jsonl
    """

    def __init__(self, timeout: int = 10):
        self.client = SimpleHttpClient(timeout=timeout)

        self.validators = {
            "TLS / SSL Issues": TlsSslValidator(),
            "Injection (SQLi, Command Injection)": InjectionValidator(),
            "XSS": XssValidator(),
            "Authentication & Session Issues": AuthSessionValidator(),
            "Security Misconfigurations": MisconfigurationValidator(),
            "Exposure / Enumeration Issues": ExposureValidator(),
            "Information Disclosure": InformationDisclosureValidator(),
            "Other": OtherValidator(),
        }

    def load_report(self, path: str) -> Dict[str, Any]:
        """
        Load either:
        - .json  -> normal JSON object
        - .jsonl -> JSON Lines, wrapped into {"findings":[...]}
        """
        if path.lower().endswith(".jsonl"):
            findings: List[Any] = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        continue

            return {
                "scan_info": {
                    "source_file": os.path.basename(path),
                    "total_findings": len(findings),
                },
                "findings": findings,
            }

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _get_confidence(self, vr) -> float:
        """
        Safely extract confidence from ValidationResult even if field names differ.
        Supports: confidence_score, confidence, validation_confidence.
        Defaults to 0.0
        """
        conf = getattr(vr, "confidence_score", None)
        if conf is None:
            conf = getattr(vr, "confidence", None)
        if conf is None:
            conf = getattr(vr, "validation_confidence", None)

        try:
            return float(conf) if conf is not None else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _canon_text(s: str) -> str:
        """
        Canonicalize strings so evidence comparisons don't break because of
        newlines, tabs, multiple spaces, etc.
        """
        return " ".join((s or "").split()).strip()

    @staticmethod
    def dedupe_info_disclosure(validated_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merge CONFIRMED Information Disclosure findings by URL so report is not inflated.
        Keeps one merged record + appends evidence list.

        Only merges:
          - vuln_class == "Information Disclosure"
          - validation_status == "confirmed"
          - same url
        """
        merged: Dict[str, Dict[str, Any]] = {}
        out: List[Dict[str, Any]] = []

        for f in validated_findings:
            vuln_class = f.get("vuln_class")
            status = f.get("validation_status")
            url = (f.get("url") or "").strip()

            if vuln_class == "Information Disclosure" and status == "confirmed" and url:
                key = url.lower()

                if key not in merged:
                    base = dict(f)
                    base["evidence_list"] = []
                    if base.get("evidence"):
                        base["evidence_list"].append(base["evidence"])
                    merged[key] = base
                else:
                    if f.get("evidence"):
                        merged[key]["evidence_list"].append(f["evidence"])

                    # keep strongest severity
                    sev_rank = {"high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
                    cur = merged[key].get("final_severity", "low")
                    new = f.get("final_severity", "low")
                    if sev_rank.get(new, 1) > sev_rank.get(cur, 1):
                        merged[key]["final_severity"] = new

                    # keep highest confidence
                    merged[key]["confidence_score"] = max(
                        float(merged[key].get("confidence_score") or 0.0),
                        float(f.get("confidence_score") or 0.0),
                    )

                    # merge correlation tools
                    m_corr = merged[key].get("correlation") or {}
                    f_corr = f.get("correlation") or {}
                    m_tools = set(m_corr.get("tools") or [])
                    f_tools = set(f_corr.get("tools") or [])
                    all_tools = sorted(m_tools | f_tools)
                    merged[key]["correlation"] = {
                        "tool_count": len(all_tools) if all_tools else int(m_corr.get("tool_count") or 1),
                        "tools": all_tools if all_tools else (m_corr.get("tools") or []),
                    }

                continue

            out.append(f)

        out.extend(merged.values())
        return out

    @staticmethod
    def dedupe_by_key(validated_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generic dedupe:
        - Merge duplicates by (vuln_class + url + evidence signature)
        - Keeps the highest confidence and strongest final severity
        - Appends evidence_list for audit.

        ✅ FIXED HERE:
        evidence_list is de-duplicated using canonicalized evidence (whitespace normalized)
        so repeated Nuclei results don't inflate evidence_list.
        """
        sev_rank = {"high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}

        def canon(s: str) -> str:
            return " ".join((s or "").split()).strip()

        merged: Dict[str, Dict[str, Any]] = {}
        out: List[Dict[str, Any]] = []

        for f in validated_findings:
            url = (f.get("url") or "").strip().lower()
            vuln = (f.get("vuln_class") or "").strip().lower()

            ev_raw = f.get("evidence") or ""
            ev_clean = canon(ev_raw)

            # evidence signature (finding_name=...) but canonicalized
            sig = canon(ev_raw.split("|")[0] if "|" in ev_raw else ev_raw).lower()

            key = f"{vuln}::{url}::{sig}"

            if not url:
                out.append(f)
                continue

            if key not in merged:
                base = dict(f)
                base["evidence_list"] = []
                if ev_clean:
                    base["evidence_list"].append(ev_clean)
                merged[key] = base
                continue

            # Merge into existing (no duplicates)
            if ev_clean and ev_clean not in merged[key]["evidence_list"]:
                merged[key]["evidence_list"].append(ev_clean)

            # Highest confidence wins
            merged[key]["confidence_score"] = max(
                float(merged[key].get("confidence_score") or 0.0),
                float(f.get("confidence_score") or 0.0),
            )

            # Strongest final severity wins
            cur = merged[key].get("final_severity", "low")
            new = f.get("final_severity", "low")
            if sev_rank.get(new, 0) > sev_rank.get(cur, 0):
                merged[key]["final_severity"] = new

            # Prefer confirmed over manual
            if merged[key].get("validation_status") != "confirmed" and f.get("validation_status") == "confirmed":
                merged[key]["validation_status"] = "confirmed"
                merged[key]["validation_reason"] = f.get("validation_reason")

        out.extend(merged.values())
        return out

    def validate_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        raw = extract_raw_findings(report)
        normalized = normalize_findings(raw)

        validated_findings: List[Dict[str, Any]] = []

        for nf in normalized:
            validator = self.validators.get(nf.vuln_class, self.validators["Other"])
            vr = validator.validate(nf, self.client)

            validated_findings.append(
                {
                    "vuln_class": nf.vuln_class,
                    "original_tool": nf.original_tool,
                    "severity": nf.severity,
                    "url": nf.url,
                    "evidence": nf.evidence,
                    "validation_status": vr.validation_status,
                    "validation_reason": vr.validation_reason,
                    "confidence_score": self._get_confidence(vr),
                }
            )

        # Feature 1: Evidence correlation (post-process confidence + reason)
        validated_findings = apply_evidence_correlation(validated_findings, normalized)

        # Feature 2: Severity recalculation (post-validation)
        for vf in validated_findings:
            self.apply_confidence_resolution(vf)

            corr = vf.get("correlation") or {}
            tool_count = int(corr.get("tool_count") or 1)

            vf["final_severity"] = recalc_final_severity(
                validation_status=vf.get("validation_status", ""),
                confidence_score=float(vf.get("confidence_score") or 0.0),
                correlation_tool_count=tool_count,
            )

        # Professional polish: merge duplicate confirmed info-disclosure by URL
        validated_findings = self.dedupe_info_disclosure(validated_findings)

        # ✅ Generic dedupe (fixes your duplicated evidence_list issue)
        validated_findings = self.dedupe_by_key(validated_findings)

        # summary (audit-friendly)
        summary = self._build_summary(validated_findings)

        confirmed = [f for f in validated_findings if f.get("validation_status") == "confirmed"]
        manual = [f for f in validated_findings if f.get("validation_status") == "needs_manual_review"]
        rejected = [f for f in validated_findings if f.get("validation_status") == "false_positive"]

        return {
            "summary": summary,
            "validated_findings": validated_findings,
            "confirmed_findings": confirmed,
            "manual_review_findings": manual,
            "rejected_false_positives": rejected,
        }

    @staticmethod
    def _build_summary(validated_findings: List[Dict[str, Any]]) -> Dict[str, int]:
        total = len(validated_findings)
        confirmed = sum(1 for f in validated_findings if f.get("validation_status") == "confirmed")
        false_positive = sum(1 for f in validated_findings if f.get("validation_status") == "false_positive")
        needs_manual_review = sum(1 for f in validated_findings if f.get("validation_status") == "needs_manual_review")

        return {
            "total_findings": total,
            "confirmed": confirmed,
            "false_positive": false_positive,
            "needs_manual_review": needs_manual_review,
        }

    def run(self, input_path: str, output_path: str) -> Dict[str, Any]:
        report = self.load_report(input_path)
        validated = self.validate_report(report)
        self.save(output_path, validated)
        return validated

    @staticmethod
    def save(path: str, data: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def apply_confidence_resolution(vf: dict) -> None:
        """
        Only auto-resolve findings that are *testable*.
        Never auto-mark false_positive if validation couldn't happen (timeouts/no-url/etc).
        """
        status = vf.get("validation_status")
        confidence = float(vf.get("confidence_score", 0.0))
        reason = (vf.get("validation_reason") or "").lower()

        if status != "needs_manual_review":
            return

        untestable_markers = [
            "no url",
            "cannot",
            "requires a parameterized endpoint",
            "no query parameters",
            "request failed",
            "timeout",
            "network",
            "rate limited",
            "proxy",
        ]
        if any(m in reason for m in untestable_markers):
            return

        if confidence < 0.4:
            vf["validation_reason"] = (vf.get("validation_reason") or "") + " (Low confidence → keep manual review)"
            return

        if confidence > 0.8:
            vf["validation_status"] = "confirmed"
            vf["validation_reason"] = (vf.get("validation_reason") or "") + " (Auto-resolved: high confidence)"
            return


def main() -> None:
    parser = argparse.ArgumentParser(description="Validation Engine")
    parser.add_argument("--input", required=True, help="Path to combined_report_raw.json / .jsonl")
    parser.add_argument("--output", required=True, help="Path to output validated report JSON")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds for validation requests")
    args = parser.parse_args()

    ve = ValidationEngine(timeout=args.timeout)
    ve.run(args.input, args.output)
    print(f"[+] Validated report written to: {args.output}")


if __name__ == "__main__":
    main()
