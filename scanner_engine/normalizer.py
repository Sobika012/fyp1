import re
from datetime import datetime


class Normalizer:
    """
    Universal schema normalizer for all integrated security tools.
    Every tool must return findings in this format.
    """

    # ==============================
    # Severity Weighting System
    # ==============================

    SEVERITY_WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 5,
        "LOW": 3,
        "INFO": 1
    }

    # ==============================
    # Helper: Severity -> Risk Score
    # ==============================

    @staticmethod
    def score_from_severity(severity: str) -> int:
        if not severity:
            return 1
        sev = str(severity).upper()
        return Normalizer.SEVERITY_WEIGHTS.get(sev, 1)

    # ==============================
    # Core Universal Schema Creator
    # ==============================

    @staticmethod
    def create_finding(tool, url, finding_name, severity, description, raw, category="general", confirmed=False):    
        """
        Creates standardized finding object.
        """
        severity = (severity or "INFO").upper()

        return {
            "tool": tool,
            "url": url,
            "finding_name": finding_name,
            "severity": severity,
            "risk_score": Normalizer.score_from_severity(severity),
            "category": category,
            "confirmed": bool(confirmed),
            "description": description,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "raw_output": raw
        }

    # ======================================================
    # NUCLEI PARSER (Improved category + honest severity)
    # ======================================================

    @staticmethod
    def from_nuclei(json_line):
        info = json_line.get("info", {}) or {}
        tags = set([str(t).lower() for t in (info.get("tags") or [])])
        template_path = (json_line.get("template-path") or "").lower()
        template_id = (json_line.get("template-id") or "").lower()
        ntype = (json_line.get("type") or "").lower()

        name = info.get("name", "Unknown Finding")
        desc = info.get("description", "") or ""

        raw_sev = (info.get("severity") or "info").lower()

        # -----------------------------
        # 1) Decide category bucket
        # -----------------------------
        category = "informational"

        # DNS / tech / discovery → recon
        if ntype == "dns" or "tech" in tags or "discovery" in tags or "/technologies/" in template_path:
            category = "reconnaissance"

        # Misconfiguration
        if "misconfig" in tags or "/misconfiguration/" in template_path or "missing-security-headers" in template_id:
            category = "misconfiguration"

        # Exposure
        if "exposure" in tags or "/exposures/" in template_path or "files" in tags:
            category = "exposure"

        # Vulnerability (actual vuln templates)
        vuln_tags = {
            "cve", "sqli", "xss", "rce", "lfi", "ssrf", "csrf", "xxe", "ssti", "open-redirect"
        }
        if (tags & vuln_tags) or "/vulnerabilities/" in template_path:
            category = "vulnerability"

        # -----------------------------
        # 2) Normalize severity
        # -----------------------------
        sev_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "unknown": "INFO"
        }
        severity = sev_map.get(raw_sev, "INFO")

        # Upgrade some common “info” findings that are real issues
        if category == "exposure" and severity == "INFO":
            severity = "MEDIUM"
        if category == "misconfiguration" and severity == "INFO":
            severity = "LOW"

        # -----------------------------
        # 3) confirmed flag
        # -----------------------------
        confirmed = False  # Nuclei findings are not “confirmed exploit” by default

        return Normalizer.create_finding(
            tool="nuclei",
            url=json_line.get("matched-at", "") or json_line.get("url", ""),
            finding_name=name,
            severity=severity,
            description=desc,
            raw=json_line,
            category=category,
            confirmed=confirmed
        )

    # ======================================================
    # FFUF PARSER (With Smart Severity Detection)
    # ======================================================

    @staticmethod
    def from_ffuf(result_dict):
        url = (result_dict.get("url", "") or "").lower()
        status = result_dict.get("status")
        length = result_dict.get("length")

        severity = "INFO"

        # Smart severity detection
        if any(keyword in url for keyword in ["admin", "login"]):
            severity = "MEDIUM"
        if any(keyword in url for keyword in [".env", "config", "backup", ".git"]):
            severity = "HIGH"
        if any(keyword in url for keyword in ["dump", "database", "sql"]):
            severity = "CRITICAL"

        return Normalizer.create_finding(
            tool="ffuf",
            url=result_dict.get("url", ""),
            finding_name="Hidden Resource Discovered",
            severity=severity,
            description=f"Status: {status} | Size: {length}",
            raw=result_dict,
            category="discovery",
            confirmed=False
        )

    # ======================================================
    # WHATWEB PARSER
    # ======================================================

    @staticmethod
    def from_whatweb(plugin_data):
        findings = []

        target = plugin_data.get("target", "")
        plugins = plugin_data.get("plugins", {}) or {}

        for tech_name, tech_details in plugins.items():
            description = f"Detected technology: {tech_name}"

            if isinstance(tech_details, dict):
                version = tech_details.get("version")
                if version:
                    description += f" (Version: {version})"

            findings.append(
                Normalizer.create_finding(
                    tool="whatweb",
                    url=target,
                    finding_name=f"Technology Detected: {tech_name}",
                    severity="INFO",
                    description=description,
                    raw=tech_details,
                    category="reconnaissance",
                    confirmed=False
                )
            )

        return findings

    # ======================================================
    # SQLMAP PARSER (Confirmed)
    # ======================================================

    @staticmethod
    def from_sqlmap(url, stdout):
        stdout_lower = (stdout or "").lower()

        vulnerable_patterns = [
            r"is vulnerable",
            r"appears to be injectable",
            r"parameter .* is vulnerable",
            r"sql injection vulnerability",
            r"back-end dbms"
        ]

        is_vulnerable = any(re.search(pattern, stdout_lower) for pattern in vulnerable_patterns)

        if is_vulnerable:
            return Normalizer.create_finding(
                tool="sqlmap",
                url=url,
                finding_name="SQL Injection Confirmed",
                severity="CRITICAL",
                description="SQLMap confirmed injectable parameter vulnerability.",
                raw=stdout,
                category="vulnerability",
                confirmed=True
            )

        return None

    # ======================================================
    # Generic Text Fallback
    # ======================================================

    @staticmethod
    def from_text(tool_name, url, raw_text, severity="INFO"):
        return Normalizer.create_finding(
            tool=tool_name,
            url=url,
            finding_name=f"{tool_name.capitalize()} Discovery",
            severity=severity,
            description=(raw_text or "").strip()[:300],
            raw=raw_text,
            category="general",
            confirmed=False
        )
