#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Tuple

# -----------------------------
# Helpers: safe get + normalize
# -----------------------------
def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def norm_str(x: Any) -> str:
    return str(x).strip()

def norm_lower(x: Any) -> str:
    return norm_str(x).lower()

def clamp01(x: Any) -> float:
    try:
        v = float(x)
    except Exception:
        return 0.0
    if v < 0:
        return 0.0
    if v > 1:
        return 1.0
    return v

# -----------------------------
# Flexible field extraction
# -----------------------------
def pick_first(d: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """Return the first existing non-empty value from possible keys."""
    for k in keys:
        if k in d and d.get(k) not in (None, "", [], {}):
            return d.get(k)
    return default

def extract_findings(validated_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Support different layouts."""
    for key in ["validated_findings", "findings", "results", "items"]:
        v = validated_doc.get(key)
        if isinstance(v, list):
            return v
    return []

# -----------------------------
# Scoring model (0-100)
# -----------------------------
SEVERITY_SCORE = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 5,
    "informational": 5,
}

STATUS_SCORE = {
    "confirmed": 25,
    "needs_manual_review": 10,
    "manual_review": 10,
    "unknown": 10,
    "false_positive": 0,
}

def severity_points(sev: str) -> int:
    s = norm_lower(sev)
    return SEVERITY_SCORE.get(s, 5)

def status_points(status: str) -> int:
    s = norm_lower(status)
    return STATUS_SCORE.get(s, 10)

def evidence_points(evidence_count: int) -> int:
    if evidence_count <= 0:
        return 0
    if evidence_count == 1:
        return 5
    if evidence_count == 2:
        return 10
    return 15

# -----------------------------
# CVSS estimation + exploit status
# -----------------------------
def estimate_cvss(item: Dict[str, Any]) -> float:
    """
    Estimate CVSS base score (0.0-10.0) using severity + vuln_class mapping.
    Fix A: cap INFO/LOW so recon doesn't become critical.
    Fix B: detect WAF/tech detections in evidence and cap them.
    """
    sev = norm_lower(pick_first(item, ["final_severity", "normalized_severity", "severity"], "info"))
    vclass = norm_lower(pick_first(item, ["vuln_class", "category", "type"], ""))

    base = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.0,
        "info": 1.0,
        "informational": 1.0,
    }.get(sev, 1.0)

    # Adjust by vuln type (only if it is not a recon/tech detection)
    if "rce" in vclass or "command" in vclass:
        base = max(base, 9.0)
    elif "injection" in vclass or "sqli" in vclass:
        base = max(base, 8.5)
    elif "xss" in vclass:
        base = max(base, 6.1)
    elif "information disclosure" in vclass or "tech" in vclass:
        base = min(base, 4.0)

    # ---------- Fix B: cap tech/recon detections by checking evidence text ----------
    ev_text = str(item.get("evidence", "")).lower()
    ev_list = item.get("evidence_list", [])
    if isinstance(ev_list, list):
        ev_text += " " + " ".join(str(x).lower() for x in ev_list)

    tech_markers = [
        "waf detection",
        "technology detected",
        "tech detected",
        "fingerprint",
        "whatweb",
        "server:",
        "x-powered-by",
        "header",
        "headers",
        "information disclosure via http headers",
    ]
    if any(m in ev_text for m in tech_markers):
        base = min(base, 4.0)

    # ---------- Fix A: cap based on severity so INFO/LOW never becomes critical ----------
    if sev in ["info", "informational"]:
        base = min(base, 4.0)
    elif sev == "low":
        base = min(base, 5.0)

    # clamp
    if base < 0:
        base = 0.0
    if base > 10:
        base = 10.0

    return round(base, 1)

def exploit_status(item: Dict[str, Any]) -> str:
    """
    Exploit availability indicator:
    - known: explicit exploit/PoC reference detected
    - likely: confirmed + high-impact vuln class (SQLi/RCE/etc.)
    - unknown: otherwise
    """
    refs_text = ""

    ev_list = item.get("evidence_list", [])
    if isinstance(ev_list, list):
        refs_text += " ".join(str(x) for x in ev_list)

    if isinstance(item.get("evidence"), str):
        refs_text += " " + item["evidence"]

    refs_text = refs_text.lower()

    exploit_markers = ["exploit-db", "packetstorm", "metasploit", "poc", "proof of concept", "github.com"]
    if any(m in refs_text for m in exploit_markers):
        return "known"

    status = norm_lower(pick_first(item, ["validation_status", "status"], "needs_manual_review"))
    vclass = norm_lower(pick_first(item, ["vuln_class", "category", "type"], ""))

    if status == "confirmed" and ("injection" in vclass or "sqli" in vclass or "rce" in vclass or "command" in vclass):
        return "likely"

    return "unknown"

def exploit_bonus(status: str) -> int:
    if status == "known":
        return 5
    if status == "likely":
        return 2
    return 0

# -----------------------------
# Priority scoring
# -----------------------------
def compute_priority_score(item: Dict[str, Any]) -> Tuple[int, List[str], Dict[str, Any]]:
    reasons: List[str] = []
    sev = pick_first(item, ["final_severity", "normalized_severity", "severity", "risk", "level"], "INFO")
    status = pick_first(item, ["validation_status", "status", "validated_status"], "needs_manual_review")

    conf_raw = pick_first(item, ["confidence", "confidence_score", "score", "validator_confidence"], 0.0)
    try:
        conf_val = float(conf_raw)
    except Exception:
        conf_val = 0.0

    if conf_val > 1.0:
        conf_val = conf_val / 100.0
    conf_val = clamp01(conf_val)

    evidence_list = pick_first(item, ["evidence_list", "evidence", "proof", "matches", "references"], [])
    if isinstance(evidence_list, list):
        ecount = len(evidence_list)
    else:
        ecount = int(pick_first(item, ["evidence_count", "correlation_count"], 0) or 0)

    corr = item.get("correlation", {}) or {}
    tool_count = int(corr.get("tool_count", 0) or 0)
    if tool_count >= 2:
        ecount = max(ecount, tool_count)

    sev_pts = severity_points(sev)
    stat_pts = status_points(status)
    conf_pts = int(round(conf_val * 20))
    ev_pts = evidence_points(ecount)

    reasons.append(f"Severity={norm_str(sev)} (+{sev_pts})")
    reasons.append(f"Validation={norm_str(status)} (+{stat_pts})")
    reasons.append(f"Confidence={conf_val:.2f} (+{conf_pts})")
    reasons.append(f"EvidenceCount={ecount} (+{ev_pts})")

    total = sev_pts + stat_pts + conf_pts + ev_pts

    # ---- Estimated CVSS + exploit (proposal objective) ----
    cvss_est = estimate_cvss(item)
    ex_status = exploit_status(item)
    ex_bonus = exploit_bonus(ex_status)

    risk_score = min(100, int(round(cvss_est * 10)) + ex_bonus)

    reasons.append(f"CVSS_estimated={cvss_est:.1f}")
    reasons.append(f"Exploit={ex_status} (+{ex_bonus})")

    breakdown = {
        "severity_points": sev_pts,
        "status_points": stat_pts,
        "confidence_points": conf_pts,
        "evidence_points": ev_pts,
        "cvss_estimated": cvss_est,
        "exploit_status": ex_status,
        "exploit_bonus": ex_bonus,
        "risk_score": risk_score,
    }
    return total, reasons, breakdown

def label_from_score(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"

# -----------------------------
# Build prioritized report
# -----------------------------
def build_prioritized_report(validated_doc: Dict[str, Any]) -> Dict[str, Any]:
    findings = extract_findings(validated_doc)

    prioritized: List[Dict[str, Any]] = []
    dropped_false_pos = 0

    for idx, item in enumerate(findings, start=1):
        status = pick_first(item, ["validation_status", "status", "validated_status"], "needs_manual_review")
        if norm_lower(status) == "false_positive":
            dropped_false_pos += 1
            continue

        score, reasons, breakdown = compute_priority_score(item)

        # label based on risk_score first
        label = label_from_score(int(breakdown.get("risk_score", score) or score))

        fid = pick_first(item, ["id", "finding_id"], f"F-{idx:04d}")

        enriched = dict(item)
        enriched["finding_id"] = fid
        enriched["priority_score"] = score
        enriched["priority_label"] = label
        enriched["priority_reasons"] = reasons
        enriched["priority_breakdown"] = breakdown
        enriched["cvss_estimated"] = breakdown.get("cvss_estimated")
        enriched["exploit_status"] = breakdown.get("exploit_status")
        enriched["risk_score"] = breakdown.get("risk_score")

        prioritized.append(enriched)

    prioritized.sort(key=lambda x: (x.get("risk_score", 0), x.get("priority_score", 0)), reverse=True)

    summary = {"total_prioritized": len(prioritized), "dropped_false_positives": dropped_false_pos, "p1": 0, "p2": 0, "p3": 0, "p4": 0}
    for p in prioritized:
        lbl = p.get("priority_label", "P4")
        if lbl == "P1":
            summary["p1"] += 1
        elif lbl == "P2":
            summary["p2"] += 1
        elif lbl == "P3":
            summary["p3"] += 1
        else:
            summary["p4"] += 1

    out = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "input_summary": validated_doc.get("summary", {}),
        "scan_info": validated_doc.get("scan_info", validated_doc.get("scan", {})),
        "prioritization_model": {
            "priority_score_weights": {
                "severity": 40,
                "validation_status": 25,
                "confidence": 20,
                "evidence": 15
            },
            "risk_score_model": "risk_score = min(100, round(cvss_estimated*10) + exploit_bonus)",
            "exploit_bonus": {"known": 5, "likely": 2, "unknown": 0},
            "labels": {"P1": ">=80", "P2": "60-79", "P3": "40-59", "P4": "<40"},
        },
        "summary": summary,
        "prioritized_findings": prioritized,
    }
    return out

# -----------------------------
# CLI
# -----------------------------
def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 prioritize_findings.py <validated_report.json>")
        return 1

    in_path = sys.argv[1]
    validated = load_json(in_path)

    out_doc = build_prioritized_report(validated)

    out_dir = os.path.dirname(os.path.abspath(in_path)) or "."
    out_path = os.path.join(out_dir, "prioritized_report.json")
    save_json(out_path, out_doc)

    print("[+] Prioritized report saved:", out_path)
    print("[+] Summary:", out_doc["summary"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
