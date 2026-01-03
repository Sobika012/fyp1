#!/usr/bin/env python3
"""
Automated Vulnerability Discovery, Validation & Prioritization Pipeline (AVDVP)

Two-Phase Scanning Architecture:
- Phase 1 (Reconnaissance): Fast, low-risk signal detection (WhatWeb, Nuclei)
- Phase 2 (Deep Scan): Active testing and confirmation (Nikto, Wapiti, SQLMap, FFUF, ZAP)

Phase 2 requires explicit --deep-scan flag. No auto-triggering.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import requests

# ZAP fast-mode configuration
ZAP_PORT = 8090
ZAP_API = f"http://127.0.0.1:{ZAP_PORT}"
ZAP_CMD = [
    "zaproxy",
    "-daemon",
    "-port",
    str(ZAP_PORT),
    "-config",
    "api.disablekey=true",
    "-config",
    "ajaxSpider.enabled=false",
    "-config",
    "spider.maxDepth=2",
    "-config",
    "ascan.policy=Default",
    "-config",
    "ascan.maxScanDuration=180",
    "-config",
    "ascan.maxRuleDuration=15",
]

# Per-tool timeouts (seconds)
# Phase 1 tools: short timeouts for fast reconnaissance
# Phase 2 tools: longer timeouts for thorough deep scanning
TIMEOUTS = {
    "whatweb": 120,      # Phase 1: Tech fingerprinting (fast)
    "nuclei": 180,       # Phase 1: Template-based detection (low/medium only)
    "nikto": 240,        # Phase 2: Server misconfiguration checks
    "wapiti": 300,       # Phase 2: Application vulnerability scanning
    "sqlmap": 300,       # Phase 2: SQL injection testing (if parameters exist)
    "ffuf": 240,         # Phase 2: Directory fuzzing
    "zap": 480,          # Phase 2: Full dynamic analysis (spider + active scan)
}


def save_json(path, data):
    """Save data as JSON to the specified path."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON saved to: {path}")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[-] Error saving JSON to {path}: {exc}")


def run_command(cmd, timeout, cwd=None):
    """Run a command with timeout; return stdout/stderr/returncode/timeout flags."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {"stdout": exc.stdout or "", "stderr": exc.stderr or "", "returncode": None, "timeout": True}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "command not found", "returncode": None, "timeout": False}
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc), "returncode": None, "timeout": False}


def create_output_dir(target):
    """Create a timestamped output directory for scan results."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w\-_.]", "_", target.replace("://", "_"))
    path = os.path.join("scans", "output", f"{timestamp}_{safe_target}")
    os.makedirs(path, exist_ok=True)
    return path


def has_parameters(target):
    """Return True if URL has query parameters."""
    try:
        return bool(parse_qs(urlparse(target).query))
    except Exception:
        return False






# ------------------------- Scanner Functions ------------------------- #

def run_nikto(target, output_dir):
    """Phase 2: Server misconfiguration and header analysis."""
    print(f"\n[+] Nikto -> {target}")
    out_file = os.path.join(output_dir, "nikto.txt")
    cmd = ["nikto", "-h", target, "-Tuning", "x", "-o", out_file]
    res = run_command(cmd, timeout=TIMEOUTS["nikto"])

    result = {
        "status": "timeout" if res["timeout"] else ("completed" if res["returncode"] == 0 else "completed_with_errors"),
        "output_file": out_file,
        "findings": [],
    }
    if res["stderr"]:
        result["stderr"] = res["stderr"][:1500]
    if res["timeout"]:
        return result

    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = [ln.strip() for ln in f if ln.strip().startswith("+")]
            result["findings"] = lines[:100]
            result["summary"] = {"total_findings": len(lines)}
        except Exception as exc:
            result["error"] = str(exc)
    else:
        result["error"] = "missing output file"
    return result


def run_wapiti(target, output_dir):
    """Phase 2: Application vulnerability scanning (xss,sql,file,exec modules, depth=2)."""
    print(f"\n[+] Wapiti -> {target}")
    out_file = os.path.join(output_dir, "wapiti.json")
    cmd = [
        "wapiti",
        "-u",
        target,
        "-m",
        "xss,sql,file,exec",  # Focused modules only
        "-d",
        "2",  # Shallow crawl depth
        "-f",
        "json",
        "-o",
        out_file,
    ]
    res = run_command(cmd, timeout=TIMEOUTS["wapiti"])

    result = {
        "status": "timeout" if res["timeout"] else ("completed" if res["returncode"] == 0 else "completed_with_errors"),
        "output_file": out_file,
        "vulnerabilities": [],
    }
    if res["stderr"]:
        result["stderr"] = res["stderr"][:1500]
    if res["timeout"]:
        return result

    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            vulns = []
            if isinstance(data, dict):
                for vtype, entries in data.items():
                    if isinstance(entries, list):
                        for entry in entries:
                            if isinstance(entry, dict):
                                vulns.append(
                                    {
                                        "type": vtype,
                                        "url": entry.get("url", ""),
                                        "parameter": entry.get("parameter", ""),
                                        "method": entry.get("method", ""),
                                    }
                                )
            result["vulnerabilities"] = vulns
            result["summary"] = {
                "total_vulnerabilities": len(vulns),
                "types": sorted({v["type"] for v in vulns if v.get("type")}),
            }
        except Exception as exc:
            result["error"] = str(exc)
    else:
        result["error"] = "missing output file"
    return result


def run_sqlmap(target, output_dir):
    """Phase 2: SQL injection testing (only if URL has parameters, risk=1, level=1)."""
    print(f"\n[+] SQLMap -> {target}")
    if not has_parameters(target):
        return {"status": "skipped", "reason": "URL has no query parameters", "phase": 2}

    sql_dir = os.path.join(output_dir, "sqlmap")
    os.makedirs(sql_dir, exist_ok=True)
    cmd = ["sqlmap", "-u", target, "--batch", "--risk=1", "--level=1", "--output-dir", sql_dir]
    res = run_command(cmd, timeout=TIMEOUTS["sqlmap"])

    result = {
        "status": "timeout" if res["timeout"] else ("completed" if res["returncode"] == 0 else "completed_with_errors"),
        "output_dir": sql_dir,
        "summary": {},
    }
    if res["stderr"]:
        result["stderr"] = res["stderr"][:1500]
    if res["timeout"]:
        return result

    log_file = os.path.join(sql_dir, "log")
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                result["summary"]["log_preview"] = f.read()[:2000]
        except Exception as exc:
            result["error"] = str(exc)
    result["summary"]["output_files"] = sorted(os.listdir(sql_dir))
    return result


def zap_running():
    try:
        r = requests.get(f"{ZAP_API}/JSON/core/view/version/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def start_zap():
    if zap_running():
        print("[+] ZAP already running")
        return True
    print("[+] Starting ZAP (fast mode)")
    res = run_command(ZAP_CMD, timeout=30)
    if res["stderr"] and "command not found" in res["stderr"]:
        print("[-] zaproxy not found in PATH")
        return False
    for _ in range(120):
        if zap_running():
            print("[+] ZAP is up")
            return True
        time.sleep(2)
    print("[-] ZAP failed to start in time")
    return False




def run_zap(target, output_dir):
    """Phase 2: Full dynamic analysis (spider depth=2 + active scan)."""
    print(f"\n[+] OWASP ZAP -> {target}")
    if not start_zap():
        return {"status": "error", "message": "ZAP not available"}

    result = {"status": "completed", "output_file": None, "vulnerabilities": []}
    try:
        session = f"scan_{int(time.time())}"
        requests.get(f"{ZAP_API}/JSON/core/action/newSession/", params={"name": session}, timeout=10)

        spider_id = requests.get(
            f"{ZAP_API}/JSON/spider/action/scan/",
            params={"url": target, "maxChildren": 0, "recurse": True},
            timeout=10,
        ).json().get("scan")
        while True:
            status = requests.get(
                f"{ZAP_API}/JSON/spider/view/status/", params={"scanId": spider_id}, timeout=10
            ).json().get("status")
            if status and int(status) >= 100:
                break
            time.sleep(2)

        ascan_id = requests.get(
            f"{ZAP_API}/JSON/ascan/action/scan/", params={"url": target, "recurse": True}, timeout=10
        ).json().get("scan")
        while True:
            status = requests.get(
                f"{ZAP_API}/JSON/ascan/view/status/", params={"scanId": ascan_id}, timeout=10
            ).json().get("status")
            if status and int(status) >= 100:
                break
            time.sleep(3)

        report_file = os.path.join(output_dir, "zap_report.html")
        report = requests.get(f"{ZAP_API}/OTHER/core/other/htmlreport/", timeout=30)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report.text)
        result["output_file"] = report_file

        alerts = requests.get(
            f"{ZAP_API}/JSON/core/view/alerts/", params={"baseurl": target, "start": 0, "count": 9999}, timeout=20
        ).json().get("alerts", [])
        vulns = []
        for a in alerts:
            vulns.append(
                {
                    "name": a.get("name", ""),
                    "risk": a.get("risk", ""),
                    "confidence": a.get("confidence", ""),
                    "url": a.get("url", ""),
                    "description": (a.get("description") or "")[:200],
                }
            )
        result["vulnerabilities"] = vulns
        result["summary"] = {
            "total_alerts": len(vulns),
            "high": len([v for v in vulns if v.get("risk", "").lower() == "high"]),
            "medium": len([v for v in vulns if v.get("risk", "").lower() == "medium"]),
            "low": len([v for v in vulns if v.get("risk", "").lower() == "low"]),
        }
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    return result


def run_ffuf(target, output_dir):
    """Phase 2: Directory fuzzing (small wordlist, HTTP 200/301/302 only)."""
    print(f"\n[+] FFUF -> {target}")
    out_file = os.path.join(output_dir, "ffuf.json")
    cmd = [
        "ffuf",
        "-u",
        f"{target.rstrip('/')}/FUZZ",
        "-w",
        "/usr/share/wordlists/dirb/common.txt",  # Small wordlist for speed
        "-o",
        out_file,
        "-of",
        "json",
    ]
    res = run_command(cmd, timeout=TIMEOUTS["ffuf"])

    result = {
        "status": "timeout" if res["timeout"] else ("completed" if res["returncode"] == 0 else "completed_with_errors"),
        "output_file": out_file,
        "paths": [],
    }
    if res["stderr"]:
        result["stderr"] = res["stderr"][:1500]
    if res["timeout"]:
        return result

    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            results = data.get("results", []) if isinstance(data, dict) else []
            paths = []
            for item in results:
                url = item.get("url")
                status = item.get("status")
                length = item.get("length")
                # keep only meaningful HTTP codes to reduce noise
                if url and status in (200, 301, 302):
                    paths.append(f"{url} (Status: {status}, Length: {length})")
            result["paths"] = paths
            result["summary"] = {"total_paths": len(paths)}
        except Exception as exc:
            result["error"] = str(exc)
    else:
        result["error"] = "missing output file"
    return result




def run_nuclei(target, output_dir):
    """Phase 1: Template-based detection (low/medium, misconfig/exposure/backup only)."""
    print(f"\n[+] Nuclei -> {target}")
    out_file = os.path.join(output_dir, "nuclei.jsonl")
    cmd = [
        "nuclei",
        "-u",
        target,
        "-severity",
        "low,medium",  # Strict: no high/critical in Phase 1
        "-tags",
        "misconfig,exposure,backup",  # Strict: only safe detection categories
        "-jsonl",
        "-o",
        out_file,
        "-silent",
    ]
    res = run_command(cmd, timeout=TIMEOUTS["nuclei"])

    result = {
        "status": "timeout" if res["timeout"] else ("completed" if res["returncode"] == 0 else "completed_with_errors"),
        "output_file": out_file,
        "findings": [],
    }
    if res["stderr"]:
        result["stderr"] = res["stderr"][:2000]
    if res["timeout"]:
        return result

    if os.path.exists(out_file):
        try:
            findings = []
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        findings.append(
                            {
                                "template": entry.get("template-id", ""),
                                "severity": entry.get("info", {}).get("severity", ""),
                                "matcher": entry.get("matcher-name", ""),
                                "type": entry.get("type", ""),
                                "host": entry.get("host", ""),
                                "path": entry.get("matched-at", entry.get("matched", "")),
                            }
                        )
                    except json.JSONDecodeError:
                        # If non-JSON lines appear, keep minimal info
                        findings.append({"raw": line})
            result["findings"] = findings
            result["summary"] = {
                "total_findings": len(findings),
                "by_severity": {
                    "low": len([f for f in findings if f.get("severity", "").lower() == "low"]),
                    "medium": len([f for f in findings if f.get("severity", "").lower() == "medium"]),
                },
            }
        except Exception as exc:
            result["error"] = str(exc)
    else:
        result["error"] = "output file missing"
    return result


def run_whatweb(target, output_dir):
    """Phase 1: Technology fingerprinting (reads headers, no active testing)."""
    print(f"\n[+] WhatWeb -> {target}")
    out_file = os.path.join(output_dir, "whatweb.txt")
    cmd = [
    "whatweb",
    "--no-errors",
    "--log-brief", out_file,
    target
    ]

    res = run_command(cmd, timeout=TIMEOUTS["whatweb"])

    result = {
        "status": "timeout" if res["timeout"] else ("completed" if res["returncode"] == 0 else "completed_with_errors"),
        "output_file": out_file,
        "fingerprint": {},
    }
    if res["stderr"]:
        result["stderr"] = res["stderr"][:1500]
    if res["timeout"]:
        return result

    # Simple parsing for tech hints
     # Read WhatWeb output from file (since --log-brief writes directly)
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
                if content:
                    result["fingerprint"]["raw"] = content
        except Exception:
            pass

    return result


# ------------------------- Orchestration ------------------------- #

def run_phase1_reconnaissance(target, output_dir):
    """Phase 1: Fast reconnaissance (WhatWeb, Nuclei). Target: 1-2 minutes."""
    print("\n" + "=" * 70)
    print(f"Phase 1: Reconnaissance - {target}")
    print("=" * 70)

    results = {}
    results["whatweb"] = run_whatweb(target, output_dir)
    results["nuclei"] = run_nuclei(target, output_dir)
    # Note: Subdomain enumeration deferred to future scope expansion
    
    return results


def run_phase2_deep_scan(target, output_dir):
    """Phase 2: Deep scan (Nikto, Wapiti, SQLMap, FFUF, ZAP). Target: 6-10 minutes."""
    print("\n" + "=" * 70)
    print(f"Phase 2: Deep Scan - {target}")
    print("=" * 70)

    results = {}
    results["nikto"] = run_nikto(target, output_dir)
    results["wapiti"] = run_wapiti(target, output_dir)
    results["sqlmap"] = run_sqlmap(target, output_dir)
    results["ffuf"] = run_ffuf(target, output_dir)
    results["zap"] = run_zap(target, output_dir)
    
    return results
def build_overall_summary(phase1, phase2):
    summary = {
        "total_vulnerabilities": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0},
        "by_source": {},
    }

    # -------- Phase 1: Nuclei --------
    nuclei = phase1.get("nuclei", {})
    findings = nuclei.get("findings", [])
    summary["by_source"]["nuclei"] = len(findings)

    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1
            summary["total_vulnerabilities"] += 1

    # -------- Phase 2: Nikto --------
    nikto = phase2.get("nikto", {})
    nikto_findings = nikto.get("findings", [])
    summary["by_source"]["nikto"] = len(nikto_findings)

    # Nikto findings are mostly LOW/MEDIUM
    summary["by_severity"]["low"] += len(nikto_findings)
    summary["total_vulnerabilities"] += len(nikto_findings)

    # -------- Phase 2: Others --------
    for tool in ["wapiti", "sqlmap", "zap"]:
        tool_data = phase2.get(tool, {})
        vulns = tool_data.get("vulnerabilities", [])
        summary["by_source"][tool] = len(vulns)
        summary["total_vulnerabilities"] += len(vulns)

    summary["notes"] = (
        "Summary aggregates unique findings from all scanners. "
        "Directory enumeration and informational paths are excluded."
    )

    return summary


def run_all_scanners(target, deep_scan=False):
    """Main orchestration: Phase 1 (always) and Phase 2 (if --deep-scan)."""
    print("\n" + "=" * 70)
    print(f"Starting scan for: {target}")
    print(f"Mode: Phase 1 only" if not deep_scan else "Mode: Phase 1 + Phase 2")
    print("=" * 70)

    output_dir = create_output_dir(target)

    # Phase 1: Reconnaissance (always runs)
    phase1_results = run_phase1_reconnaissance(target, output_dir)

    # Phase 2: Deep scan (only if explicitly requested)
    if deep_scan:
        phase2_results = run_phase2_deep_scan(target, output_dir)
    else:
        phase2_results = {
            "nikto": {"status": "skipped", "reason": "Phase 2 not requested"},
            "wapiti": {"status": "skipped", "reason": "Phase 2 not requested"},
            "sqlmap": {"status": "skipped", "reason": "Phase 2 not requested"},
            "ffuf": {"status": "skipped", "reason": "Phase 2 not requested"},
            "zap": {"status": "skipped", "reason": "Phase 2 not requested"},
        }

    # Structure output with clear phase separation
    results = {
        "scan_metadata": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "output_dir": output_dir,
            "phase1_completed": True,
            "phase2_completed": deep_scan,
        },
        "overall_summary": build_overall_summary(phase1_results, phase2_results),
        "phase1": phase1_results,
        "phase2": phase2_results,
    }

    combined_path = os.path.join(output_dir, "combined_report.json")
    save_json(combined_path, results)

    print("\n" + "=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print(f"Output dir: {output_dir}")
    print(f"Phase 1: Completed")
    print(f"Phase 2: {'Completed' if deep_scan else 'Skipped'}")
    print("=" * 70 + "\n")
    return results


def safety_confirmation():
    print("\n" + "!" * 60)
    print("WARNING: Scan only authorized targets.")
    print("Unauthorized scanning is illegal and unethical.")
    print("!" * 60)
    if input("Type YES to continue: ").strip() != "YES":
        print("[-] Scan aborted (authorization not confirmed).")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Automated Web Vulnerability Scanning Pipeline (safe modes)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="Target URL (e.g., http://192.168.56.104)")
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Run Phase 2 deep scan (Nikto, Wapiti, SQLMap, FFUF, ZAP full). Default: Phase 1 only (WhatWeb, Nuclei)."
    )
    args = parser.parse_args()

    if not safety_confirmation():
        sys.exit(1)

    try:
        run_all_scanners(args.target, deep_scan=args.deep_scan)
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        sys.exit(1)
    except Exception as exc:
        print(f"[-] Fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

