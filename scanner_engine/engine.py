import sys
import argparse
import logging
import os
import re
import json
import time
from http.cookies import SimpleCookie
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

from modules import whatweb, ffuf, nuclei, sqlmap, crawler
from deduplicator import Deduplicator
from builder import ReportBuilder

# ==============================
# CONFIGURATION (8GB SAFE MODE)
# ==============================

MAX_WORKERS = 3
SQLMAP_WORKERS = 1
MAX_SQLMAP_TARGETS = 4
OUTPUT_BASE_DIR = os.path.join("scans", "output")

# Mode budgets (seconds)
BASIC_BUDGET = 180     # 3 minutes
DEEP_BUDGET = 600      # 10 minutes

# Optional: in DEEP mode, scan some ffuf paths with nuclei (risk-based)
DEEP_SCAN_FFUF_PATHS = False
MAX_NUCLEI_FFUF_URLS = 20

# Risk keywords for selecting FFUF URLs for deep nuclei
RISK_KEYWORDS = (
    "admin", "login", "signin", "dashboard",
    ".env", ".git", "config", "backup", "db",
    "phpinfo", "console", "debug", "swagger",
    "api", "graphql", "wp-admin"
)

# ==============================
# LOGGING SETUP
# ==============================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)

# ==============================
# HELPER FUNCTIONS
# ==============================

def normalize_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url.strip())
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    final = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        final += f"?{parsed.query}"
    return final

def parse_data_param_names(data, is_json=False):
    if not data:
        return tuple()
    if is_json:
        try:
            parsed = json.loads(data)
            if isinstance(parsed, dict):
                return tuple(sorted([str(k) for k in parsed.keys()]))
        except Exception:
            return tuple()
    try:
        return tuple(sorted(parse_qs(data).keys()))
    except Exception:
        return tuple()

def normalize_sql_target(target):
    if isinstance(target, str):
        return {"type": "get", "url": normalize_url(target), "method": "GET"}
    if not isinstance(target, dict):
        return None
    out = dict(target)
    out["url"] = normalize_url(out.get("url", ""))
    out["method"] = str(out.get("method", "GET")).upper()
    return out

def dedupe_sql_targets(targets):
    seen = set()
    clean = []
    for target in targets:
        t = normalize_sql_target(target)
        if not t:
            continue
        url = t.get("url", "")
        method = t.get("method", "GET")
        is_json = bool(t.get("is_json", False))
        try:
            p = urlparse(url)
            if method == "GET":
                params = tuple(sorted(parse_qs(p.query).keys()))
            else:
                params = parse_data_param_names(t.get("data", ""), is_json=is_json)
            key = (p.netloc, p.path, method, params)
        except Exception:
            key = str(target)
        if key not in seen:
            seen.add(key)
            clean.append(t)
    return clean

def parse_cookie_string(cookie_string):
    if not cookie_string:
        return None
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_string)
    except Exception:
        return None
    out = {}
    for name, morsel in cookie.items():
        out[name] = morsel.value
    return out or None

def parse_headers_list(headers_list):
    if not headers_list:
        return None
    parsed = {}
    for item in headers_list:
        if not isinstance(item, str) or ":" not in item:
            continue
        k, v = item.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k and v:
            parsed[k] = v
    return parsed or None

def build_run_output_dir(target_url: str, scan_id: str | None = None) -> str:
    # If scan_id provided, use it directly (dashboard/API needs deterministic folder)
    if scan_id:
        run_dir = os.path.join(OUTPUT_BASE_DIR, scan_id)
        os.makedirs(run_dir, exist_ok=True)
        return run_dir

    # Otherwise keep your current behavior (timestamp-based folder)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_token = target_url.strip().replace("://", "_")
    target_token = re.sub(r"[^A-Za-z0-9._-]", "_", target_token)
    target_token = re.sub(r"_+", "_", target_token).strip("_")
    run_dir_name = f"{timestamp}_{target_token}_"
    run_dir = os.path.join(OUTPUT_BASE_DIR, run_dir_name)

    suffix = 1
    while os.path.exists(run_dir):
        run_dir = os.path.join(OUTPUT_BASE_DIR, f"{run_dir_name}{suffix}")
        suffix += 1

    os.makedirs(run_dir, exist_ok=False)
    return run_dir

def _time_left(deadline: float) -> int:
    return max(0, int(deadline - time.time()))

def select_risky_ffuf_urls(ffuf_findings):
    urls = []
    for f in ffuf_findings or []:
        url = (f.get("url") or "").lower()
        if not url:
            continue
        if any(k in url for k in RISK_KEYWORDS):
            urls.append(f.get("url"))
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:MAX_NUCLEI_FFUF_URLS]

# ==============================
# MAIN SCAN LOGIC
# ==============================

def run_automated_scan(target_url: str, mode: str = "basic", sqlmap_options=None, scan_id=None):
    all_findings = []
    run_dir = build_run_output_dir(target_url, scan_id=scan_id)
    budget = BASIC_BUDGET if mode == "basic" else DEEP_BUDGET
    deadline = time.time() + budget

    logger.info(f"🚀 STARTING OPTIMIZED SCAN ON: {target_url}")
    logger.info(f"[*] Mode: {mode.upper()}")
    logger.info(f"[*] Output directory: {run_dir}")

    # budget almost finished? exit early cleanly
    if _time_left(deadline) <= 10:
        logger.info("[-] No time left in budget. Exiting early.")
        return

    try:
        # ============================================
        # Phase 1–3: Parallel lightweight tools
        # ============================================
        logger.info("Phase 1-3: Running WhatWeb, FFUF, Nuclei in parallel...")

        discovered_ffuf_findings = []

        # ✅ FIXED nuclei timeout (THIS IS THE MAIN FIX)
        if mode == "basic":
            # give nuclei almost full budget, keep small buffer for reporting
            nuclei_timeout = min(170, max(60, _time_left(deadline) - 10))
        else:
            nuclei_timeout = min(300, max(120, _time_left(deadline) - 60))

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(whatweb.scan, target_url, run_dir): "whatweb",
                executor.submit(ffuf.scan, target_url, None, run_dir): "ffuf",
                executor.submit(nuclei.scan, target_url, None, False, run_dir, nuclei_timeout, mode): "nuclei"
            }

            for future in as_completed(futures):
                tool = futures[future]
                try:
                    result = future.result()
                    if result:
                        all_findings.extend(result)
                        if tool == "ffuf":
                            discovered_ffuf_findings = result
                    logger.info(f"[✓] {tool} completed.")
                except Exception as e:
                    logger.error(f"[!] Error in {tool}: {str(e)}")

        # ============================================
        # Phase 3.5: (DEEP optional) Nuclei scan on risky FFUF paths
        # ============================================
        if mode == "deep" and DEEP_SCAN_FFUF_PATHS and discovered_ffuf_findings and _time_left(deadline) > 60:
            risky_urls = select_risky_ffuf_urls(discovered_ffuf_findings)
            if risky_urls:
                logger.info(f"Phase 3.5: DEEP nuclei scan on {len(risky_urls)} risky FFUF URLs...")
                try:
                    extra = nuclei.scan(
                        target_url=None,
                        urls=risky_urls,
                        is_file_input=False,
                        output_dir=run_dir,
                        timeout=nuclei_timeout,
                        mode=mode
                    )
                    if extra:
                        all_findings.extend(extra)
                except Exception as e:
                    logger.error(f"[!] Error in deep nuclei-on-ffuf: {e}")

        # ============================================
        # Phase 4: SQL Injection Verification (DEEP only)
        # ============================================
        if mode == "basic":
            logger.info("Phase 4: SQL Injection verification skipped (basic mode)")
        else:
            logger.info("Phase 4: SQL Injection verification (deep mode)...")

            if _time_left(deadline) < 60:
                logger.info("[-] Not enough time left for SQLMap. Skipping.")
            else:
                sqli_targets = []

                logger.info(f"[*] Crawling {target_url} for parameterized links...")
                crawler_targets = crawler.crawl_sqlmap_targets(
                    target_url,
                    request_headers=(sqlmap_options or {}).get("request_headers"),
                    request_cookies=(sqlmap_options or {}).get("request_cookies")
                )

                if crawler_targets:
                    logger.info(f"[+] Crawler found {len(crawler_targets)} SQLMap-ready targets.")
                    sqli_targets.extend(crawler_targets)
                else:
                    logger.info("[-] Crawler found no SQLMap-ready targets.")

                for f in all_findings:
                    name = (f.get("finding_name") or "").lower()
                    url = f.get("url") or ""
                    if "sql" in name and "inject" in name and "?" in url:
                        sqli_targets.append({"type": "nuclei-suspect-get", "url": url, "method": "GET"})

                sqli_targets = dedupe_sql_targets(sqli_targets)[:MAX_SQLMAP_TARGETS]

                if not sqli_targets:
                    logger.info("[-] No SQLMap targets found.")
                else:
                    logger.info(f"[!] SQLMap targets selected: {len(sqli_targets)}")

                    with ThreadPoolExecutor(max_workers=SQLMAP_WORKERS) as executor:
                        futures = [
                            executor.submit(sqlmap.scan, target, run_dir, sqlmap_options)
                            for target in sqli_targets
                        ]
                        for future in as_completed(futures):
                            try:
                                result = future.result()
                                if result:
                                    all_findings.extend(result)
                            except Exception as e:
                                logger.error(f"[!] SQLMap error: {str(e)}")

        # ============================================
        # Phase 5: Save RAW + Deduplicate + Report
        # ============================================
        logger.info("Phase 5: Saving RAW findings, deduplicating and generating report...")

        # 1) Save RAW (no dedup)
        raw_path = os.path.join(run_dir, "combined_report_raw.json")
        ReportBuilder.save(all_findings, filename=raw_path)
        logger.info(f"[✓] Raw findings saved: {raw_path} (count={len(all_findings)})")

        # 2) Dedup (use your new MERGE deduplicator version)
        final_findings = Deduplicator.process(all_findings)
        logger.info(f"[✓] Total findings after deduplication: {len(final_findings)}")

        # 3) Save final deduped report (same as before)
        final_path = os.path.join(run_dir, "combined_report.json")
        ReportBuilder.save(final_findings, filename=final_path)

        # 4) Summary
        ReportBuilder.print_summary(final_findings)

        if not final_findings:
            logger.info("[*] No findings detected within the selected mode/time budget. Try DEEP mode for wider coverage.")
        
    except Exception as e:
        logger.error(f"FATAL ERROR: {str(e)}", exc_info=True)

    finally:
        logger.info("✅ Scan sequence finished.")

# ==============================
# ENTRY POINT
# ==============================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional Optimized Security Engine")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--mode", choices=["basic", "deep"], default="basic", help="Scan mode (default: basic)")
    parser.add_argument("--scan-id", default=None, help="Force output folder name (used by dashboard/API)")
    parser.add_argument("--auth-cookie", default=None, help="Cookie string for authenticated scans")
    parser.add_argument("--auth-header", action="append", default=[], help="Custom header, repeatable. Example: \"X-API-Key: value\"")
    parser.add_argument("--bearer-token", default=None, help="Bearer token for Authorization header")
    parser.add_argument("--tamper", default=None, help="SQLMap tamper scripts (comma-separated)")
    parser.add_argument("--sqlmap-delay", type=float, default=0, help="Delay between SQLMap requests (seconds)")
    parser.add_argument("--no-sqli-revalidate", action="store_true", help="Disable SQLMap re-validation pass")

    args = parser.parse_args()

    if args.target:
        if not args.target.startswith("http"):
            print("[!] Error: URL must start with http:// or https://")
            sys.exit(1)

        cookie_dict = parse_cookie_string(args.auth_cookie)
        header_dict = parse_headers_list(args.auth_header)

        sqlmap_options = {
            "auth_cookie": args.auth_cookie,
            "auth_headers": args.auth_header,
            "bearer_token": args.bearer_token,
            "tamper": args.tamper,
            "delay": args.sqlmap_delay,
            "revalidate": not args.no_sqli_revalidate,
            "request_headers": header_dict,
            "request_cookies": cookie_dict
        }
        run_automated_scan(args.target, mode=args.mode, sqlmap_options=sqlmap_options, scan_id=args.scan_id)
    else:
        parser.print_help()

