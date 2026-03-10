import os
import sys
import re
import json
from urllib.parse import urlparse, parse_qs

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runner import execute
from normalizer import Normalizer


DEFAULT_TIMEOUT = 600  # 10 minutes (safe upper bound)
RAW_OUTPUT_FILE = "sqlmap.txt"


def extract_vulnerable_parameter(output_text: str):
    """
    Extract vulnerable parameter name from SQLMap output.
    """
    match = re.search(r"parameter '([^']+)'", output_text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def extract_dbms(output_text: str):
    """
    Extract detected backend DBMS from SQLMap output.
    """
    match = re.search(r"back-end DBMS: ([^\n]+)", output_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def is_target_testable(target):
    if isinstance(target, str):
        return "?" in target

    if not isinstance(target, dict):
        return False

    url = target.get("url", "")
    data = target.get("data", "")
    method = str(target.get("method", "GET")).upper()

    if method == "GET":
        return "?" in url

    return bool(url and data)


def build_headers_string(auth_headers):
    if not auth_headers:
        return None

    if isinstance(auth_headers, list):
        return "\n".join([h for h in auth_headers if isinstance(h, str) and h.strip()])

    if isinstance(auth_headers, dict):
        out = []
        for k, v in auth_headers.items():
            if str(k).strip() and str(v).strip():
                out.append(f"{k}: {v}")
        return "\n".join(out) if out else None

    return None


def build_sqlmap_command(target, options):
    opts = options or {}

    if isinstance(target, str):
        target = {
            "url": target,
            "method": "GET",
            "type": "get"
        }

    url = target.get("url", "")
    method = str(target.get("method", "GET")).upper()
    data = target.get("data")
    is_json = bool(target.get("is_json", False))

    command = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--level", str(opts.get("level", 1)),
        "--risk", str(opts.get("risk", 1)),
        "--flush-session",
        "--threads", str(opts.get("threads", 3))
    ]

    if opts.get("random_agent", True):
        command.append("--random-agent")

    # POST/form/json support
    if method == "POST":
        command.extend(["--method", "POST"])
        if data:
            command.extend(["--data", data])

    if is_json:
        command.append("--json")

    # Auth/session support
    auth_cookie = opts.get("auth_cookie")
    if auth_cookie:
        command.extend(["--cookie", auth_cookie])

    auth_headers = build_headers_string(opts.get("auth_headers"))
    bearer_token = opts.get("bearer_token")

    if bearer_token:
        bearer_header = f"Authorization: Bearer {bearer_token}"
        if auth_headers:
            auth_headers = f"{auth_headers}\n{bearer_header}"
        else:
            auth_headers = bearer_header

    if is_json:
        ct_header = "Content-Type: application/json"
        if auth_headers:
            # Add header only if not already present
            if "content-type:" not in auth_headers.lower():
                auth_headers = f"{auth_headers}\n{ct_header}"
        else:
            auth_headers = ct_header

    if auth_headers:
        command.extend(["--headers", auth_headers])

    # WAF/tamper controls
    tamper = opts.get("tamper")
    if tamper:
        if isinstance(tamper, list):
            tamper = ",".join([t for t in tamper if isinstance(t, str) and t.strip()])
        if isinstance(tamper, str) and tamper.strip():
            command.extend(["--tamper", tamper])

    delay = opts.get("delay")
    if delay is not None:
        try:
            delay_val = float(delay)
            if delay_val > 0:
                command.extend(["--delay", str(delay_val)])
        except Exception:
            pass

    return command


def get_target_label(target):
    if isinstance(target, str):
        return target

    url = target.get("url", "")
    method = str(target.get("method", "GET")).upper()
    target_type = target.get("type", "unknown")
    return f"{method} {url} ({target_type})"


def build_revalidation_command(command, options):
    opts = options or {}
    rv_level = str(opts.get("revalidate_level", max(2, int(opts.get("level", 1)))))
    rv_risk = str(opts.get("revalidate_risk", opts.get("risk", 1)))

    return command + [
        "--fresh-queries",
        "--smart",
        "--level", rv_level,
        "--risk", rv_risk
    ]


def parse_param_names(target):
    if isinstance(target, str):
        q = urlparse(target).query
        return sorted(parse_qs(q).keys())

    if not isinstance(target, dict):
        return []

    method = str(target.get("method", "GET")).upper()
    url = target.get("url", "")
    data = str(target.get("data", "") or "")
    is_json = bool(target.get("is_json", False))

    if method == "GET":
        return sorted(parse_qs(urlparse(url).query).keys())

    if is_json:
        try:
            payload = json.loads(data)
            if isinstance(payload, dict):
                return sorted([str(k) for k in payload.keys()])
        except Exception:
            return []

    try:
        return sorted(parse_qs(data).keys())
    except Exception:
        return []


def scan(target, output_dir=None, options=None):
    """
    Runs SQLMap to confirm SQL Injection vulnerability.
    Supports URL GET, POST form and JSON targets.
    Returns standardized findings list.
    """

    if not is_target_testable(target):
        print(f"[-] Skipping SQLMap (target not testable): {get_target_label(target)}")
        return []

    target_url = target if isinstance(target, str) else target.get("url", "")
    command = build_sqlmap_command(target, options)
    print(f"[*] Launching SQLMap on suspect target: {get_target_label(target)}")

    raw_output = execute(command, timeout=DEFAULT_TIMEOUT)

    if not raw_output:
        print(f"[-] No response from SQLMap on {get_target_label(target)}")
        return []

    if output_dir:
        try:
            output_path = os.path.join(output_dir, RAW_OUTPUT_FILE)
            with open(output_path, "a", encoding="utf-8") as f:
                f.write(f"=== SQLMap Output: {get_target_label(target)} ===\n")
                f.write(raw_output)
                f.write("\n\n")
        except Exception as e:
            print(f"[!] Failed to save SQLMap output: {e}")

    findings = []
    stdout_lower = raw_output.lower()

    # ================================
    # Vulnerability Detection Patterns
    # ================================

    vulnerable_patterns = [
        r"is vulnerable",
        r"appears to be injectable",
        r"parameter .* is vulnerable",
        r"sql injection vulnerability",
        r"back-end dbms"
    ]

    is_vulnerable = any(re.search(pattern, stdout_lower) for pattern in vulnerable_patterns)

    if not is_vulnerable:
        print(f"[-] SQLMap did not confirm vulnerability on {get_target_label(target)}")
        return []

    # ================================
    # Extract extra info
    # ================================

    vulnerable_param = extract_vulnerable_parameter(raw_output)
    dbms = extract_dbms(raw_output)
    tested_params = parse_param_names(target)

    revalidate_enabled = True if options is None else bool(options.get("revalidate", True))
    revalidated = None
    revalidation_output = ""

    if revalidate_enabled:
        revalidation_command = build_revalidation_command(command, options)
        revalidation_output = execute(revalidation_command, timeout=DEFAULT_TIMEOUT) or ""

        rv_lower = revalidation_output.lower()
        rv_patterns = [
            r"is vulnerable",
            r"appears to be injectable",
            r"parameter .* is vulnerable",
            r"sql injection vulnerability",
            r"back-end dbms"
        ]
        revalidated = any(re.search(pattern, rv_lower) for pattern in rv_patterns)
    else:
        revalidated = True

    description_parts = []

    if vulnerable_param:
        description_parts.append(f"Vulnerable Parameter: {vulnerable_param}")

    if dbms:
        description_parts.append(f"Backend DBMS: {dbms}")

    if tested_params:
        description_parts.append(f"Tested Parameters: {', '.join(tested_params)}")

    description_parts.append(f"HTTP Method: {str((target.get('method', 'GET') if isinstance(target, dict) else 'GET')).upper()}")

    if isinstance(target, dict) and target.get("type"):
        description_parts.append(f"Target Type: {target.get('type')}")

    if revalidate_enabled:
        description_parts.append(f"Revalidation: {'passed' if revalidated else 'failed'}")

    description_parts.append("SQLMap confirmed injectable parameter.")

    description = " | ".join(description_parts)

    finding_name = "SQL Injection Confirmed" if revalidated else "SQL Injection Suspected (Revalidation Failed)"
    severity = "CRITICAL" if revalidated else "HIGH"
    combined_raw = raw_output
    if revalidation_output:
        combined_raw = f"{raw_output}\n\n=== REVALIDATION ===\n{revalidation_output}"

    standardized = Normalizer.create_finding(
        tool="sqlmap",
        url=target_url,
        finding_name=finding_name,
        severity=severity,
        description=description,
        raw=combined_raw
    )

    findings.append(standardized)

    if revalidated:
        print(f"[!] SQLMap CONFIRMED vulnerability on {get_target_label(target)}")
    else:
        print(f"[!] SQLMap suspected vulnerability but failed revalidation on {get_target_label(target)}")

    return findings


if __name__ == "__main__":
    if len(sys.argv) > 1:
        import json
        results = scan(sys.argv[1])
        print(json.dumps(results, indent=4))
    else:
        print("Usage: python3 sqlmap.py <url_with_parameters>")
