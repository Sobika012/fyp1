import os
import json
import sys
from uuid import uuid4

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runner import execute
from normalizer import Normalizer

RAW_OUTPUT_FILE = "nuclei.jsonl"

# -------------------------
# BASIC / DEEP configs
# -------------------------

# BASIC: fast + meaningful (exposure/misconfig/tech)
BASIC_RATE_LIMIT = "25"
BASIC_CONCURRENCY = "10"          # ✅ changed (was 5)
BASIC_TIMEOUT_PER_REQUEST = "2"   # ✅ changed (was 3)
BASIC_RETRIES = "1"

# DEEP: wider coverage (slower)
DEEP_RATE_LIMIT = "40"
DEEP_CONCURRENCY = "10"
DEEP_TIMEOUT_PER_REQUEST = "5"
DEEP_RETRIES = "1"

DEEP_TAGS = "sqli,xss,rce,lfi,ssrf,xxe,ssti,open-redirect,csrf,misconfig,exposure,headers,tech"
DEEP_SEVERITY = "critical,high,medium,low,info"


def _find_templates_dir():
    """
    Try common nuclei templates locations.
    Priority:
      1) env NUCLEI_TEMPLATES
      2) ~/.local/nuclei-templates
      3) /usr/share/nuclei-templates
      4) /usr/share/nuclei-templates/http (fallback)
    """
    candidates = [
        os.environ.get("NUCLEI_TEMPLATES", "").strip(),
        os.path.expanduser("~/.local/nuclei-templates"),
        "/usr/share/nuclei-templates",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return os.path.expanduser("~/.local/nuclei-templates")


def scan(target_url=None, urls=None, is_file_input=False, output_dir=None, timeout=120, mode="basic"):
    """
    Nuclei scan (root URL or list via -l).
    - ALWAYS writes jsonl to a temp out_file then parses it.
    - BASIC: runs limited template folders (-t) => fast + stable results.
    - DEEP: runs tags+severity (broader coverage).
    Compatible with your runner.execute() that returns stdout/None.
    """

    findings = []
    mode = (mode or "basic").lower().strip()
    templates_dir = _find_templates_dir()

    # unique output (parallel-safe)
    out_file = f"nuclei_{uuid4().hex}.jsonl"

    # -------------------------
    # Build targets input
    # -------------------------
    tmp_list = None
    use_list = False

    if urls and isinstance(urls, (list, tuple)) and len(urls) > 0:
        use_list = True
        tmp_list = f"nuclei_targets_{uuid4().hex}.txt"
        with open(tmp_list, "w", encoding="utf-8") as f:
            for u in urls:
                if u:
                    f.write(u.strip() + "\n")
    else:
        if not target_url:
            return []
        target_url = target_url.strip()

    # -------------------------
    # Performance tuning
    # -------------------------
    if mode == "basic":
        rate_limit = BASIC_RATE_LIMIT
        concurrency = BASIC_CONCURRENCY
        req_timeout = BASIC_TIMEOUT_PER_REQUEST
        retries = BASIC_RETRIES
    else:
        rate_limit = DEEP_RATE_LIMIT
        concurrency = DEEP_CONCURRENCY
        req_timeout = DEEP_TIMEOUT_PER_REQUEST
        retries = DEEP_RETRIES

    # -------------------------
    # Build nuclei command
    # -------------------------
    cmd = [
        "nuclei",
        "-jsonl",
        "-silent",
        "-ni",
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-timeout", str(req_timeout),
        "-retries", str(retries),
        "-max-host-error", "5",
        "-o", out_file,
    ]

    # Targets
    if use_list and tmp_list:
        cmd.extend(["-l", tmp_list])
        print(f"[*] Starting Nuclei scan on {len(urls)} URLs (list input)...")
    else:
        cmd.extend(["-u", target_url])
        print(f"[*] Starting Nuclei scan on {target_url}...")

    # -------------------------
    # MODE behavior
    # -------------------------
    if mode == "basic":
        # ✅ BASIC: limited folders only => fast + results aaucha
        basic_template_paths = [
            os.path.join(templates_dir, "http", "exposures"),
            os.path.join(templates_dir, "http", "misconfiguration"),
            os.path.join(templates_dir, "http", "technologies", "eol"),
        ]
        added_any = False
        for p in basic_template_paths:
            if os.path.exists(p):
                cmd.extend(["-t", p])
                added_any = True

        # fallback if templates folder missing
        if not added_any:
            # tags fallback (still gives output)
            cmd.extend(["-tags", "exposure,misconfig,headers,tech,dns,discovery"])

    else:
        # DEEP: use tags + severity
        cmd.extend(["-tags", DEEP_TAGS])
        cmd.extend(["-severity", DEEP_SEVERITY])

    # -------------------------
    # Run nuclei (your runner prints timeout itself)
    # -------------------------
    execute(cmd, timeout=timeout)

    # -------------------------
    # Parse jsonl results (even if timeout)
    # -------------------------
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        finding = Normalizer.from_nuclei(obj)
                        if finding:
                            findings.append(finding)
                    except Exception:
                        continue

            # Save raw file into output_dir (optional)
            if output_dir:
                try:
                    dest = os.path.join(output_dir, RAW_OUTPUT_FILE)
                    with open(out_file, "r", encoding="utf-8", errors="ignore") as src, open(dest, "w", encoding="utf-8") as dst:
                        dst.write(src.read())
                except Exception:
                    pass

        finally:
            try:
                os.remove(out_file)
            except Exception:
                pass

    # cleanup tmp list
    if tmp_list:
        try:
            os.remove(tmp_list)
        except Exception:
            pass

    print(f"[+] Nuclei finished. Found {len(findings)} issues.")
    return findings


if __name__ == "__main__":
    if len(sys.argv) > 1:
        results = scan(target_url=sys.argv[1], mode="basic", timeout=150)
        print(json.dumps(results, indent=2))
    else:
        print("Usage: python3 nuclei.py <target_url>")
