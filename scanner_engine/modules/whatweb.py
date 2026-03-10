import os
import sys
import re

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runner import execute
from normalizer import Normalizer


DEFAULT_TIMEOUT = 120
RAW_OUTPUT_FILE = "whatweb.txt"
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _split_whatweb_technologies(tech_section):
    """
    Split WhatWeb technology list by commas that are not inside brackets.
    Example:
    Object[a,b], PHP[8.1] -> ["Object[a,b]", "PHP[8.1]"]
    """
    parts = []
    current = []
    bracket_depth = 0

    for ch in tech_section:
        if ch == "[":
            bracket_depth += 1
            current.append(ch)
        elif ch == "]":
            if bracket_depth > 0:
                bracket_depth -= 1
            current.append(ch)
        elif ch == "," and bracket_depth == 0:
            item = "".join(current).strip()
            if item:
                parts.append(item)
            current = []
        else:
            current.append(ch)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)

    return parts


def _strip_ansi(text):
    if not text:
        return text
    return ANSI_ESCAPE_RE.sub("", text)


def scan(target_url, output_dir=None):
    """
    Runs WhatWeb and parses normal text output (compatible with v0.6.3).
    """

    print(f"[*] Fingerprinting {target_url} with WhatWeb...")

    command = [
        "whatweb",
        target_url,
        "-a", "1"
    ]

    raw_output = execute(command, timeout=DEFAULT_TIMEOUT)

    findings = []

    if not raw_output:
        print(f"[-] No output from WhatWeb on {target_url}")
        return []

    clean_output = _strip_ansi(raw_output)

    if output_dir:
        try:
            output_path = os.path.join(output_dir, RAW_OUTPUT_FILE)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(clean_output)
        except Exception as e:
            print(f"[!] Failed to save WhatWeb output: {e}")

    # Example output format:
    # http://testphp.vulnweb.com [200 OK] Apache[2.4.41], PHP[7.4.3], nginx

    # Extract technology section after URL
    try:
        match = re.search(r"\[(.*?)\]\s*(.*)", clean_output)
        if match:
            tech_section = match.group(2)
            technologies = _split_whatweb_technologies(tech_section)

            for tech in technologies:
                if tech:
                    findings.append(
                        Normalizer.create_finding(
                            tool="whatweb",
                            url=target_url,
                            finding_name=f"Technology Detected: {tech}",
                            severity="INFO",
                            description=f"Detected technology: {tech}",
                            raw=clean_output,
                            category="reconnaissance"
                        )
                    )

    except Exception as e:
        print(f"[!] Error parsing WhatWeb output: {e}")

    print(f"[+] WhatWeb complete. Identified {len(findings)} technologies.")
    return findings
