import json
import os
import sys
from uuid import uuid4

# Ensure parent directory is accessible
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runner import execute
from normalizer import Normalizer


# =========================
# CONFIGURATION
# =========================

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
DEFAULT_TIMEOUT = 420  # 7 min hard limit for process
RAW_OUTPUT_FILE = "ffuf.json"


def scan(target_url, wordlist=None, output_dir=None):
    """
    Stable + Fast FFUF discovery module.

    - Uses small wordlist for demo speed
    - Uses safe thread count (40)
    - Non-interactive mode
    - Filters noisy status codes
    - Parallel-safe temp output
    """

    print(f"[*] Starting FFUF discovery on {target_url}...")

    if not wordlist:
        wordlist = DEFAULT_WORDLIST

    # Allow engine presets like "small" / "large"
    WORDLIST_PRESETS = {
        "small": DEFAULT_WORDLIST,
        "large": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    }

    if isinstance(wordlist, str):
        wordlist = WORDLIST_PRESETS.get(wordlist.lower().strip(), wordlist)

    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found: {wordlist}")
        return []

    # Ensure correct URL format
    base_url = target_url if target_url.endswith("/") else f"{target_url}/"
    fuzz_url = f"{base_url}FUZZ"

    # Unique output file (thread-safe)
    output_file = f"ffuf_{uuid4().hex}.json"

    command = [
    "ffuf",
    "-u", fuzz_url,
    "-w", wordlist,
    "-o", output_file,
    "-of", "json",
    "-mc", "200,204,301,302,307,401,403",  # include 403
    "-t", "60",
    "-timeout", "2",
    "-noninteractive",
    "-k",
    "-s"
    ]
    execute(command, timeout=DEFAULT_TIMEOUT)

    findings = []

    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                content = f.read().strip()

                if not content:
                    print("[+] FFUF complete. Found 0 paths.")
                    return []

                data = json.loads(content)

                if output_dir:
                    try:
                        output_path = os.path.join(output_dir, RAW_OUTPUT_FILE)
                        with open(output_path, "w", encoding="utf-8") as out_f:
                            json.dump(data, out_f, indent=2)
                    except Exception as e:
                        print(f"[!] Failed to save FFUF output: {e}")

                for result in data.get("results", []):
                    finding = Normalizer.from_ffuf(result)
                    if finding:
                        findings.append(finding)

        except Exception as e:
            print(f"[!] Error parsing FFUF results: {e}")

        finally:
            try:
                os.remove(output_file)
            except Exception:
                pass

    print(f"[+] FFUF complete. Found {len(findings)} paths.")
    return findings


if __name__ == "__main__":
    if len(sys.argv) > 1:
        results = scan(sys.argv[1])
        print(json.dumps(results, indent=4))
    else:
        print("Usage: python3 ffuf.py <target_url>")
