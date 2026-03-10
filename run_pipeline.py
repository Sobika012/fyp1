    
#!/usr/bin/env python3
import re
import sys
import subprocess
import argparse
from pathlib import Path


# -----------------------------
# CONFIG (edit only if needed)
# -----------------------------
ENGINE_CMD = ["python3", "scanner_engine/engine.py"]
EVALUATOR_CMD = ["python3", "evaluation/evaluate_validation.py"]
PRIORITIZER_CMD = ["python3", "prioritize_findings.py"]

# Where we will output validated report inside the scan folder
VALIDATED_FILENAME = "validated_report.json"   # you can change to validated_report_raw2.json if you want


# -----------------------------
# Helpers
# -----------------------------
def run_capture(cmd, cwd=None):
    """Run command, capture stdout/stderr, print them, return stdout."""
    print("\n[RUN]", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)
    return proc.stdout


def run(cmd, cwd=None):
    """Run command, inherit terminal output (no capture)."""
    print("\n[RUN]", " ".join(cmd))
    subprocess.check_call(cmd, cwd=cwd)


def detect_scan_folder_from_engine_output(engine_stdout: str, project_root: Path) -> Path:
    """
    Engine prints: Output directory: scans/output/<folder>
    We resolve that relative to the same project_root used to run engine.
    """
    m = re.search(r"Output directory:\s*(.+)", engine_stdout)
    if not m:
        print("[-] Could not detect 'Output directory' from engine output.")
        sys.exit(1)

    rel = m.group(1).strip()  # e.g. scans/output/20260226_...
    scan_folder = (project_root / rel).resolve()
    return scan_folder



def find_validator_script() -> Path | None:
    """
    Try common locations for your validator script.
    We assume validator takes: <combined_report.json> <validated_report.json>
    """
    candidates = [
        Path("validation/validate.py"),
        Path("validation/validator.py"),
        Path("validation/run_validation.py"),
        Path("validator/validate.py"),
        Path("validator/validator.py"),
        Path("validation_engine/validate.py"),
        Path("validation_engine/validator.py"),
        Path("validation_script.py"),
        Path("validate.py"),
    ]
    for p in candidates:
        if p.exists():
            return p.resolve()
    return None


def build_validator_cmd(validator_path: Path, combined_path: Path, validated_out: Path) -> list[str]:
    """
    Most common interface: python3 <validator.py> <combined> <validated_out>
    If your validator needs different args, edit this function.
    """
    return ["python3", str(validator_path), str(combined_path), str(validated_out)]


# -----------------------------
# Main pipeline
# -----------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_pipeline.py <target_url> [basic|deep]")
        sys.exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("mode", choices=["basic", "deep"])
    parser.add_argument("--scan-id", default=None)
    args = parser.parse_args()

    url = args.url
    mode = args.mode
    
    project_root = Path(__file__).parent.resolve()

    # 1) Run scanner engine and capture output
    engine_cmd = ENGINE_CMD + [url, "--mode", mode]
    if args.scan_id:
        engine_cmd += ["--scan-id", args.scan_id]

    engine_stdout = run_capture(engine_cmd, cwd=str(project_root))
    # 2) Get the exact scan folder created in THIS run
    scan_folder = detect_scan_folder_from_engine_output(engine_stdout, project_root)
    print("[+] Using scan folder:", scan_folder)

    # 3) Locate combined_report.json from this scan
    combined = scan_folder / "combined_report.json"
    if not combined.exists():
        # fallback: some runs may produce combined_report_raw.json
        raw = scan_folder / "combined_report_raw.json"
        if raw.exists():
            print("[!] combined_report.json not found, using combined_report_raw.json instead.")
            combined = raw
        else:
            print("[-] No combined report found in scan folder.")
            print("Expected:", scan_folder / "combined_report.json")
            sys.exit(1)

    # 4) Validation step (Option B) - validator takes ONLY combined_report path
    validated = scan_folder / VALIDATED_FILENAME

    print("[+] Running validator on:", combined)
    run(["python3", "-m", "validation.run_validator", str(combined)], cwd=str(project_root))

    # Validator may write output with different names; try to find it
    possible_validated = [
        scan_folder / "validated_report.json",
        scan_folder / "validated_report_raw.json",
        scan_folder / "validated_report_raw2.json",
        scan_folder / "validated_report.jsonl", 
    ]

    validated_found = None
    for p in possible_validated:
        if p.exists():
            validated_found = p
            break

    if validated_found is None:
        print("\n[-] Validator ran but no validated report was found in scan folder.")
        print("Checked:", [str(p) for p in possible_validated])
        sys.exit(1)

    validated = validated_found
    print("[+] Validated report:", validated)
    
    # 5) Evaluation metrics
    run(EVALUATOR_CMD + [str(combined), str(validated)], cwd=str(project_root))

    # 6) Prioritization
    run(PRIORITIZER_CMD + [str(validated)], cwd=str(project_root))

    # 7) Final confirmation
    metrics = scan_folder / "validation_metrics.json"
    prioritized = scan_folder / "prioritized_report.json"

    print("\n✅ Pipeline complete.")
    print("Outputs:")
    print(" -", combined)
    print(" -", validated)
    print(" -", metrics if metrics.exists() else "(missing) validation_metrics.json")
    print(" -", prioritized if prioritized.exists() else "(missing) prioritized_report.json")


if __name__ == "__main__":
    main()

