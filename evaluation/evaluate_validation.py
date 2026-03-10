
#!/usr/bin/env python3
"""
Validation Effectiveness Evaluator (FYP Helper Script)

This script *does not modify or depend on your scanning/validation engine*.

It simply reads:
  1) combined_report.json   -> raw scan output (accepted but not modified)
  2) validated_report.json  -> post-validation output

And calculates three key metrics:

  - False Positive Rate (FPR)
      FPR = false_positive / total_findings

  - Validation Resolution Rate (VRR)
      VRR = (confirmed + false_positive) / total_findings

  - Manual Review Rate (MRR)
      MRR = needs_manual_review / total_findings

Results are:
  - printed to the terminal
  - saved to validation_metrics.json
"""

import json
import os
import sys
from typing import Any, Dict, Tuple


def load_json(path: str) -> Dict[str, Any]:
    """
    Load a JSON file and return it as a Python dictionary.

    This function is small and easy to explain in a viva:
    - It checks if the file exists
    - It opens the file safely
    - It parses JSON into a Python dictionary
    """
    if not os.path.exists(path):
        print(f"[-] File not found: {path}")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        print(f"[-] Failed to parse JSON from {path}: {exc}")
        sys.exit(1)


def extract_counts(validated: Dict[str, Any]) -> Tuple[int, int, int, int]:
    """
    Extract core counts from validated_report.json.

    We use:
      - total_findings
      - confirmed
      - false_positive
      - needs_manual_review

    We try to use the 'summary' section if it exists.
    If not, we recompute counts from 'validated_findings'.
    """
    summary = validated.get("summary", {}) or {}
    vf_list = validated.get("validated_findings", []) or []

    # 1. Get total_findings
    total = summary.get("total_findings")
    if not isinstance(total, int):
        total = len(vf_list)

    # 2. If summary already has counts, prefer them but fall back to recomputation
    confirmed = summary.get("confirmed")
    false_positive = summary.get("false_positive")
    needs_manual_review = summary.get("needs_manual_review")

    # If any of the counts are missing, recompute from validated_findings
    if not isinstance(confirmed, int) or not isinstance(false_positive, int) or not isinstance(
        needs_manual_review, int
    ):
        confirmed = 0
        false_positive = 0
        needs_manual_review = 0
        for item in vf_list:
            status = str(item.get("validation_status", "")).lower()
            if status == "confirmed":
                confirmed += 1
            elif status == "false_positive":
                false_positive += 1
            elif status == "needs_manual_review":
                needs_manual_review += 1

        # If summary existed, we keep total from there, but we still trust our recomputed counts.
        if not isinstance(total, int) or total <= 0:
            total = len(vf_list)

    return total, confirmed, false_positive, needs_manual_review


def compute_metrics(
    total: int,
    confirmed: int,
    false_positive: int,
    needs_manual_review: int,
) -> Dict[str, Any]:
    """
    Compute FPR, VRR, and MRR.

    All metrics are safe and simple:
      - If total == 0, all rates are 0.0 to avoid division by zero.
      - Values are rounded to 2 decimal places for reporting.
    """
    if total <= 0:
        fpr = 0.0
        vrr = 0.0
        mrr = 0.0
    else:
        fpr = false_positive / total
        vrr = (confirmed + false_positive) / total
        mrr = needs_manual_review / total

    return {
        "total_findings": total,
        "confirmed": confirmed,
        "false_positive": false_positive,
        "needs_manual_review": needs_manual_review,
        "false_positive_rate": round(fpr, 2),
        "validation_resolution_rate": round(vrr, 2),
        "manual_review_rate": round(mrr, 2),
    }
def compute_before_metrics(total_findings: int) -> Dict[str, Any]:
    """
    Metrics BEFORE validation.
    Assumption:
    - All scanner findings require manual review before validation.
    """
    return {
        "manual_review_rate_before": 1.0,
        "needs_manual_review_before": total_findings,
    }


def compute_comparison(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare BEFORE vs AFTER validation impact.
    """
    reduction = before["manual_review_rate_before"] - after["manual_review_rate"]

    return {
        "manual_review_rate_before": round(before["manual_review_rate_before"], 2),
        "manual_review_rate_after": round(after["manual_review_rate"], 2),
        "manual_review_reduction": round(reduction, 2),
    }


def save_metrics(path: str, metrics: Dict[str, Any]) -> None:
    """
    Save the metrics dictionary to a JSON file.

    This keeps the results easy to share in your report or append to your FYP appendix.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        print(f"[+] Metrics saved to: {path}")
    except Exception as exc:
        print(f"[-] Failed to save metrics to {path}: {exc}")


def print_metrics(metrics: Dict[str, Any]) -> None:
    """
    Print the metrics in a clear, viva-friendly format.
    """
    print("\n================= VALIDATION METRICS =================")
    print(f"Total findings          : {metrics['total_findings']}")
    print(f"  - Confirmed           : {metrics['confirmed']}")
    print(f"  - False positives     : {metrics['false_positive']}")
    print(f"  - Needs manual review : {metrics['needs_manual_review']}")
    print("------------------------------------------------------")
    print(f"False Positive Rate (FPR)         : {metrics['false_positive_rate']:.2f}")
    print(f"Validation Resolution Rate (VRR)  : {metrics['validation_resolution_rate']:.2f}")
    print(f"Manual Review Rate (MRR)          : {metrics['manual_review_rate']:.2f}")
    print("======================================================\n")


def main() -> int:
    """
    Main entry point.

    Usage:
        python3 evaluate_validation.py path/to/combined_report.json path/to/validated_report.json

    Note:
    - combined_report.json is accepted for completeness, but this script focuses on
      validated_report.json to measure how effective the validation step was.
    """
    if len(sys.argv) != 3:
        print("Usage: python3 evaluate_validation.py <combined_report.json> <validated_report.json>")
        return 1

    combined_path = sys.argv[1]
    validated_path = sys.argv[2]

    # Load files (combined_report is not modified; included for future extensions)
    _ = load_json(combined_path)  # currently unused, but kept for interface completeness
    validated = load_json(validated_path)

    # Extract counts from validated_report.json
    total, confirmed, false_positive, needs_manual_review = extract_counts(validated)

    # Compute metrics
    metrics = compute_metrics(
        total=total,
        confirmed=confirmed,
        false_positive=false_positive,
        needs_manual_review=needs_manual_review,
    )

    # BEFORE vs AFTER validation comparison
    before_metrics = compute_before_metrics(metrics["total_findings"])
    comparison = compute_comparison(before_metrics, metrics)
    
    metrics["comparison"] = comparison


    # Decide where to save metrics (same directory as validated_report.json)
    out_dir = os.path.dirname(os.path.abspath(validated_path)) or "."
    out_path = os.path.join(out_dir, "validation_metrics.json")

    # Output
    print_metrics(metrics)
    save_metrics(out_path, metrics)

    return 0


if __name__ == "__main__":
    sys.exit(main())
                                                                                                                                                                                                                                           
