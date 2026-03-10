import json
from datetime import datetime

class ReportBuilder:
    @staticmethod
    def save(findings, filename="combined_report.json"):
        """
        Saves the list of findings into a pretty-printed JSON file.
        """
        # Create a summary of what was found
        report_data = {
            "scan_info": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_findings": len(findings),
                "severity_counts": {
                    "CRITICAL": len([f for f in findings if (f.get("severity") or "").upper() == "CRITICAL"]),
                    "HIGH": len([f for f in findings if (f.get("severity") or "").upper() == "HIGH"]),
                    "MEDIUM": len([f for f in findings if (f.get("severity") or "").upper() == "MEDIUM"]),
                    "LOW": len([f for f in findings if (f.get("severity") or "").upper() == "LOW"]),
                    "INFO": len([f for f in findings if (f.get("severity") or "").upper() == "INFO"])
                }
            },
            "findings": findings
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                # indent=4 makes the JSON readable for humans
                json.dump(report_data, f, indent=4)
            
            print(f"\n[✓] Report successfully generated: {filename}")
            print(f"[*] Summary: {report_data['scan_info']['total_findings']} total issues found.")
            
        except Exception as e:
            print(f"[!] Error building report: {e}")

    @staticmethod
    def print_summary(findings):
        """
        Prints a quick color-coded summary to the terminal.
        """
        print("\n" + "="*40)
        print("         SCAN SUMMARY")
        print("="*40)
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            # Simple terminal highlighting
            if sev == "CRITICAL":
                print(f"[CRITICAL] {f.get('finding_name', 'Unknown')} -> {f.get('url', '')}")
            elif sev == "HIGH":
                print(f"[HIGH]     {f.get('finding_name', 'Unknown')} -> {f.get('url', '')}")
            else:
                print(f"[{sev}] {f.get('finding_name', 'Unknown')}")
        print("="*40)
