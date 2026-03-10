import json
import os
from datetime import datetime

class ReportBuilder:
    @staticmethod
    def save(findings, filename="final_report.json"):
        """
        Consolidates all findings into a structured JSON report.
        """
        report_data = {
            "scan_info": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_findings": len(findings),
                "severity_counts": {
                    "CRITICAL": len([f for f in findings if f['severity'] == "CRITICAL"]),
                    "HIGH": len([f for f in findings if f['severity'] == "HIGH"]),
                    "MEDIUM": len([f for f in findings if f['severity'] == "MEDIUM"]),
                    "LOW": len([f for f in findings if f['severity'] == "LOW"]),
                    "INFO": len([f for f in findings if f['severity'] == "INFO"])
                }
            },
            "findings": findings
        }

        try:
            with open(filename, "w") as f:
                json.dump(report_data, f, indent=4)
            
            print(f"\n[✓] Report successfully generated: {filename}")
            
        except Exception as e:
            print(f"[!] Error building report: {e}")

    @staticmethod
    def print_summary(findings):
        """
        Displays a professional summary in the terminal.
        """
        print("\n" + "="*60)
        print(f"{'FINAL SCAN SUMMARY':^60}")
        print("="*60)
        
        if not findings:
            print(f"{'No findings identified.':^60}")
        else:
            for f in findings:
                sev = f.get('severity', 'INFO')
                name = f.get('finding_name', 'Unknown')
                url = f.get('url', 'N/A')
                
                # Check if it was validated by Phase 5 (SQLMap)
                status = " [VALIDATED]" if f.get('validated') else ""
                
                print(f"[{sev:^8}] {name}{status}")
                print(f"           Target: {url}\n")
        
        print("="*60)
