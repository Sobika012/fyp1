"""
Validation Engine package (FYP-friendly).

Goal:
- Read combined_report.json (multi-phase, multi-tool scan output)
- Extract + normalize findings into a common structure
- Group by vulnerability class (not by tool)
- Validate with simple, class-based logic to reduce false positives
- Output validated_report.json
"""


