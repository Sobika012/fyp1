#!/usr/bin/env python3

import os
import sys

from validation.engine import ValidationEngine
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 -m validation.run_validator <combined_report.json | combined_report.jsonl>")
        sys.exit(1)

    input_path = sys.argv[1]

    if not os.path.exists(input_path):
        print(f"File not found: {input_path}")
        sys.exit(1)

    # Output file next to input, regardless of .json or .jsonl
    from pathlib import Path
    in_path = Path(input_path)
    # Always save in the same directory with a clean name
    output_path = str(in_path.with_name("validated_report.json"))
    
    engine = ValidationEngine()
    engine.run(input_path, output_path)

    print("[+] Validation completed")
    print(f"[+] Output saved to: {output_path}")


if __name__ == "__main__":
    main()

