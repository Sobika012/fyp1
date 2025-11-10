#!/bin/bash
# Usage: ./run_basic_scans.sh <target_ip_or_host>
TARGET="$1"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target_ip_or_host>"
  exit 1
fi
OUTDIR="$(pwd)/scans/output/$(date +%Y%m%d_%H%M%S)_${TARGET}"
mkdir -p "$OUTDIR"

echo "[*] nmap - service detection for $TARGET"
nmap -sV -oN "$OUTDIR/nmap_basic.txt" "$TARGET"

echo "[*] nikto - web scan for $TARGET"
# if user passed a URL use it, otherwise assume http://<target>
if [[ "$TARGET" =~ ^https?:// ]]; then
  NIKTO_TARGET="$TARGET"
else
  NIKTO_TARGET="http://${TARGET}"
fi
nikto -h "$NIKTO_TARGET" -o "$OUTDIR/nikto_basic.txt"

echo "[*] sqlmap - quick safe scan (will not run heavy destructive flags)"
# only run sqlmap if a parameter-like URL is provided, try to detect '?'
if [[ "$TARGET" == *"?"* ]]; then
  sqlmap -u "$TARGET" --batch --level=1 --risk=1 --threads=1 --output-dir="$OUTDIR/sqlmap_results" || true
else
  echo "[i] sqlmap skipped: no query string detected in target URL"
fi

echo "[*] Done. Outputs saved: $OUTDIR"
